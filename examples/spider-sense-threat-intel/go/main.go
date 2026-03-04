package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"

	clawdstrike "github.com/backbay-labs/clawdstrike-go"
	"github.com/backbay-labs/clawdstrike-go/guards"
)

const (
	threshold     = 0.86
	ambiguityBand = 0.06
)

type behaviorProfilesDoc struct {
	Profiles []behaviorProfile `json:"profiles"`
}

type behaviorProfile struct {
	ProfileID          string    `json:"profile_id"`
	Embedding          []float64 `json:"embedding"`
	DriftWarnThreshold float64   `json:"drift_warn_threshold"`
	DriftDenyThreshold float64   `json:"drift_deny_threshold"`
}

type scenariosDoc struct {
	Scenarios []scenario `json:"scenarios"`
}

type scenario struct {
	ScenarioID string    `json:"scenario_id"`
	ProfileID  string    `json:"profile_id"`
	Embedding  []float64 `json:"embedding"`
}

type patternEntry struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	Stage     string    `json:"stage"`
	Label     string    `json:"label"`
	Embedding []float64 `json:"embedding"`
}

type normalizedRow struct {
	ScenarioID             string                 `json:"scenario_id"`
	ProfileID              string                 `json:"profile_id"`
	SpiderVerdict          string                 `json:"spider_verdict"`
	DecisionStatus         string                 `json:"decision_status"`
	Severity               string                 `json:"severity"`
	TopScore               float64                `json:"top_score"`
	TopMatch               map[string]interface{} `json:"top_match"`
	ProfileSimilarity      float64                `json:"profile_similarity"`
	ProfileDriftScore      float64                `json:"profile_drift_score"`
	ProfileDriftState      string                 `json:"profile_drift_state"`
	CombinedRecommendation string                 `json:"combined_recommendation"`
}

func main() {
	policy := flag.String("policy", "baseline", "policy tier: baseline|hardened")
	scenarioID := flag.String("scenario", "all", "scenario id or 'all'")
	jsonOut := flag.Bool("json", false, "emit JSON output")
	flag.Parse()

	if *policy != "baseline" && *policy != "hardened" {
		failf("invalid --policy: %s", *policy)
	}

	exampleRoot := filepath.Clean(filepath.Join(".", ".."))
	if err := os.Chdir(exampleRoot); err != nil {
		failf("chdir %s: %v", exampleRoot, err)
	}

	policyPath := "policy.baseline.yaml"
	if *policy == "hardened" {
		policyPath = "policy.hardened.yaml"
	}

	var profilesDoc behaviorProfilesDoc
	if err := loadJSON(filepath.Join("data", "behavior_profiles.json"), &profilesDoc); err != nil {
		failf("load behavior profiles: %v", err)
	}
	profilesByID := make(map[string]behaviorProfile, len(profilesDoc.Profiles))
	for _, p := range profilesDoc.Profiles {
		profilesByID[p.ProfileID] = p
	}

	var scenariosDoc scenariosDoc
	if err := loadJSON(filepath.Join("data", "scenarios.json"), &scenariosDoc); err != nil {
		failf("load scenarios: %v", err)
	}
	var patternDB []patternEntry
	if err := loadJSON(filepath.Join("data", "pattern_db.s2intel-v1.json"), &patternDB); err != nil {
		failf("load pattern DB: %v", err)
	}

	selected := make([]scenario, 0, len(scenariosDoc.Scenarios))
	for _, s := range scenariosDoc.Scenarios {
		if *scenarioID == "all" || s.ScenarioID == *scenarioID {
			selected = append(selected, s)
		}
	}
	if len(selected) == 0 {
		failf("scenario not found: %s", *scenarioID)
	}

	cs, err := clawdstrike.FromPolicy(policyPath)
	if err != nil {
		failf("load policy %s: %v", policyPath, err)
	}

	rows := make([]normalizedRow, 0, len(selected))
	for _, s := range selected {
		profile, ok := profilesByID[s.ProfileID]
		if !ok {
			failf("missing profile %s for scenario %s", s.ProfileID, s.ScenarioID)
		}

		decision := cs.Check(guards.Custom("spider_sense", map[string]interface{}{
			"embedding": floatSliceToAny(s.Embedding),
		}))
		details := asMap(decision.Details)
		screenTopScore, screenTopMatch := screenEmbedding(s.Embedding, patternDB)
		topMatch := screenTopMatch
		if len(topMatch) == 0 {
			topMatch = asMap(details["top_match"])
		}
		spiderVerdict := verdictFromTopScore(screenTopScore)
		decisionStatus := statusFromVerdict(spiderVerdict)
		severity := severityFromVerdict(spiderVerdict)

		profileSimilarity := clamp(cosine(profile.Embedding, s.Embedding), -1.0, 1.0)
		profileDrift := clamp(1.0-profileSimilarity, 0.0, 2.0)
		driftState := classifyDrift(profile, profileDrift)
		recommendation := combinedRecommendation(decisionStatus, driftState)

		row := normalizedRow{
			ScenarioID:     s.ScenarioID,
			ProfileID:      s.ProfileID,
			SpiderVerdict:  spiderVerdict,
			DecisionStatus: decisionStatus,
			Severity:       severity,
			TopScore:       screenTopScore,
			TopMatch: map[string]interface{}{
				"id":       topMatch["id"],
				"category": topMatch["category"],
				"stage":    topMatch["stage"],
				"label":    topMatch["label"],
			},
			ProfileSimilarity:      profileSimilarity,
			ProfileDriftScore:      profileDrift,
			ProfileDriftState:      driftState,
			CombinedRecommendation: recommendation,
		}
		rows = append(rows, row)
	}

	if *jsonOut {
		payload := map[string]interface{}{
			"policy": *policy,
			"rows":   rows,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			failf("encode output: %v", err)
		}
		return
	}

	fmt.Printf("=== Spider-Sense Threat Intel Example (Go, %s) ===\n\n", *policy)
	fmt.Printf("%-32s %-6s %-10s %-7s %-7s %-10s %s\n",
		"scenario", "status", "verdict", "top", "drift", "drift_state", "recommendation")
	fmt.Println("------------------------------------------------------------------------------------------------")
	for _, row := range rows {
		fmt.Printf("%-32s %-6s %-10s %-7.3f %-7.3f %-10s %s\n",
			row.ScenarioID,
			row.DecisionStatus,
			row.SpiderVerdict,
			row.TopScore,
			row.ProfileDriftScore,
			row.ProfileDriftState,
			row.CombinedRecommendation,
		)
		if id, ok := row.TopMatch["id"].(string); ok && id != "" {
			fmt.Printf("  top_match: %s (%v/%v)\n", id, row.TopMatch["category"], row.TopMatch["stage"])
		}
	}
}

func loadJSON(path string, out interface{}) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func floatSliceToAny(values []float64) []interface{} {
	out := make([]interface{}, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	return out
}

func cosine(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	denom := math.Sqrt(na) * math.Sqrt(nb)
	if denom == 0 || math.IsNaN(denom) || math.IsInf(denom, 0) {
		return 0
	}
	return dot / denom
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func classifyDrift(profile behaviorProfile, drift float64) string {
	if drift >= profile.DriftDenyThreshold {
		return "anomalous"
	}
	if drift >= profile.DriftWarnThreshold {
		return "elevated"
	}
	return "normal"
}

func combinedRecommendation(decisionStatus, driftState string) string {
	if decisionStatus == "deny" {
		return "block"
	}
	if decisionStatus == "warn" && driftState == "anomalous" {
		return "block"
	}
	if decisionStatus == "warn" {
		return "review"
	}
	if driftState == "anomalous" {
		return "review_high"
	}
	if driftState == "elevated" {
		return "review"
	}
	return "allow"
}

func asMap(value interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	if typed, ok := value.(map[string]interface{}); ok {
		return typed
	}
	return map[string]interface{}{}
}

func screenEmbedding(embedding []float64, patterns []patternEntry) (float64, map[string]interface{}) {
	if len(patterns) == 0 {
		return 0, map[string]interface{}{}
	}
	bestScore := math.Inf(-1)
	var best patternEntry
	found := false
	for _, pattern := range patterns {
		score := cosine(embedding, pattern.Embedding)
		if score > bestScore {
			bestScore = score
			best = pattern
			found = true
		}
	}
	if !found || math.IsNaN(bestScore) || math.IsInf(bestScore, 0) {
		return 0, map[string]interface{}{}
	}
	return bestScore, map[string]interface{}{
		"id":       best.ID,
		"category": best.Category,
		"stage":    best.Stage,
		"label":    best.Label,
	}
}

func verdictFromTopScore(score float64) string {
	if score >= threshold+ambiguityBand {
		return "deny"
	}
	if score <= threshold-ambiguityBand {
		return "allow"
	}
	return "ambiguous"
}

func statusFromVerdict(verdict string) string {
	switch verdict {
	case "deny":
		return "deny"
	case "ambiguous":
		return "warn"
	default:
		return "allow"
	}
}

func severityFromVerdict(verdict string) string {
	switch verdict {
	case "deny":
		return "error"
	case "ambiguous":
		return "warning"
	default:
		return "info"
	}
}

func failf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
