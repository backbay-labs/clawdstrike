package guards

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// OriginProvider identifies the provider that produced an origin-aware event.
// Well-known providers use constants, but custom string values are also valid.
type OriginProvider string

const (
	OriginProviderSlack   OriginProvider = "slack"
	OriginProviderTeams   OriginProvider = "teams"
	OriginProviderGitHub  OriginProvider = "github"
	OriginProviderJira    OriginProvider = "jira"
	OriginProviderEmail   OriginProvider = "email"
	OriginProviderDiscord OriginProvider = "discord"
	OriginProviderWebhook OriginProvider = "webhook"
)

// SpaceType identifies the type of container an origin event came from.
// Custom string values are allowed.
type SpaceType string

const (
	SpaceTypeChannel     SpaceType = "channel"
	SpaceTypeGroup       SpaceType = "group"
	SpaceTypeDM          SpaceType = "dm"
	SpaceTypeThread      SpaceType = "thread"
	SpaceTypeIssue       SpaceType = "issue"
	SpaceTypeTicket      SpaceType = "ticket"
	SpaceTypePullRequest SpaceType = "pull_request"
	SpaceTypeEmailThread SpaceType = "email_thread"
)

// Visibility identifies the origin container's visibility level.
type Visibility string

const (
	VisibilityPrivate        Visibility = "private"
	VisibilityInternal       Visibility = "internal"
	VisibilityPublic         Visibility = "public"
	VisibilityExternalShared Visibility = "external_shared"
	VisibilityUnknown        Visibility = "unknown"
)

// ActorType identifies the actor class that triggered the origin event.
type ActorType string

const (
	ActorTypeHuman   ActorType = "human"
	ActorTypeBot     ActorType = "bot"
	ActorTypeService ActorType = "service"
	ActorTypeUnknown ActorType = "unknown"
)

// ProvenanceConfidence indicates how strong the origin provenance evidence is.
type ProvenanceConfidence string

const (
	ProvenanceConfidenceStrong  ProvenanceConfidence = "strong"
	ProvenanceConfidenceMedium  ProvenanceConfidence = "medium"
	ProvenanceConfidenceWeak    ProvenanceConfidence = "weak"
	ProvenanceConfidenceUnknown ProvenanceConfidence = "unknown"
)

// OriginContext is the canonical origin-aware request context.
// It marshals using snake_case keys and accepts common camelCase aliases on input.
type OriginContext struct {
	Provider             OriginProvider         `json:"provider"`
	TenantID             string                 `json:"tenant_id,omitempty"`
	SpaceID              string                 `json:"space_id,omitempty"`
	SpaceType            SpaceType              `json:"space_type,omitempty"`
	ThreadID             string                 `json:"thread_id,omitempty"`
	ActorID              string                 `json:"actor_id,omitempty"`
	ActorType            ActorType              `json:"actor_type,omitempty"`
	ActorRole            string                 `json:"actor_role,omitempty"`
	Visibility           Visibility             `json:"visibility,omitempty"`
	ExternalParticipants *bool                  `json:"external_participants,omitempty"`
	Tags                 []string               `json:"tags,omitempty"`
	Sensitivity          string                 `json:"sensitivity,omitempty"`
	ProvenanceConfidence ProvenanceConfidence   `json:"provenance_confidence,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

type originContextWire struct {
	Provider             OriginProvider         `json:"provider"`
	TenantID             string                 `json:"tenant_id,omitempty"`
	SpaceID              string                 `json:"space_id,omitempty"`
	SpaceType            SpaceType              `json:"space_type,omitempty"`
	ThreadID             string                 `json:"thread_id,omitempty"`
	ActorID              string                 `json:"actor_id,omitempty"`
	ActorType            ActorType              `json:"actor_type,omitempty"`
	ActorRole            string                 `json:"actor_role,omitempty"`
	Visibility           Visibility             `json:"visibility,omitempty"`
	ExternalParticipants *bool                  `json:"external_participants,omitempty"`
	Tags                 []string               `json:"tags,omitempty"`
	Sensitivity          string                 `json:"sensitivity,omitempty"`
	ProvenanceConfidence ProvenanceConfidence   `json:"provenance_confidence,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

var originFieldAliases = map[string]string{
	"tenantId":             "tenant_id",
	"spaceId":              "space_id",
	"spaceType":            "space_type",
	"threadId":             "thread_id",
	"actorId":              "actor_id",
	"actorType":            "actor_type",
	"actorRole":            "actor_role",
	"externalParticipants": "external_participants",
	"provenanceConfidence": "provenance_confidence",
}

var originKnownFields = map[string]struct{}{
	"provider":              {},
	"tenant_id":             {},
	"space_id":              {},
	"space_type":            {},
	"thread_id":             {},
	"actor_id":              {},
	"actor_type":            {},
	"actor_role":            {},
	"visibility":            {},
	"external_participants": {},
	"tags":                  {},
	"sensitivity":           {},
	"provenance_confidence": {},
	"metadata":              {},
}

// NewOriginContext creates a canonical origin context with the required provider field set.
func NewOriginContext(provider OriginProvider) *OriginContext {
	return &OriginContext{
		Provider: provider,
		Tags:     []string{},
	}
}

func (o *OriginContext) WithTenantID(id string) *OriginContext {
	o.TenantID = id
	return o
}

func (o *OriginContext) WithSpaceID(id string) *OriginContext {
	o.SpaceID = id
	return o
}

func (o *OriginContext) WithSpaceType(spaceType SpaceType) *OriginContext {
	o.SpaceType = spaceType
	return o
}

func (o *OriginContext) WithThreadID(id string) *OriginContext {
	o.ThreadID = id
	return o
}

func (o *OriginContext) WithActorID(id string) *OriginContext {
	o.ActorID = id
	return o
}

func (o *OriginContext) WithActorType(actorType ActorType) *OriginContext {
	o.ActorType = actorType
	return o
}

func (o *OriginContext) WithActorRole(role string) *OriginContext {
	o.ActorRole = role
	return o
}

func (o *OriginContext) WithVisibility(visibility Visibility) *OriginContext {
	o.Visibility = visibility
	return o
}

func (o *OriginContext) WithExternalParticipants(value bool) *OriginContext {
	o.ExternalParticipants = &value
	return o
}

func (o *OriginContext) WithTags(tags ...string) *OriginContext {
	o.Tags = append([]string(nil), tags...)
	return o
}

func (o *OriginContext) AddTag(tag string) *OriginContext {
	o.Tags = append(o.Tags, tag)
	return o
}

func (o *OriginContext) WithSensitivity(sensitivity string) *OriginContext {
	o.Sensitivity = sensitivity
	return o
}

func (o *OriginContext) WithProvenanceConfidence(confidence ProvenanceConfidence) *OriginContext {
	o.ProvenanceConfidence = confidence
	return o
}

func (o *OriginContext) WithMetadata(metadata map[string]interface{}) *OriginContext {
	if metadata == nil {
		o.Metadata = nil
		return o
	}
	o.Metadata = cloneOriginMetadataMap(metadata)
	return o
}

func (o *OriginContext) Clone() *OriginContext {
	if o == nil {
		return nil
	}

	cloned := *o
	if o.ExternalParticipants != nil {
		value := *o.ExternalParticipants
		cloned.ExternalParticipants = &value
	}
	if o.Tags != nil {
		cloned.Tags = append([]string(nil), o.Tags...)
	}
	if o.Metadata != nil {
		cloned.Metadata = cloneOriginMetadataMap(o.Metadata)
	}
	return &cloned
}

func cloneOriginMetadataMap(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return nil
	}

	cloned := make(map[string]interface{}, len(metadata))
	for key, value := range metadata {
		cloned[key] = cloneOriginMetadataValue(value)
	}
	return cloned
}

func cloneOriginMetadataValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]interface{}:
		return cloneOriginMetadataMap(typed)
	case []interface{}:
		cloned := make([]interface{}, len(typed))
		for i, item := range typed {
			cloned[i] = cloneOriginMetadataValue(item)
		}
		return cloned
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return value
		}
		cloned := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			clonedValue := cloneOriginMetadataValue(iter.Value().Interface())
			if clonedValue == nil {
				cloned.SetMapIndex(iter.Key(), reflect.Zero(rv.Type().Elem()))
			} else {
				cloned.SetMapIndex(iter.Key(), reflect.ValueOf(clonedValue))
			}
		}
		return cloned.Interface()
	case reflect.Slice:
		if rv.IsNil() {
			return value
		}
		cloned := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := 0; i < rv.Len(); i++ {
			clonedValue := cloneOriginMetadataValue(rv.Index(i).Interface())
			if clonedValue == nil {
				cloned.Index(i).Set(reflect.Zero(rv.Type().Elem()))
			} else {
				cloned.Index(i).Set(reflect.ValueOf(clonedValue))
			}
		}
		return cloned.Interface()
	default:
		return value
	}
}

// UnmarshalJSON accepts canonical snake_case fields and camelCase aliases.
// Unknown or duplicate fields are rejected instead of being silently ignored.
func (o *OriginContext) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	normalized := make(map[string]json.RawMessage, len(raw))
	for key, value := range raw {
		canonical := key
		if alias, ok := originFieldAliases[key]; ok {
			canonical = alias
		}
		if _, ok := originKnownFields[canonical]; !ok {
			return fmt.Errorf("guards: unknown origin field %q", key)
		}
		if _, exists := normalized[canonical]; exists {
			return fmt.Errorf("guards: duplicate origin field %q", canonical)
		}
		normalized[canonical] = value
	}

	normalizedJSON, err := json.Marshal(normalized)
	if err != nil {
		return err
	}

	var decoded originContextWire
	if err := json.Unmarshal(normalizedJSON, &decoded); err != nil {
		return err
	}
	if decoded.Provider == "" {
		return fmt.Errorf("guards: origin provider is required")
	}

	*o = OriginContext(decoded)
	return nil
}

// OutputSendPayload is the canonical payload for origin-aware outbound data checks.
type OutputSendPayload struct {
	Text     string                 `json:"text"`
	Target   string                 `json:"target,omitempty"`
	MimeType string                 `json:"mime_type,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// NewOutputSendPayload creates an origin.output_send payload with the required text field set.
func NewOutputSendPayload(text string) *OutputSendPayload {
	return &OutputSendPayload{Text: text}
}

func (p *OutputSendPayload) WithTarget(target string) *OutputSendPayload {
	p.Target = target
	return p
}

func (p *OutputSendPayload) WithMimeType(mimeType string) *OutputSendPayload {
	p.MimeType = mimeType
	return p
}

func (p *OutputSendPayload) WithMetadata(metadata map[string]interface{}) *OutputSendPayload {
	if metadata == nil {
		p.Metadata = nil
		return p
	}
	p.Metadata = cloneOriginMetadataMap(metadata)
	return p
}

func (p *OutputSendPayload) GuardAction() GuardAction {
	payload := map[string]interface{}{"text": p.Text}
	if p.Target != "" {
		payload["target"] = p.Target
	}
	if p.MimeType != "" {
		payload["mime_type"] = p.MimeType
	}
	if p.Metadata != nil {
		payload["metadata"] = cloneOriginMetadataMap(p.Metadata)
	}
	return Custom("origin.output_send", payload)
}

// OutputSend creates the canonical origin.output_send custom action.
func OutputSend(text string) GuardAction {
	return NewOutputSendPayload(text).GuardAction()
}
