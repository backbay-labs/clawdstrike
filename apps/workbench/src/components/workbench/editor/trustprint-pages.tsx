import { useState, useCallback } from "react";
import { TrustprintPatternExplorer } from "./trustprint-pattern-explorer";
import { TrustprintProviderWizard } from "./trustprint-provider-wizard";
import { TrustprintThresholdTuner } from "./trustprint-threshold-tuner";

export function TrustprintPatternsPage() {
  const [selectedId, setSelectedId] = useState<string>();
  return (
    <div className="h-full w-full overflow-auto bg-[#0b0d13] p-4">
      <TrustprintPatternExplorer
        patterns={[]}
        selectedPatternId={selectedId}
        onSelectPattern={setSelectedId}
      />
    </div>
  );
}

export function TrustprintProvidersPage() {
  const [config, setConfig] = useState({
    embedding_api_url: "",
    embedding_api_key: "",
    embedding_model: "",
  });
  const handleChange = useCallback(
    (updates: Partial<typeof config>) => {
      setConfig((prev) => ({ ...prev, ...updates }));
    },
    [],
  );
  return (
    <div className="h-full w-full overflow-auto bg-[#0b0d13] p-4">
      <TrustprintProviderWizard config={config} onChange={handleChange} />
    </div>
  );
}

export function TrustprintThresholdsPage() {
  const [threshold, setThreshold] = useState(0.7);
  const [ambiguityBand, setAmbiguityBand] = useState(0.1);
  return (
    <div className="h-full w-full overflow-auto bg-[#0b0d13] p-4">
      <TrustprintThresholdTuner
        threshold={threshold}
        ambiguityBand={ambiguityBand}
        onThresholdChange={setThreshold}
        onAmbiguityBandChange={setAmbiguityBand}
      />
    </div>
  );
}
