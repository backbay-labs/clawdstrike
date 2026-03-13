// ---------------------------------------------------------------------------
// Trustprint Provider Wizard — guided embedding provider setup for Spider Sense
// ---------------------------------------------------------------------------

import { useState, useCallback, useMemo } from "react";
import {
  IconBrain,
  IconSparkles,
  IconCompass,
  IconSettings,
  IconLock,
  IconEye,
  IconEyeOff,
  IconCheck,
  IconX,
  IconLoader2,
  IconArrowRight,
  IconArrowLeft,
  IconCircleDot,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  testEmbeddingConnection,
  type ConnectionTestResult,
} from "@/lib/workbench/trustprint-connection";

// ---------------------------------------------------------------------------
// Provider data
// ---------------------------------------------------------------------------

interface ModelOption {
  id: string;
  name: string;
  dims: number;
  description: string;
}

interface EmbeddingProvider {
  id: string;
  name: string;
  url: string;
  icon: string;
  description: string;
  models: ModelOption[];
}

const EMBEDDING_PROVIDERS: EmbeddingProvider[] = [
  {
    id: "openai",
    name: "OpenAI",
    url: "https://api.openai.com/v1/embeddings",
    icon: "IconBrain",
    description: "Most popular, high quality embeddings",
    models: [
      { id: "text-embedding-3-small", name: "text-embedding-3-small", dims: 1536, description: "Fast, cost-effective" },
      { id: "text-embedding-3-large", name: "text-embedding-3-large", dims: 3072, description: "Highest quality" },
      { id: "text-embedding-ada-002", name: "text-embedding-ada-002", dims: 1536, description: "Legacy model" },
    ],
  },
  {
    id: "cohere",
    name: "Cohere",
    url: "https://api.cohere.ai/v1/embed",
    icon: "IconSparkles",
    description: "Multilingual support, good for diverse text",
    models: [
      { id: "embed-english-v3.0", name: "embed-english-v3.0", dims: 1024, description: "Best English quality" },
      { id: "embed-multilingual-v3.0", name: "embed-multilingual-v3.0", dims: 1024, description: "100+ languages" },
      { id: "embed-english-light-v3.0", name: "embed-english-light-v3.0", dims: 384, description: "Fastest, lightweight" },
    ],
  },
  {
    id: "voyage",
    name: "Voyage AI",
    url: "https://api.voyageai.com/v1/embeddings",
    icon: "IconCompass",
    description: "Optimized for code and technical text",
    models: [
      { id: "voyage-3", name: "voyage-3", dims: 1024, description: "General purpose" },
      { id: "voyage-3-lite", name: "voyage-3-lite", dims: 512, description: "Fast and lightweight" },
      { id: "voyage-code-3", name: "voyage-code-3", dims: 1024, description: "Code-optimized" },
    ],
  },
  {
    id: "custom",
    name: "Custom",
    url: "",
    icon: "IconSettings",
    description: "Any OpenAI-compatible embedding API",
    models: [],
  },
];

const ICON_MAP: Record<string, typeof IconBrain> = {
  IconBrain,
  IconSparkles,
  IconCompass,
  IconSettings,
};

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface TrustprintProviderWizardProps {
  /** Current spider_sense config */
  config: {
    embedding_api_url?: string;
    embedding_api_key?: string;
    embedding_model?: string;
  };
  /** Callback when config changes */
  onChange: (updates: Partial<{
    embedding_api_url: string;
    embedding_api_key: string;
    embedding_model: string;
  }>) => void;
  /** Compact inline mode for guard card */
  compact?: boolean;
}

// ---------------------------------------------------------------------------
// Wizard steps
// ---------------------------------------------------------------------------

type WizardStep = 1 | 2 | 3;

// ---------------------------------------------------------------------------
// Step 1: Choose Provider
// ---------------------------------------------------------------------------

function ProviderCard({
  provider,
  selected,
  onClick,
}: {
  provider: EmbeddingProvider;
  selected: boolean;
  onClick: () => void;
}) {
  const Icon = ICON_MAP[provider.icon] ?? IconSettings;

  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={`provider-card-${provider.id}`}
      className={cn(
        "flex flex-col items-start gap-2 p-3 rounded-lg border text-left transition-all",
        selected
          ? "border-[#d4a84b] bg-[#d4a84b]/5"
          : "border-[#2d3240] bg-[#131721] hover:border-[#2d3240]/80 hover:bg-[#131721]/80",
      )}
    >
      <div className="flex items-center gap-2">
        <Icon
          size={16}
          stroke={1.5}
          className={cn(selected ? "text-[#d4a84b]" : "text-[#6f7f9a]")}
        />
        <span
          className={cn(
            "text-xs font-medium",
            selected ? "text-[#ece7dc]" : "text-[#6f7f9a]",
          )}
        >
          {provider.name}
        </span>
      </div>
      <span className="text-[10px] text-[#6f7f9a] leading-relaxed">
        {provider.description}
      </span>
      {provider.url && (
        <span className="text-[9px] font-mono text-[#6f7f9a]/60 truncate w-full">
          {provider.url}
        </span>
      )}
    </button>
  );
}

function StepProvider({
  selectedProviderId,
  customUrl,
  onSelect,
  onCustomUrlChange,
  onNext,
}: {
  selectedProviderId: string | null;
  customUrl: string;
  onSelect: (provider: EmbeddingProvider) => void;
  onCustomUrlChange: (url: string) => void;
  onNext: () => void;
}) {
  const canProceed = selectedProviderId !== null &&
    (selectedProviderId !== "custom" || customUrl.trim().length > 0);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h4 className="text-xs font-syne font-semibold text-[#ece7dc] mb-1">
          Choose Provider
        </h4>
        <p className="text-[10px] text-[#6f7f9a]">
          Select an embedding API provider for Spider Sense threat detection.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {EMBEDDING_PROVIDERS.map((provider) => (
          <ProviderCard
            key={provider.id}
            provider={provider}
            selected={selectedProviderId === provider.id}
            onClick={() => onSelect(provider)}
          />
        ))}
      </div>

      {selectedProviderId === "custom" && (
        <div className="flex flex-col gap-1.5">
          <label className="text-[10px] text-[#6f7f9a]">Custom API URL</label>
          <input
            type="text"
            value={customUrl}
            onChange={(e) => onCustomUrlChange(e.target.value)}
            placeholder="https://your-api.example.com/v1/embeddings"
            className="h-8 w-full rounded-md border border-[#2d3240] bg-[#131721] px-2.5 py-1 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors"
          />
        </div>
      )}

      <div className="flex justify-end">
        <button
          type="button"
          onClick={onNext}
          disabled={!canProceed}
          className={cn(
            "flex items-center gap-1.5 h-8 px-4 rounded-lg text-xs font-medium transition-all",
            canProceed
              ? "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]"
              : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] opacity-50 cursor-not-allowed",
          )}
        >
          Next
          <IconArrowRight size={13} stroke={2} />
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 2: API Key & Model
// ---------------------------------------------------------------------------

function StepCredentials({
  apiKey,
  selectedModel,
  provider,
  customModel,
  onApiKeyChange,
  onModelChange,
  onCustomModelChange,
  onNext,
  onBack,
}: {
  apiKey: string;
  selectedModel: string;
  provider: EmbeddingProvider;
  customModel: string;
  onApiKeyChange: (key: string) => void;
  onModelChange: (modelId: string) => void;
  onCustomModelChange: (model: string) => void;
  onNext: () => void;
  onBack: () => void;
}) {
  const [showKey, setShowKey] = useState(false);

  const isCustomProvider = provider.id === "custom";
  const effectiveModel = isCustomProvider ? customModel : selectedModel;
  const canProceed = apiKey.trim().length > 0 && effectiveModel.trim().length > 0;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h4 className="text-xs font-syne font-semibold text-[#ece7dc] mb-1">
          API Key & Model
        </h4>
        <p className="text-[10px] text-[#6f7f9a]">
          Configure credentials and select an embedding model for {provider.name}.
        </p>
      </div>

      {/* API Key */}
      <div className="flex flex-col gap-1.5">
        <label className="text-xs text-[#ece7dc] flex items-center gap-1.5">
          <IconLock size={12} stroke={1.5} className="text-[#d4a84b]" />
          API Key
        </label>
        <div className="relative">
          <input
            type={showKey ? "text" : "password"}
            value={apiKey}
            onChange={(e) => onApiKeyChange(e.target.value)}
            placeholder="sk-..."
            data-testid="api-key-input"
            className="h-8 w-full rounded-md border border-[#2d3240] bg-[#131721] px-2.5 pr-9 py-1 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors"
          />
          <button
            type="button"
            onClick={() => setShowKey((p) => !p)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
            title={showKey ? "Hide key" : "Show key"}
          >
            {showKey ? (
              <IconEyeOff size={14} stroke={1.5} />
            ) : (
              <IconEye size={14} stroke={1.5} />
            )}
          </button>
        </div>
        <span className="text-[9px] text-[#6f7f9a]/70">
          Keys are stored locally. Use test/dev keys only.
        </span>
      </div>

      {/* Model selection */}
      <div className="flex flex-col gap-1.5">
        <label className="text-xs text-[#ece7dc]">
          Embedding Model
        </label>

        {isCustomProvider ? (
          <input
            type="text"
            value={customModel}
            onChange={(e) => onCustomModelChange(e.target.value)}
            placeholder="model-name"
            className="h-8 w-full rounded-md border border-[#2d3240] bg-[#131721] px-2.5 py-1 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors"
          />
        ) : (
          <div className="flex flex-col gap-1.5">
            {provider.models.map((model) => (
              <button
                key={model.id}
                type="button"
                onClick={() => onModelChange(model.id)}
                data-testid={`model-option-${model.id}`}
                className={cn(
                  "flex items-center justify-between gap-2 px-3 py-2 rounded-md border text-left transition-all",
                  selectedModel === model.id
                    ? "border-[#d4a84b] bg-[#d4a84b]/5"
                    : "border-[#2d3240] bg-[#131721] hover:border-[#2d3240]/80",
                )}
              >
                <div className="flex flex-col gap-0.5 min-w-0">
                  <span
                    className={cn(
                      "text-xs font-mono",
                      selectedModel === model.id ? "text-[#ece7dc]" : "text-[#6f7f9a]",
                    )}
                  >
                    {model.name}
                  </span>
                  <span className="text-[9px] text-[#6f7f9a]/70">
                    {model.description}
                  </span>
                </div>
                <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0">
                  {model.dims} dims
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={onBack}
          className="flex items-center gap-1.5 h-8 px-3 rounded-lg text-xs font-medium text-[#6f7f9a] hover:text-[#ece7dc] bg-[#131721] border border-[#2d3240] transition-colors"
        >
          <IconArrowLeft size={13} stroke={1.5} />
          Back
        </button>
        <button
          type="button"
          onClick={onNext}
          disabled={!canProceed}
          className={cn(
            "flex items-center gap-1.5 h-8 px-4 rounded-lg text-xs font-medium transition-all",
            canProceed
              ? "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]"
              : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] opacity-50 cursor-not-allowed",
          )}
        >
          Next
          <IconArrowRight size={13} stroke={2} />
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 3: Test Connection
// ---------------------------------------------------------------------------

function StepTest({
  url,
  apiKey,
  model,
  onBack,
  onSave,
  onSkip,
}: {
  url: string;
  apiKey: string;
  model: string;
  onBack: () => void;
  onSave: () => void;
  onSkip: () => void;
}) {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<ConnectionTestResult | null>(null);

  const handleTest = useCallback(async () => {
    setTesting(true);
    setResult(null);
    try {
      const res = await testEmbeddingConnection(url, apiKey, model);
      setResult(res);
    } catch (err) {
      setResult({
        success: false,
        error: err instanceof Error ? err.message : "Test failed unexpectedly",
      });
    } finally {
      setTesting(false);
    }
  }, [url, apiKey, model]);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h4 className="text-xs font-syne font-semibold text-[#ece7dc] mb-1">
          Test Connection
        </h4>
        <p className="text-[10px] text-[#6f7f9a]">
          Verify that the embedding API is reachable and responding correctly.
        </p>
      </div>

      {/* Connection summary */}
      <div className="flex flex-col gap-1.5 p-3 rounded-lg bg-[#131721] border border-[#2d3240]">
        <div className="flex items-center gap-2 text-[10px]">
          <span className="text-[#6f7f9a]">Endpoint:</span>
          <span className="font-mono text-[#ece7dc] truncate">{url}</span>
        </div>
        <div className="flex items-center gap-2 text-[10px]">
          <span className="text-[#6f7f9a]">Model:</span>
          <span className="font-mono text-[#ece7dc]">{model}</span>
        </div>
      </div>

      {/* Test button */}
      <button
        type="button"
        onClick={handleTest}
        disabled={testing}
        data-testid="test-connection-button"
        className={cn(
          "flex items-center justify-center gap-2 h-10 rounded-lg text-sm font-medium transition-all w-full",
          testing
            ? "bg-[#d4a84b]/20 text-[#d4a84b] cursor-wait"
            : "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]",
        )}
      >
        {testing ? (
          <>
            <IconLoader2 size={16} stroke={2} className="animate-spin" />
            Testing connection...
          </>
        ) : result ? (
          "Retry Test"
        ) : (
          "Test Connection"
        )}
      </button>

      {/* Result display */}
      {result && !testing && (
        <div
          className={cn(
            "flex flex-col gap-2 p-3 rounded-lg border",
            result.success
              ? "bg-[#3dbf84]/5 border-[#3dbf84]/20"
              : "bg-[#c45c5c]/5 border-[#c45c5c]/20",
          )}
          data-testid="test-result"
        >
          <div className="flex items-center gap-2">
            {result.success ? (
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[#3dbf84]/20">
                <IconCheck size={12} stroke={2} className="text-[#3dbf84]" />
              </span>
            ) : (
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-[#c45c5c]/20">
                <IconX size={12} stroke={2} className="text-[#c45c5c]" />
              </span>
            )}
            <span
              className={cn(
                "text-xs font-medium",
                result.success ? "text-[#3dbf84]" : "text-[#c45c5c]",
              )}
            >
              {result.success ? "Connected!" : "Connection failed"}
            </span>
          </div>

          {result.success && (
            <>
              <p className="text-[10px] text-[#ece7dc] font-mono">
                Model: {result.modelName}
                {result.dimensions != null && ` (${result.dimensions} dimensions)`}
              </p>
              {result.latencyMs != null && (
                <p className="text-[10px] text-[#6f7f9a]">
                  Response time: {result.latencyMs}ms
                </p>
              )}
            </>
          )}

          {!result.success && result.error && (
            <p className="text-[10px] text-[#c45c5c]/90 font-mono">
              {result.error}
            </p>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={onBack}
          className="flex items-center gap-1.5 h-8 px-3 rounded-lg text-xs font-medium text-[#6f7f9a] hover:text-[#ece7dc] bg-[#131721] border border-[#2d3240] transition-colors"
        >
          <IconArrowLeft size={13} stroke={1.5} />
          Back
        </button>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onSkip}
            className="text-[10px] text-[#6f7f9a] hover:text-[#ece7dc] transition-colors underline underline-offset-2"
          >
            Skip test — I'll configure later
          </button>
          {result?.success && (
            <button
              type="button"
              onClick={onSave}
              data-testid="save-config-button"
              className="flex items-center gap-1.5 h-8 px-4 rounded-lg text-xs font-medium bg-[#3dbf84] text-[#05060a] hover:bg-[#4dd99a] transition-colors"
            >
              <IconCheck size={13} stroke={2} />
              Save Configuration
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step indicator
// ---------------------------------------------------------------------------

function StepIndicator({ current }: { current: WizardStep }) {
  const steps = [
    { step: 1 as WizardStep, label: "Provider" },
    { step: 2 as WizardStep, label: "Credentials" },
    { step: 3 as WizardStep, label: "Test" },
  ];

  return (
    <div className="flex items-center gap-1 mb-4">
      {steps.map(({ step, label }, index) => (
        <div key={step} className="flex items-center gap-1">
          {index > 0 && (
            <div
              className={cn(
                "w-6 h-px",
                current >= step ? "bg-[#d4a84b]" : "bg-[#2d3240]",
              )}
            />
          )}
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                "flex items-center justify-center w-5 h-5 rounded-full text-[9px] font-mono font-medium",
                current === step
                  ? "bg-[#d4a84b] text-[#05060a]"
                  : current > step
                    ? "bg-[#d4a84b]/20 text-[#d4a84b]"
                    : "bg-[#2d3240] text-[#6f7f9a]",
              )}
            >
              {current > step ? (
                <IconCheck size={10} stroke={2} />
              ) : (
                step
              )}
            </span>
            <span
              className={cn(
                "text-[9px] font-mono",
                current >= step ? "text-[#ece7dc]" : "text-[#6f7f9a]",
              )}
            >
              {label}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Compact mode
// ---------------------------------------------------------------------------

type ConnectionStatus = "untested" | "success" | "failed";

function CompactView({
  config,
  onExpand,
}: {
  config: TrustprintProviderWizardProps["config"];
  onExpand: () => void;
}) {
  const provider = useMemo(() => {
    if (!config.embedding_api_url) return null;
    return EMBEDDING_PROVIDERS.find((p) => config.embedding_api_url === p.url) ?? null;
  }, [config.embedding_api_url]);

  const providerName = provider?.name ?? (config.embedding_api_url ? "Custom" : "None");
  const providerIcon = provider ? ICON_MAP[provider.icon] : IconSettings;
  const Icon = providerIcon ?? IconSettings;

  // Derive connection status — always "untested" in compact view for now.
  // Future: persist last test result in local storage keyed by provider URL.
  const status = "untested" as ConnectionStatus;

  return (
    <div className="flex items-center gap-2" data-testid="compact-view">
      {/* Provider badge */}
      <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#131721] border border-[#2d3240] text-[#ece7dc] font-mono text-[10px] rounded-md">
        <Icon size={11} stroke={1.5} className="text-[#d4a84b]" />
        {providerName}
      </span>

      {/* Model badge */}
      {config.embedding_model && (
        <span className="inline-flex items-center px-2 py-0.5 bg-[#131721] border border-[#2d3240] text-[#6f7f9a] font-mono text-[10px] rounded-md truncate max-w-[160px]">
          {config.embedding_model}
        </span>
      )}

      {/* Status dot */}
      <IconCircleDot
        size={10}
        stroke={2}
        className={cn(
          status === "success" && "text-[#3dbf84]",
          status === "failed" && "text-[#c45c5c]",
          status === "untested" && "text-[#6f7f9a]",
        )}
      />

      {/* Configure button */}
      <button
        type="button"
        onClick={onExpand}
        className="ml-auto px-2.5 py-1 text-[10px] font-mono text-[#d4a84b] border border-[#2d3240] rounded-md hover:border-[#d4a84b]/40 hover:bg-[#131721] transition-colors"
      >
        Configure
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function TrustprintProviderWizard({
  config,
  onChange,
  compact = false,
}: TrustprintProviderWizardProps) {
  const [step, setStep] = useState<WizardStep>(1);
  const [expanded, setExpanded] = useState(false);

  // Local wizard state (committed to parent via onChange on save/skip)
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(() => {
    if (!config.embedding_api_url) return null;
    const match = EMBEDDING_PROVIDERS.find((p) => p.url === config.embedding_api_url);
    return match?.id ?? "custom";
  });

  const [customUrl, setCustomUrl] = useState(() => {
    if (!config.embedding_api_url) return "";
    const match = EMBEDDING_PROVIDERS.find((p) => p.url === config.embedding_api_url);
    return match ? "" : config.embedding_api_url;
  });

  const [apiKey, setApiKey] = useState(config.embedding_api_key ?? "");
  const [selectedModel, setSelectedModel] = useState(config.embedding_model ?? "");
  const [customModel, setCustomModel] = useState(
    config.embedding_model && selectedProviderId === "custom" ? config.embedding_model : "",
  );

  // Derived
  const provider = useMemo(
    () => EMBEDDING_PROVIDERS.find((p) => p.id === selectedProviderId) ?? null,
    [selectedProviderId],
  );

  const resolvedUrl = useMemo(() => {
    if (!provider) return "";
    return provider.id === "custom" ? customUrl : provider.url;
  }, [provider, customUrl]);

  const resolvedModel = useMemo(() => {
    if (!provider) return "";
    return provider.id === "custom" ? customModel : selectedModel;
  }, [provider, customModel, selectedModel]);

  // Handlers
  const handleSelectProvider = useCallback((p: EmbeddingProvider) => {
    setSelectedProviderId(p.id);
    if (p.id !== "custom" && p.models.length > 0) {
      setSelectedModel(p.models[0].id);
    }
  }, []);

  const commitConfig = useCallback(() => {
    onChange({
      embedding_api_url: resolvedUrl,
      embedding_api_key: apiKey,
      embedding_model: resolvedModel,
    });
    if (compact) {
      setExpanded(false);
    }
  }, [onChange, resolvedUrl, apiKey, resolvedModel, compact]);

  // Compact mode
  if (compact && !expanded) {
    return (
      <CompactView
        config={config}
        onExpand={() => setExpanded(true)}
      />
    );
  }

  return (
    <div
      className={cn(
        "flex flex-col",
        compact
          ? "p-3 rounded-lg border border-[#2d3240] bg-[#0b0d13]"
          : "",
      )}
      data-testid="trustprint-provider-wizard"
    >
      <StepIndicator current={step} />

      {step === 1 && (
        <StepProvider
          selectedProviderId={selectedProviderId}
          customUrl={customUrl}
          onSelect={handleSelectProvider}
          onCustomUrlChange={setCustomUrl}
          onNext={() => setStep(2)}
        />
      )}

      {step === 2 && provider && (
        <StepCredentials
          apiKey={apiKey}
          selectedModel={selectedModel}
          provider={provider}
          customModel={customModel}
          onApiKeyChange={setApiKey}
          onModelChange={setSelectedModel}
          onCustomModelChange={setCustomModel}
          onNext={() => setStep(3)}
          onBack={() => setStep(1)}
        />
      )}

      {step === 3 && (
        <StepTest
          url={resolvedUrl}
          apiKey={apiKey}
          model={resolvedModel}
          onBack={() => setStep(2)}
          onSave={commitConfig}
          onSkip={commitConfig}
        />
      )}
    </div>
  );
}
