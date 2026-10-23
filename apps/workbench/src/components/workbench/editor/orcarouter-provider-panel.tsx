/**
 * OrcaRouter Cyber Inference provider panel.
 *
 * Two authentication choices are always visible side by side:
 *   1. paste an existing API key (`sk-orca-…`),
 *   2. "Connect with OrcaRouter" (OAuth 2.0 + PKCE, out-of-band code).
 *
 * Both end in the same durable OrcaRouter API key and the same model
 * catalogue, so the model selectors below never need to know which one was
 * used. Model options always come from `GET <api>/models`; the selectors are
 * filtered per entry (embedding vs. chat) and never degrade to free text.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  IconAlertTriangle,
  IconCheck,
  IconChevronDown,
  IconExternalLink,
  IconKey,
  IconLoader2,
  IconRefresh,
  IconShieldLock,
  IconX,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  ApiKeyCredentialAdapter,
  createPkceAdapter,
  OrcaRouterCredentialManager,
  type OrcaRouterCredential,
} from "@/lib/orcarouter/credentials";
import {
  fetchOrcaRouterCatalog,
  filterModels,
  ORCAROUTER_VERIFIED_SEED,
  reconcileSelection,
  sortChatModels,
  type OrcaRouterCatalog,
  type OrcaRouterCatalogStatus,
  type OrcaRouterModel,
} from "@/lib/orcarouter/catalog";
import {
  ORCAROUTER_CYBER_MODELS_URL,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_FALLBACK_MODEL,
  ORCAROUTER_KEY_DASHBOARD_URL,
  ORCAROUTER_PROVIDER_PAGE_URL,
  isOrcaRouterCyberModel,
  redactOrcaRouterKey,
  resolveOrcaRouterOrigins,
  type OrcaRouterOrigins,
} from "@/lib/orcarouter/provider";

export interface OrcaRouterSelection {
  embeddingModel: string;
  chatModel: string;
}

export interface OrcaRouterProviderPanelProps {
  selection: OrcaRouterSelection;
  onSelectionChange: (selection: OrcaRouterSelection) => void;
  /** Notified with the active credential so the host can persist derived config. */
  onCredential?: (credential: OrcaRouterCredential | null) => void;
  /** Injected in tests; defaults to the workbench secure store. */
  credentialManager?: OrcaRouterCredentialManager;
  origins?: OrcaRouterOrigins;
  /** Injected in tests. */
  fetchFn?: typeof fetch;
  /** Opens the consent screen; defaults to window.open. */
  openExternal?: (url: string) => void;
}

const EMBEDDING_REQUIREMENT = { capability: "embedding" as const, modalities: [] };
const CHAT_REQUIREMENT = { capability: "chat" as const, modalities: [] };

function modelLabel(model: OrcaRouterModel): string {
  const tags: string[] = [];
  if (model.id === ORCAROUTER_DEFAULT_MODEL) tags.push("default");
  if (isOrcaRouterCyberModel(model.id)) tags.push("cyber");
  if (model.id === ORCAROUTER_FALLBACK_MODEL) tags.push("fallback");
  return tags.length > 0 ? `${model.name} · ${tags.join(" · ")}` : model.name;
}

function ModelSelect({
  id,
  label,
  hint,
  models,
  value,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  hint?: string;
  models: OrcaRouterModel[];
  value: string;
  disabled?: boolean;
  onChange: (modelId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const selected = models.find((model) => model.id === value) ?? null;

  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs text-[#ece7dc]" htmlFor={`${id}-trigger`}>
        {label}
      </label>
      {hint && <p className="text-[9px] text-[#6f7f9a]/70 leading-relaxed">{hint}</p>}
      <div className="relative">
        <button
          type="button"
          id={`${id}-trigger`}
          data-testid={`${id}-trigger`}
          aria-haspopup="listbox"
          aria-expanded={open}
          disabled={disabled || models.length === 0}
          onClick={() => setOpen((prev) => !prev)}
          className={cn(
            "flex h-9 w-full items-center justify-between gap-2 rounded-md border px-2.5 text-left text-xs transition-colors",
            "border-[#2d3240] bg-[#131721] text-[#ece7dc]",
            (disabled || models.length === 0) && "opacity-50 cursor-not-allowed",
            open && "border-[#d4a84b]/60",
          )}
        >
          <span className="truncate font-mono">{selected ? modelLabel(selected) : "Select a model"}</span>
          <IconChevronDown size={13} stroke={1.5} className="shrink-0 text-[#6f7f9a]" />
        </button>

        {open && models.length > 0 && (
          <div
            role="listbox"
            data-testid={`${id}-panel`}
            aria-label={label}
            className="absolute left-0 right-0 z-30 mt-1 max-h-64 overflow-auto rounded-md border border-[#2d3240] bg-[#131721] py-1 shadow-xl shadow-black/60"
          >
            {models.map((model) => (
              <button
                key={model.id}
                type="button"
                role="option"
                aria-selected={model.id === value}
                data-testid={`${id}-option-${model.id}`}
                onClick={() => {
                  onChange(model.id);
                  setOpen(false);
                }}
                className={cn(
                  "flex w-full flex-col gap-0.5 px-2.5 py-1.5 text-left transition-colors",
                  model.id === value ? "bg-[#d4a84b]/10" : "hover:bg-[#1b2030]",
                )}
              >
                <span className="font-mono text-[11px] text-[#ece7dc]">{modelLabel(model)}</span>
                <span className="text-[9px] text-[#6f7f9a]">
                  {model.id}
                  {model.contextLength ? ` · ${Math.round(model.contextLength / 1000)}k ctx` : ""}
                  {isOrcaRouterCyberModel(model.id) ? " · security teams (business verification)" : ""}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function OrcaRouterProviderPanel({
  selection,
  onSelectionChange,
  onCredential,
  credentialManager,
  origins: originsProp,
  fetchFn,
  openExternal,
}: OrcaRouterProviderPanelProps) {
  const origins = useMemo(
    () => originsProp ?? resolveOrcaRouterOrigins(),
    [originsProp],
  );
  const manager = useMemo(
    () => credentialManager ?? new OrcaRouterCredentialManager({ origins, fetchFn }),
    [credentialManager, origins, fetchFn],
  );

  const [credential, setCredential] = useState<OrcaRouterCredential | null>(null);
  const [catalog, setCatalog] = useState<OrcaRouterCatalog | null>(null);
  const [catalogStatus, setCatalogStatus] = useState<OrcaRouterCatalogStatus>("loading");

  const [authMethod, setAuthMethod] = useState<"api_key" | "pkce">("api_key");
  const [apiKeyDraft, setApiKeyDraft] = useState("");
  const [keyHint, setKeyHint] = useState<{ kind: "error" | "ok"; message: string } | null>(null);

  const [attempt, setAttempt] = useState<{ attemptId: string; authorizeUrl: string } | null>(null);
  const [connectPhase, setConnectPhase] = useState<"idle" | "exchanging" | "connected" | "error">(
    "idle",
  );
  const [connectError, setConnectError] = useState<string | null>(null);
  const [codeDraft, setCodeDraft] = useState("");
  const attemptGeneration = useRef(0);
  const pkceAdapter = useMemo(
    () => createPkceAdapter({ origins, fetchFn }),
    [origins, fetchFn],
  );

  useEffect(() => {
    const unsubscribe = manager.subscribe((next) => setCredential(next));
    void manager.load();
    return unsubscribe;
  }, [manager]);

  useEffect(() => {
    onCredential?.(credential);
  }, [credential, onCredential]);

  const refreshCatalog = useCallback(
    async (key: string) => {
      setCatalogStatus("loading");
      const result = await fetchOrcaRouterCatalog({
        origins,
        apiKey: key,
        fetchFn,
        lastKnownGood: catalog?.source === "live" ? catalog.models : undefined,
      });
      setCatalog(result.catalog);
      setCatalogStatus(result.status);
    },
    [catalog, fetchFn, origins],
  );

  useEffect(() => {
    if (!credential?.apiKey || credential.status === "needsReauth") {
      setCatalog(null);
      setCatalogStatus("loading");
      return;
    }
    void refreshCatalog(credential.apiKey);
    // Intentionally keyed on generation: a re-auth must refetch the catalogue.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [credential?.generation, credential?.status]);

  const liveEmbeddingModels = useMemo(
    () => (catalog ? filterModels(catalog.models, EMBEDDING_REQUIREMENT) : []),
    [catalog],
  );
  // Some workspaces have no embedding-capable model in the catalogue (the
  // catalogue may advertise chat only) while `orcarouter/auto` still serves the
  // embeddings endpoint. Fall back to the verified route and say so, rather
  // than leaving the guard unconfigurable.
  const embeddingFromVerifiedSeed =
    catalog !== null && catalog.source === "live" && liveEmbeddingModels.length === 0;
  const embeddingModels = useMemo(
    () =>
      embeddingFromVerifiedSeed
        ? filterModels(ORCAROUTER_VERIFIED_SEED, EMBEDDING_REQUIREMENT)
        : liveEmbeddingModels,
    [embeddingFromVerifiedSeed, liveEmbeddingModels],
  );
  const chatModels = useMemo(
    () => (catalog ? sortChatModels(filterModels(catalog.models, CHAT_REQUIREMENT)) : []),
    [catalog],
  );

  // Drop selections that the current catalogue no longer supports.
  useEffect(() => {
    if (catalogStatus === "loading") return;
    const embedding = reconcileSelection(selection.embeddingModel, embeddingModels);
    const chat = reconcileSelection(selection.chatModel, chatModels);
    if (embedding.cleared || chat.cleared) {
      onSelectionChange({
        embeddingModel: embedding.selected ?? "",
        chatModel: chat.selected ?? "",
      });
    }
  }, [catalogStatus, embeddingModels, chatModels, onSelectionChange, selection]);

  const saveApiKey = useCallback(async () => {
    setKeyHint(null);
    try {
      await manager.connect(new ApiKeyCredentialAdapter(apiKeyDraft));
      setApiKeyDraft("");
      setKeyHint({ kind: "ok", message: "OrcaRouter key saved to the workbench secure store" });
    } catch (err) {
      setKeyHint({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not save the key",
      });
    }
  }, [apiKeyDraft, manager]);

  const clearCredential = useCallback(async () => {
    await manager.clear();
    setKeyHint({ kind: "ok", message: "OrcaRouter credential cleared" });
  }, [manager]);

  const startConnect = useCallback(async () => {
    setConnectPhase("idle");
    setConnectError(null);
    attemptGeneration.current += 1;
    const generation = attemptGeneration.current;
    try {
      const result = await pkceAdapter.begin();
      if (generation !== attemptGeneration.current) return;
      setAttempt({ attemptId: result.attemptId, authorizeUrl: result.authorizeUrl });
      const opener = openExternal ?? ((url: string) => window.open(url, "_blank", "noopener"));
      opener(result.authorizeUrl);
    } catch (err) {
      setConnectPhase("error");
      setConnectError(err instanceof Error ? err.message : "Could not start authorization");
    }
  }, [openExternal, pkceAdapter]);

  const cancelConnect = useCallback(() => {
    attemptGeneration.current += 1;
    pkceAdapter.cancel();
    setCodeDraft("");
    setAttempt(null);
    setConnectPhase("idle");
    setConnectError(null);
  }, [pkceAdapter]);

  // A back-forward-cache restore must not leave the panel stuck on "busy":
  // clear the busy flag and the authorization hint synchronously.
  useEffect(() => {
    const onPageHide = () => {
      attemptGeneration.current += 1;
      pkceAdapter.cancel();
      setCodeDraft("");
      setAttempt(null);
      setConnectPhase("idle");
      setConnectError(null);
    };
    window.addEventListener("pagehide", onPageHide);
    return () => window.removeEventListener("pagehide", onPageHide);
  }, [pkceAdapter]);

  const completeConnect = useCallback(async () => {
    if (!attempt) return;
    const generation = attemptGeneration.current;
    setConnectPhase("exchanging");
    setConnectError(null);
    try {
      const acquisition = await pkceAdapter.complete(attempt.attemptId, codeDraft);
      if (generation !== attemptGeneration.current) return;
      await manager.persist(acquisition);
      setCodeDraft("");
      setAttempt(null);
      setConnectPhase("connected");
    } catch (err) {
      if (generation !== attemptGeneration.current) return;
      setConnectPhase("error");
      setConnectError(err instanceof Error ? err.message : "Authorization failed");
    }
  }, [attempt, codeDraft, manager, pkceAdapter]);

  const maskVisible = credential ? redactOrcaRouterKey(credential.apiKey) : "";
  const needsReauth = credential?.status === "needsReauth";
  const controlsEnabled = Boolean(credential) && !needsReauth;

  return (
    <div className="flex flex-col gap-4" data-testid="orcarouter-panel">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <IconShieldLock size={14} stroke={1.6} className="text-[#d4a84b]" />
          <span className="text-xs font-syne font-semibold text-[#ece7dc]">
            OrcaRouter Cyber Inference
          </span>
        </div>
        <p className="text-[10px] leading-relaxed text-[#6f7f9a]">
          Named inference provider for authorized security work. Requests are scoped to this
          workspace; the key is billed to the operator&apos;s OrcaRouter account and can be revoked
          at any time.
        </p>
        <div className="flex flex-wrap gap-2 pt-1">
          <a
            href={ORCAROUTER_PROVIDER_PAGE_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[9px] text-[#d4a84b] hover:underline"
          >
            Cyber provider <IconExternalLink size={9} stroke={2} />
          </a>
          <a
            href={ORCAROUTER_CYBER_MODELS_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[9px] text-[#d4a84b] hover:underline"
          >
            Cyber model catalogue <IconExternalLink size={9} stroke={2} />
          </a>
          <a
            href={ORCAROUTER_KEY_DASHBOARD_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[9px] text-[#6f7f9a] hover:underline"
          >
            Revoke authorized apps <IconExternalLink size={9} stroke={2} />
          </a>
        </div>
      </div>

      {needsReauth && (
        <div className="rounded-md border border-[#c45c5c]/40 bg-[#c45c5c]/10 p-2 text-[10px] text-[#c45c5c]">
          This OrcaRouter credential was rejected (401). Reconnect or paste a new key — there is no
          automatic refresh.
        </div>
      )}

      {credential && (
        <div
          className="flex items-center justify-between rounded-md border border-[#2d3240] bg-[#131721] px-2.5 py-2"
          data-testid="orcarouter-credential-status"
        >
          <div className="flex flex-col">
            <span className="font-mono text-[10px] text-[#ece7dc]" data-testid="orcarouter-masked-key">
              {maskVisible}
            </span>
            <span className="text-[9px] text-[#6f7f9a]">
              {credential.source === "pkce" ? "Connected with OrcaRouter" : "API key"}
              {credential.userId ? ` · user ${credential.userId}` : ""} · generation{" "}
              {credential.generation}
            </span>
          </div>
          <button
            type="button"
            onClick={() => void clearCredential()}
            data-testid="orcarouter-clear-credential"
            className="rounded-md border border-[#2d3240] px-2 py-1 text-[9px] text-[#6f7f9a] hover:text-[#ece7dc]"
          >
            Clear
          </button>
        </div>
      )}

      {/* Two explicit authentication choices */}
      <div className="flex gap-1 rounded-lg border border-[#2d3240] bg-[#0b0d13] p-1" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={authMethod === "api_key"}
          data-testid="orcarouter-auth-tab-api-key"
          onClick={() => setAuthMethod("api_key")}
          className={cn(
            "flex flex-1 items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-[10px] font-medium transition-colors",
            authMethod === "api_key"
              ? "bg-[#131721] text-[#ece7dc]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]",
          )}
        >
          <IconKey size={11} stroke={1.7} /> API key
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={authMethod === "pkce"}
          data-testid="orcarouter-auth-tab-pkce"
          onClick={() => setAuthMethod("pkce")}
          className={cn(
            "flex flex-1 items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-[10px] font-medium transition-colors",
            authMethod === "pkce"
              ? "bg-[#131721] text-[#ece7dc]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]",
          )}
        >
          <IconShieldLock size={11} stroke={1.7} /> Connect with OrcaRouter
        </button>
      </div>

      {authMethod === "api_key" ? (
        <div className="flex flex-col gap-1.5" data-testid="orcarouter-api-key-section">
          <label className="text-[10px] text-[#6f7f9a]" htmlFor="orcarouter-api-key-input">
            Paste an existing OrcaRouter key
          </label>
          <div className="relative">
            <input
              id="orcarouter-api-key-input"
              type="password"
              value={apiKeyDraft}
              onChange={(event) => setApiKeyDraft(event.target.value)}
              placeholder="sk-orca-…"
              autoComplete="off"
              spellCheck={false}
              data-testid="orcarouter-api-key-input"
              className="h-8 w-full rounded-md border border-[#2d3240] bg-[#131721] px-2.5 py-1 font-mono text-xs text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50"
            />
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[9px] text-[#6f7f9a]/70">
              Stored in the workbench secure store; never written to policy YAML by this panel.
            </span>
            <button
              type="button"
              onClick={() => void saveApiKey()}
              disabled={apiKeyDraft.trim().length === 0}
              data-testid="orcarouter-save-key"
              className={cn(
                "h-7 rounded-md px-3 text-[10px] font-medium transition-colors",
                apiKeyDraft.trim().length > 0
                  ? "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]"
                  : "cursor-not-allowed border border-[#2d3240] bg-[#131721] text-[#6f7f9a] opacity-60",
              )}
            >
              Save key
            </button>
          </div>
          {keyHint && (
            <p
              data-testid="orcarouter-key-hint"
              className={cn(
                "text-[9px]",
                keyHint.kind === "error" ? "text-[#c45c5c]" : "text-[#3dbf84]",
              )}
            >
              {keyHint.message}
            </p>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-2" data-testid="orcarouter-pkce-section">
          <p className="text-[10px] leading-relaxed text-[#6f7f9a]">
            Authorize in your browser; OrcaRouter shows a short code. No client secret is used —
            PKCE binds the code to this session.
          </p>
          {!attempt && connectPhase === "idle" && (
            <button
              type="button"
              onClick={() => void startConnect()}
              data-testid="orcarouter-connect-button"
              className="flex h-8 items-center justify-center gap-1.5 rounded-md bg-[#d4a84b] px-3 text-[10px] font-medium text-[#05060a] hover:bg-[#e8c36a]"
            >
              <IconShieldLock size={12} stroke={1.8} /> Connect with OrcaRouter
            </button>
          )}

          {attempt && (
            <div className="flex flex-col gap-2 rounded-md border border-[#2d3240] bg-[#131721] p-2.5">
              <span className="text-[9px] text-[#6f7f9a]">
                Open the consent screen, approve, then paste the code shown there.
              </span>
              <a
                href={attempt.authorizeUrl}
                target="_blank"
                rel="noreferrer"
                className="truncate font-mono text-[9px] text-[#d4a84b] hover:underline"
                data-testid="orcarouter-authorize-url"
              >
                {attempt.authorizeUrl}
              </a>
              <input
                type="text"
                value={codeDraft}
                onChange={(event) => setCodeDraft(event.target.value)}
                placeholder="Authorization code"
                autoComplete="off"
                spellCheck={false}
                data-testid="orcarouter-code-input"
                className="h-8 w-full rounded-md border border-[#2d3240] bg-[#0b0d13] px-2.5 font-mono text-xs text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50"
              />
              <div className="flex items-center justify-between">
                <button
                  type="button"
                  onClick={cancelConnect}
                  data-testid="orcarouter-cancel-connect"
                  className="text-[9px] text-[#6f7f9a] underline hover:text-[#ece7dc]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => void completeConnect()}
                  disabled={connectPhase === "exchanging" || codeDraft.trim().length === 0}
                  data-testid="orcarouter-complete-connect"
                  className={cn(
                    "h-7 rounded-md px-3 text-[10px] font-medium",
                    connectPhase === "exchanging"
                      ? "cursor-wait bg-[#d4a84b]/20 text-[#d4a84b]"
                      : "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]",
                  )}
                >
                  {connectPhase === "exchanging" ? (
                    <span className="flex items-center gap-1">
                      <IconLoader2 size={11} className="animate-spin" /> Exchanging…
                    </span>
                  ) : (
                    "Finish connect"
                  )}
                </button>
              </div>
            </div>
          )}

          {connectPhase === "connected" && (
            <p className="flex items-center gap-1 text-[10px] text-[#3dbf84]">
              <IconCheck size={11} stroke={2} /> Connected — the key is stored locally.
            </p>
          )}

          {connectPhase === "error" && (
            <div className="flex flex-col gap-1.5 rounded-md border border-[#c45c5c]/30 bg-[#c45c5c]/5 p-2">
              <span className="flex items-center gap-1 text-[10px] text-[#c45c5c]" data-testid="orcarouter-connect-error">
                <IconX size={11} stroke={2} /> {connectError ?? "Authorization failed"}
              </span>
              <button
                type="button"
                onClick={() => void startConnect()}
                data-testid="orcarouter-retry-connect"
                className="self-start text-[9px] text-[#d4a84b] underline"
              >
                Try again
              </button>
            </div>
          )}
        </div>
      )}

      {/* Model selection — always catalogue-driven */}
      <div className="flex flex-col gap-3 border-t border-[#2d3240] pt-3">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono text-[#ece7dc]">Models</span>
          <div className="flex items-center gap-2">
            <span
              data-testid="orcarouter-catalog-status"
              className={cn(
                "text-[9px]",
                catalogStatus === "ready" && "text-[#3dbf84]",
                catalogStatus === "degraded" && "text-[#d4a84b]",
                catalogStatus === "error" && "text-[#c45c5c]",
                catalogStatus === "loading" && "text-[#6f7f9a]",
              )}
            >
              {catalogStatus === "ready" && `live catalogue · ${catalog?.models.length ?? 0} models`}
              {catalogStatus === "degraded" && `degraded · ${catalog?.source ?? "seed"}`}
              {catalogStatus === "loading" && "loading catalogue…"}
              {catalogStatus === "error" && "catalogue unavailable"}
            </span>
            <button
              type="button"
              onClick={() => credential && void refreshCatalog(credential.apiKey)}
              disabled={!controlsEnabled}
              data-testid="orcarouter-refresh-catalog"
              className="flex items-center gap-1 rounded-md border border-[#2d3240] px-1.5 py-0.5 text-[9px] text-[#6f7f9a] hover:text-[#ece7dc] disabled:opacity-40"
            >
              <IconRefresh size={9} stroke={2} /> Refresh
            </button>
          </div>
        </div>

        {catalogStatus === "degraded" && catalog?.note && (
          <p className="flex items-start gap-1 text-[9px] text-[#d4a84b]" data-testid="orcarouter-catalog-note">
            <IconAlertTriangle size={10} stroke={1.8} className="mt-0.5 shrink-0" />
            {catalog.note}
          </p>
        )}

        {!credential && (
          <p className="text-[9px] text-[#6f7f9a]/80" data-testid="orcarouter-catalog-empty">
            Add a key or connect an account to load the model catalogue.
          </p>
        )}

        {credential && catalogStatus !== "loading" && embeddingFromVerifiedSeed && (
          <p className="text-[9px] text-[#d4a84b]" data-testid="orcarouter-embedding-fallback-note">
            The live catalogue advertises no embedding-capable model for this workspace; showing the
            verified OrcaRouter embedding route (orcarouter/auto).
          </p>
        )}

        <ModelSelect
          id="orcarouter-embedding-model"
          label="Embedding model"
          hint="Used by the Trustprint (Spider Sense) guard for behavioural screening."
          models={embeddingModels}
          value={selection.embeddingModel}
          disabled={!controlsEnabled}
          onChange={(modelId) => onSelectionChange({ ...selection, embeddingModel: modelId })}
        />

        <ModelSelect
          id="orcarouter-chat-model"
          label="Reasoning model (LLM deep path)"
          hint="Used for ambiguous-case reasoning when the deep path is enabled. Default is orcarouter/auto."
          models={chatModels}
          value={selection.chatModel}
          disabled={!controlsEnabled}
          onChange={(modelId) => onSelectionChange({ ...selection, chatModel: modelId })}
        />
      </div>
    </div>
  );
}
