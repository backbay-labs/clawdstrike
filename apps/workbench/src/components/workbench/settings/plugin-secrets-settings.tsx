import { useState, useEffect, useCallback } from "react";
import {
  IconEye,
  IconEyeOff,
  IconCheck,
  IconX,
  IconLoader2,
  IconShieldLock,
  IconPlugConnected,
  IconKey,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { secureStore } from "@/lib/workbench/secure-store";
import { pluginRegistry } from "@/lib/plugins/plugin-registry";
import { getThreatIntelSource } from "@/lib/workbench/threat-intel-registry";
import { getBuiltinThreatIntelDescriptor } from "@/lib/plugins/threat-intel/catalog";
import type { RegisteredPlugin } from "@/lib/plugins/types";
import type { PluginSecretDeclaration } from "@/lib/plugins/types";

function getIntelPlugins(): RegisteredPlugin[] {
  return pluginRegistry.getAll().filter((p) =>
    p.manifest.categories.includes("intel"),
  );
}

function secretStoreKey(pluginId: string, secretKey: string): string {
  return `plugin:${pluginId}:${secretKey}`;
}

interface SecretFieldProps {
  pluginId: string;
  secret: PluginSecretDeclaration;
}

function SecretField({ pluginId, secret }: SecretFieldProps) {
  const [value, setValue] = useState("");
  const [showValue, setShowValue] = useState(false);
  const [hasSaved, setHasSaved] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveResult, setSaveResult] = useState<"success" | "error" | null>(null);
  const [isEditing, setIsEditing] = useState(false);

  const storeKey = secretStoreKey(pluginId, secret.key);

  useEffect(() => {
    let cancelled = false;
    secureStore.has(storeKey).then((exists) => {
      if (!cancelled) {
        setHasSaved(exists);
      }
    }).catch(() => {
      if (!cancelled) setHasSaved(false);
    });
    return () => {
      cancelled = true;
    };
  }, [storeKey]);

  const handleSave = useCallback(async () => {
    if (!value.trim()) return;
    setIsSaving(true);
    setSaveResult(null);
    try {
      await secureStore.set(storeKey, value);
      setSaveResult("success");
      setHasSaved(true);
      setIsEditing(false);
      setValue("");
      setTimeout(() => setSaveResult(null), 2000);
    } catch {
      setSaveResult("error");
      setTimeout(() => setSaveResult(null), 3000);
    } finally {
      setIsSaving(false);
    }
  }, [storeKey, value]);

  const handleChange = useCallback(() => {
    setIsEditing(true);
    setHasSaved(false);
    setValue("");
  }, []);

  // Saved state: show masked dots and Change button
  if (hasSaved && !isEditing) {
    return (
      <div className="flex flex-col gap-1.5">
        <label className="text-xs font-medium text-[#ece7dc]">{secret.label}</label>
        <div className="flex items-center gap-2">
          <div className="flex-1 h-8 px-2.5 rounded-lg border border-[#2d3240] bg-[#131721] flex items-center">
            <span className="text-xs text-[#6f7f9a] tracking-wider">
              &#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;
            </span>
          </div>
          <button
            data-testid={`change-${pluginId}-${secret.key}`}
            onClick={handleChange}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-medium border border-[#2d3240] bg-[#131721] text-[#ece7dc] hover:border-[#d4a84b]/40 hover:text-[#d4a84b] transition-colors"
          >
            Change
          </button>
        </div>
        {secret.description && (
          <span className="text-[10px] text-[#6f7f9a]">{secret.description}</span>
        )}
      </div>
    );
  }

  // Editing/new state: show input field
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={`secret-${pluginId}-${secret.key}`} className="text-xs font-medium text-[#ece7dc]">
        {secret.label}
      </label>
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <input
            id={`secret-${pluginId}-${secret.key}`}
            type={showValue ? "text" : "password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={`Enter ${secret.label.toLowerCase()}`}
            className="w-full h-8 px-2.5 pr-9 rounded-lg border border-[#2d3240] bg-[#131721] text-xs text-[#ece7dc] font-mono placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/50 focus:outline-none focus:ring-1 focus:ring-[#d4a84b]/20 transition-colors"
          />
          <button
            type="button"
            data-testid={`toggle-${pluginId}-${secret.key}`}
            onClick={() => setShowValue(!showValue)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          >
            {showValue ? (
              <IconEyeOff size={14} stroke={1.5} />
            ) : (
              <IconEye size={14} stroke={1.5} />
            )}
          </button>
        </div>
        <button
          data-testid={`save-${pluginId}-${secret.key}`}
          onClick={handleSave}
          disabled={isSaving || !value.trim()}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-medium border transition-colors",
            isSaving
              ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] cursor-wait"
              : !value.trim()
                ? "text-[#6f7f9a] border-[#2d3240] bg-[#131721] opacity-50 cursor-not-allowed"
                : "text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b]",
          )}
        >
          {isSaving ? (
            <IconLoader2 size={12} stroke={1.5} className="animate-spin" />
          ) : (
            <IconKey size={12} stroke={1.5} />
          )}
          Save
        </button>
      </div>
      {saveResult === "success" && (
        <div className="flex items-center gap-1.5 text-[10px] text-[#3dbf84]">
          <IconCheck size={11} stroke={2} />
          <span>Saved successfully</span>
        </div>
      )}
      {saveResult === "error" && (
        <div className="flex items-center gap-1.5 text-[10px] text-[#c45c5c]">
          <IconX size={11} stroke={2} />
          <span>Failed to save</span>
        </div>
      )}
      {secret.description && (
        <span className="text-[10px] text-[#6f7f9a]">{secret.description}</span>
      )}
    </div>
  );
}

interface PluginCardProps {
  plugin: RegisteredPlugin;
}

function PluginCard({ plugin }: PluginCardProps) {
  const { manifest } = plugin;
  const secrets = manifest.requiredSecrets ?? [];
  const [testResult, setTestResult] = useState<"success" | "error" | null>(null);
  const [testMessage, setTestMessage] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  // Fallback: if no requiredSecrets, derive from threatIntelSources contribution name
  const effectiveSecrets: PluginSecretDeclaration[] =
    secrets.length > 0
      ? secrets
      : manifest.contributions?.threatIntelSources?.map((source) => ({
          key: "api_key",
          label: `${source.name} API Key`,
          description: `API key for ${source.name}`,
        })) ?? [];

  const handleTestConnection = useCallback(async () => {
    setIsTesting(true);
    setTestResult(null);
    setTestMessage(null);

    try {
      const builtinDescriptor = getBuiltinThreatIntelDescriptor(manifest.id);
      let source = manifest.contributions?.threatIntelSources?.[0]
        ? getThreatIntelSource(manifest.contributions.threatIntelSources[0].id)
        : undefined;

      if (builtinDescriptor) {
        const secrets = await Promise.all(
          builtinDescriptor.secretKeys.map((key) =>
            secureStore.get(secretStoreKey(manifest.id, key)),
          ),
        );

        if (secrets.some((secret) => !secret?.trim())) {
          setTestResult("error");
          setTestMessage("Save all required secrets before testing the connection.");
          return;
        }

        source = builtinDescriptor.create(secrets);
      }

      if (!source?.healthCheck) {
        setTestResult("error");
        setTestMessage("Connection testing is not available for this plugin.");
        return;
      }

      const result = await source.healthCheck();
      setTestResult(result.healthy ? "success" : "error");
      setTestMessage(
        result.message ?? (result.healthy ? "Connection successful." : "Connection failed."),
      );
    } catch (error) {
      setTestResult("error");
      setTestMessage(
        error instanceof Error ? error.message : "Connection test failed.",
      );
    } finally {
      setIsTesting(false);
    }
  }, [manifest]);

  return (
    <div className="flex flex-col gap-4 p-4 rounded-lg border border-[#2d3240] bg-[#131721]/50">
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-[#d4a84b]/10 border border-[#d4a84b]/20">
          <IconShieldLock size={16} stroke={1.5} className="text-[#d4a84b]" />
        </div>
        <div>
          <h3 className="text-xs font-semibold text-[#ece7dc]">{manifest.displayName}</h3>
          <p className="text-[10px] text-[#6f7f9a]">{manifest.description}</p>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        {effectiveSecrets.map((secret) => (
          <SecretField
            key={secret.key}
            pluginId={manifest.id}
            secret={secret}
          />
        ))}
      </div>

      <div className="pt-2 border-t border-[#2d3240]/40">
        <button
          data-testid={`test-${manifest.id}`}
          onClick={handleTestConnection}
          disabled={isTesting}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-medium border border-[#2d3240] bg-[#131721] text-[#ece7dc] hover:border-[#3dbf84]/40 hover:text-[#3dbf84] transition-colors"
        >
          {isTesting ? (
            <IconLoader2 size={12} stroke={1.5} className="animate-spin" />
          ) : (
            <IconPlugConnected size={12} stroke={1.5} />
          )}
          Test Connection
        </button>
        {testResult === "success" && testMessage && (
          <div className="mt-2 flex items-center gap-1.5 text-[10px] text-[#3dbf84]">
            <IconCheck size={11} stroke={2} />
            <span>{testMessage}</span>
          </div>
        )}
        {testResult === "error" && testMessage && (
          <div className="mt-2 flex items-center gap-1.5 text-[10px] text-[#c45c5c]">
            <IconX size={11} stroke={2} />
            <span>{testMessage}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export function PluginSecretsSettings() {
  const intelPlugins = getIntelPlugins();

  if (intelPlugins.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-12">
        <IconShieldLock size={28} stroke={1.5} className="text-[#6f7f9a]/15" />
        <p className="text-[12px] text-[#6f7f9a]/40 text-center max-w-xs">
          No threat intelligence plugins installed. Install plugins from the marketplace to configure API keys.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start gap-2 p-3 rounded-lg bg-[#d4a84b]/5 border border-[#d4a84b]/10">
        <IconKey size={14} stroke={1.5} className="text-[#d4a84b] shrink-0 mt-0.5" />
        <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
          API keys are encrypted at rest using Stronghold secure storage on desktop.
          On web, sensitive keys are stored in ephemeral memory and cleared when the tab closes.
        </p>
      </div>

      {intelPlugins.map((plugin) => (
        <PluginCard key={plugin.manifest.id} plugin={plugin} />
      ))}
    </div>
  );
}
