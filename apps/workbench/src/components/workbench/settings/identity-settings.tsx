// ---------------------------------------------------------------------------
// Identity Settings — operator identity management, device list, key export/import.
// ---------------------------------------------------------------------------
import { useState, useCallback } from "react";
import {
  IconFingerprint,
  IconEdit,
  IconCheck,
  IconX,
  IconDownload,
  IconUpload,
  IconDevices,
  IconLink,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useOperator } from "@/lib/workbench/operator-store";
import { deriveSigil, deriveSigilColor } from "@/lib/workbench/sentinel-manager";
import type { SigilType } from "@/lib/workbench/sentinel-manager";

// ---------------------------------------------------------------------------
// Sigil renderer (matches existing pattern from swarm-detail)
// ---------------------------------------------------------------------------

export const SIGIL_SYMBOLS: Record<SigilType, string> = {
  diamond: "\u25C6",
  eye: "\u25C9",
  wave: "\u223F",
  crown: "\u2655",
  spiral: "\u2386",
  key: "\u26BF",
  star: "\u2605",
  moon: "\u263D",
};

// ---------------------------------------------------------------------------
// IdentitySettings
// ---------------------------------------------------------------------------

export function IdentitySettings() {
  const {
    currentOperator,
    updateDisplayName,
    exportKey,
    importKey,
  } = useOperator();

  const [editingName, setEditingName] = useState(false);
  const [nameValue, setNameValue] = useState("");

  // Export
  const [showExport, setShowExport] = useState(false);
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [exportResult, setExportResult] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  // Import
  const [showImport, setShowImport] = useState(false);
  const [importData, setImportData] = useState("");
  const [importPassphrase, setImportPassphrase] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [importSuccess, setImportSuccess] = useState(false);

  const handleEditName = useCallback(() => {
    if (!currentOperator) return;
    setNameValue(currentOperator.displayName);
    setEditingName(true);
  }, [currentOperator]);

  const handleSaveName = useCallback(() => {
    if (nameValue.trim()) {
      updateDisplayName(nameValue.trim());
    }
    setEditingName(false);
  }, [nameValue, updateDisplayName]);

  const handleExport = useCallback(async () => {
    if (!exportPassphrase) return;
    setExportError(null);
    setExportResult(null);
    try {
      const result = await exportKey(exportPassphrase);
      if (!result) {
        setExportError("No secret key available to export.");
        return;
      }
      setExportResult(result);
    } catch (e) {
      setExportError(e instanceof Error ? e.message : "Export failed");
    }
  }, [exportPassphrase, exportKey]);

  const handleImport = useCallback(async () => {
    if (!importData.trim() || !importPassphrase) return;
    setImportError(null);
    setImportSuccess(false);
    try {
      const result = await importKey(importData.trim(), importPassphrase);
      if (!result) {
        setImportError("Import failed — check passphrase and data.");
        return;
      }
      setImportSuccess(true);
      setShowImport(false);
      setImportData("");
      setImportPassphrase("");
    } catch (e) {
      setImportError(e instanceof Error ? e.message : "Import failed");
    }
  }, [importData, importPassphrase, importKey]);

  if (!currentOperator) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <IconFingerprint size={24} className="text-[#6f7f9a]/30 mb-3" />
        <p className="text-[12px] text-[#6f7f9a]/60">
          No operator identity found. Create one to manage your keys and devices.
        </p>
      </div>
    );
  }

  const sigil = deriveSigil(currentOperator.fingerprint) as SigilType;
  const sigilColor = deriveSigilColor(currentOperator.fingerprint);
  const sigilSymbol = SIGIL_SYMBOLS[sigil] ?? "\u25C6";

  return (
    <div className="flex flex-col gap-6">
      {/* Identity card */}
      <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721] p-5">
        <div className="flex items-start gap-4">
          {/* Sigil */}
          <div
            className="w-12 h-12 rounded-xl flex items-center justify-center text-xl shrink-0"
            style={{ backgroundColor: sigilColor + "20", color: sigilColor }}
          >
            {sigilSymbol}
          </div>

          <div className="flex-1 min-w-0">
            {/* Display name */}
            <div className="flex items-center gap-2">
              {editingName ? (
                <div className="flex items-center gap-1.5">
                  <input
                    type="text"
                    value={nameValue}
                    onChange={(e) => setNameValue(e.target.value)}
                    autoFocus
                    maxLength={64}
                    className="rounded-md border border-[#d4a84b]/40 bg-[#05060a] px-2 py-1 text-[13px] text-[#ece7dc] outline-none w-48"
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleSaveName();
                      if (e.key === "Escape") setEditingName(false);
                    }}
                  />
                  <button
                    onClick={handleSaveName}
                    className="text-[#3dbf84] hover:text-[#3dbf84]/80 transition-colors"
                  >
                    <IconCheck size={14} stroke={1.5} />
                  </button>
                  <button
                    onClick={() => setEditingName(false)}
                    className="text-[#6f7f9a]/50 hover:text-[#ece7dc] transition-colors"
                  >
                    <IconX size={14} stroke={1.5} />
                  </button>
                </div>
              ) : (
                <>
                  <span className="text-[13px] font-semibold text-[#ece7dc]">
                    {currentOperator.displayName}
                  </span>
                  <button
                    onClick={handleEditName}
                    className="text-[#6f7f9a]/40 hover:text-[#ece7dc] transition-colors"
                  >
                    <IconEdit size={12} stroke={1.5} />
                  </button>
                </>
              )}
            </div>

            {/* Fingerprint */}
            <div className="flex items-center gap-2 mt-1">
              <IconFingerprint size={12} className="text-[#6f7f9a]/40" stroke={1.5} />
              <span className="text-[10px] font-mono text-[#6f7f9a]/60 tracking-wider">
                {currentOperator.fingerprint}
              </span>
            </div>

            {/* Metadata */}
            <div className="flex items-center gap-4 mt-2 text-[9px] text-[#6f7f9a]/40">
              <span>Created {new Date(currentOperator.createdAt).toLocaleDateString()}</span>
              <span title="Unique visual identifier derived from an operator's cryptographic fingerprint">Sigil: {sigil}</span>
              <span>{currentOperator.devices.length} device{currentOperator.devices.length !== 1 ? "s" : ""}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Devices */}
      <SettingsSection
        icon={<IconDevices size={14} stroke={1.5} />}
        label="Devices"
        description="Devices linked to this operator identity"
      >
        <div className="rounded-md border border-[#2d3240]/60 overflow-hidden">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="border-b border-[#2d3240]/40 bg-[#0b0d13]">
                <th className="text-left px-3 py-2 text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 font-semibold">
                  Device ID
                </th>
                <th className="text-left px-3 py-2 text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 font-semibold">
                  Name
                </th>
                <th className="text-left px-3 py-2 text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 font-semibold">
                  Last Seen
                </th>
              </tr>
            </thead>
            <tbody>
              {currentOperator.devices.map((d) => (
                <tr key={d.deviceId} className="border-b border-[#2d3240]/20 last:border-0">
                  <td className="px-3 py-2 font-mono text-[#ece7dc]/60 truncate max-w-[120px]">
                    {d.deviceId}
                  </td>
                  <td className="px-3 py-2 text-[#ece7dc]/70">{d.deviceName}</td>
                  <td className="px-3 py-2 text-[#6f7f9a]/50">
                    {new Date(d.lastSeenAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SettingsSection>

      {/* Key Management */}
      <SettingsSection
        icon={<IconDownload size={14} stroke={1.5} />}
        label="Key Management"
        description="Export or import your operator secret key"
      >
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setShowExport(!showExport); setShowImport(false); }}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium border transition-colors",
              showExport
                ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10"
                : "text-[#6f7f9a] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/20 hover:text-[#ece7dc]",
            )}
          >
            <IconDownload size={12} stroke={1.5} />
            Export Key
          </button>
          <button
            onClick={() => { setShowImport(!showImport); setShowExport(false); }}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium border transition-colors",
              showImport
                ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10"
                : "text-[#6f7f9a] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/20 hover:text-[#ece7dc]",
            )}
          >
            <IconUpload size={12} stroke={1.5} />
            Import Key
          </button>
        </div>

        {/* Export panel */}
        {showExport && (
          <div className="mt-3 rounded-md border border-[#2d3240]/60 bg-[#0b0d13] p-4 flex flex-col gap-3">
            <div>
              <label className="text-[10px] uppercase tracking-wider text-[#6f7f9a]/60 font-semibold">
                Passphrase
              </label>
              <input
                type="password"
                value={exportPassphrase}
                onChange={(e) => setExportPassphrase(e.target.value)}
                placeholder="Enter a passphrase to encrypt your key"
                className="mt-1 w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40"
              />
            </div>
            <button
              onClick={handleExport}
              disabled={!exportPassphrase}
              className={cn(
                "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[11px] font-medium transition-colors",
                exportPassphrase
                  ? "bg-[#d4a84b]/10 border border-[#d4a84b]/30 text-[#d4a84b] hover:bg-[#d4a84b]/20"
                  : "bg-[#2d3240]/30 border border-[#2d3240]/40 text-[#6f7f9a]/30 cursor-not-allowed",
              )}
            >
              <IconDownload size={12} stroke={1.5} />
              Export
            </button>
            {exportError && (
              <div className="flex items-center gap-2 text-[11px] text-[#c45c5c]">
                <IconAlertTriangle size={12} stroke={1.5} />
                {exportError}
              </div>
            )}
            {exportResult && (
              <textarea
                readOnly
                value={exportResult}
                rows={3}
                className="w-full rounded-md border border-[#3dbf84]/20 bg-[#05060a] px-3 py-2 text-[9px] font-mono text-[#ece7dc]/60 outline-none resize-none"
              />
            )}
          </div>
        )}

        {/* Import panel */}
        {showImport && (
          <div className="mt-3 rounded-md border border-[#2d3240]/60 bg-[#0b0d13] p-4 flex flex-col gap-3">
            <div>
              <label className="text-[10px] uppercase tracking-wider text-[#6f7f9a]/60 font-semibold">
                Encrypted Key Data
              </label>
              <textarea
                value={importData}
                onChange={(e) => setImportData(e.target.value)}
                placeholder="Paste the exported key data..."
                rows={3}
                className="mt-1 w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[10px] font-mono text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 resize-none"
              />
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider text-[#6f7f9a]/60 font-semibold">
                Passphrase
              </label>
              <input
                type="password"
                value={importPassphrase}
                onChange={(e) => setImportPassphrase(e.target.value)}
                placeholder="Enter the passphrase used during export"
                className="mt-1 w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[12px] text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40"
              />
            </div>
            <button
              onClick={handleImport}
              disabled={!importData.trim() || !importPassphrase}
              className={cn(
                "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[11px] font-medium transition-colors",
                importData.trim() && importPassphrase
                  ? "bg-[#d4a84b]/10 border border-[#d4a84b]/30 text-[#d4a84b] hover:bg-[#d4a84b]/20"
                  : "bg-[#2d3240]/30 border border-[#2d3240]/40 text-[#6f7f9a]/30 cursor-not-allowed",
              )}
            >
              <IconUpload size={12} stroke={1.5} />
              Import
            </button>
            {importError && (
              <div className="flex items-center gap-2 text-[11px] text-[#c45c5c]">
                <IconAlertTriangle size={12} stroke={1.5} />
                {importError}
              </div>
            )}
            {importSuccess && (
              <div className="flex items-center gap-2 text-[11px] text-[#3dbf84]">
                <IconCheck size={12} stroke={1.5} />
                Key imported successfully.
              </div>
            )}
          </div>
        )}
      </SettingsSection>

      {/* IdP Federation */}
      <SettingsSection
        icon={<IconLink size={14} stroke={1.5} />}
        label="IdP Federation"
        description="Link your operator identity to an enterprise identity provider"
      >
        <button
          disabled
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium border text-[#6f7f9a]/30 border-[#2d3240]/40 bg-[#131721]/50 cursor-not-allowed"
        >
          <IconLink size={12} stroke={1.5} />
          Link Enterprise Identity
        </button>
        <p className="text-[10px] text-[#6f7f9a]/40 mt-1.5">
          OIDC and SAML federation will be available in a future release.
        </p>
      </SettingsSection>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared layout
// ---------------------------------------------------------------------------

function SettingsSection({
  icon,
  label,
  description,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <span className="text-[#d4a84b]">{icon}</span>
        <span className="text-xs font-medium text-[#ece7dc]">{label}</span>
      </div>
      <span className="text-[10px] text-[#6f7f9a] -mt-1 ml-[22px]">{description}</span>
      <div className="ml-[22px]">{children}</div>
    </div>
  );
}
