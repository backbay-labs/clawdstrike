import { useEffect, useState } from "react";
import {
  getWorkspaceGitDiffSummary,
  getWorkspaceGitStatus,
  type WorkspaceGitDiffSummary,
  type WorkspaceGitStatusSummary,
} from "@/services/workspace";

interface WorkspaceGitPanelProps {
  rootId?: string;
  activePath?: string;
  onOpenPath?: (relativePath: string) => void;
  loadStatus?: (rootId: string) => Promise<WorkspaceGitStatusSummary>;
  loadDiffSummary?: (rootId: string, relativePath?: string) => Promise<WorkspaceGitDiffSummary>;
}

export function WorkspaceGitPanel({
  rootId,
  activePath,
  onOpenPath,
  loadStatus = getWorkspaceGitStatus,
  loadDiffSummary = getWorkspaceGitDiffSummary,
}: WorkspaceGitPanelProps) {
  const [status, setStatus] = useState<WorkspaceGitStatusSummary>();
  const [selectedPath, setSelectedPath] = useState<string>();
  const [diffSummary, setDiffSummary] = useState<WorkspaceGitDiffSummary>();
  const [errorMessage, setErrorMessage] = useState<string>();
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    if (!rootId) {
      setStatus(undefined);
      setSelectedPath(undefined);
      setDiffSummary(undefined);
      setErrorMessage(undefined);
      setIsLoading(false);
      return () => {
        cancelled = true;
      };
    }

    async function loadPanel() {
      const activeRootId = rootId;
      if (!activeRootId) return;

      setIsLoading(true);
      setErrorMessage(undefined);

      try {
        const nextStatus = await loadStatus(activeRootId);
        if (cancelled) return;

        const preferredPath =
          activePath && nextStatus.changedFiles.some((file) => file.relativePath === activePath)
            ? activePath
            : nextStatus.changedFiles[0]?.relativePath;

        setStatus(nextStatus);
        setSelectedPath(preferredPath);

        const nextDiffSummary = await loadDiffSummary(activeRootId, preferredPath);
        if (cancelled) return;
        setDiffSummary(nextDiffSummary);
      } catch (error) {
        if (cancelled) return;
        setStatus(undefined);
        setDiffSummary(undefined);
        setErrorMessage(error instanceof Error ? error.message : "Workspace git status failed.");
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    void loadPanel();
    return () => {
      cancelled = true;
    };
  }, [activePath, loadDiffSummary, loadStatus, rootId]);

  async function handleSelectPath(relativePath?: string) {
    const activeRootId = rootId;
    if (!activeRootId) return;
    setSelectedPath(relativePath);
    setIsLoading(true);
    setErrorMessage(undefined);

    try {
      const nextDiffSummary = await loadDiffSummary(activeRootId, relativePath);
      setDiffSummary(nextDiffSummary);
    } catch (error) {
      setDiffSummary(undefined);
      setErrorMessage(error instanceof Error ? error.message : "Workspace git diff failed.");
    } finally {
      setIsLoading(false);
    }
  }

  if (!rootId) {
    return <GitState title="No trusted root selected" description="Register a workspace root before git status can load." />;
  }

  if (errorMessage) {
    return <GitState title="Git status failed" description={errorMessage} tone="error" />;
  }

  if (isLoading && !status) {
    return <GitState title="Loading repository state" description="Fetching branch, status, and diff summary." />;
  }

  if (!status) {
    return <GitState title="No repository data" description="Git status is not available for the active trusted root." />;
  }

  return (
    <div className="grid h-full min-h-0 gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(280px,0.9fr)]" data-testid="workspace-git-panel">
      <section className="flex min-h-0 flex-col rounded-xl border border-sdr-border bg-sdr-bg-primary/20 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-medium text-sdr-text-primary">Repository status</div>
            <div className="mt-1 text-xs text-sdr-text-muted">
              {status.branch} · ahead {status.ahead} · behind {status.behind}
            </div>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge label={`Staged ${status.stagedCount}`} />
            <Badge label={`Unstaged ${status.unstagedCount}`} />
            <Badge label={`Untracked ${status.untrackedCount}`} />
          </div>
        </div>

        <div className="mt-4 space-y-2 overflow-auto">
          {status.changedFiles.map((file) => (
            <button
              key={file.relativePath}
              type="button"
              onClick={() => void handleSelectPath(file.relativePath)}
              className={`flex w-full items-center justify-between gap-3 rounded-xl border px-3 py-3 text-left ${
                selectedPath === file.relativePath
                  ? "border-[color:rgba(213,173,87,0.55)] bg-[rgba(213,173,87,0.08)]"
                  : "border-sdr-border bg-sdr-bg-primary/20"
              }`}
            >
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-sdr-text-primary">{file.relativePath}</div>
                <div className="mt-1 text-xs text-sdr-text-muted">
                  {file.stagedStatus.trim() || "·"} / {file.unstagedStatus.trim() || "·"} · +{file.additions} -{file.deletions}
                </div>
              </div>
              <span className="rounded-full border border-sdr-border px-2 py-1 text-[11px] uppercase tracking-[0.12em] text-sdr-text-muted">
                Diff
              </span>
            </button>
          ))}
        </div>
      </section>

      <section className="flex min-h-0 flex-col rounded-xl border border-sdr-border bg-sdr-bg-primary/20 p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-sm font-medium text-sdr-text-primary">
              {diffSummary?.relativePath ?? "Workspace diff summary"}
            </div>
            <div className="mt-1 text-xs text-sdr-text-muted">
              {diffSummary?.fileCount ?? 0} files · +{diffSummary?.additions ?? 0} -{diffSummary?.deletions ?? 0}
            </div>
          </div>
          {selectedPath ? (
            <button
              type="button"
              onClick={() => onOpenPath?.(selectedPath)}
              className="rounded-full border border-[color:rgba(213,173,87,0.55)] px-3 py-1 text-xs uppercase tracking-[0.12em] text-sdr-text-primary"
            >
              Open file
            </button>
          ) : null}
        </div>

        <div className="mt-4 space-y-2 overflow-auto text-xs text-sdr-text-secondary" data-testid="workspace-git-diff-preview">
          {(diffSummary?.previewLines ?? ["No diff summary yet."]).map((line) => (
            <pre
              key={line}
              className="overflow-auto rounded-lg border border-sdr-border bg-sdr-bg-primary/30 px-3 py-2 font-mono"
            >
              {line}
            </pre>
          ))}
        </div>
      </section>
    </div>
  );
}

function Badge({ label }: { label: string }) {
  return (
    <span className="rounded-full border border-sdr-border px-2 py-1 text-sdr-text-muted">
      {label}
    </span>
  );
}

function GitState({
  title,
  description,
  tone = "default",
}: {
  title: string;
  description: string;
  tone?: "default" | "error";
}) {
  return (
    <div
      className={`rounded-xl border p-4 text-sm ${
        tone === "error"
          ? "border-red-500/40 bg-red-500/10 text-red-100"
          : "border-dashed border-sdr-border bg-sdr-bg-primary/20 text-sdr-text-secondary"
      }`}
    >
      <div className="font-medium">{title}</div>
      <p className="mt-2 text-xs opacity-80">{description}</p>
    </div>
  );
}
