import {
  useRef,
  useState,
  useCallback,
  useMemo,
  useEffect,
  type WheelEvent as ReactWheelEvent,
  type MouseEvent as ReactMouseEvent,
} from "react";
import {
  IconPlus,
  IconTrash,
  IconFocus2,
  IconZoomIn,
  IconZoomOut,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  layoutScenarioGraph,
  type ScenarioNode,
  type ScenarioGraphLayout,
} from "@/lib/workbench/scenario-graph-engine";


const ACTION_ACCENT: Record<string, string> = {
  file_access: "#3dbf84",
  file_write: "#3dbf84",
  network_egress: "#5b8def",
  shell_command: "#c45c5c",
  mcp_tool_call: "#d4a84b",
  patch_apply: "#9b7ed8",
  user_input: "#e0a458",
};

const EXPECT_COLORS: Record<string, string> = {
  allow: "#3dbf84",
  deny: "#c45c5c",
  warn: "#d4a84b",
};

const ACTION_OPTIONS = [
  { value: "file_access", label: "File Read" },
  { value: "file_write", label: "File Write" },
  { value: "network_egress", label: "Network" },
  { value: "shell_command", label: "Shell" },
  { value: "mcp_tool_call", label: "MCP Tool" },
  { value: "patch_apply", label: "Patch" },
  { value: "user_input", label: "User Input" },
];


export interface ScenarioGraphScenario {
  name: string;
  action: string;
  target: string;
  expect?: string;
  content?: string;
}

interface ScenarioGraphProps {
  scenarios: ScenarioGraphScenario[];
  results?: Map<string, { verdict: string; passed: boolean | null; guard: string | null }>;
  onUpdate: (scenarios: ScenarioGraphScenario[]) => void;
  className?: string;
}


export function ScenarioGraph({ scenarios, results, onUpdate, className }: ScenarioGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  // Pan/zoom state
  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const [zoom, setZoom] = useState(1);
  const isPanningRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });

  // Selection
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);

  // Compute layout
  const layout = useMemo<ScenarioGraphLayout>(
    () => layoutScenarioGraph(scenarios),
    [scenarios],
  );

  // Merge results into nodes
  const nodesWithResults = useMemo(() => {
    if (!results) return layout.nodes;
    return layout.nodes.map((n) => {
      if (n.kind !== "scenario") return n;
      // Extract index from id "scenario-N"
      const idx = parseInt(n.id.replace("scenario-", ""), 10);
      const scenario = scenarios[idx];
      if (!scenario) return n;
      const r = results.get(scenario.name);
      if (!r) return n;
      return { ...n, result: r };
    });
  }, [layout.nodes, results, scenarios]);

  // Fit-to-viewport on layout change
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    if (layout.width === 0 || layout.height === 0) {
      setPanX(0);
      setPanY(0);
      setZoom(1);
      return;
    }
    const padded = 40;
    const zw = (rect.width - padded * 2) / layout.width;
    const zh = (rect.height - padded * 2) / layout.height;
    const newZoom = Math.min(Math.max(Math.min(zw, zh), 0.3), 1.5);
    setPanX((rect.width - layout.width * newZoom) / 2);
    setPanY((rect.height - layout.height * newZoom) / 2);
    setZoom(newZoom);
  }, [layout]);

  // --- Pan/Zoom handlers ---

  const onMouseDown = useCallback((e: ReactMouseEvent) => {
    if ((e.target as HTMLElement).closest("[data-node]")) return;
    isPanningRef.current = true;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const onMouseMove = useCallback((e: ReactMouseEvent) => {
    if (!isPanningRef.current) return;
    const dx = e.clientX - lastMouseRef.current.x;
    const dy = e.clientY - lastMouseRef.current.y;
    setPanX((p) => p + dx);
    setPanY((p) => p + dy);
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const onMouseUp = useCallback(() => {
    isPanningRef.current = false;
  }, []);

  const onWheel = useCallback(
    (e: ReactWheelEvent) => {
      e.stopPropagation();
      const container = containerRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      const newZoom = Math.min(Math.max(zoom * factor, 0.15), 4);
      const wx = (x - panX) / zoom;
      const wy = (y - panY) / zoom;
      setPanX(x - wx * newZoom);
      setPanY(y - wy * newZoom);
      setZoom(newZoom);
    },
    [zoom, panX, panY],
  );

  const onBackgroundClick = useCallback((e: ReactMouseEvent) => {
    if ((e.target as HTMLElement).closest("[data-node]")) return;
    setSelectedIdx(null);
  }, []);

  const fitToScreen = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const rect = container.getBoundingClientRect();
    if (layout.width === 0 || layout.height === 0) return;
    const padded = 40;
    const zw = (rect.width - padded * 2) / layout.width;
    const zh = (rect.height - padded * 2) / layout.height;
    const newZoom = Math.min(Math.max(Math.min(zw, zh), 0.3), 1.5);
    setPanX((rect.width - layout.width * newZoom) / 2);
    setPanY((rect.height - layout.height * newZoom) / 2);
    setZoom(newZoom);
  }, [layout]);

  // --- Edit handlers ---

  const updateScenario = useCallback(
    (idx: number, updates: Partial<ScenarioGraphScenario>) => {
      const next = scenarios.map((s, i) => (i === idx ? { ...s, ...updates } : s));
      onUpdate(next);
    },
    [scenarios, onUpdate],
  );

  const deleteScenario = useCallback(
    (idx: number) => {
      const next = scenarios.filter((_, i) => i !== idx);
      onUpdate(next);
      setSelectedIdx(null);
    },
    [scenarios, onUpdate],
  );

  const addScenarioAfter = useCallback(
    (idx: number) => {
      const newScenario: ScenarioGraphScenario = {
        name: `Scenario ${scenarios.length + 1}`,
        action: "file_access",
        target: "",
      };
      const next = [...scenarios];
      next.splice(idx + 1, 0, newScenario);
      onUpdate(next);
      setSelectedIdx(idx + 1);
    },
    [scenarios, onUpdate],
  );

  const addScenarioEnd = useCallback(() => {
    const newScenario: ScenarioGraphScenario = {
      name: `Scenario ${scenarios.length + 1}`,
      action: "file_access",
      target: "",
    };
    onUpdate([...scenarios, newScenario]);
    setSelectedIdx(scenarios.length);
  }, [scenarios, onUpdate]);

  const selectedScenario = selectedIdx !== null ? scenarios[selectedIdx] : null;

  return (
    <div className={cn("flex flex-col h-full", className)}>
      {/* Graph area */}
      <div
        ref={containerRef}
        className="relative flex-1 cursor-grab active:cursor-grabbing overflow-hidden"
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onClick={onBackgroundClick}
        onWheel={onWheel}
      >
        {/* Toolbar */}
        <div className="absolute left-3 top-3 z-10 flex items-center gap-0.5 rounded-md border border-[#1a1f2e] bg-[#0b0d13]/95 px-1.5 py-1 backdrop-blur-sm">
          <ToolbarBtn icon={IconFocus2} label="Fit" onClick={fitToScreen} />
          <ToolbarBtn
            icon={IconZoomIn}
            label="In"
            onClick={() => setZoom((z) => Math.min(z * 1.25, 4))}
          />
          <ToolbarBtn
            icon={IconZoomOut}
            label="Out"
            onClick={() => setZoom((z) => Math.max(z / 1.25, 0.15))}
          />
          <Sep />
          <ToolbarBtn icon={IconPlus} label="Add" onClick={addScenarioEnd} />
        </div>

        {/* Zoom indicator */}
        <div className="absolute bottom-3 left-3 z-10 rounded border border-[#1a1f2e] bg-[#0b0d13]/90 px-2 py-0.5 text-[10px] tabular-nums text-[#6f7f9a]/60 font-mono">
          {Math.round(zoom * 100)}%
        </div>

        {/* Node count */}
        <div className="absolute right-3 top-3 z-10 rounded px-2 py-0.5 text-[9px] font-mono text-[#6f7f9a]/50">
          {scenarios.length} scenario{scenarios.length !== 1 ? "s" : ""}
        </div>

        <svg className="h-full w-full" style={{ background: "#05060a" }}>
          <defs>
            <pattern id="scenario-grid-dot" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="12" cy="12" r="0.5" fill="#1a1f2e" />
            </pattern>
            <marker
              id="scenario-arrow"
              markerWidth="6"
              markerHeight="6"
              refX="5"
              refY="3"
              orient="auto"
            >
              <path d="M 0 0 L 6 3 L 0 6 Z" fill="#2d3240" />
            </marker>
          </defs>

          <rect width="100%" height="100%" fill="url(#scenario-grid-dot)" />

          <g data-viewport="" transform={`translate(${panX},${panY}) scale(${zoom})`}>
            {/* Edges */}
            {layout.edges.map((edge) => (
              <path
                key={`${edge.from}-${edge.to}`}
                d={edge.path}
                fill="none"
                stroke="#2d3240"
                strokeWidth={1.5}
                markerEnd="url(#scenario-arrow)"
                opacity={0.5}
              />
            ))}

            {/* Nodes */}
            {nodesWithResults.map((node) => {
              if (node.kind === "start" || node.kind === "end") {
                return <PillNode key={node.id} node={node} />;
              }

              const idx = parseInt(node.id.replace("scenario-", ""), 10);
              const isSelected = selectedIdx === idx;

              return (
                <ScenarioNodeEl
                  key={node.id}
                  node={node}
                  isSelected={isSelected}
                  onClick={() => setSelectedIdx(idx)}
                />
              );
            })}
          </g>
        </svg>
      </div>

      {/* Edit form for selected node */}
      {selectedScenario && selectedIdx !== null && (
        <div className="shrink-0 border-t border-[#1a1f2e] bg-[#0b0d13] px-4 py-3">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
              Edit Scenario #{selectedIdx + 1}
            </span>
            <div className="flex-1" />
            <button
              onClick={() => addScenarioAfter(selectedIdx)}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-[#2d3240] rounded transition-colors"
            >
              <IconPlus size={9} stroke={1.5} />
              Add After
            </button>
            <button
              onClick={() => deleteScenario(selectedIdx)}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#c45c5c] border border-[#2d3240] rounded transition-colors"
            >
              <IconTrash size={9} stroke={1.5} />
              Delete
            </button>
          </div>
          <div className="grid grid-cols-[1fr_140px_1fr_100px] gap-2">
            {/* Name */}
            <div>
              <label className="block text-[8px] font-mono uppercase text-[#6f7f9a]/60 mb-0.5">Name</label>
              <input
                type="text"
                value={selectedScenario.name}
                onChange={(e) => updateScenario(selectedIdx, { name: e.target.value })}
                className="w-full bg-[#131721] text-[#ece7dc] border border-[#2d3240] rounded px-2 py-1 text-[10px] font-mono outline-none focus:border-[#d4a84b]/50"
              />
            </div>
            {/* Action */}
            <div>
              <label className="block text-[8px] font-mono uppercase text-[#6f7f9a]/60 mb-0.5">Action</label>
              <select
                value={selectedScenario.action}
                onChange={(e) => updateScenario(selectedIdx, { action: e.target.value })}
                className="w-full bg-[#131721] text-[#ece7dc] border border-[#2d3240] rounded px-2 py-1 text-[10px] font-mono outline-none focus:border-[#d4a84b]/50"
              >
                {ACTION_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>
            {/* Target */}
            <div>
              <label className="block text-[8px] font-mono uppercase text-[#6f7f9a]/60 mb-0.5">Target</label>
              <input
                type="text"
                value={selectedScenario.target}
                onChange={(e) => updateScenario(selectedIdx, { target: e.target.value })}
                className="w-full bg-[#131721] text-[#ece7dc] border border-[#2d3240] rounded px-2 py-1 text-[10px] font-mono outline-none focus:border-[#d4a84b]/50"
              />
            </div>
            {/* Expect */}
            <div>
              <label className="block text-[8px] font-mono uppercase text-[#6f7f9a]/60 mb-0.5">Expect</label>
              <select
                value={selectedScenario.expect ?? ""}
                onChange={(e) =>
                  updateScenario(selectedIdx, {
                    expect: e.target.value || undefined,
                  })
                }
                className="w-full bg-[#131721] text-[#ece7dc] border border-[#2d3240] rounded px-2 py-1 text-[10px] font-mono outline-none focus:border-[#d4a84b]/50"
              >
                <option value="">None</option>
                <option value="allow">allow</option>
                <option value="deny">deny</option>
                <option value="warn">warn</option>
              </select>
            </div>
          </div>
          {/* Content textarea for file_write/user_input */}
          {(selectedScenario.action === "file_write" || selectedScenario.action === "user_input") && (
            <div className="mt-2">
              <label className="block text-[8px] font-mono uppercase text-[#6f7f9a]/60 mb-0.5">Content</label>
              <textarea
                value={selectedScenario.content ?? ""}
                onChange={(e) => updateScenario(selectedIdx, { content: e.target.value || undefined })}
                rows={3}
                className="w-full bg-[#131721] text-[#ece7dc] border border-[#2d3240] rounded px-2 py-1 text-[10px] font-mono outline-none resize-y focus:border-[#d4a84b]/50"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function PillNode({ node }: { node: ScenarioNode }) {
  return (
    <g transform={`translate(${node.x},${node.y})`}>
      <rect
        width={node.width}
        height={node.height}
        rx={node.height / 2}
        ry={node.height / 2}
        fill="#2d3240"
        stroke="#1a1f2e"
        strokeWidth={1}
      />
      <text
        x={node.width / 2}
        y={node.height / 2}
        textAnchor="middle"
        dominantBaseline="central"
        fill="#6f7f9a"
        fontSize={9}
        fontFamily="'JetBrains Mono', ui-monospace, monospace"
        fontWeight={600}
        className="select-none uppercase"
        letterSpacing="0.05em"
      >
        {node.name}
      </text>
    </g>
  );
}

function ScenarioNodeEl({
  node,
  isSelected,
  onClick,
}: {
  node: ScenarioNode;
  isSelected: boolean;
  onClick: () => void;
}) {
  const accent = ACTION_ACCENT[node.action] ?? "#6f7f9a";
  const hasResult = !!node.result;
  const passed = node.result?.passed;

  let borderColor = isSelected ? "#d4a84b" : "#2d3240";
  let glowColor: string | null = null;

  if (hasResult) {
    if (passed === true) {
      borderColor = isSelected ? "#d4a84b" : "#3dbf84";
      glowColor = "#3dbf84";
    } else if (passed === false) {
      borderColor = isSelected ? "#d4a84b" : "#c45c5c";
      glowColor = "#c45c5c";
    }
  }

  // Truncate long text
  const nameDisplay = node.name.length > 22 ? node.name.slice(0, 21) + "\u2026" : node.name;
  const targetDisplay = node.target.length > 24 ? node.target.slice(0, 23) + "\u2026" : node.target;

  return (
    <g
      data-node={node.id}
      transform={`translate(${node.x},${node.y})`}
      className="cursor-pointer"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
    >
      {/* Main rect */}
      <rect
        width={node.width}
        height={node.height}
        rx={6}
        ry={6}
        fill="#131721"
        stroke={borderColor}
        strokeWidth={isSelected ? 1.5 : 1}
      />

      {/* Left accent bar */}
      <rect
        x={0}
        y={8}
        width={2.5}
        height={node.height - 16}
        rx={1.25}
        fill={isSelected ? "#d4a84b" : accent}
        opacity={isSelected ? 1 : 0.7}
      />

      {/* Name text */}
      <text
        x={12}
        y={20}
        fill="#ece7dc"
        fontSize={10}
        fontFamily="'JetBrains Mono', ui-monospace, monospace"
        fontWeight={500}
        className="select-none"
      >
        {nameDisplay}
      </text>

      {/* Action + target */}
      <text
        x={12}
        y={36}
        fill="#6f7f9a"
        fontSize={8}
        fontFamily="'JetBrains Mono', ui-monospace, monospace"
        className="select-none"
      >
        {node.action}: {targetDisplay}
      </text>

      {/* Expect badge */}
      {node.expect && (
        <g transform={`translate(${node.width - 42}, 6)`}>
          <rect
            width={36}
            height={14}
            rx={7}
            fill={`${EXPECT_COLORS[node.expect] ?? "#6f7f9a"}18`}
            stroke={`${EXPECT_COLORS[node.expect] ?? "#6f7f9a"}40`}
            strokeWidth={0.5}
          />
          <text
            x={18}
            y={7}
            textAnchor="middle"
            dominantBaseline="central"
            fill={EXPECT_COLORS[node.expect] ?? "#6f7f9a"}
            fontSize={7}
            fontFamily="'JetBrains Mono', ui-monospace, monospace"
            fontWeight={600}
            className="select-none uppercase"
          >
            {node.expect}
          </text>
        </g>
      )}

      {/* Result verdict badge in top-right corner */}
      {node.result && (
        <g transform={`translate(${node.width - 42}, ${node.height - 18})`}>
          <rect
            width={36}
            height={14}
            rx={3}
            fill={`${node.result.passed === true ? "#3dbf84" : node.result.passed === false ? "#c45c5c" : "#d4a84b"}20`}
          />
          <text
            x={18}
            y={7}
            textAnchor="middle"
            dominantBaseline="central"
            fill={node.result.passed === true ? "#3dbf84" : node.result.passed === false ? "#c45c5c" : "#d4a84b"}
            fontSize={7}
            fontFamily="'JetBrains Mono', ui-monospace, monospace"
            fontWeight={700}
            className="select-none uppercase"
          >
            {node.result.verdict}
          </text>
        </g>
      )}

      {/* Glow effect for result state */}
      {glowColor && !isSelected && (
        <rect
          width={node.width}
          height={node.height}
          rx={6}
          ry={6}
          fill="none"
          stroke={glowColor}
          strokeWidth={0.5}
          opacity={0.3}
          style={{ filter: "blur(4px)" }}
        />
      )}

      {/* Selected glow */}
      {isSelected && (
        <rect
          width={node.width}
          height={node.height}
          rx={6}
          ry={6}
          fill="none"
          stroke="#d4a84b"
          strokeWidth={0.5}
          opacity={0.3}
          style={{ filter: "blur(4px)" }}
        />
      )}
    </g>
  );
}


function ToolbarBtn({
  icon: Icon,
  label,
  onClick,
}: {
  icon: React.ComponentType<{ size?: number; stroke?: number }>;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      className="flex h-6 items-center gap-1 rounded px-1.5 text-[9px] text-[#6f7f9a]/60 transition-colors hover:bg-[#1a1f2e] hover:text-[#ece7dc]/80 font-mono"
    >
      <Icon size={13} stroke={1.5} />
      <span className="hidden lg:inline">{label}</span>
    </button>
  );
}

function Sep() {
  return <div className="mx-0.5 h-3 w-px bg-[#1a1f2e]" />;
}
