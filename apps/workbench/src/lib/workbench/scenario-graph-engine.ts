/**
 * Scenario graph layout engine.
 *
 * Arranges test scenarios as a left-to-right flow graph with a Start pill,
 * scenario nodes in rows of up to 3, and an End pill. Edges connect nodes
 * sequentially with horizontal lines within rows and curved connectors
 * between rows.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScenarioNode {
  id: string;
  name: string;
  action: string;
  target: string;
  expect?: "allow" | "deny" | "warn";
  content?: string;
  // Layout
  x: number;
  y: number;
  width: number;
  height: number;
  // Whether this is a start/end sentinel
  kind: "start" | "end" | "scenario";
  // Result (populated after run)
  result?: { verdict: string; passed: boolean | null; guard: string | null };
}

export interface ScenarioEdge {
  from: string;
  to: string;
  path: string; // SVG path d
}

export interface ScenarioGraphLayout {
  nodes: ScenarioNode[];
  edges: ScenarioEdge[];
  width: number;
  height: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_W = 200;
const NODE_H = 56;
const PILL_W = 60;
const PILL_H = 32;
const GAP_X = 40;
const GAP_Y = 24;
const MAX_PER_ROW = 3;
const PADDING = 40;

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

export function layoutScenarioGraph(
  scenarios: Array<{
    name: string;
    action: string;
    target: string;
    expect?: string;
    content?: string;
  }>,
): ScenarioGraphLayout {
  const nodes: ScenarioNode[] = [];
  const edges: ScenarioEdge[] = [];

  if (scenarios.length === 0) {
    // Just start + end
    const startNode: ScenarioNode = {
      id: "__start__",
      name: "Start",
      action: "",
      target: "",
      x: PADDING,
      y: PADDING,
      width: PILL_W,
      height: PILL_H,
      kind: "start",
    };
    const endNode: ScenarioNode = {
      id: "__end__",
      name: "End",
      action: "",
      target: "",
      x: PADDING + PILL_W + GAP_X,
      y: PADDING,
      width: PILL_W,
      height: PILL_H,
      kind: "end",
    };
    nodes.push(startNode, endNode);
    edges.push({
      from: "__start__",
      to: "__end__",
      path: buildHorizontalEdge(startNode, endNode),
    });
    return {
      nodes,
      edges,
      width: endNode.x + PILL_W + PADDING,
      height: PILL_H + PADDING * 2,
    };
  }

  // Build rows: each row has up to MAX_PER_ROW scenario nodes
  const rows: Array<Array<{ idx: number; name: string; action: string; target: string; expect?: string; content?: string }>> = [];
  for (let i = 0; i < scenarios.length; i++) {
    const rowIdx = Math.floor(i / MAX_PER_ROW);
    if (!rows[rowIdx]) rows[rowIdx] = [];
    rows[rowIdx].push({ idx: i, ...scenarios[i] });
  }

  // Compute row widths to determine total width
  // Each row: pill(start, only row 0) + gap + [node + gap] * count + pill(end, only last row)
  // Actually, Start pill precedes first node, End pill follows last node

  // Place the Start pill
  const startY = PADDING + (NODE_H - PILL_H) / 2; // Vertically center with first row
  const startNode: ScenarioNode = {
    id: "__start__",
    name: "Start",
    action: "",
    target: "",
    x: PADDING,
    y: startY,
    width: PILL_W,
    height: PILL_H,
    kind: "start",
  };
  nodes.push(startNode);

  // Place scenario nodes in rows
  const scenarioNodes: ScenarioNode[] = [];
  let maxRowWidth = 0;

  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    const rowY = PADDING + r * (NODE_H + GAP_Y);

    // First row starts after the start pill
    const rowStartX = r === 0 ? PADDING + PILL_W + GAP_X : PADDING;

    for (let c = 0; c < row.length; c++) {
      const s = row[c];
      const x = rowStartX + c * (NODE_W + GAP_X);
      const node: ScenarioNode = {
        id: `scenario-${s.idx}`,
        name: s.name,
        action: s.action,
        target: s.target,
        expect: s.expect as "allow" | "deny" | "warn" | undefined,
        content: s.content,
        x,
        y: rowY,
        width: NODE_W,
        height: NODE_H,
        kind: "scenario",
      };
      nodes.push(node);
      scenarioNodes.push(node);

      const rightEdge = x + NODE_W;
      if (rightEdge > maxRowWidth) maxRowWidth = rightEdge;
    }
  }

  // Place the End pill after the last scenario node
  const lastScenario = scenarioNodes[scenarioNodes.length - 1];
  const lastRow = rows[rows.length - 1];
  const lastRowY = PADDING + (rows.length - 1) * (NODE_H + GAP_Y);

  let endX: number;
  let endY: number;

  if (lastRow.length < MAX_PER_ROW) {
    // End pill goes to the right of the last node in the last row
    endX = lastScenario.x + NODE_W + GAP_X;
    endY = lastRowY + (NODE_H - PILL_H) / 2;
  } else {
    // Last row is full, end pill goes on a new row
    endX = PADDING;
    endY = lastRowY + NODE_H + GAP_Y + (NODE_H - PILL_H) / 2;
  }

  const endNode: ScenarioNode = {
    id: "__end__",
    name: "End",
    action: "",
    target: "",
    x: endX,
    y: endY,
    width: PILL_W,
    height: PILL_H,
    kind: "end",
  };
  nodes.push(endNode);

  const endRightEdge = endX + PILL_W;
  if (endRightEdge > maxRowWidth) maxRowWidth = endRightEdge;

  // Build edges: Start -> scenario-0, scenario-i -> scenario-(i+1), last-scenario -> End
  // Start -> first node
  edges.push({
    from: "__start__",
    to: scenarioNodes[0].id,
    path: buildHorizontalEdge(startNode, scenarioNodes[0]),
  });

  // Sequential edges between scenario nodes
  for (let i = 0; i < scenarioNodes.length - 1; i++) {
    const from = scenarioNodes[i];
    const to = scenarioNodes[i + 1];
    const fromRow = Math.floor(i / MAX_PER_ROW);
    const toRow = Math.floor((i + 1) / MAX_PER_ROW);

    if (fromRow === toRow) {
      // Same row: straight horizontal edge
      edges.push({
        from: from.id,
        to: to.id,
        path: buildHorizontalEdge(from, to),
      });
    } else {
      // Row transition: curved connector
      edges.push({
        from: from.id,
        to: to.id,
        path: buildRowTransitionEdge(from, to),
      });
    }
  }

  // Last scenario -> End
  const lastScenarioNode = scenarioNodes[scenarioNodes.length - 1];
  const lastScenarioRow = Math.floor((scenarioNodes.length - 1) / MAX_PER_ROW);
  const endRow = lastRow.length < MAX_PER_ROW ? lastScenarioRow : lastScenarioRow + 1;

  if (lastScenarioRow === endRow) {
    edges.push({
      from: lastScenarioNode.id,
      to: "__end__",
      path: buildHorizontalEdge(lastScenarioNode, endNode),
    });
  } else {
    edges.push({
      from: lastScenarioNode.id,
      to: "__end__",
      path: buildRowTransitionEdge(lastScenarioNode, endNode),
    });
  }

  const totalWidth = maxRowWidth + PADDING;
  const totalHeight = endNode.y + endNode.height + PADDING;

  return { nodes, edges, width: totalWidth, height: totalHeight };
}

// ---------------------------------------------------------------------------
// Edge path builders
// ---------------------------------------------------------------------------

function buildHorizontalEdge(from: ScenarioNode, to: ScenarioNode): string {
  const fromCy = from.y + from.height / 2;
  const toCy = to.y + to.height / 2;
  const x1 = from.x + from.width;
  const x2 = to.x;
  const midX = (x1 + x2) / 2;
  return `M ${x1} ${fromCy} C ${midX} ${fromCy}, ${midX} ${toCy}, ${x2} ${toCy}`;
}

function buildRowTransitionEdge(from: ScenarioNode, to: ScenarioNode): string {
  // From: right edge, center-y of 'from' node
  // To: left edge, center-y of 'to' node
  // Curved path that goes down from right side of from-node to left side of to-node
  const x1 = from.x + from.width;
  const y1 = from.y + from.height / 2;
  const x2 = to.x;
  const y2 = to.y + to.height / 2;

  const midY = (y1 + y2) / 2;
  const overshootX = Math.max(x1 + 30, x2 + (from.width * 0.5));

  return `M ${x1} ${y1} C ${overshootX} ${y1}, ${x2 - 30} ${midY}, ${x2 - 20} ${midY} S ${x2 - 30} ${y2}, ${x2} ${y2}`;
}
