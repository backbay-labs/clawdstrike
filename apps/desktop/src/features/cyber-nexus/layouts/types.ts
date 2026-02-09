import type { NexusLayoutMode, StrikecellConnection, StrikecellDomainId, StrikecellStatus } from "../types";

export interface NexusLayoutNode {
  id: StrikecellDomainId;
  activityCount: number;
  status: StrikecellStatus;
}

export interface LayoutPosition {
  x: number;
  y: number;
  z: number;
  col: number;
  row: number;
}

export interface LayoutResult {
  positions: Map<StrikecellDomainId, LayoutPosition>;
}

export interface LayoutContext {
  nodes: NexusLayoutNode[];
  connections: StrikecellConnection[];
}

export interface LayoutMeta {
  id: NexusLayoutMode;
  name: string;
  shortcut: string;
  icon: string;
}
