export type PaneFocusDirection = "left" | "right" | "up" | "down";
export type PaneSplitDirection = "horizontal" | "vertical";

export interface PaneView {
  id: string;
  route: string;
  label: string;
  dirty?: boolean;
  fileType?: string;
}

export interface PaneGroup {
  id: string;
  type: "group";
  views: PaneView[];
  activeViewId: string | null;
}

export interface PaneSplit {
  id: string;
  type: "split";
  direction: PaneSplitDirection;
  children: [PaneNode, PaneNode];
  sizes: [number, number];
}

export type PaneNode = PaneGroup | PaneSplit;
