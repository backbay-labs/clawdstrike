import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { PaneContainer } from "./pane-container";
import { usePaneStore } from "./pane-store";
import type { PaneNode } from "./pane-types";

function PaneNodeRenderer({ node }: { node: PaneNode }) {
  const activePaneId = usePaneStore((state) => state.activePaneId);

  if (node.type === "group") {
    return <PaneContainer pane={node} active={node.id === activePaneId} />;
  }

  const panelDirection = node.direction === "vertical" ? "horizontal" : "vertical";

  return (
    <ResizablePanelGroup
      direction={panelDirection}
      className="h-full w-full"
      onLayout={(sizes) => {
        if (sizes.length >= 2) {
          usePaneStore.getState().resizeSplit(node.id, [sizes[0], sizes[1]]);
        }
      }}
    >
      <ResizablePanel defaultSize={node.sizes[0]} minSize={20}>
        <PaneNodeRenderer node={node.children[0]} />
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel defaultSize={node.sizes[1]} minSize={20}>
        <PaneNodeRenderer node={node.children[1]} />
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

export function PaneRoot() {
  const root = usePaneStore((state) => state.root);

  return (
    <div data-testid="pane-root" className="h-full w-full overflow-hidden p-3 spirit-field-stain-host">
      <PaneNodeRenderer node={root} />
    </div>
  );
}
