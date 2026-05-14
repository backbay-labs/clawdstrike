import type {
  PaneFocusDirection,
  PaneGroup,
  PaneNode,
  PaneSplit,
  PaneSplitDirection,
  PaneView,
} from "./pane-types";

export function createPaneGroup(view: PaneView): PaneGroup {
  return {
    id: crypto.randomUUID(),
    type: "group",
    views: [view],
    activeViewId: view.id,
  };
}

export function findPaneNode(root: PaneNode, id: string): PaneNode | null {
  if (root.id === id) return root;
  if (root.type === "group") return null;
  return findPaneNode(root.children[0], id) ?? findPaneNode(root.children[1], id);
}

export function findPaneGroup(root: PaneNode, id: string): PaneGroup | null {
  const node = findPaneNode(root, id);
  return node?.type === "group" ? node : null;
}

export function findParentSplit(
  root: PaneNode,
  childId: string,
): { parent: PaneSplit; childIndex: 0 | 1 } | null {
  if (root.type === "group") return null;
  if (root.children[0].id === childId) {
    return { parent: root, childIndex: 0 };
  }
  if (root.children[1].id === childId) {
    return { parent: root, childIndex: 1 };
  }
  return (
    findParentSplit(root.children[0], childId)
    ?? findParentSplit(root.children[1], childId)
  );
}

export function getAllPaneGroups(root: PaneNode): PaneGroup[] {
  if (root.type === "group") return [root];
  return [...getAllPaneGroups(root.children[0]), ...getAllPaneGroups(root.children[1])];
}

export function getFirstPaneGroup(root: PaneNode): PaneGroup {
  return root.type === "group" ? root : getFirstPaneGroup(root.children[0]);
}

export function replaceNode(
  root: PaneNode,
  targetId: string,
  replacer: (node: PaneNode) => PaneNode,
): PaneNode {
  if (root.id === targetId) {
    return replacer(root);
  }
  if (root.type === "group") {
    return root;
  }
  return {
    ...root,
    children: [
      replaceNode(root.children[0], targetId, replacer),
      replaceNode(root.children[1], targetId, replacer),
    ],
  };
}

export function splitPane(
  root: PaneNode,
  paneId: string,
  direction: PaneSplitDirection,
  sibling: PaneGroup,
): PaneNode {
  return replaceNode(root, paneId, (node) => {
    if (node.type !== "group") return node;
    return {
      id: crypto.randomUUID(),
      type: "split",
      direction,
      children: [node, sibling],
      sizes: [50, 50],
    };
  });
}

export function closePane(root: PaneNode, paneId: string): PaneNode | null {
  if (root.type === "group") {
    return root.id === paneId ? null : root;
  }

  const [first, second] = root.children;
  if (first.id === paneId) return second;
  if (second.id === paneId) return first;

  const nextFirst = closePane(first, paneId);
  const nextSecond = closePane(second, paneId);

  if (!nextFirst) return nextSecond;
  if (!nextSecond) return nextFirst;

  return {
    ...root,
    children: [nextFirst, nextSecond],
  };
}

export function updatePaneSizes(
  root: PaneNode,
  splitId: string,
  sizes: [number, number],
): PaneNode {
  return replaceNode(root, splitId, (node) =>
    node.type === "split" ? { ...node, sizes } : node,
  );
}

export function getAdjacentPane(
  root: PaneNode,
  paneId: string,
  direction: PaneFocusDirection,
): PaneGroup | null {
  const groups = getAllPaneGroups(root);
  const index = groups.findIndex((group) => group.id === paneId);
  if (index === -1) return null;

  const delta = direction === "left" || direction === "up" ? -1 : 1;
  return groups[index + delta] ?? null;
}

export function setActivePaneView(
  root: PaneNode,
  paneId: string,
  viewId: string | null,
): PaneNode {
  return replaceNode(root, paneId, (node) =>
    node.type === "group" ? { ...node, activeViewId: viewId } : node,
  );
}

export function setPaneActiveRoute(
  root: PaneNode,
  paneId: string,
  route: string,
  label: string,
): PaneNode {
  return replaceNode(root, paneId, (node) => {
    if (node.type !== "group") return node;

    const currentIndex = node.views.findIndex((view) => view.id === node.activeViewId);
    if (currentIndex >= 0) {
      const nextViews = [...node.views];
      nextViews[currentIndex] = {
        ...nextViews[currentIndex],
        route,
        label,
      };
      return {
        ...node,
        views: nextViews,
      };
    }

    const view: PaneView = {
      id: crypto.randomUUID(),
      route,
      label,
    };
    return {
      ...node,
      views: [view],
      activeViewId: view.id,
    };
  });
}

export function getPaneActiveView(group: PaneGroup): PaneView | null {
  return group.views.find((view) => view.id === group.activeViewId) ?? group.views[0] ?? null;
}

export function addViewToGroup(
  root: PaneNode,
  paneId: string,
  view: PaneView,
): PaneNode {
  return replaceNode(root, paneId, (node) =>
    node.type === "group"
      ? { ...node, views: [...node.views, view], activeViewId: view.id }
      : node,
  );
}

export function removeViewFromGroup(
  root: PaneNode,
  paneId: string,
  viewId: string,
): PaneNode {
  return replaceNode(root, paneId, (node) => {
    if (node.type !== "group") return node;
    const nextViews = node.views.filter((v) => v.id !== viewId);
    let nextActiveId = node.activeViewId;
    if (viewId === node.activeViewId && nextViews.length > 0) {
      const closedIdx = node.views.findIndex((v) => v.id === viewId);
      nextActiveId =
        nextViews[Math.min(closedIdx, nextViews.length - 1)]?.id ?? null;
    }
    return { ...node, views: nextViews, activeViewId: nextActiveId };
  });
}
