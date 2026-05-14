type ModulePreloadContext = {
  hostId: string;
  hostType: "html" | "js";
};

const OBSERVATORY_WORLD_CANVAS_ID =
  "/src/features/observatory/components/ObservatoryWorldCanvas.tsx";
const OBSERVATORY_FLOW_RUNTIME_CHUNK_NAME = "ObservatoryFlowRuntimeScene";
const PHYSICS_CHUNK_PREFIX = "assets/vendor-physics";

function normalizeModuleId(id: string) {
  return id.split("\\").join("/");
}

function matchesNodeModulePackage(id: string, packageName: string) {
  const normalizedId = normalizeModuleId(id);
  const packageRoot = `/node_modules/${packageName}`;
  const packageIndex = normalizedId.lastIndexOf(packageRoot);
  if (packageIndex === -1) {
    return false;
  }

  const remainder = normalizedId.slice(packageIndex + packageRoot.length);
  return remainder === "" || remainder.startsWith("/") || remainder.startsWith("?");
}

export function resolveWorkbenchManualChunk(id: string) {
  if (
    matchesNodeModulePackage(id, "three") ||
    matchesNodeModulePackage(id, "three-mesh-bvh")
  ) {
    return "vendor-three";
  }

  if (matchesNodeModulePackage(id, "zustand")) {
    return "vendor-state";
  }

  if (
    matchesNodeModulePackage(id, "@react-three/fiber") ||
    matchesNodeModulePackage(id, "@react-three/drei") ||
    matchesNodeModulePackage(id, "suspend-react") ||
    matchesNodeModulePackage(id, "camera-controls") ||
    matchesNodeModulePackage(id, "maath") ||
    matchesNodeModulePackage(id, "meshline") ||
    matchesNodeModulePackage(id, "three-stdlib") ||
    matchesNodeModulePackage(id, "troika-three-text") ||
    matchesNodeModulePackage(id, "troika-three-utils") ||
    matchesNodeModulePackage(id, "troika-worker-utils")
  ) {
    return "vendor-r3f";
  }

  if (
    matchesNodeModulePackage(id, "@react-three/rapier")
  ) {
    return "vendor-physics-react";
  }

  if (matchesNodeModulePackage(id, "@dimforge/rapier3d-compat")) {
    return "vendor-physics-core";
  }

  if (
    matchesNodeModulePackage(id, "codemirror") ||
    matchesNodeModulePackage(id, "@codemirror/autocomplete") ||
    matchesNodeModulePackage(id, "@codemirror/lang-yaml") ||
    matchesNodeModulePackage(id, "@codemirror/language") ||
    matchesNodeModulePackage(id, "@codemirror/lint") ||
    matchesNodeModulePackage(id, "@codemirror/search") ||
    matchesNodeModulePackage(id, "@codemirror/state") ||
    matchesNodeModulePackage(id, "@codemirror/theme-one-dark") ||
    matchesNodeModulePackage(id, "@codemirror/view")
  ) {
    return "vendor-codemirror";
  }

  if (
    matchesNodeModulePackage(id, "react-resizable-panels") ||
    matchesNodeModulePackage(id, "react-syntax-highlighter") ||
    matchesNodeModulePackage(id, "lucide-react") ||
    matchesNodeModulePackage(id, "@tabler/icons-react") ||
    matchesNodeModulePackage(id, "motion")
  ) {
    return "vendor-ui";
  }

  if (matchesNodeModulePackage(id, "yaml")) {
    return "vendor-yaml";
  }

  return undefined;
}

export function resolveWorkbenchModulePreloadDependencies(
  url: string,
  deps: string[],
  context: ModulePreloadContext,
) {
  if (
    context.hostType === "js" &&
    normalizeModuleId(context.hostId).endsWith(OBSERVATORY_WORLD_CANVAS_ID) &&
    url.includes(OBSERVATORY_FLOW_RUNTIME_CHUNK_NAME)
  ) {
    return deps.filter((dep) => !dep.startsWith(PHYSICS_CHUNK_PREFIX));
  }

  return deps;
}
