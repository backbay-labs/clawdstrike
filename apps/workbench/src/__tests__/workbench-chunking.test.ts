import { describe, expect, it } from "vitest";
import {
  resolveWorkbenchManualChunk,
  resolveWorkbenchModulePreloadDependencies,
} from "../../build/workbench-chunking";

describe("workbench chunking", () => {
  it("splits Rapier core from the React wrapper", () => {
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/node_modules/@react-three/rapier/dist/index.mjs",
      ),
    ).toBe("vendor-physics-react");
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/node_modules/@dimforge/rapier3d-compat/rapier.mjs",
      ),
    ).toBe("vendor-physics-core");
  });

  it("isolates the shared 3d stack from the physics runtime", () => {
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/node_modules/@react-three/fiber/dist/index.js",
      ),
    ).toBe("vendor-r3f");
    expect(
      resolveWorkbenchManualChunk("/repo/apps/workbench/node_modules/three/build/three.module.js"),
    ).toBe("vendor-three");
    expect(
      resolveWorkbenchManualChunk("/repo/apps/workbench/node_modules/react/index.js"),
    ).toBeUndefined();
  });

  it("keeps zustand out of the heavy react-three-fiber chunk", () => {
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/node_modules/zustand/esm/index.mjs",
      ),
    ).toBe("vendor-state");
  });

  it("does not let package prefixes override more specific chunk groups", () => {
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/node_modules/three-stdlib/math/CurveModifier.js",
      ),
    ).toBe("vendor-r3f");
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/node_modules/three-stdlib/node_modules/three/build/three.module.js",
      ),
    ).toBe("vendor-three");
  });

  it("leaves unrelated modules ungrouped", () => {
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx",
      ),
    ).toBeUndefined();
    expect(
      resolveWorkbenchManualChunk(
        "/repo/apps/workbench/node_modules/@codemirror/view/dist/index.js",
      ),
    ).toBe("vendor-codemirror");
  });

  it("skips physics preloads only for the world-canvas flow-runtime edge", () => {
    expect(
      resolveWorkbenchModulePreloadDependencies(
        "assets/ObservatoryFlowRuntimeScene-abc123.js",
        [
          "assets/ObservatoryFlowPhysicsBootstrap-def456.js",
          "assets/vendor-physics-xyz789.js",
          "assets/vendor-ui-123abc.js",
        ],
        {
          hostId:
            "/repo/apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx",
          hostType: "js",
        },
      ),
    ).toEqual([
      "assets/ObservatoryFlowPhysicsBootstrap-def456.js",
      "assets/vendor-ui-123abc.js",
    ]);
  });

  it("keeps preload dependencies intact for every other import edge", () => {
    const deps = [
      "assets/ObservatoryFlowPhysicsBootstrap-def456.js",
      "assets/vendor-physics-xyz789.js",
    ];

    expect(
      resolveWorkbenchModulePreloadDependencies(
        "assets/ObservatoryFlowRuntimeScene-abc123.js",
        deps,
        {
          hostId:
            "/repo/apps/workbench/src/features/observatory/components/SomeOtherScene.tsx",
          hostType: "js",
        },
      ),
    ).toEqual(deps);

    expect(
      resolveWorkbenchModulePreloadDependencies(
        "assets/index-main.js",
        deps,
        {
          hostId: "/repo/apps/workbench/index.html",
          hostType: "html",
        },
      ),
    ).toEqual(deps);
  });

  it("normalizes Windows-style host ids before filtering preloads", () => {
    expect(
      resolveWorkbenchModulePreloadDependencies(
        "assets/ObservatoryFlowRuntimeScene-abc123.js",
        [
          "assets/ObservatoryFlowPhysicsBootstrap-def456.js",
          "assets/vendor-physics-xyz789.js",
        ],
        {
          hostId:
            "C:\\repo\\apps\\workbench\\src\\features\\observatory\\components\\ObservatoryWorldCanvas.tsx",
          hostType: "js",
        },
      ),
    ).toEqual(["assets/ObservatoryFlowPhysicsBootstrap-def456.js"]);
  });
});
