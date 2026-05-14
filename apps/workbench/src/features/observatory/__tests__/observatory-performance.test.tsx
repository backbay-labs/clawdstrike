import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import type { Data3DTexture } from "three";
import {
  OBSERVATORY_PRELOAD_URLS,
  createObservatoryPerformanceProfile,
  createObservatoryLodPolicy,
  preloadObservatoryAssets,
  resetObservatoryAssetPreloadForTests,
  shouldKeepObservatoryRealtimeActive,
  shouldRenderObservatoryPostFx,
} from "@/features/observatory/utils/observatory-performance";
import { ObservatoryPostFX } from "@/features/observatory/components/ObservatoryPostFX";

vi.mock("@react-three/drei", () => ({
  useGLTF: {
    preload: vi.fn(),
  },
}));

vi.mock("@react-three/postprocessing", () => ({
  EffectComposer: ({ children }: { children: ReactNode }) => (
    <div data-testid="effect-composer">{children}</div>
  ),
  Bloom: () => <div data-testid="effect-bloom" />,
  Autofocus: () => <div data-testid="effect-autofocus" />,
  Vignette: () => <div data-testid="effect-vignette" />,
  LUT: () => <div data-testid="effect-lut" />,
  ToneMapping: () => <div data-testid="effect-tonemapping" />,
  SMAA: () => <div data-testid="effect-smaa" />,
}));

describe("createObservatoryPerformanceProfile", () => {
  it("keeps atlas mode on the lighter profile", () => {
    expect(
      createObservatoryPerformanceProfile({
        mode: "atlas",
        activeHeroInteraction: false,
        playerInputEnabled: false,
      }),
    ).toEqual({
      dpr: [1, 1.25],
      mountFlowSystems: false,
      mountVfxPools: false,
      enablePhysics: false,
      enableParticles: false,
      enableBloom: false,
      enableAutofocus: false,
      enableLut: true,
      enableVignette: true,
      enableToneMapping: true,
      enableSmaa: false,
      enableWeather: true,
      weatherBudget: "reduced",
    });
  });

  it("enables the heavier effects only for interactive flow mode", () => {
    const profile = createObservatoryPerformanceProfile({
      mode: "flow",
      activeHeroInteraction: true,
      playerInputEnabled: true,
    });

    expect(profile.mountFlowSystems).toBe(true);
    expect(profile.mountVfxPools).toBe(true);
    expect(profile.enablePhysics).toBe(true);
    expect(profile.enableParticles).toBe(true);
    expect(profile.enableBloom).toBe(true);
    expect(profile.enableAutofocus).toBe(true);
    expect(profile.enableSmaa).toBe(true);
    expect(profile.enableWeather).toBe(true);
    expect(profile.weatherBudget).toBe("full");
    expect(profile.dpr).toEqual([1, 1.5]);
  });

  it("drops expensive effects when reduced motion is requested", () => {
    const profile = createObservatoryPerformanceProfile({
      mode: "flow",
      activeHeroInteraction: true,
      playerInputEnabled: true,
      prefersReducedMotion: true,
    });

    expect(profile.enablePhysics).toBe(true);
    expect(profile.mountFlowSystems).toBe(true);
    expect(profile.mountVfxPools).toBe(false);
    expect(profile.enableParticles).toBe(false);
    expect(profile.enableBloom).toBe(false);
    expect(profile.enableAutofocus).toBe(false);
    expect(profile.enableSmaa).toBe(false);
    expect(profile.enableWeather).toBe(false);
    expect(profile.weatherBudget).toBe("off");
    expect(profile.dpr).toEqual([1, 1.1]);
  });

  it("keeps fly-by mode off the expensive flow runtime until the sweep finishes", () => {
    const profile = createObservatoryPerformanceProfile({
      mode: "flow",
      flyByActive: true,
      activeHeroInteraction: false,
      playerInputEnabled: true,
    });

    expect(profile.mountFlowSystems).toBe(false);
    expect(profile.enablePhysics).toBe(false);
    expect(profile.enableParticles).toBe(false);
    expect(profile.enableSmaa).toBe(false);
    expect(profile.enableWeather).toBe(true);
    expect(profile.weatherBudget).toBe("full");
  });

  it("backs off bloom, particles, and smaa when runtime quality regresses", () => {
    const profile = createObservatoryPerformanceProfile({
      mode: "flow",
      activeHeroInteraction: true,
      playerInputEnabled: true,
      runtimeQuality: "low",
    });

    expect(profile.mountFlowSystems).toBe(true);
    expect(profile.mountVfxPools).toBe(false);
    expect(profile.enableParticles).toBe(false);
    expect(profile.enableBloom).toBe(false);
    expect(profile.enableAutofocus).toBe(false);
    expect(profile.enableSmaa).toBe(false);
    expect(profile.dpr).toEqual([1, 1.1]);
  });

  it("exposes a single post-fx gate for the canvas shell", () => {
    const atlasProfile = createObservatoryPerformanceProfile({
      mode: "atlas",
      activeHeroInteraction: false,
      playerInputEnabled: false,
      spiritBound: false,
    });
    const flowProfile = createObservatoryPerformanceProfile({
      mode: "flow",
      activeHeroInteraction: true,
      playerInputEnabled: true,
    });

    expect(shouldRenderObservatoryPostFx(atlasProfile)).toBe(true);
    expect(shouldRenderObservatoryPostFx({
      ...atlasProfile,
      enableLut: false,
      enableToneMapping: false,
      enableVignette: false,
    })).toBe(false);
    expect(shouldRenderObservatoryPostFx(flowProfile)).toBe(true);
  });
});

describe("Observatory runtime policy helpers", () => {
  it("keeps idle flow and atlas scenes on demand", () => {
    expect(
      shouldKeepObservatoryRealtimeActive({
        activeHeroInteraction: false,
        eruptionCount: 0,
        flyByActive: false,
        missionTargetStationId: null,
        playerInputEnabled: false,
        probeStatus: "ready",
        replayScrubbing: false,
        selectedStationId: null,
        shouldInvalidateOnRouteChange: false,
      }),
    ).toBe(false);

    expect(
      shouldKeepObservatoryRealtimeActive({
        activeHeroInteraction: false,
        eruptionCount: 0,
        flyByActive: false,
        missionTargetStationId: null,
        playerInputEnabled: false,
        probeStatus: "ready",
        replayScrubbing: false,
        selectedStationId: null,
        shouldInvalidateOnRouteChange: true,
      }),
    ).toBe(false);
  });

  it("returns explicit focus, near, far, and dormant LOD bands", () => {
    const policy = createObservatoryLodPolicy({
      focusRadius: 10,
      nearRadius: 24,
      farRadius: 40,
    });

    expect(
      policy.resolveDistrictTier({
        activeStationId: null,
        distanceToCamera: 4,
        likelyStationId: null,
        missionTargetStationId: null,
        selectedStationId: null,
        stationId: "signal",
      }),
    ).toBe("focus");
    expect(
      policy.resolveDistrictTier({
        activeStationId: null,
        distanceToCamera: 16,
        likelyStationId: "receipts",
        missionTargetStationId: null,
        selectedStationId: null,
        stationId: "receipts",
      }),
    ).toBe("near");
    expect(
      policy.resolveDistrictTier({
        activeStationId: null,
        distanceToCamera: 32,
        likelyStationId: null,
        missionTargetStationId: null,
        selectedStationId: null,
        stationId: "run",
      }),
    ).toBe("far");
    expect(
      policy.resolveDistrictTier({
        activeStationId: null,
        distanceToCamera: 60,
        likelyStationId: null,
        missionTargetStationId: null,
        selectedStationId: null,
        stationId: "watch",
      }),
    ).toBe("dormant");
  });
});

describe("preloadObservatoryAssets", () => {
  beforeEach(() => {
    resetObservatoryAssetPreloadForTests();
  });

  it("preloads every unique observatory asset url", () => {
    const preload = vi.fn();

    preloadObservatoryAssets(preload);

    expect(preload.mock.calls.map(([url]) => url)).toEqual(OBSERVATORY_PRELOAD_URLS);

    preloadObservatoryAssets(preload);
    expect(preload).toHaveBeenCalledTimes(OBSERVATORY_PRELOAD_URLS.length);
  });
});

describe("ObservatoryPostFX", () => {
  const lut = {} as Data3DTexture;

  it("renders only the enabled heavy effects", () => {
    render(
      <ObservatoryPostFX
        activeHeroPropPosition={[1, 2, 3]}
        profile={{
          enableAutofocus: false,
          enableBloom: false,
          enableLut: true,
          enableSmaa: false,
          enableToneMapping: true,
          enableVignette: true,
        }}
        spiritLut={lut}
      />,
    );

    expect(screen.getByTestId("effect-composer")).toBeDefined();
    expect(screen.queryByTestId("effect-bloom")).toBeNull();
    expect(screen.queryByTestId("effect-autofocus")).toBeNull();
    expect(screen.getByTestId("effect-lut")).toBeDefined();
    expect(screen.getByTestId("effect-vignette")).toBeDefined();
    expect(screen.getByTestId("effect-tonemapping")).toBeDefined();
    expect(screen.queryByTestId("effect-smaa")).toBeNull();
  });
});
