import { describe, expect, it, beforeEach, vi } from "vitest";
import * as THREE from "three";
import {
  createNormalizedObservatoryModelInstance,
  getObservatoryModelFootprint,
  resetObservatoryModelCacheForTests,
} from "@/features/observatory/utils/observatory-models";

function createTestScene(): THREE.Object3D {
  const scene = new THREE.Group();
  const material = new THREE.MeshBasicMaterial();
  const mesh = new THREE.Mesh(new THREE.BoxGeometry(2, 2, 2), material);
  mesh.position.set(0, 2, 0);
  scene.add(mesh);
  return scene;
}

describe("observatory-models", () => {
  beforeEach(() => {
    resetObservatoryModelCacheForTests();
  });

  it("caches the footprint and normalizes the model root only once per asset url", () => {
    const scene = createTestScene();
    const spy = vi.spyOn(THREE.Box3.prototype, "setFromObject");

    const firstFootprint = getObservatoryModelFootprint("asset://signal", scene);
    const firstInstance = createNormalizedObservatoryModelInstance("asset://signal", scene);
    const secondFootprint = getObservatoryModelFootprint("asset://signal", scene);
    const secondInstance = createNormalizedObservatoryModelInstance("asset://signal", scene);

    expect(spy).toHaveBeenCalledTimes(1);
    expect(firstFootprint).toBe(secondFootprint);
    expect(firstFootprint.bottomOffset).toBe(1);
    expect(firstInstance).not.toBe(secondInstance);
    expect(firstInstance.position.y).toBe(-1);
    expect(secondInstance.position.y).toBe(-1);
    expect(scene.position.y).toBe(0);

    spy.mockRestore();
  });

  it("exposes normalized bounds metadata for callers that want layout data without cloning again", () => {
    const scene = createTestScene();

    const footprint = getObservatoryModelFootprint("asset://operator", scene);

    expect(footprint.bounds.min).toEqual([-1, 1, -1]);
    expect(footprint.bounds.max).toEqual([1, 3, 1]);
    expect(footprint.bounds.center).toEqual([0, 2, 0]);
    expect(footprint.bounds.size).toEqual([2, 2, 2]);
  });
});
