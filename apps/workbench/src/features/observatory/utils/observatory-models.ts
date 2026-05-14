import * as THREE from "three";

export interface ObservatoryModelFootprint {
  bounds: {
    center: [number, number, number];
    max: [number, number, number];
    min: [number, number, number];
    size: [number, number, number];
  };
  bottomOffset: number;
}

interface CachedObservatoryModel {
  footprint: ObservatoryModelFootprint;
  template: THREE.Object3D;
}

const normalizedModelCache = new Map<string, CachedObservatoryModel>();

export function createNormalizedObservatoryModelInstance(
  sourceUrl: string,
  sourceScene: THREE.Object3D,
): THREE.Object3D {
  const cached = normalizedModelCache.get(sourceUrl);
  if (cached) {
    return normalizeObservatoryModelClone(cached.template, cached.footprint.bottomOffset);
  }

  const footprint = buildObservatoryModelFootprint(sourceScene);
  const template = sourceScene.clone(true);

  normalizedModelCache.set(sourceUrl, {
    footprint,
    template,
  });

  return normalizeObservatoryModelClone(template, footprint.bottomOffset);
}

export function getObservatoryModelFootprint(
  sourceUrl: string,
  sourceScene: THREE.Object3D,
): ObservatoryModelFootprint {
  const cached = normalizedModelCache.get(sourceUrl);
  if (cached) {
    return cached.footprint;
  }

  const footprint = buildObservatoryModelFootprint(sourceScene);
  normalizedModelCache.set(sourceUrl, {
    footprint,
    template: sourceScene.clone(true),
  });
  return footprint;
}

export function resetObservatoryModelCacheForTests(): void {
  normalizedModelCache.clear();
}

function buildObservatoryModelFootprint(sourceScene: THREE.Object3D): ObservatoryModelFootprint {
  const bounds = new THREE.Box3().setFromObject(sourceScene);
  const center = new THREE.Vector3();
  const size = new THREE.Vector3();
  bounds.getCenter(center);
  bounds.getSize(size);

  const min = tupleFromVector3(bounds.min);
  const max = tupleFromVector3(bounds.max);
  const centerTuple = tupleFromVector3(center);
  const sizeTuple = tupleFromVector3(size);
  const bottomOffset = Number.isFinite(bounds.min.y) ? bounds.min.y : 0;

  return {
    bounds: {
      center: centerTuple,
      max,
      min,
      size: sizeTuple,
    },
    bottomOffset,
  };
}

function tupleFromVector3(vector: THREE.Vector3): [number, number, number] {
  return [vector.x, vector.y, vector.z];
}

function normalizeObservatoryModelClone(
  template: THREE.Object3D,
  bottomOffset: number,
): THREE.Object3D {
  const instance = template.clone(true);
  if (Number.isFinite(bottomOffset) && bottomOffset !== 0) {
    instance.position.y -= bottomOffset;
  }
  return instance;
}
