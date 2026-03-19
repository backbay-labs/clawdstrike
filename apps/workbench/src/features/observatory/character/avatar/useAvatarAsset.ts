import { useEffect, useMemo, useState } from "react";
import { Color, Vector2, type AnimationClip, type Material, type Mesh, type Object3D } from "three";
import { GLTFLoader } from "three/examples/jsm/loaders/GLTFLoader.js";
import { clone } from "three/examples/jsm/utils/SkeletonUtils.js";

type CachedAvatarAsset = {
  animations: AnimationClip[];
  scene: Object3D;
};

export type ObservatoryAvatarAssetState =
  | { status: "fallback" }
  | { sourceUrl: string; status: "loading" }
  | {
      animations: AnimationClip[];
      scene: Object3D;
      sourceUrl: string;
      status: "ready";
    }
  | { error: Error; sourceUrl: string; status: "error" };

const assetCache = new Map<string, Promise<CachedAvatarAsset>>();
const loader = new GLTFLoader();

export function useAvatarAsset(
  assetUrl?: string | null,
  animationAssetUrls: readonly string[] = [],
  materialSourceUrl?: string | null,
): ObservatoryAvatarAssetState {
  const [state, setState] = useState<ObservatoryAvatarAssetState>({
    status: "fallback",
  });
  const animationSources = useMemo(
    () =>
      animationAssetUrls
        .map((value) => value?.trim())
        .filter((value): value is string => Boolean(value)),
    [animationAssetUrls],
  );
  const materialSource = materialSourceUrl?.trim() || null;

  useEffect(() => {
    const sourceUrl = assetUrl?.trim();

    if (!sourceUrl) {
      setState({ status: "fallback" });
      return;
    }

    let cancelled = false;
    setState({ sourceUrl, status: "loading" });

    loadAvatarAsset(sourceUrl, animationSources, materialSource)
      .then((asset) => {
        if (cancelled) {
          return;
        }

        setState({
          animations: asset.animations,
          scene: clone(asset.scene),
          sourceUrl,
          status: "ready",
        });
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }

        setState({
          error:
            error instanceof Error
              ? error
              : new Error(`Failed to load avatar asset ${sourceUrl}`),
          sourceUrl,
          status: "error",
        });
      });

    return () => {
      cancelled = true;
    };
  }, [animationSources, assetUrl, materialSource]);

  return state;
}

function loadAvatarAsset(
  sourceUrl: string,
  animationSources: readonly string[],
  materialSourceUrl: string | null,
): Promise<CachedAvatarAsset> {
  const cacheKey = JSON.stringify({
    animationSources,
    materialSourceUrl,
    sourceUrl,
  });
  const cached = assetCache.get(cacheKey);

  if (cached) {
    return cached;
  }

  const promise = new Promise<CachedAvatarAsset>((resolve, reject) => {
    loader.load(sourceUrl, async (loaded) => {
      try {
        const companionAnimations = await Promise.all(
          animationSources.map((animationSource) =>
            loadAvatarCompanionAnimations(animationSource),
          ),
        );
        if (materialSourceUrl) {
          const materialSource = await loadAvatarMaterialSource(materialSourceUrl);
          applyAvatarMaterials(loaded.scene, materialSource);
        }
        resolve({
          animations: [
            ...loaded.animations,
            ...companionAnimations.flat(),
          ],
          scene: loaded.scene,
        });
      } catch (error) {
        reject(
          error instanceof Error
            ? error
            : new Error(`Failed to load avatar asset companions for ${sourceUrl}`),
        );
      }
    }, undefined, (error) => {
      reject(
        error instanceof Error
          ? error
          : new Error(`Failed to load avatar asset ${sourceUrl}`),
      );
    });
  });

  assetCache.set(cacheKey, promise);
  return promise;
}

function loadAvatarCompanionAnimations(
  sourceUrl: string,
): Promise<AnimationClip[]> {
  return new Promise<AnimationClip[]>((resolve, reject) => {
    loader.load(
      sourceUrl,
      (loaded) => {
        resolve(loaded.animations);
      },
      undefined,
      (error) => {
        reject(
          error instanceof Error
            ? error
            : new Error(`Failed to load avatar companion asset ${sourceUrl}`),
        );
      },
    );
  });
}

function loadAvatarMaterialSource(sourceUrl: string): Promise<Object3D> {
  return new Promise<Object3D>((resolve, reject) => {
    loader.load(
      sourceUrl,
      (loaded) => {
        resolve(loaded.scene);
      },
      undefined,
      (error) => {
        reject(
          error instanceof Error
            ? error
            : new Error(`Failed to load avatar material source ${sourceUrl}`),
        );
      },
    );
  });
}

function applyAvatarMaterials(targetScene: Object3D, materialSourceScene: Object3D): void {
  const donorMeshes = findSceneMeshes(materialSourceScene);

  if (donorMeshes.length === 0) {
    return;
  }

  const donorByName = new Map(donorMeshes.map((mesh) => [mesh.name, mesh] as const));
  const fallbackDonor = donorMeshes[0];

  for (const targetMesh of findSceneMeshes(targetScene)) {
    const donor = donorByName.get(targetMesh.name) ?? fallbackDonor;
    if (!donor?.material) {
      continue;
    }

    targetMesh.material = cloneMaterialSet(donor.material, Boolean((targetMesh as Mesh & { isSkinnedMesh?: boolean }).isSkinnedMesh));
  }
}

function findSceneMeshes(scene: Object3D): Mesh[] {
  const meshes: Mesh[] = [];
  scene.traverse((child) => {
    const candidate = child as Mesh;
    if ("isMesh" in candidate && candidate.isMesh) {
      meshes.push(candidate);
    }
  });
  return meshes;
}

function cloneMaterialSet(
  material: Material | Material[],
  enableSkinning: boolean,
): Material | Material[] {
  if (Array.isArray(material)) {
    return material.map((entry) => cloneOneMaterial(entry, enableSkinning));
  }
  return cloneOneMaterial(material, enableSkinning);
}

function cloneOneMaterial(material: Material, enableSkinning: boolean): Material {
  const nextMaterial = material.clone();
  const colorCapable = nextMaterial as Material & { color?: Color };
  const roughCapable = nextMaterial as Material & { roughness?: number };
  const metalCapable = nextMaterial as Material & { metalness?: number };
  const normalCapable = nextMaterial as Material & { normalScale?: Vector2 };
  const envCapable = nextMaterial as Material & { envMapIntensity?: number };
  const aoCapable = nextMaterial as Material & { aoMapIntensity?: number };
  const emissiveCapable = nextMaterial as Material & {
    emissive?: Color;
    emissiveIntensity?: number;
  };
  if ("skinning" in nextMaterial) {
    (nextMaterial as Material & { skinning: boolean }).skinning = enableSkinning;
  }
  if (colorCapable.color) {
    const gradedColor = colorCapable.color.clone();
    gradedColor.lerp(new Color("#dbe7f5"), 0.34);
    gradedColor.offsetHSL(0, -0.28, 0.07);
    colorCapable.color.copy(gradedColor);
  }
  if (roughCapable.roughness != null) {
    roughCapable.roughness = Math.max(0.34, Math.min(0.52, roughCapable.roughness));
  } else if ("roughness" in nextMaterial) {
    roughCapable.roughness = 0.44;
  }
  if (metalCapable.metalness != null) {
    metalCapable.metalness = Math.max(0.1, Math.min(0.18, metalCapable.metalness));
  } else if ("metalness" in nextMaterial) {
    metalCapable.metalness = 0.12;
  }
  if ("normalScale" in nextMaterial) {
    normalCapable.normalScale = new Vector2(0.92, 0.92);
  }
  if ("envMapIntensity" in nextMaterial) {
    envCapable.envMapIntensity = 0.7;
  }
  if ("aoMapIntensity" in nextMaterial) {
    aoCapable.aoMapIntensity = 1.15;
  }
  if (emissiveCapable.emissive) {
    emissiveCapable.emissive = new Color("#07131f");
  }
  if ("emissiveIntensity" in nextMaterial) {
    emissiveCapable.emissiveIntensity = 0.08;
  }
  nextMaterial.needsUpdate = true;
  return nextMaterial;
}
