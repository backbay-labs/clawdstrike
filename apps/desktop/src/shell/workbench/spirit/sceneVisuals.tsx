import * as THREE from "three";

export type SpiritContourPreset = "overlay" | "companion";

export function blendHex(base: string, mix: string, alpha: number): string {
  const color = new THREE.Color(base);
  color.lerp(new THREE.Color(mix), alpha);
  return `#${color.getHexString()}`;
}

export function renderSpiritContourGeometry(
  contour: string,
  preset: SpiritContourPreset = "overlay",
) {
  switch (contour) {
    case "reticle-vector":
      return preset === "overlay" ? (
        <octahedronGeometry args={[0.92, 1]} />
      ) : (
        <octahedronGeometry args={[0.64, 1]} />
      );
    case "aperture-reveal":
      return preset === "overlay" ? (
        <sphereGeometry args={[0.82, 28, 28]} />
      ) : (
        <sphereGeometry args={[0.58, 24, 24]} />
      );
    case "chamber-bracket":
      return preset === "overlay" ? (
        <dodecahedronGeometry args={[0.88, 0]} />
      ) : (
        <dodecahedronGeometry args={[0.62, 0]} />
      );
    case "thread-arc":
      return preset === "overlay" ? (
        <torusKnotGeometry args={[0.56, 0.18, 88, 14]} />
      ) : (
        <torusKnotGeometry args={[0.42, 0.12, 72, 12]} />
      );
    case "proof-stack":
      return preset === "overlay" ? (
        <cylinderGeometry args={[0.72, 0.92, 1.1, 7]} />
      ) : (
        <cylinderGeometry args={[0.48, 0.62, 0.82, 7]} />
      );
    default:
      return preset === "overlay" ? (
        <icosahedronGeometry args={[0.86, 1]} />
      ) : (
        <icosahedronGeometry args={[0.6, 1]} />
      );
  }
}
