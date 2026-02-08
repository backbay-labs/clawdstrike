/**
 * SOCBackground - Persistent ambient 3D scene behind all SOC content
 */
import { Canvas } from "@react-three/fiber";
import { Canvas3DErrorBoundary } from "@/components/Canvas3DErrorBoundary";
import { ThreatRadar } from "@backbay/glia/primitives";
import { SecurityShield } from "@backbay/glia/primitives";
import { NetworkTopology } from "@backbay/glia/primitives";
import { EnvironmentLayer } from "@backbay/glia/primitives";
import { useSocData } from "@/services/socDataService";

export function SOCBackground() {
  const { data: threats } = useSocData("threats", 60000);
  const { data: topology } = useSocData("network", 60000);

  const bgThreats = (threats ?? []).slice(0, 5);
  const bgNodes = (topology?.nodes ?? []).slice(0, 8);
  const bgNodeIds = new Set(bgNodes.map((n) => n.id));
  const bgEdges = (topology?.edges ?? []).filter(
    (e) => bgNodeIds.has(e.source) && bgNodeIds.has(e.target)
  );

  return (
    <>
      {/* 3D Canvas layer */}
      <Canvas3DErrorBoundary silent>
        <Canvas
          camera={{ position: [0, 8, 12], fov: 60 }}
          frameloop="demand"
          dpr={[1, 1.5]}
          gl={{ antialias: false, powerPreference: "low-power" }}
          style={{
            position: "fixed",
            inset: 0,
            width: "100vw",
            height: "100vh",
            zIndex: 0,
            pointerEvents: "none",
          }}
        >
          <ambientLight intensity={0.15} />
          <pointLight position={[10, 10, 10]} intensity={0.3} />

          {/* Threat radar - center */}
          <ThreatRadar threats={bgThreats} scanSpeed={0.3} showLabels={false} />

          {/* Security shield - right */}
          <group position={[6, 0, 0]}>
            <SecurityShield level={85} status="active" />
          </group>

          {/* Network topology - left */}
          <group position={[-6, 0, 0]}>
            <NetworkTopology nodes={bgNodes} edges={bgEdges} layout="radial" theme="cyber" showTraffic />
          </group>
        </Canvas>
      </Canvas3DErrorBoundary>

      {/* Environment overlay */}
      <div style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none" }}>
        <EnvironmentLayer preset="cyberpunk-city" intensity={0.3} />
      </div>

      {/* Vignette overlay */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          background: "radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.7) 100%)",
          pointerEvents: "none",
          zIndex: 1,
        }}
      />
    </>
  );
}
