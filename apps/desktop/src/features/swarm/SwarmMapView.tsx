/**
 * SwarmMapView - 3D visualization of agent identities and delegation chains
 */
import { Suspense, useState, useCallback } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls, Environment } from "@react-three/drei";
import { EnvironmentLayer } from "@backbay/glia/primitives";
import { GlowButton } from "@backbay/glia/primitives";
import { useSwarm, useSelectedAgent } from "@/context/SwarmContext";
import { useConnection } from "@/context/ConnectionContext";
import { AgentNodes } from "./components/AgentNodes";
import { DelegationEdges } from "./components/DelegationEdges";
import { AgentDetailPanel } from "./components/AgentDetailPanel";
import { SwarmLegend } from "./components/SwarmLegend";

export function SwarmMapView() {
  const { status } = useConnection();
  const { agents, delegations, selectAgent, fetchSwarm, isLoading, error } = useSwarm();
  const selectedAgent = useSelectedAgent();
  const [showLegend, setShowLegend] = useState(true);

  const handleRefresh = useCallback(() => {
    fetchSwarm();
  }, [fetchSwarm]);

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full text-sdr-text-secondary">
        Not connected to daemon
      </div>
    );
  }

  return (
    <div className="relative h-full">
      {/* 3D Canvas */}
      <div className="absolute inset-0">
        <EnvironmentLayer preset="cyberpunk-city" intensity={0.2} />
        <Canvas
          camera={{ position: [0, 5, 12], fov: 50 }}
          style={{ background: "#0a0a0f" }}
        >
          <Suspense fallback={null}>
            {/* Lighting */}
            <ambientLight intensity={0.4} />
            <pointLight position={[10, 10, 10]} intensity={0.8} />
            <pointLight position={[-10, -10, -10]} intensity={0.4} color="#3b82f6" />

            {/* Environment for reflections */}
            <Environment preset="night" />

            {/* Grid helper */}
            <gridHelper args={[20, 20, "#1f1f2a", "#1f1f2a"]} position={[0, -2, 0]} />

            {/* Agent nodes */}
            <AgentNodes
              agents={agents}
              selectedId={selectedAgent?.id}
              onSelect={(id) => selectAgent(id)}
            />

            {/* Delegation edges */}
            <DelegationEdges edges={delegations} agents={agents} />

            {/* Camera controls */}
            <OrbitControls
              enablePan
              enableZoom
              enableRotate
              minDistance={5}
              maxDistance={30}
              autoRotate={agents.length > 0 && !selectedAgent}
              autoRotateSpeed={0.5}
            />
          </Suspense>
        </Canvas>
      </div>

      {/* Header overlay */}
      <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-sdr-bg-primary to-transparent pointer-events-none">
        <div>
          <h1 className="text-lg font-semibold text-sdr-text-primary">Swarm Map</h1>
          <p className="text-sm text-sdr-text-muted">
            {agents.length} agents, {delegations.length} delegations
          </p>
        </div>

        <div className="flex items-center gap-2 pointer-events-auto">
          <GlowButton
            onClick={() => setShowLegend(!showLegend)}
            variant="secondary"
          >
            {showLegend ? "Hide" : "Show"} Legend
          </GlowButton>
          <GlowButton
            onClick={handleRefresh}
            disabled={isLoading}
            variant="secondary"
          >
            {isLoading ? "Loading..." : "Refresh"}
          </GlowButton>
        </div>
      </div>

      {/* Legend */}
      {showLegend && (
        <div className="absolute bottom-4 left-4">
          <SwarmLegend />
        </div>
      )}

      {/* Agent detail panel */}
      {selectedAgent && (
        <div className="absolute top-0 right-0 bottom-0 w-80">
          <AgentDetailPanel agent={selectedAgent} onClose={() => selectAgent(undefined)} />
        </div>
      )}

      {/* Empty state */}
      {agents.length === 0 && !isLoading && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center">
            <p className="text-sdr-text-secondary">No agents found</p>
            <p className="text-sm text-sdr-text-muted mt-1">
              Agents will appear here when registered with the daemon
            </p>
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="absolute bottom-4 right-4 max-w-sm p-3 bg-sdr-accent-red/10 border border-sdr-accent-red/30 rounded-lg">
          <p className="text-sm text-sdr-accent-red">{error}</p>
        </div>
      )}
    </div>
  );
}
