import { useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Stars } from "@react-three/drei";
import * as THREE from "three";

// ---- Types ----

interface WorkbenchReceiptData {
  verdict: "allow" | "deny";
  policyName: string;
  signature: string;
  timestamp: number;
  agentId?: string;
}

// ---- Mock receipt data ----
// No Tauri file I/O in this milestone — live receipt loading deferred.

const MOCK_RECEIPT: WorkbenchReceiptData = {
  verdict: "allow",
  policyName: "strict",
  signature: "ed25519:a1b2c3d4e5f6789abc...",
  timestamp: Date.now(),
  agentId: "agent-workbench",
};

// ---- Vault-rack fallback geometry ----
// Inline procedural mesh matching the vault-rack fallback kind in ObservatoryWorldCanvas.
// GLB useGLTF loading is NOT used here — this is an isolated R3F Canvas.

function VaultRackMesh() {
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((_, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.3; // slow ambient rotation
    }
  });

  return (
    <group>
      {/* Base rack body */}
      <mesh ref={meshRef}>
        <boxGeometry args={[1.2, 1.8, 0.5]} />
        <meshStandardMaterial color="#1a2035" roughness={0.7} metalness={0.4} />
      </mesh>
      {/* Vault door face */}
      <mesh position={[0, 0, 0.26]}>
        <boxGeometry args={[1.0, 1.6, 0.04]} />
        <meshStandardMaterial
          color="#7ee6f2"
          roughness={0.3}
          metalness={0.8}
          emissive="#7ee6f2"
          emissiveIntensity={0.12}
        />
      </mesh>
      {/* Rack slots (decorative) */}
      {[-0.4, 0, 0.4].map((y) => (
        <mesh key={y} position={[0, y, 0.27]}>
          <boxGeometry args={[0.8, 0.12, 0.02]} />
          <meshStandardMaterial color="#0a0d14" />
        </mesh>
      ))}
    </group>
  );
}

function VaultScene() {
  return (
    <>
      <ambientLight intensity={0.4} />
      <pointLight position={[3, 3, 3]} intensity={1.2} color="#7ee6f2" />
      <pointLight position={[-3, -2, -3]} intensity={0.6} color="#3dbf84" />
      <VaultRackMesh />
      <Stars radius={30} depth={10} count={800} factor={2} saturation={0} fade speed={0.5} />
      <OrbitControls
        enablePan={false}
        minDistance={2}
        maxDistance={8}
        autoRotate
        autoRotateSpeed={0.5}
      />
    </>
  );
}

// ---- ReceiptPreviewTab ----

export function ReceiptPreviewTab() {
  const receipt = MOCK_RECEIPT;
  const verdictColor = receipt.verdict === "allow" ? "#3dbf84" : "#c45c5c";
  const date = new Date(receipt.timestamp).toLocaleTimeString();

  return (
    <div className="flex flex-col flex-1 overflow-hidden bg-[#080b12]">
      {/* 3D canvas area — top 60% */}
      <div className="flex-[3] relative min-h-0">
        <Canvas
          camera={{ position: [0, 0, 4], fov: 50 }}
          frameloop="demand"
          className="absolute inset-0"
          style={{ background: "linear-gradient(to bottom, #080b12, #050810)" }}
        >
          <VaultScene />
        </Canvas>
      </div>

      {/* Metadata panel — bottom 40% */}
      <div className="flex-[2] border-t border-[#202531] bg-[#0a0d14] px-6 py-4 space-y-3 overflow-auto">
        <p className="text-[10px] font-mono text-[#6f7f9a] uppercase tracking-widest">
          Evidence Receipt
        </p>
        <div className="grid grid-cols-2 gap-x-6 gap-y-2">
          <div>
            <p className="text-[9px] font-mono text-[#4a5568] uppercase">Verdict</p>
            <p
              className="text-sm font-mono font-bold"
              style={{ color: verdictColor }}
              data-testid="receipt-verdict"
            >
              {receipt.verdict.toUpperCase()}
            </p>
          </div>
          <div>
            <p className="text-[9px] font-mono text-[#4a5568] uppercase">Policy</p>
            <p
              className="text-sm font-mono text-[#c8d2e0]"
              data-testid="receipt-policy"
            >
              {receipt.policyName}
            </p>
          </div>
          <div className="col-span-2">
            <p className="text-[9px] font-mono text-[#4a5568] uppercase">Signature</p>
            <p
              className="text-[10px] font-mono text-[#6f7f9a] truncate"
              data-testid="receipt-sig"
            >
              {receipt.signature}
            </p>
          </div>
          <div>
            <p className="text-[9px] font-mono text-[#4a5568] uppercase">Time</p>
            <p className="text-[10px] font-mono text-[#6f7f9a]">{date}</p>
          </div>
          {receipt.agentId !== undefined && (
            <div>
              <p className="text-[9px] font-mono text-[#4a5568] uppercase">Agent</p>
              <p className="text-[10px] font-mono text-[#6f7f9a]">{receipt.agentId}</p>
            </div>
          )}
        </div>
        <p className="text-[9px] font-mono text-[#2a3245] italic pt-1">
          Mock data — live receipt loading deferred
        </p>
      </div>
    </div>
  );
}
