/**
 * SOCBackground - Persistent ambient 3D scene behind all SOC content
 */
import { Canvas } from "@react-three/fiber";
import { ThreatRadar } from "@backbay/glia/primitives";
import { SecurityShield } from "@backbay/glia/primitives";
import { NetworkTopology } from "@backbay/glia/primitives";
import { EnvironmentLayer } from "@backbay/glia/primitives";
import type { Threat } from "@backbay/glia/primitives";
import type { NetworkNode, NetworkEdge } from "@backbay/glia/primitives";

const MOCK_THREATS: Threat[] = [
  { id: "t1", angle: 0.8, distance: 0.7, severity: 0.9, type: "malware", active: true, label: "TROJAN-X42" },
  { id: "t2", angle: 2.1, distance: 0.4, severity: 0.5, type: "anomaly", active: true, label: "DNS-ANOMALY" },
  { id: "t3", angle: 3.5, distance: 0.85, severity: 0.8, type: "intrusion", active: false, label: "BRUTE-SSH" },
  { id: "t4", angle: 4.7, distance: 0.3, severity: 0.3, type: "phishing", active: true, label: "SPEAR-PHISH" },
  { id: "t5", angle: 5.6, distance: 0.6, severity: 0.95, type: "ddos", active: true, label: "SYN-FLOOD" },
  { id: "t6", angle: 1.4, distance: 0.55, severity: 0.6, type: "anomaly", active: false, label: "PORT-SCAN" },
];

const MOCK_NODES: NetworkNode[] = [
  { id: "n1", type: "firewall", hostname: "fw-edge-01", ip: "10.0.0.1", status: "healthy", services: ["iptables", "snort"], position: [0, 0, 0] },
  { id: "n2", type: "server", hostname: "dc-primary", ip: "10.0.1.10", status: "healthy", services: ["ldap", "dns", "kerberos"], position: [-2, 1, 0] },
  { id: "n3", type: "server", hostname: "web-prod-01", ip: "10.0.2.20", status: "warning", services: ["nginx", "node"], vulnerabilities: 3, position: [2, 1, 0] },
  { id: "n4", type: "router", hostname: "core-sw-01", ip: "10.0.0.2", status: "healthy", services: ["ospf", "bgp"], position: [0, 2, 0] },
  { id: "n5", type: "workstation", hostname: "eng-ws-07", ip: "10.0.3.107", status: "compromised", services: ["rdp"], vulnerabilities: 8, position: [-2, -1, 0] },
  { id: "n6", type: "cloud", hostname: "aws-vpc-01", ip: "172.16.0.1", status: "healthy", services: ["s3", "ec2", "rds"], position: [2, -1, 0] },
];

const MOCK_EDGES: NetworkEdge[] = [
  { id: "e1", source: "n1", target: "n4", protocol: "tcp", port: 443, encrypted: true, status: "active" },
  { id: "e2", source: "n4", target: "n2", protocol: "tcp", port: 389, encrypted: true, status: "active" },
  { id: "e3", source: "n4", target: "n3", protocol: "https", port: 443, encrypted: true, status: "active" },
  { id: "e4", source: "n4", target: "n5", protocol: "rdp", port: 3389, encrypted: false, status: "suspicious" },
  { id: "e5", source: "n4", target: "n6", protocol: "https", port: 443, encrypted: true, status: "active" },
  { id: "e6", source: "n5", target: "n2", protocol: "smb", port: 445, encrypted: false, status: "suspicious" },
];

export function SOCBackground() {
  return (
    <>
      {/* 3D Canvas layer */}
      <Canvas
        camera={{ position: [0, 8, 12], fov: 60 }}
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
        <ThreatRadar threats={MOCK_THREATS} scanSpeed={0.3} showLabels={false} />

        {/* Security shield - right */}
        <group position={[6, 0, 0]}>
          <SecurityShield level={85} status="active" />
        </group>

        {/* Network topology - left */}
        <group position={[-6, 0, 0]}>
          <NetworkTopology nodes={MOCK_NODES} edges={MOCK_EDGES} layout="radial" theme="cyber" showTraffic />
        </group>
      </Canvas>

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
