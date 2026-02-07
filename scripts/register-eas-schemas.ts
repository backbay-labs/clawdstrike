/**
 * register-eas-schemas.ts — One-time EAS schema registration on Base L2.
 *
 * Registers three ClawdStrike schemas on the EAS SchemaRegistry:
 *   1. Policy Attestation (revocable)
 *   2. Checkpoint Anchor (not revocable)
 *   3. Key Rotation (revocable)
 *
 * Usage:
 *   EAS_SIGNER_PRIVATE_KEY=0x... npx ts-node scripts/register-eas-schemas.ts
 *
 * Environment variables:
 *   EAS_SIGNER_PRIVATE_KEY  — hex-encoded private key for the signer wallet
 *   EAS_RPC_URL             — (optional) RPC URL, defaults to Base mainnet
 *   EAS_CHAIN               — (optional) "mainnet" or "sepolia", defaults to "mainnet"
 */

import { SchemaRegistry } from "@ethereum-attestation-service/eas-sdk";
import { ethers } from "ethers";

// Contract addresses (same on Base mainnet and Sepolia)
const SCHEMA_REGISTRY_ADDRESS = "0xA7b39296258348C78294F95B872b282326A97BDF";

const CHAINS: Record<string, { rpcUrl: string; chainId: number }> = {
  mainnet: {
    rpcUrl: "https://mainnet.base.org",
    chainId: 8453,
  },
  sepolia: {
    rpcUrl: "https://sepolia.base.org",
    chainId: 84532,
  },
};

// Schema definitions
const SCHEMAS = [
  {
    name: "Policy Attestation",
    schema:
      "bytes32 bundleHash, string feedId, string entryId, bytes32 curatorKey, uint64 feedSeq, string policyVersion",
    revocable: true,
  },
  {
    name: "Checkpoint Anchor",
    schema:
      "bytes32 checkpointHash, uint64 checkpointSeq, uint64 treeSize, bytes32 logOperatorKey, bytes32 witnessKey",
    revocable: false,
  },
  {
    name: "Key Rotation",
    schema:
      "bytes32 oldKey, bytes32 newKey, string feedId, uint64 rotationSeq, string reason",
    revocable: true,
  },
];

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

async function main() {
  const privateKey = process.env.EAS_SIGNER_PRIVATE_KEY;
  if (!privateKey) {
    console.error("Error: EAS_SIGNER_PRIVATE_KEY environment variable is required");
    process.exit(1);
  }

  const chainName = process.env.EAS_CHAIN || "mainnet";
  const chain = CHAINS[chainName];
  if (!chain) {
    console.error(`Error: Unknown chain "${chainName}". Use "mainnet" or "sepolia".`);
    process.exit(1);
  }

  const rpcUrl = process.env.EAS_RPC_URL || chain.rpcUrl;

  console.log(`Registering EAS schemas on Base ${chainName}`);
  console.log(`  RPC URL: ${rpcUrl}`);
  console.log(`  Chain ID: ${chain.chainId}`);
  console.log(`  SchemaRegistry: ${SCHEMA_REGISTRY_ADDRESS}`);
  console.log();

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = new ethers.Wallet(privateKey, provider);
  const address = await signer.getAddress();
  console.log(`  Signer address: ${address}`);

  const balance = await provider.getBalance(address);
  console.log(`  Signer balance: ${ethers.formatEther(balance)} ETH`);
  console.log();

  const registry = new SchemaRegistry(SCHEMA_REGISTRY_ADDRESS);
  registry.connect(signer);

  const results: Array<{ name: string; uid: string }> = [];

  for (const schemaDef of SCHEMAS) {
    console.log(`Registering: ${schemaDef.name}`);
    console.log(`  Schema: ${schemaDef.schema}`);
    console.log(`  Revocable: ${schemaDef.revocable}`);

    const tx = await registry.register({
      schema: schemaDef.schema,
      resolverAddress: ZERO_ADDRESS,
      revocable: schemaDef.revocable,
    });

    const uid = await tx.wait();
    console.log(`  UID: ${uid}`);
    console.log();

    results.push({ name: schemaDef.name, uid });
  }

  // Print summary for eas-anchor.toml
  console.log("=== Add to eas-anchor.toml [schemas] section ===");
  console.log();
  console.log("[schemas]");
  for (const r of results) {
    const key = r.name
      .toLowerCase()
      .replace(/ /g, "_")
      .concat("_uid");
    console.log(`${key} = "${r.uid}"`);
  }
}

main().catch((err) => {
  console.error("Schema registration failed:", err);
  process.exit(1);
});
