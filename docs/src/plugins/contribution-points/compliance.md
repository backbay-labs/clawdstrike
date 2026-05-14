# Compliance Frameworks

Compliance framework contributions provide compliance mapping definitions that map guards and policies to regulatory requirements (e.g. HIPAA, SOC 2, PCI-DSS, NIST 800-53).

## ComplianceFrameworkContribution interface

```typescript,ignore
interface ComplianceFrameworkContribution {
  /** Unique identifier for this framework. */
  id: string;
  /** Human-readable name (e.g. "NIST 800-53"). */
  name: string;
  /** Description of the compliance framework. */
  description: string;
  /** Path to the framework definition module within the plugin package. */
  entrypoint: string;
}
```

## Registering a compliance framework

Declare the framework in the manifest's `contributions.complianceFrameworks` array. The `entrypoint` points to a module that exports the full framework definition:

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";

export default createPlugin({
  manifest: {
    id: "acme.hipaa-compliance",
    name: "hipaa-compliance",
    displayName: "HIPAA Compliance",
    description: "Maps ClawdStrike guards to HIPAA security requirements",
    version: "1.0.0",
    publisher: "Acme",
    categories: ["compliance"],
    trust: "community",
    activationEvents: ["onStartup"],
    contributions: {
      complianceFrameworks: [
        {
          id: "acme.hipaa",
          name: "HIPAA Security Rule",
          description: "Health Insurance Portability and Accountability Act security requirements",
          entrypoint: "dist/hipaa-framework.js",
        },
      ],
    },
  },

  activate(ctx) {
    // The compliance framework is loaded via the entrypoint.
    // Registration is handled by the compliance framework registry.
    console.log("HIPAA compliance framework activated");
  },
});
```

## Framework definition module

The `entrypoint` module should export a compliance framework definition that maps guard evaluations and policy configurations to regulatory controls. The exact shape of the framework definition is determined by the compliance framework registry API.

A typical framework definition includes:

- **Controls**: A list of regulatory controls with IDs and descriptions
- **Mappings**: Associations between ClawdStrike guards/policies and framework controls
- **Evidence requirements**: What audit evidence each control requires

```typescript,ignore
// dist/hipaa-framework.js (skeleton)
export default {
  id: "acme.hipaa",
  name: "HIPAA Security Rule",
  version: "2024.1",
  controls: [
    {
      id: "164.312(a)(1)",
      title: "Access Control",
      description: "Implement technical policies and procedures for information systems",
    },
    {
      id: "164.312(c)(1)",
      title: "Integrity",
      description: "Implement policies and procedures to protect ePHI from improper alteration",
    },
    // ... additional controls
  ],
  mappings: [
    {
      controlId: "164.312(a)(1)",
      guards: ["forbidden_path", "path_allowlist"],
      evidenceType: "receipt",
    },
    {
      controlId: "164.312(c)(1)",
      guards: ["patch_integrity", "secret_leak"],
      evidenceType: "receipt",
    },
  ],
};
```
