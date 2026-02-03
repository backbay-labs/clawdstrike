# Guard Versioning and Compatibility

## Document Information

| Field | Value |
|-------|-------|
| **Status** | Draft |
| **Version** | 0.1.0 |
| **Authors** | Clawdstrike Architecture Team |
| **Last Updated** | 2026-02-02 |
| **Prerequisites** | overview.md, plugin-system.md |

---

## 1. Problem Statement

### 1.1 Versioning Challenges

A guard ecosystem introduces complex versioning requirements:

1. **SDK Version Compatibility**: Guards depend on SDK APIs that evolve
2. **Policy Schema Changes**: Policy YAML format may change
3. **Guard Dependencies**: Guards may depend on other guards
4. **Cross-Language Parity**: TypeScript and Rust SDKs must stay aligned
5. **Backward Compatibility**: Existing policies must continue working
6. **Security Updates**: Critical patches need fast rollout

### 1.2 Failure Scenarios

| Scenario | Impact | Without Solution |
|----------|--------|------------------|
| SDK breaking change | Guards crash at runtime | Silent failures, security gaps |
| Deprecated guard API | Guard stops working after SDK update | Policy enforcement breaks |
| Conflicting guard versions | Two guards need different SDK versions | One guard fails to load |
| Schema version mismatch | Old policy with new engine | Unparseable policy |
| Transitive dependency conflict | Guard A needs X@1, Guard B needs X@2 | Module resolution fails |

### 1.3 Goals

1. **Semantic versioning** for all components (SDK, guards, policies)
2. **Clear compatibility contracts** between components
3. **Graceful degradation** when versions mismatch
4. **Automated compatibility checking** at policy load time
5. **Migration tooling** for version upgrades

---

## 2. Versioning Scheme

### 2.1 Component Versions

```
+------------------------------------------------------------------+
|                    Version Hierarchy                              |
+------------------------------------------------------------------+
|                                                                    |
|  Clawdstrike Runtime                                              |
|  ├── Version: 1.2.3                                               |
|  ├── SDK API Version: 1.0                                         |
|  └── Policy Schema Version: 1.0.0                                 |
|                                                                    |
|  Guard Plugin                                                      |
|  ├── Package Version: 2.0.1                                       |
|  ├── Min SDK Version: 0.5.0                                       |
|  └── Max SDK Version: 2.x                                         |
|                                                                    |
|  Policy File                                                       |
|  └── Schema Version: 1.0.0                                        |
|                                                                    |
+------------------------------------------------------------------+
```

### 2.2 Semantic Versioning Rules

All components follow [SemVer 2.0](https://semver.org/):

| Version Part | When to Bump | Example |
|--------------|--------------|---------|
| **MAJOR** | Breaking changes | SDK API signature change |
| **MINOR** | New features, backward compatible | New guard capability |
| **PATCH** | Bug fixes, backward compatible | Security fix |

### 2.3 API Stability Levels

```typescript
/**
 * API stability annotations
 */

/**
 * @stable - Will not change in breaking way within major version
 */
export interface Guard { /* ... */ }

/**
 * @beta - May change in minor versions, breaking changes announced
 */
export interface CompositionRule { /* ... */ }

/**
 * @experimental - May change or be removed at any time
 */
export interface AsyncGuardMetrics { /* ... */ }

/**
 * @deprecated - Will be removed in next major version
 * @migration Use NewApiName instead
 */
export interface OldApiName { /* ... */ }
```

---

## 3. Compatibility Matrix

### 3.1 SDK to Runtime Compatibility

```
+------------------------------------------------------------------+
|               SDK ↔ Runtime Compatibility Matrix                  |
+------------------------------------------------------------------+
|                                                                    |
|  SDK Version  │  Runtime 0.x  │  Runtime 1.x  │  Runtime 2.x     |
|  ─────────────┼───────────────┼───────────────┼────────────────  |
|  SDK 0.5      │  ✓            │  ✓ (compat)   │  ✗              |
|  SDK 1.0      │  ✗            │  ✓            │  ✓ (compat)     |
|  SDK 1.5      │  ✗            │  ✓            │  ✓ (compat)     |
|  SDK 2.0      │  ✗            │  ✗            │  ✓              |
|                                                                    |
|  ✓ = Full support                                                 |
|  ✓ (compat) = Compatibility mode, may lack features              |
|  ✗ = Not supported                                                |
|                                                                    |
+------------------------------------------------------------------+
```

### 3.2 Policy Schema Compatibility

```yaml
# Policy schema version is independent of runtime version
# but must be supported by the runtime

# Supported schema versions by runtime:
# Runtime 0.x: schema 0.1 - 0.9
# Runtime 1.x: schema 1.0 - 1.x, 0.9 (legacy mode)
# Runtime 2.x: schema 2.0 - 2.x, 1.x (compat mode)
```

### 3.3 Guard Cross-Compatibility

```
+------------------------------------------------------------------+
|            Guard Version Resolution                               |
+------------------------------------------------------------------+
|                                                                    |
|  Policy requires:                                                  |
|    - @guard/secrets@^1.0.0                                        |
|    - @guard/egress@~2.1.0                                         |
|                                                                    |
|  Resolution:                                                       |
|    1. Find all versions matching constraints                      |
|    2. Select highest version compatible with SDK                  |
|    3. Check for conflicts between guards                          |
|    4. Load selected versions                                      |
|                                                                    |
|  Conflict example:                                                 |
|    @guard/secrets@1.5 requires SDK >= 1.0                        |
|    @guard/egress@2.1 requires SDK <= 0.9                         |
|    → Conflict: No SDK version satisfies both                     |
|                                                                    |
+------------------------------------------------------------------+
```

---

## 4. Version Constraints

### 4.1 Constraint Syntax

Guards declare SDK compatibility using npm-style version ranges:

```json
{
  "clawdstrike": {
    "minVersion": "0.5.0",
    "maxVersion": "2.x"
  }
}
```

| Constraint | Meaning | Example |
|------------|---------|---------|
| `1.2.3` | Exact version | Only 1.2.3 |
| `^1.2.3` | Compatible with 1.2.3 | >= 1.2.3 < 2.0.0 |
| `~1.2.3` | Approximately 1.2.3 | >= 1.2.3 < 1.3.0 |
| `1.x` | Any 1.x version | >= 1.0.0 < 2.0.0 |
| `>=1.0.0` | At least 1.0.0 | >= 1.0.0 |
| `>=1.0.0 <2.0.0` | Range | 1.0.0 to 1.x |

### 4.2 Policy Version Constraints

```yaml
# policy.yaml
version: "1.0.0"  # Policy schema version

guards:
  custom:
    # Specific version
    - package: "@guard/secrets"
      version: "1.5.2"

    # Range constraint
    - package: "@guard/egress"
      version: "^2.0.0"

    # Latest compatible
    - package: "@guard/audit"
      version: "*"  # Any version compatible with current SDK
```

### 4.3 Lockfile

```json
// clawdstrike.lock.json
{
  "lockfileVersion": 1,
  "clawdstrikeVersion": "1.2.3",
  "sdkVersion": "1.0.0",
  "policySchemaVersion": "1.0.0",
  "guards": {
    "@guard/secrets": {
      "version": "1.5.2",
      "resolved": "https://registry.npmjs.org/@guard/secrets/-/secrets-1.5.2.tgz",
      "integrity": "sha512-abc123...",
      "sdkCompatibility": {
        "min": "0.8.0",
        "max": "2.x"
      },
      "dependencies": {}
    },
    "@guard/egress": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/@guard/egress/-/egress-2.1.0.tgz",
      "integrity": "sha512-def456...",
      "sdkCompatibility": {
        "min": "1.0.0",
        "max": "2.x"
      },
      "dependencies": {
        "minimatch": "^5.0.0"
      }
    }
  },
  "resolvedAt": "2026-01-15T10:30:00Z"
}
```

---

## 5. Version Resolution

### 5.1 Resolution Algorithm

```typescript
// version-resolver.ts

interface GuardConstraint {
  package: string;
  version: string;
}

interface ResolvedGuard {
  package: string;
  version: string;
  sdkCompatibility: VersionRange;
}

class VersionResolver {
  private sdkVersion: string;
  private registry: GuardRegistry;

  /**
   * Resolve guard versions for a policy
   */
  async resolve(constraints: GuardConstraint[]): Promise<ResolvedGuard[]> {
    const resolved: ResolvedGuard[] = [];

    for (const constraint of constraints) {
      const guard = await this.resolveOne(constraint);
      resolved.push(guard);
    }

    // Check for conflicts
    this.checkConflicts(resolved);

    return resolved;
  }

  /**
   * Resolve a single guard constraint
   */
  private async resolveOne(constraint: GuardConstraint): Promise<ResolvedGuard> {
    // Get all versions from registry
    const versions = await this.registry.getVersions(constraint.package);

    // Filter by constraint
    const matching = versions.filter(v =>
      semver.satisfies(v.version, constraint.version)
    );

    // Filter by SDK compatibility
    const compatible = matching.filter(v =>
      this.isSDKCompatible(v.sdkCompatibility)
    );

    if (compatible.length === 0) {
      throw new ResolutionError(
        `No version of ${constraint.package} matching ${constraint.version} ` +
        `is compatible with SDK ${this.sdkVersion}`
      );
    }

    // Select highest compatible version
    const selected = compatible.sort((a, b) =>
      semver.rcompare(a.version, b.version)
    )[0];

    return selected;
  }

  /**
   * Check if guard is compatible with current SDK
   */
  private isSDKCompatible(range: VersionRange): boolean {
    if (range.min && semver.lt(this.sdkVersion, range.min)) {
      return false;
    }
    if (range.max && !semver.satisfies(this.sdkVersion, range.max)) {
      return false;
    }
    return true;
  }

  /**
   * Check for conflicts between resolved guards
   */
  private checkConflicts(guards: ResolvedGuard[]): void {
    // Check for duplicate packages with different versions
    const byPackage = new Map<string, ResolvedGuard[]>();

    for (const guard of guards) {
      const existing = byPackage.get(guard.package) || [];
      existing.push(guard);
      byPackage.set(guard.package, existing);
    }

    for (const [pkg, versions] of byPackage) {
      if (versions.length > 1) {
        const unique = new Set(versions.map(v => v.version));
        if (unique.size > 1) {
          throw new ConflictError(
            `Multiple versions of ${pkg} required: ${[...unique].join(', ')}`
          );
        }
      }
    }
  }
}
```

### 5.2 Conflict Resolution Strategies

```yaml
# policy.yaml
version: "1.0.0"

# Version resolution configuration
resolution:
  # Strategy for conflicts
  strategy: "highest"  # highest, lowest, fail

  # Override specific packages
  overrides:
    "@guard/secrets": "1.5.0"  # Force specific version

  # Allow multiple versions (isolation)
  allowDuplicates:
    - "@guard/utils"  # This package can have multiple versions

  # Alias packages
  aliases:
    "@guard/secrets-v1": "@guard/secrets@1.x"
    "@guard/secrets-v2": "@guard/secrets@2.x"
```

---

## 6. Migration and Deprecation

### 6.1 Deprecation Timeline

```
+------------------------------------------------------------------+
|                  Deprecation Lifecycle                            |
+------------------------------------------------------------------+
|                                                                    |
|  T+0:  Feature marked @deprecated in docs and code               |
|        - Deprecation warning added to logs                        |
|        - Migration guide published                                |
|                                                                    |
|  T+3mo: Warning becomes more prominent                           |
|         - Console warning on every use                           |
|         - CI/CD can enable strict mode to fail on deprecated     |
|                                                                    |
|  T+6mo: Feature soft-disabled                                    |
|         - Requires explicit opt-in to use                        |
|         - Security updates only                                  |
|                                                                    |
|  T+12mo: Feature removed in next major version                   |
|          - Breaking change documented in CHANGELOG               |
|                                                                    |
+------------------------------------------------------------------+
```

### 6.2 Migration CLI

```bash
# Check for deprecated APIs in your guard
hush guard check-deprecated

# Output:
# Checking for deprecated APIs...
#
# Found 2 deprecated usages:
#
# src/guard.ts:45
#   guard.checkSync() is deprecated since SDK 1.5
#   Migration: Use guard.check() with async/await
#   Removal: SDK 2.0
#
# src/config.ts:12
#   severity: "warn" is deprecated since SDK 1.3
#   Migration: Use severity: "low" or "medium"
#   Removal: SDK 2.0
#
# Run `hush guard migrate` for automatic fixes.

# Automatic migration
hush guard migrate

# Output:
# Migrating deprecated APIs...
# ✓ Updated guard.checkSync() → guard.check() in src/guard.ts
# ✓ Updated severity: "warn" → severity: "low" in src/config.ts
#
# Migration complete. Please review changes and run tests.

# Migrate policy file
hush policy migrate policy.yaml --target-version 2.0.0

# Output:
# Migrating policy.yaml to schema 2.0.0...
# ✓ Updated version field
# ✓ Renamed guards.egress_allowlist → guards.egress
# ✓ Updated severity values
#
# Migration complete. Backup saved to policy.yaml.bak
```

### 6.3 Compatibility Shims

```typescript
// SDK includes compatibility shims for deprecated APIs

// Old API (deprecated)
interface OldGuardInterface {
  check(event: Event): boolean;  // Returns boolean
}

// New API
interface Guard {
  check(event: PolicyEvent): Promise<GuardResult>;  // Returns rich result
}

// Compatibility shim
class CompatibilityWrapper implements Guard {
  constructor(private oldGuard: OldGuardInterface) {
    console.warn(
      `Guard ${oldGuard.name} uses deprecated API. ` +
      `Please update to SDK 2.0 interface.`
    );
  }

  async check(event: PolicyEvent): Promise<GuardResult> {
    // Convert new event to old format
    const oldEvent = this.convertEvent(event);

    // Call old API
    const allowed = this.oldGuard.check(oldEvent);

    // Convert result to new format
    return allowed
      ? GuardResult.allow(this.oldGuard.name)
      : GuardResult.deny(this.oldGuard.name, 'medium', 'Denied by legacy guard');
  }
}
```

---

## 7. SDK Versioning

### 7.1 SDK Release Process

```
+------------------------------------------------------------------+
|                    SDK Release Process                            |
+------------------------------------------------------------------+
|                                                                    |
|  1. Feature Development                                           |
|     - New features developed on feature branches                  |
|     - Breaking changes on `next` branch                          |
|     - Bug fixes on `main` branch                                 |
|                                                                    |
|  2. Release Candidate                                             |
|     - RC published: @clawdstrike/guard-sdk@2.0.0-rc.1           |
|     - Guard authors can test compatibility                        |
|     - Minimum 2 weeks RC period for major versions               |
|                                                                    |
|  3. Stable Release                                                |
|     - Stable version published                                    |
|     - Migration guide finalized                                   |
|     - Compatibility matrix updated                                |
|                                                                    |
|  4. Post-Release                                                  |
|     - Old major version enters maintenance mode                   |
|     - Security fixes backported for 12 months                    |
|                                                                    |
+------------------------------------------------------------------+
```

### 7.2 SDK Version Tags

```bash
# Latest stable
npm install @clawdstrike/guard-sdk@latest
# → 1.5.2

# Next major (pre-release)
npm install @clawdstrike/guard-sdk@next
# → 2.0.0-rc.1

# Specific version
npm install @clawdstrike/guard-sdk@1.5.2

# Latest in major version
npm install @clawdstrike/guard-sdk@^1.0.0
# → 1.5.2

# Previous major (maintenance)
npm install @clawdstrike/guard-sdk@legacy-1
# → 0.9.5 (security fixes only)
```

### 7.3 TypeScript/Rust Parity

```typescript
// SDK versions are synchronized between TypeScript and Rust

// TypeScript
// @clawdstrike/guard-sdk@1.5.0

// Rust
// clawdstrike-guard-sdk = "1.5.0"

// Both SDKs:
// - Have identical major/minor versions
// - Implement same Guard interface
// - Support same capabilities
// - Use same manifest schema
```

---

## 8. Policy Schema Versioning

### 8.1 Schema Evolution

```yaml
# Schema 0.9 (legacy)
guards:
  paths:
    forbidden:
      - "**/.ssh/**"

# Schema 1.0 (current)
version: "1.0.0"
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"

# Schema 2.0 (future)
version: "2.0.0"
schema: "https://clawdstrike.dev/schemas/policy/2.0.0"
guards:
  builtin:
    forbidden_path:
      patterns:
        - "**/.ssh/**"
  custom:
    - package: "@guard/secrets"
```

### 8.2 Schema Validation

```typescript
// schema-validator.ts

import Ajv from 'ajv';

const schemas = {
  '1.0.0': require('./schemas/policy-1.0.0.json'),
  '2.0.0': require('./schemas/policy-2.0.0.json'),
};

class PolicySchemaValidator {
  private ajv: Ajv;

  constructor() {
    this.ajv = new Ajv({ allErrors: true });

    // Register all schemas
    for (const [version, schema] of Object.entries(schemas)) {
      this.ajv.addSchema(schema, `policy-${version}`);
    }
  }

  /**
   * Validate policy against schema version
   */
  validate(policy: unknown, version: string): ValidationResult {
    const schemaId = `policy-${version}`;
    const validate = this.ajv.getSchema(schemaId);

    if (!validate) {
      return {
        valid: false,
        errors: [`Unknown schema version: ${version}`],
      };
    }

    const valid = validate(policy);

    return {
      valid,
      errors: valid ? [] : this.formatErrors(validate.errors),
    };
  }

  /**
   * Auto-detect policy version
   */
  detectVersion(policy: any): string {
    if (policy.version) {
      return policy.version;
    }

    // Legacy detection
    if (policy.guards?.paths) {
      return '0.9.0';
    }

    return '1.0.0';
  }
}
```

### 8.3 Schema Migration

```typescript
// schema-migrator.ts

interface SchemaMigration {
  from: string;
  to: string;
  migrate(policy: any): any;
}

const migrations: SchemaMigration[] = [
  {
    from: '0.9.0',
    to: '1.0.0',
    migrate(policy) {
      return {
        version: '1.0.0',
        guards: {
          forbidden_path: {
            patterns: policy.guards?.paths?.forbidden || [],
          },
          egress_allowlist: {
            allow: policy.guards?.network?.allowed || [],
          },
        },
      };
    },
  },
  {
    from: '1.0.0',
    to: '2.0.0',
    migrate(policy) {
      return {
        version: '2.0.0',
        schema: 'https://clawdstrike.dev/schemas/policy/2.0.0',
        guards: {
          builtin: {
            forbidden_path: policy.guards?.forbidden_path,
            egress_allowlist: policy.guards?.egress_allowlist,
            secret_leak: policy.guards?.secret_leak,
          },
          custom: policy.guards?.custom || [],
        },
      };
    },
  },
];

class SchemaMigrator {
  /**
   * Migrate policy to target version
   */
  migrate(policy: any, targetVersion: string): any {
    let current = policy;
    let currentVersion = current.version || '0.9.0';

    while (currentVersion !== targetVersion) {
      const migration = migrations.find(m => m.from === currentVersion);

      if (!migration) {
        throw new Error(
          `No migration path from ${currentVersion} to ${targetVersion}`
        );
      }

      current = migration.migrate(current);
      currentVersion = migration.to;
    }

    return current;
  }
}
```

---

## 9. Testing Version Compatibility

### 9.1 Compatibility Test Matrix

```yaml
# .github/workflows/compatibility.yml
name: Compatibility Matrix

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  test:
    strategy:
      matrix:
        sdk-version: ['0.9', '1.0', '1.5', '2.0-rc']
        node-version: ['18', '20', '22']
        rust-version: ['1.70', '1.75', 'stable']

    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}

      - name: Install SDK ${{ matrix.sdk-version }}
        run: npm install @clawdstrike/guard-sdk@${{ matrix.sdk-version }}

      - name: Run compatibility tests
        run: npm run test:compat

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: compat-${{ matrix.sdk-version }}-node${{ matrix.node-version }}
          path: test-results/
```

### 9.2 Guard Compatibility Testing

```typescript
// tests/sdk-compat.test.ts

import { describe, it, expect } from 'vitest';
import * as sdk from '@clawdstrike/guard-sdk';

describe('SDK Compatibility', () => {
  it('should have required exports', () => {
    expect(sdk.Guard).toBeDefined();
    expect(sdk.BaseGuard).toBeDefined();
    expect(sdk.GuardResult).toBeDefined();
  });

  it('should have required Guard methods', () => {
    const guard = new TestGuard();

    expect(typeof guard.name).toBe('function');
    expect(typeof guard.handles).toBe('function');
    expect(typeof guard.check).toBe('function');
  });

  it('should support GuardResult factory methods', () => {
    const allow = GuardResult.allow('test');
    expect(allow.status).toBe('allow');

    const deny = GuardResult.deny('test', 'high', 'reason');
    expect(deny.status).toBe('deny');
    expect(deny.severity).toBe('high');
  });

  it('should handle deprecated APIs gracefully', () => {
    // Test that deprecated APIs still work
    if (sdk.legacyCheck) {
      const result = sdk.legacyCheck({});
      expect(result).toBeDefined();
    }
  });
});
```

---

## 10. Configuration Schema

### 10.1 Version Configuration

```yaml
# clawdstrike.config.yaml (global config)

versioning:
  # Require exact SDK version match
  strictSdk: false

  # Allow pre-release versions
  allowPrerelease: false

  # Automatically update patch versions
  autoUpdate:
    enabled: true
    scope: patch  # patch, minor, none

  # Lock file behavior
  lockfile:
    enabled: true
    path: clawdstrike.lock.json
    autoGenerate: true

  # Deprecation handling
  deprecations:
    # warn, error, ignore
    level: warn
    # Fail CI on deprecated usage
    failCi: true
```

### 10.2 Per-Project Configuration

```json
// package.json (npm project)
{
  "clawdstrike": {
    "sdkVersion": "^1.0.0",
    "policySchemaVersion": "1.0.0",
    "strictVersioning": true
  }
}
```

```toml
# Cargo.toml (Rust project)
[package.metadata.clawdstrike]
sdk_version = "^1.0.0"
policy_schema_version = "1.0.0"
strict_versioning = true
```

---

## 11. Security Considerations

### 11.1 Version Pinning for Security

```yaml
# For security-critical deployments, pin exact versions

guards:
  custom:
    - package: "@clawdstrike-guard/certified-secrets"
      version: "1.5.2"  # Exact version, not range
      integrity: "sha512-abc123..."  # Verify package integrity
```

### 11.2 Security Advisory Handling

```typescript
// Security advisory check during version resolution

interface SecurityAdvisory {
  package: string;
  affectedVersions: string;
  severity: 'low' | 'moderate' | 'high' | 'critical';
  recommendation: string;
  patchedVersions?: string;
}

class SecurityAdvisoryChecker {
  private advisories: SecurityAdvisory[];

  /**
   * Check resolved versions against known advisories
   */
  check(guards: ResolvedGuard[]): SecurityWarning[] {
    const warnings: SecurityWarning[] = [];

    for (const guard of guards) {
      const advisory = this.advisories.find(a =>
        a.package === guard.package &&
        semver.satisfies(guard.version, a.affectedVersions)
      );

      if (advisory) {
        warnings.push({
          package: guard.package,
          version: guard.version,
          advisory,
          action: this.recommendAction(advisory),
        });
      }
    }

    return warnings;
  }

  private recommendAction(advisory: SecurityAdvisory): string {
    if (advisory.patchedVersions) {
      return `Upgrade to ${advisory.patchedVersions}`;
    }
    if (advisory.severity === 'critical') {
      return 'Remove this guard immediately';
    }
    return advisory.recommendation;
  }
}
```

### 11.3 Version Tampering Protection

```typescript
// Verify package integrity

import * as crypto from 'crypto';

async function verifyPackageIntegrity(
  packageName: string,
  version: string,
  expectedIntegrity: string
): Promise<boolean> {
  // Download package
  const tarball = await downloadPackage(packageName, version);

  // Calculate integrity hash
  const hash = crypto
    .createHash('sha512')
    .update(tarball)
    .digest('base64');

  const actualIntegrity = `sha512-${hash}`;

  if (actualIntegrity !== expectedIntegrity) {
    throw new IntegrityError(
      `Package integrity mismatch for ${packageName}@${version}. ` +
      `Expected ${expectedIntegrity}, got ${actualIntegrity}`
    );
  }

  return true;
}
```

---

## 12. Implementation Phases

### Phase 1: Basic Versioning (Weeks 1-2)

- [ ] Semver validation for all components
- [ ] SDK version constraints in manifests
- [ ] Basic version resolution

### Phase 2: Lockfile Support (Weeks 3-4)

- [ ] Lockfile generation
- [ ] Lockfile validation
- [ ] `hush guard lock` command

### Phase 3: Migration Tooling (Weeks 5-6)

- [ ] Deprecation detection
- [ ] Automatic migration CLI
- [ ] Policy schema migration

### Phase 4: Compatibility Matrix (Weeks 7-8)

- [ ] Cross-version testing
- [ ] Compatibility documentation
- [ ] CI integration

### Phase 5: Security Integration (Weeks 9-10)

- [ ] Security advisory checking
- [ ] Integrity verification
- [ ] Vulnerability scanning

---

## 13. Open Questions

1. **Q: How long do we support old major versions?**
   - Proposed: 12 months security fixes, 6 months feature backports

2. **Q: Should we allow multiple SDK versions in one runtime?**
   - Pro: Maximum flexibility
   - Con: Complexity, memory overhead
   - Proposed: No, single SDK version per runtime

3. **Q: How do we handle emergency security patches?**
   - Proposed: Patch releases can break semver if security requires

4. **Q: Should we have an LTS release track?**
   - Pro: Stability for enterprises
   - Con: Maintenance burden
   - Proposed: Yes, one LTS per year with 24-month support

---

*This versioning system ensures long-term ecosystem stability while enabling innovation. See overview.md for the complete extensibility architecture.*
