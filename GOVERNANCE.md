# ClawdStrike Governance

## Current Model: BDFL + Maintainer Council

ClawdStrike uses a Benevolent Dictator For Life (BDFL) governance model with
a Maintainer Council for the initial phase of the project.

### BDFL

The BDFL has final authority on all project decisions.

- **Current BDFL:** Connor (GitHub: @connor)

### Maintainer Council

Maintainers have commit access and review authority within their component areas.

| Maintainer | Component Area | GitHub |
|------------|---------------|--------|
| (TBD)      | Guards / Policy Engine | |
| (TBD)      | Spine Protocol | |
| (TBD)      | Desktop / SDK | |
| (TBD)      | Bridges / Infrastructure | |
| (TBD)      | Documentation / Community | |

### Decision Process

1. **Minor changes** (bug fixes, docs, typos): Single maintainer approval
2. **Feature additions** (new guards, adapters): Maintainer approval + CI pass
3. **Architecture changes** (new crates, protocol changes): RFC required
4. **Security-sensitive changes** (crypto, guard logic, Spine protocol): Two maintainer reviews
5. **Governance changes**: BDFL approval

### RFC Process

Significant design decisions are documented as RFCs in `docs/rfcs/`:

1. Author opens a PR adding `docs/rfcs/NNNN-title.md`
2. Community comment period: 14 days minimum
3. Maintainer Council discusses in weekly call
4. BDFL approves, requests changes, or rejects
5. Approved RFCs are merged and implementation can begin

### Component Ownership

| Component | Directory | Owner(s) |
|-----------|-----------|----------|
| Crypto primitives | `crates/hush-core/` | Guards maintainer |
| Guard engine | `crates/clawdstrike/` | Guards maintainer |
| Spine protocol | `crates/spine/` | Spine maintainer |
| Tetragon bridge | `crates/tetragon-bridge/` | Bridges maintainer |
| Hubble bridge | `crates/hubble-bridge/` | Bridges maintainer |
| hushd daemon | `crates/hushd/` | Guards maintainer |
| CLI | `crates/hush-cli/` | Guards maintainer |
| Desktop app | `apps/desktop/` | Desktop maintainer |
| TypeScript SDK | `packages/hush-ts/` | Desktop maintainer |
| Python SDK | `packages/hush-py/` | Community maintainer |
| Rulesets | `rulesets/` | Any maintainer |
| Documentation | `docs/` | Any maintainer |
| Helm chart | `deploy/helm/` | Bridges maintainer |

### Becoming a Maintainer

Maintainer candidates are nominated by existing maintainers based on:
- Sustained, high-quality contributions (6+ merged PRs)
- Demonstrated understanding of the codebase and design philosophy
- Constructive participation in reviews and discussions
- Alignment with the project's fail-closed security philosophy

The BDFL approves all maintainer additions.

## Future Evolution

### Phase 2: Steering Committee (12-24 months)

When the contributor base grows beyond the founding team:
- Transition to a 5-member elected Steering Committee
- BDFL retains veto on security-critical decisions only
- Sub-teams form around components with designated leads
- Annual elections for Steering Committee seats

### Phase 3: CNCF Sandbox (24+ months)

Requirements for CNCF Sandbox application:
- 2+ maintainers from different organizations
- Apache 2.0 license (completed)
- Adopt CNCF governance template
- Security audit completed
- 3+ production adopters

## Community Channels

| Channel | Purpose |
|---------|---------|
| [GitHub Discussions](https://github.com/backbay-labs/clawdstrike/discussions) | Q&A, feature ideas, architecture |
| [Discord](https://discord.gg/clawdstrike) | Real-time chat, contributor coordination |
| Weekly community call | Demos, roadmap, contributor spotlights |
| Monthly security office hours | Guard design, threat modeling |
