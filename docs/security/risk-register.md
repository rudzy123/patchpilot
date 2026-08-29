# Architecture and security risk register

Prioritized risks for PatchPilot's v0.1 **architecture phase**. Likelihood and impact are qualitative (H/M/L). This is not a quantitative FAIR analysis and not a residual-risk acceptance for a certified program.

Status values: `open`, `mitigated-in-design`, `accepted`, `watch`.

Mitigated-in-design means documents specify controls; **runtime residual remains until code, tests, and operations exist**.

Decision deadline: before the first implementing PR for that area, unless noted.

| ID | Description | L | I | Pri | Area | Planned mitigation | Residual | Deadline | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | Cross-tenant IDOR or missing org predicate | M | H | P0 | Tenancy | [tenant-isolation.md](../architecture/tenant-isolation.md); required tests | Until implemented | First tenant API PR | mitigated-in-design |
| R2 | Malicious or huge SBOM exhausts API/worker | H | H | P0 | Ingestion | Configurable limit **proposals** ([ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md)); quarantine; no URL fetch; worker-thread parser budget | Limit values unvalidated; runtime not in Batch 1 | First upload PR | mitigated-in-design |
| R3 | Object storage public or guessable keys | M | H | P0 | Storage | Private bucket; org-prefixed content-addressed keys | Operator ACL | First storage adapter | mitigated-in-design |
| R4 | Job replay duplicates findings or ignores org | M | H | P0 | Jobs | Outbox, idempotency, reload org, leases | At-least-once | First worker PR | mitigated-in-design |
| R5 | Development adapters enabled in production | M | H | P0 | Config | Config gating; tests | Human error | First config package | mitigated-in-design |
| R6 | Prototype pollution / parser crash loops | M | H | P1 | Ingestion | Depth, node, and semantic limits; worker-thread time-box (not `Promise.race`); DLQ | Novel payloads; parser runtime not in Batch 1 | First parser PR | mitigated-in-design |
| R7 | Package/ecosystem confusion in correlation | M | H | P1 | Matching | No fuzzy match; adapters | GIGO SBOMs | First correlate PR | mitigated-in-design |
| R8 | Poisoned or stale intel silently trusted | M | M | P1 | Intel | Provenance, freshness UI, additive records | Public catalogs | First intel PR | mitigated-in-design |
| R9 | XSS via component names | M | H | P1 | Web | Escape; no raw JSON | New sinks | First UI PR | mitigated-in-design |
| R10 | CSRF on session cookie | M | H | P1 | Authn | [ADR 0019](../adr/0019-local-password-sessions.md) SameSite + Origin + synchronizer token | Session 6 auth exists; Session 8 upload routes not yet | First session PR | mitigated-in-design |
| R11 | Secret or SBOM logging | M | H | P1 | Telemetry | Canonical redaction tests | Sink bypass | First logger PR | mitigated-in-design |
| R12 | Audit UPDATE/DELETE or cascade evidence loss | L | H | P1 | Audit | Insert-only; FK policy; DB role | Superuser | First audit table | mitigated-in-design |
| R13 | Incorrect priority / false "fixed" / incomplete SBOM | M | H | P1 | Policy/findings | Factors, policy version, coverage heuristic, rescan ≠ task | Weights arbitrary; heuristic | First score + rescan PR | mitigated-in-design |
| R14 | SSRF via future URL fetch or mis-allowlist | L | H | P1 | Egress | No SBOM fetch; allowlists | Misconfig | First HTTP adapter | mitigated-in-design |
| R15 | Authn lockout and MFA unspecified | H | M | P1 | Authn | Rate limits in [ADR 0019](../adr/0019-local-password-sessions.md); [OD-17](../architecture/open-decisions.md) | No MFA | Before treating stuffing resistance as complete | open |
| R16 | Credential KEK management weak or lost | M | H | P1 | Secrets | [OD-4](../architecture/open-decisions.md) | Lost KEK = lost creds | Before tenant credentials | open |
| R17 | Redis exposed → queue injection | M | H | P1 | Jobs | Network isolation | Operator duty | First compose | mitigated-in-design |
| R18 | Backup exposure | M | H | P1 | Deploy | Operator encrypt; Restricted class | Accepted | Ongoing | accepted |
| R19 | Instance operator reads all DBs | H | H | P2 | Tenancy | Honest self-host; no app bypass | Disk access | n/a | accepted |
| R20 | Supply-chain / CI compromise | M | H | P2 | Process | Lockfile later; SECURITY.md | Residual | First dependencies | watch |
| R21 | OSV rate limit blocks correlation | M | M | P2 | Intel | Backoff, cache, degraded | Delay | First intel PR | mitigated-in-design |
| R22 | Org policy override mistakes ranking | M | M | P2 | Policy | Immutable versions; history | Operator error | First override PR | mitigated-in-design |
| R23 | Duplicate SHA-256 across assets | L | M | P2 | Ingestion | Duplicate only same org+asset | Extra storage | First upload | mitigated-in-design |
| R24 | Finding identity includes version via full PURL or delayed CVE | M | H | P1 | Findings | Versionless identity + OSV id; CVE is alias ([finding-lifecycle.md](../architecture/finding-lifecycle.md)) | Product still may want version-scoped findings later | First correlate PR | mitigated-in-design |
| R25 | Future webhook forgery | L | H | P2 | Integrations | No listeners; GitHub not MVP | When added | GitHub ADR | watch |
| R26 | Optional AI leakage | L | H | P2 | AI | Disabled; ADR 0017 | If enabled | Before any AI PR | mitigated-in-design |
| R27 | Teams unused → confused authz | L | L | P3 | Domain | Owners are not authz | Misuse | n/a | watch |
| R28 | Future CLI skips API authz | L | H | P3 | Clients | CLI deferred; must call API | If bypassed | CLI ADR | watch |
| R29 | DoS of public feeds (external) | L | L | P3 | Intel | Out of product scope | n/a | n/a | accepted |
| R30 | Compliance theater in UI copy | M | M | P2 | Product | Review checklist; non-goals | Copy drift | Every UI PR | mitigated-in-design |
| R31 | Numeric ingestion limits unvalidated | H | M | P1 | Ingestion | Labelled proposals with floors/ceilings in `@patchpilot/config`; perf tests still required | Too tight/loose | Before production-minded release | open |
| R32 | Database-only audit not WORM | M | M | P1 | Audit | Document limitations; DB grants | Superuser | First audit table | mitigated-in-design |
| R33 | Coverage heuristic false inconclusive/resolved | M | M | P2 | Findings | 50% drop proposal; tune | Heuristic | First rescan PR | watch |
| R34 | Exclusive finding states clobber acceptance/mitigation/FP | M | H | P1 | Findings | Occupancy rules in [finding-lifecycle.md](../architecture/finding-lifecycle.md) | UI still must show both records | First finding state PR | mitigated-in-design |
| R35 | Derived graph keyed only by SBOM (reprocess / observations) | M | H | P1 | Ingestion | Key occurrences and observations by `sbomIngestionId` | Extra rows | First parser persist PR | mitigated-in-design |
| R36 | Older SBOM completing last becomes current | M | H | P1 | Findings | Current = max `receivedAt` among `completed` | Clock skew on upload time (server sets `receivedAt`) | First rescan PR | mitigated-in-design |
| R37 | Divergent RiskCalculation idempotency keys | M | M | P1 | Jobs | Single `inputFingerprint` in [reliability-model.md](../architecture/reliability-model.md) | Fingerprint bugs | First score PR | mitigated-in-design |
| R38 | Unauthenticated org signup on exposed instance | M | H | P1 | Authn | No public registration ([ADR 0019](../adr/0019-local-password-sessions.md)) | First-user HTTP still deferred | Before invite/bootstrap PR | mitigated-in-design |

## P0 meaning

P0 items must have tests and review on the first implementing PR for that area. Architecture alone does not close them.

## Open architecture decisions that drive risk

See [open-decisions.md](../architecture/open-decisions.md). Highest coupling: **OD-17** (R15), **OD-4** (R16), **OD-10** (R19), **OD-15** (R7), **OD-18** (proxy trust). OD-1, OD-2, and OD-3 are closed by [ADR 0019](../adr/0019-local-password-sessions.md). Session 8 completion semantics are closed by [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md).

## Related documents

- [Threat model](threat-model.md)
- [Unresolved architecture decisions](../architecture/open-decisions.md)
