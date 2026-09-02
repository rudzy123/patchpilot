# Architecture and security risk register

Prioritized risks for PatchPilot's v0.1 **architecture phase**. Likelihood and impact are qualitative (H/M/L). This is not a quantitative FAIR analysis and not a residual-risk acceptance for a certified program.

Status values: `open`, `mitigated-in-design`, `accepted`, `watch`.

Mitigated-in-design means documents specify controls; **runtime residual remains until code, tests, and operations exist**.

Decision deadline: before the first implementing PR for that area, unless noted.

| ID | Description | L | I | Pri | Area | Planned mitigation | Residual | Deadline | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | Cross-tenant IDOR or missing org predicate | M | H | P0 | Tenancy | [tenant-isolation.md](../architecture/tenant-isolation.md); required tests | Until implemented | First tenant API PR | mitigated-in-design |
| R2 | Malicious or huge SBOM exhausts API/worker | H | H | P0 | Ingestion | Streaming size cap, JSON structural limits, semantic limits, worker-thread termination budget, quarantine, no URL fetch ([ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md)) | Limit values still unvalidated against representative SBOMs (see R31) | Implemented Session 8 | mitigated-in-design |
| R3 | Object storage public or guessable keys | M | H | P0 | Storage | Private bucket; org-and-asset-prefixed content-addressed keys; no ACL; no presigner in production code (build-enforced) | Operator must actually enforce bucket privacy | Implemented Session 8 | mitigated-in-design |
| R4 | Job replay duplicates findings or ignores org | M | H | P0 | Jobs | Outbox, deterministic job ids, org predicate on every reload, insert-once graph persist, BackgroundJob lease | At-least-once delivery | Implemented Session 8 for `sbom.ingest` | mitigated-in-design |
| R5 | Development adapters enabled in production | M | H | P0 | Config | Config gating; tests | Human error | First config package | mitigated-in-design |
| R6 | Prototype pollution / parser crash loops | M | H | P1 | Ingestion | Secure JSON parse, prototype-key rejection, depth/node/string limits, worker-thread termination (not `Promise.race`), quarantine instead of retry | Novel payloads | Implemented Session 8 | mitigated-in-design |
| R7 | Package/ecosystem confusion in correlation | M | H | P1 | Matching | No fuzzy match; adapters | GIGO SBOMs | First correlate PR | mitigated-in-design |
| R8 | Poisoned or stale intel silently trusted | M | M | P1 | Intel | Provenance, additive revisions, guarded current-projection activation, freshness UI later ([ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)) | Public catalogs; scheduled import not operational | First intel PR | mitigated-in-design |
| R9 | XSS via component names | M | H | P1 | Web | Escape; no raw JSON | New sinks | First UI PR | mitigated-in-design |
| R10 | CSRF on session cookie | M | H | P1 | Authn | [ADR 0019](../adr/0019-local-password-sessions.md) SameSite + Origin + synchronizer token | Enforced on auth and SBOM upload routes | Implemented Session 6 and 8 | mitigated-in-design |
| R11 | Secret or SBOM logging | M | H | P1 | Telemetry | Canonical redaction tests | Sink bypass | First logger PR | mitigated-in-design |
| R12 | Audit UPDATE/DELETE or cascade evidence loss | L | H | P1 | Audit | Insert-only; FK policy; DB role | Superuser | First audit table | mitigated-in-design |
| R13 | Incorrect priority / false "fixed" / incomplete SBOM | M | H | P1 | Policy/findings | Factors, policy version, coverage heuristic, rescan ≠ task | Weights arbitrary; heuristic | First score + rescan PR | mitigated-in-design |
| R14 | SSRF via future URL fetch or mis-allowlist | L | H | P1 | Egress | No SBOM fetch; no advisory/note URL fetch; compiled allowlist; reject non-public destinations; CISA lookup-pin plus post-connect verification ([ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)) | Misconfig; pinning is not DNSSEC | First HTTP adapter | mitigated-in-design |
| R15 | Authn lockout and MFA unspecified | H | M | P1 | Authn | Rate limits in [ADR 0019](../adr/0019-local-password-sessions.md); [OD-17](../architecture/open-decisions.md) | No MFA | Before treating stuffing resistance as complete | open |
| R16 | Credential KEK management weak or lost | M | H | P1 | Secrets | [OD-4](../architecture/open-decisions.md) | Lost KEK = lost creds | Before tenant credentials | open |
| R17 | Redis exposed → queue injection | M | H | P1 | Jobs | Network isolation | Operator duty | First compose | mitigated-in-design |
| R18 | Backup exposure | M | H | P1 | Deploy | Operator encrypt; Restricted class | Accepted | Ongoing | accepted |
| R19 | Instance operator reads all DBs | H | H | P2 | Tenancy | Honest self-host; no app bypass | Disk access | n/a | accepted |
| R20 | Supply-chain / CI compromise | M | H | P2 | Process | Lockfile later; SECURITY.md | Residual | First dependencies | watch |
| R21 | OSV query or dump fetch blocks or discloses inventory | M | M | P2 | Intel | Session 9 uses bulk/snapshot import, not package-query APIs; bounded retry later; last accepted catalog remains | Delay; archive size unknown | First intel PR | mitigated-in-design |
| R22 | Org policy override mistakes ranking | M | M | P2 | Policy | Immutable versions; history | Operator error | First override PR | mitigated-in-design |
| R23 | Duplicate SHA-256 across assets | L | M | P2 | Ingestion | Duplicate only same org+asset | Extra storage | First upload | mitigated-in-design |
| R24 | Finding identity includes version via full PURL or delayed CVE | M | H | P1 | Findings | Versionless identity + OSV id; CVE is alias ([finding-lifecycle.md](../architecture/finding-lifecycle.md)) | Product still may want version-scoped findings later | First correlate PR | mitigated-in-design |
| R25 | Future webhook forgery | L | H | P2 | Integrations | No listeners; GitHub not MVP | When added | GitHub ADR | watch |
| R26 | Optional AI leakage | L | H | P2 | AI | Disabled; ADR 0017 | If enabled | Before any AI PR | mitigated-in-design |
| R27 | Teams unused → confused authz | L | L | P3 | Domain | Owners are not authz | Misuse | n/a | watch |
| R28 | Future CLI skips API authz | L | H | P3 | Clients | CLI deferred; must call API | If bypassed | CLI ADR | watch |
| R29 | DoS of public feeds (external) | L | L | P3 | Intel | Out of product scope | n/a | n/a | accepted |
| R30 | Compliance theater in UI copy | M | M | P2 | Product | Review checklist; non-goals | Copy drift | Every UI PR | mitigated-in-design |
| R31 | Numeric ingestion limits unvalidated | H | M | P1 | Ingestion | Labelled proposals with floors/ceilings in `@patchpilot/config`; perf tests still required | Too tight/loose; still unmeasured after Session 8 | Before production-minded release | open |
| R32 | Database-only audit not WORM | M | M | P1 | Audit | Document limitations; DB grants | Superuser | First audit table | mitigated-in-design |
| R33 | Coverage heuristic false inconclusive/resolved | M | M | P2 | Findings | 50% drop proposal; tune | Heuristic | First rescan PR | watch |
| R34 | Exclusive finding states clobber acceptance/mitigation/FP | M | H | P1 | Findings | Occupancy rules in [finding-lifecycle.md](../architecture/finding-lifecycle.md) | UI still must show both records | First finding state PR | mitigated-in-design |
| R35 | Derived graph keyed only by SBOM (reprocess / observations) | M | H | P1 | Ingestion | Key occurrences and observations by `sbomIngestionId` | Extra rows | First parser persist PR | mitigated-in-design |
| R36 | Older SBOM completing last becomes current | M | H | P1 | Findings | Current = max `receivedAt` among `completed` | Clock skew on upload time (server sets `receivedAt`) | First rescan PR | mitigated-in-design |
| R37 | Divergent RiskCalculation idempotency keys | M | M | P1 | Jobs | Single `inputFingerprint` in [reliability-model.md](../architecture/reliability-model.md) | Fingerprint bugs | First score PR | mitigated-in-design |
| R38 | Unauthenticated org signup on exposed instance | M | H | P1 | Authn | No public registration ([ADR 0019](../adr/0019-local-password-sessions.md)) | First-user HTTP still deferred | Before invite/bootstrap PR | mitigated-in-design |
| R39 | Orphan objects accumulate with no reconciliation job | H | M | P1 | Storage | `SBOM_ORPHAN_GRACE_SECONDS` policy floor defined; upload deletes temporary objects best-effort and never deletes promoted evidence | No job reads the grace period; orphans grow until an operator acts | Before an operator-hosted release | open |
| R40 | Retryable ingestion failure stalls with no redelivery | H | M | P1 | Jobs | State returns to `queued` consistently and idempotently; operator replay is safe | No BullMQ `attempts` on `sbom.ingest` and no BackgroundJob poller; detection is manual | Before an operator-hosted release | open |
| R41 | No BackgroundJob lease heartbeat | M | M | P2 | Jobs | SBOM ingest still never calls `renewLease`. KEV sync service renews the same job lease when invoked. Config still forbids SBOM parser and storage timeouts at or above the SBOM lease | An SBOM run exceeding the 15-minute lease can be claimed twice. KEV heartbeat is unused until a worker starts the service | Before raising the SBOM parser budget | open |
| R42 | Stored evidence altered after upload | L | H | P1 | Storage | Re-read verifies byte length and SHA-256 while streaming; mismatch quarantines rather than retries | Attacker with both bucket and database write | Implemented Session 8 | mitigated-in-design |
| R43 | Idempotency reservation expires during slow client upload | M | M | P2 | Ingestion | TTL must exceed 2× object-storage operation timeout; concurrent same-key requests get 409 while unexpired | Fingerprint excludes body; no reservation renewal; reclaim can orphan promoted bytes | Before operator-hosted release | open |
| R44 | Partial OSV/KEV import becomes current catalog | M | H | P1 | Intel | Guarded activation after complete source unit; no freshness advance on partial failure ([ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)) | Staging schema deferred | First intel persist PR | mitigated-in-design |
| R45 | Unmeasured or oversized intel import exhausts worker | H | H | P1 | Intel | KEV body measured 2026-08-31 (1,621,705 bytes, 1,687 entries) with typed 4 MiB / 4,096 defaults in `@patchpilot/config`. Batch 7B bounded collection and parser ceilings apply when the service is invoked. Worker concurrency is 2 so KEV work does not fully block SBOM ingest. OSV `all.zip` measured (~1.43 GiB / ~8.74 GiB / 890,787 entries) but runtime remains disabled; those values are not download authorization | KEV limits are one observation plus safety margins, not CISA maxima. OSV archive runtime still has no selected ZIP library or operator limits | Before first OSV import runtime PR | open |
| R46 | Session 9 import creates Findings or discloses tenant packages | M | H | P0 | Intel / Findings | Zero-Finding invariant; no inventory-driven queries ([ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)) | Later correlation must not silently reuse import jobs | First intel PR | mitigated-in-design |
| R47 | Unique `osvId` blocks KEV-only or provider-neutral identity | M | M | P1 | Intel | Canonical CVE identity tables exist and are frozen ([ADR 0023](../adr/0023-provider-neutral-cve-identity.md)); do not invent synthetic OSV ids | `osvId` still required; KEV-only CVEs still cannot be Vulnerability rows; adapters not implemented | Adapter batches | open |
| R48 | Intelligence snapshot orphan after DB commit failure | H | M | P1 | Storage | Same class as SBOM orphans; keys internal; no signed URLs | No intel reconcile job | Before operator-hosted intel | open |
| R49 | Malformed legacy `cve_id` omitted from identity backfill | M | M | P2 | Intel | Accept only exact `^CVE-[0-9]{4}-[0-9]{4,19}$`; leave malformed values unlinked and unrepaired | Those advisories have no `CveIdentity` until a later exact rewrite | After identity freeze | mitigated-in-design |
| R50 | Unicode or case-variant CVE strings colliding with canonical identity | L | H | P1 | Intel | POSIX CHECK, `VARCHAR(28)`, default collation, no CITEXT, no silent trim/upper | Application ports must still reject noncanonical input | Identity persistence adapters | mitigated-in-design |
| R51 | Immutable identity or link row cannot be corrected in place | M | M | P2 | Intel | Append-only triggers; no update/delete path; forward-fix migration later if needed | Wrong exact canonical insert is permanent without a later migration | Before adapter writes | mitigated-in-design |
| R52 | Future tenant Finding join omitting the trusted organization predicate | M | H | P0 | Tenancy | Identity tables have no `organization_id`; any later Finding join must apply authorized org first | Runtime join does not exist in Batch 3B | First Finding/KEV read path | mitigated-in-design |
| R53 | KEV membership treated as tenant exposure | M | H | P1 | Intel / Findings | No KEV foreign key; membership is later read-time equality only; zero-Finding remains | Derivation and Finding APIs are not implemented | First KEV membership read | mitigated-in-design |

## P0 meaning

P0 items must have tests and review on the first implementing PR for that area. Architecture alone does not close them.

## Open architecture decisions that drive risk

See [open-decisions.md](../architecture/open-decisions.md). Highest coupling: **OD-17** (R15), **OD-4** (R16), **OD-10** (R19), **OD-15** (R7), **OD-18** (proxy trust), **OD-19** (R47), **OD-8** (R45). OD-1, OD-2, and OD-3 are closed by [ADR 0019](../adr/0019-local-password-sessions.md). Session 8 completion semantics are closed by [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md). Session 9 import-only catalog access is closed by [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md). Canonical CVE identity is accepted by [ADR 0023](../adr/0023-provider-neutral-cve-identity.md); Batch 3B applied and froze the identity migration (R47, R49–R53).

## Related documents

- [Threat model](threat-model.md)
- [Unresolved architecture decisions](../architecture/open-decisions.md)
