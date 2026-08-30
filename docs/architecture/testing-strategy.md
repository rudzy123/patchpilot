# Testing strategy

Tests are part of the definition of done for significant features, not a follow-up wish. Unit and integration tests use **Vitest**. Browser end-to-end tests use **Playwright**. Rules: [testing.mdc](../../.cursor/rules/testing.mdc).

This strategy is for v0.1 architecture. Session 4 wires GitHub Actions for unit tests, integration tests, and static analysis. Playwright browser journeys are still not implemented, and there is no GitHub-hosted E2E workflow until real Playwright tests exist ([CI-DEFER-1](../development/ci.md#deferred-ci-work)). Authors run the equivalent local commands and report actual results when hosted jobs have not finished.

## Layers

| Layer | What to test | Must not |
| --- | --- | --- |
| Domain / policy-engine | Invariants, factor math, finding identity, state transitions | Boot Fastify, Next.js, Redis, MinIO |
| SBOM parser | Allowlist, limits, fixtures, prototype-key rejection | Live network; customer SBOMs |
| Use cases | Authz denials, org scoping, idempotency | Import Prisma in the test subject (inject fakes) |
| API | Zod validation, error taxonomy, CSRF/session, rate-limit headers | Domain rules duplicated in the handler |
| Persistence | Constraints, org predicates, no cascade-delete of evidence | Share dirty data between tests |
| Worker | Replay twice = one effect; org mismatch dead-letters | Trust payload org |
| Playwright | MVP journey happy path + empty/error/forbidden | Substitute for unit tests of scoring or tenancy |

## Test types (v0.1 plan)

| Type | Role |
| --- | --- |
| Unit | Domain, policy-engine, redaction, matching adapters with fixtures |
| Domain state-machine | Finding, ingestion, task, acceptance, job, integration, credential |
| Property-based | Policy determinism; idempotent replay; org predicate always present |
| Repository integration | PostgreSQL constraints, org unique keys, no evidence cascade-delete, Session 5 clean/upgrade migrations, append-only audit, outbox checks, seed isolation |
| Redis/worker | Lease expiry, retry, DLQ, replay |
| Object-storage adapter | Org-prefixed keys; private ACL assumptions |
| Contract | OpenAPI vs handler Zod |
| Provider-adapter fixtures | OSV/KEV JSON fixtures; **no live OSV/KEV in normal CI** |
| API authorization | CSRF, session, role matrix |
| Cross-tenant security | Required |
| Playwright | MVP journey |
| Performance | Limit tests; not a pass/fail gate until baselines exist |
| Parser fuzzing / malicious-input | Depth, prototype keys, huge strings — no exploit write-ups |
| Resilience | Feed 5xx, Redis down, storage 503 |
| Backup restoration | Operator procedure test when compose exists |
| Migration | Apply from empty |
| Architecture-boundary | Domain must not import Prisma/Fastify |
| Log-redaction | Token-like strings |

## Determinism

- No arbitrary sleeps. Wait on conditions, events, or fake timers.
- Freeze time to UTC for expiry, KEV dates, and `retrievedAt`.
- Prefer fixtures over live OSV/KEV. Mark true integration tests explicitly.
- Sample SBOMs minimized, no secrets, no proprietary documents.

## Security-sensitive tests (required)

Even if a glob did not attach:

1. **Tenant isolation:** org A cannot read org B assets, SBOMs, findings, exports, credentials ([tenant isolation](tenant-isolation.md)).
2. **ID lookup without org** fails at repository port.
3. **Job replay** idempotency.
4. **Job org mismatch** does not mutate.
5. **Upload rejects** wrong content-type, oversized body, disallowed specVersion (no exploit payload).
6. **Intelligence** additive write; conflict retains both; withdrawn does not delete findings.
7. **Policy** same inputs → same priority; recalc does not erase old **RiskCalculation**.
8. **Audit** insert-only (attempted update fails).
9. **Redaction** unit tests on logger (token-like strings).
10. **Development adapters** cannot be constructed when `deploymentEnvironment` is `production` or `allowDevelopmentAdapters` is false.
11. **KEV absence** does not auto-close findings or present "not exploited."
12. **Coverage:** a thinner SBOM does not yield `absent`/`resolved` (heuristic fixtures).
13. **Out-of-range:** mixed in-range and out-of-range occurrences of the same **versionless** identity do not `resolved`.
14. **Worker I/O:** tests or architecture-boundary checks that feed/storage adapters are not invoked inside a mocked DB transaction.
15. **Export isolation:** org A cannot download org B export snapshots.
16. **Policy replay:** stored factors + `policyDefinitionSha256` reproduce the same priority.
17. **Versionless identity:** upgrading `foo@1.0.0` → `foo@2.0.0` updates observation, does not create a second finding for the same OSV id; a versioned PURL must not be used as the finding key.
18. **Current ingestion race:** older SBOM completing after a newer `completed` upload does not change finding state or `lastSuccessfulSbomIngestionId`.
19. **Workflow occupancy:** inconclusive observation does not move `risk_accepted` / `mitigated` / `false_positive` to `inconclusive`; task completion does not move those states to `verification_pending`.
20. **Ingestion complete:** persist_graph alone does not mark `completed`.
21. **CVE alias:** adding a CVE to an existing OSV vulnerability does not mint a duplicate finding.

### Session 8 Batch 9 parser tests (not this batch)

Persistence does not add self-edge warning behavior. The adapter continues to reject a normalized graph that violates its DTO invariants, including a remaining self-edge. Batch 9 parser tests must prove:

1. The parser receives a self-edge.
2. The parser omits it from normalized edges.
3. The parser increments the `self_dependency_skipped` warning count.
4. Persistence receives a graph with no self-edge.

Do not commit working exploit payloads.

## Fixtures

| Fixture | Use |
| --- | --- |
| Minimal CycloneDX 1.5 JSON with one npm component | Happy parse |
| Same hash uploaded twice | Duplicate/idempotency |
| Nested JSON at depth 33 | Depth reject |
| Component count over 10,000 (generated in test, not a 10k file in git if avoidable—generate) | Limit |
| OSV hit / miss / wrong ecosystem / withdrawn | Matcher |
| KEV snapshot with and without CVE | Enrichment change; absence must not auto-resolve |
| Two versions of one package, one still in range | Must not `resolved` |
| Older SBOM completes after newer | Must not become current |
| Two orgs | Isolation |

## Coverage expectations for the MVP journey

Playwright (when web exists): create org → asset → upload → see finding with policy version and factors → assign task → record acceptance → upload newer SBOM → see observation result → export. Also forbidden org id and empty inventory.

## Related documents

- [Definition of done](../development/definition-of-done.md)
- [Review checklist](../development/review-checklist.md)
- [Secure development plan](../security/secure-development-plan.md)
