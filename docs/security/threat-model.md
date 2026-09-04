# Threat model

This threat model covers PatchPilot v0.1 as a **self-hosted modular monolith** processing untrusted SBOMs and shared vulnerability catalogs. It is a design aid, not a certification, penetration-test report, or proof of exploitability.

In scope: the ten security-sensitive areas in [AGENTS.md](../../AGENTS.md). Out of scope: vulnerabilities in the user's scanned applications that PatchPilot merely reports; DoS against public OSV/KEV as a service PatchPilot does not operate.

Report product vulnerabilities privately per [SECURITY.md](../../SECURITY.md). Do not publish exploit payloads here.

## Session 8 status notes

[ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md) records graph-complete ingestion. Typed limits live in `@patchpilot/config`. Session 8 is now implemented end to end: HTTP upload, private object storage, outbox relay, worker-thread parser, and the ingestion processor.

- `completed` means verified evidence and persisted graph. It does **not** mean exhaustive inventory or remediation. `empty` / `no_dependencies` are not “no software” / “no dependencies.”
- Parser wall-clock budget is **worker-thread termination**. `Promise.race` around synchronous `JSON.parse` or Ajv is **not** a control and must not be substituted for one.
- Private object storage uses tenant-and-Asset-scoped keys. No public ACLs and no signed or presigned object URLs exist; a boundary test fails the build if presigner APIs appear in production code.
- Upload routes now exist and enforce session authentication, exact Origin match, a synchronizer CSRF token, `sbom:upload` on the active organization, a required `Idempotency-Key`, per-route size limits, and peer-IP plus per-organization rate limits with `trustProxy=false`.
- Every ingestion failure resolves to a closed-set safe failure code. Codes are what reach logs, audit payloads, and API responses; document content, Ajv output, and exception text do not.
- The ingestion processor verifies `objectKey` tenant scope against the reloaded **SBOM** row before storage GET. A worker thread that exits without posting a result is `parser_crash`, not a hung promise.
- `SBOM_IDEMPOTENCY_TTL_SECONDS` must exceed twice `OBJECT_STORAGE_OPERATION_TIMEOUT_MS` at process start. Slow client streams can still outlive a reservation; renewal during upload is not implemented.
- Still absent, and therefore still residual: web upload UI, retry and quarantine-release APIs, object-storage orphan reconciliation, BackgroundJob lease heartbeat, and idempotency reservation renewal during streaming upload.

## Session 9 status notes

[ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) records an import-only shared catalog. Session 9 is not complete. [ADR 0010](../adr/0010-osv-correlation.md) remains future correlation, not the import path.

- Session 9 recorded OSV GCS bulk export (`all.zip` completeness baseline) and the CISA KEV JSON snapshot. [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) does **not** approve `all.zip` for the first implementation. Tenant package-query APIs are rejected. OSV runtime remains disabled.
- Provider responses are untrusted. Raw bodies belong in private object storage. PostgreSQL stores metadata, hashes, normalized revisions, and current projections. No public or signed snapshot URLs.
- Partial normalization must never become the current catalog. Content SHA-256 is import idempotency. HTTP 304 is not product not-modified.
- Session 9 must not match components, write Findings or FindingObservations, enrich findings, score, remediate, enqueue `finding.recalculate`, or query tenant inventories.
- Parser isolation follows Session 8: parse outside transactions; `worker.terminate()` if termination is required; `Promise.race` is not a kill switch. ZIP remains deferred and unauthorized; no archive dependency is selected or authorized.
- Provider HTTP is allowlisted HTTPS (`node:https.request`) with redirects disabled, proxy environment ignored, and rejection of private, loopback, link-local, metadata-service, and other non-public destinations. Advisory reference URLs are never fetched.
- DNS lookup pinning plus post-connect verification is implemented for CISA KEV. It is not DNSSEC.
- The Batch 7B synchronization service exists. Batch 8B starts the worker scheduler, Outbox mapping, and BullMQ intelligence processor. Batch 9B adds authenticated sanitized provider-status GETs (`intelligence:read`; [ADR 0022](../adr/0022-intelligence-provider-status-authorization.md)). Still absent: web dashboard, manual sync/retry, detailed SyncRun APIs, matching, and any Finding workflow. OD-10 remains open. Status GETs do not call CISA and do not write AuditEvent rows.

## Session 10 status notes

[ADR 0023](../adr/0023-provider-neutral-cve-identity.md) records provider-neutral canonical CVE identity. Batch 3B applied and froze migration `20260902120000_canonical_cve_identity` (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Session 11 Batch 5C adds `20260904120000_osv_acquisition_persistence_foundation` (SHA-256 `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`). Session 11 Batch 5C-R adds `20260904180000_osv_parsed_revision_id_check_correction` (SHA-256 `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`) so parsed-revision inserts no longer fail on PostgreSQL POSIX `{0,511}`. The persistent development database has thirteen finished migrations.

- Canonical identity is global and append-only. It is not tenant-owned and has no `organization_id`.
- The advisory-to-CVE link is source-free. Provenance stays on `VulnerabilitySourceRecord` and KEV generations.
- Backfill copies only exact canonical `vulnerability.cve_id` values. Malformed legacy values remain unlinked and unrepaired. Tests must not print those values.
- Unicode lookalikes, lowercase, and whitespace variants do not match the POSIX CHECK. They cannot collide with a canonical identity string.
- KEV membership is read-time exact equality against the accepted active generation (Session 10 Batch 5B). Listing in KEV is active-catalog membership, not tenant exposure, and is not a Finding.
- Session 10 remains zero-Finding. The identity migration must not write Findings, FindingObservations, Evidence, RiskCalculations, or `finding.recalculate`.

## Session 11 status notes

[ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) selects OSV as the future affected-version authority and instance-owned catalog acquisition as the approved direction. Exact object/listing transport remains unreviewed. Implementation is not authorized until that review completes.

- Tenant package query APIs are rejected. Tenant PURLs, package names, and versions must not be sent to a provider.
- CISA KEV remains an independent exploitation signal. Tenant SBOMs remain inventory. OSV data alone does not prove tenant exposure and does not create a Finding.
- ZIP remains absent and unauthorized. `all.zip` is not the first-implementation assumption. No archive dependency is authorized.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. No OSV runtime, matching, fan-out, or Finding write exists. Session 11 remains zero-Finding.
- Session 11 Batch 4B defines an isolated advisory parser protocol (metadata-only envelopes, fail-closed failure taxonomy, untrusted worker-output validation). Batch 4B-P closes parser resource-policy v1 as PatchPilot security ceilings (not provider guarantees) and authorizes synthetic bounded reference-parser requests. Batch 4C implements an in-process reference parser for one bounded synthetic advisory (byte-count and SHA-256 verification, fatal UTF-8, secure JSON, pinned local schema, structural bounds, top-level id confirmation). Batch 4D adversarially reviews that parser with synthetic hostile inputs and hardens identity whitespace/control rejection, abort checks, and unexpected-exception mapping. Batch 4E closes the production isolation design (`worker_threads`, exact timeouts, schema load inside the isolate, one-request-at-a-time Ajv, pool size 1, sequential reuse, recycle on protocol failure). Batch 4F implements the isolated worker and parent host. Batch 4F-R verified that path under Node.js 24 with synthetic fixtures. `worker_threads` is not an OS sandbox. Duplicate JSON object keys are not detected (last-key-wins; not a source or identity bypass; must be resolved or explicitly accepted before OSV enablement). Provider-object body retrieval limits remain `unavailable` (OD-8). Pending-queue size remains unapproved, so runtime composition stays blocked. The worker does not retrieve provider bodies, persist catalogs, or enable OSV.
- Session 11 Batch 5B adds framework-independent OSV persistence **contracts** only (identities, completeness, reconciliation, quarantine, active-pointer CAS intent, repository ports). Activation contracts do not trigger matching.
- Session 11 Batch 5C adds Prisma models and frozen migration `20260904120000_osv_acquisition_persistence_foundation` (SHA-256 `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`). Batch 5C-R adds `20260904180000_osv_parsed_revision_id_check_correction` (thirteen migrations; SHA-256 `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`) replacing only the unsatisfiable parsed OSV ID CHECK. Body bytes remain outside PostgreSQL. No active OSV generation is seeded.
- Session 11 Batch 5D adds PostgreSQL adapters (`createOsvAcquisitionPersistence`) with immutable-conflict reload, generation and attachment graphs, transactional parser-attempt/revision writes, deterministic reconciliation, append-only quarantine and presence, and active-pointer compare-and-swap. Cross-scope previous generations fail closed. Parsed-revision persistence succeeds after Batch 5C-R. Object storage, provider retrieval, synchronization, matching, and Findings remain absent. OSV remains disabled. Session 11 remains zero-Finding.
- Session 11 Batch 5E adds an immutable S3-compatible adapter for OSV provider-body snapshots and parsed structural documents (`S3OsvAdvisoryObjectStorage`) plus staged-attachment orchestration. Provider keys are never storage paths. PostgreSQL and object storage are not one transaction. Write-once SHA-256 identities, read-back hashing, conflict detection, recovery without false attached state, and cleanup eligibility exist. Tests use synthetic local bytes only. No provider retrieval, synchronization, matching, Findings, or OSV enablement. There is no destructive cleanup service.

[ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md) records fail-closed package identity and evaluation architecture. No comparator or evaluator exists.

- There is no generic name matcher, lexical version comparator, or universal semver implementation.
- The implemented ecosystem set is empty. Unsupported ecosystems, GIT ranges, unknown versions, and malformed provider data must not become `not_affected`.
- The future evaluator is tenant-agnostic and must not fetch PURL, advisory, or repository URLs.
- Evaluation remains zero-Finding in Session 11 and Session 12.

## Assets to protect

| Asset | Class | Why it matters |
| --- | --- | --- |
| Original SBOM bytes | Restricted | Source graph, internal package names |
| Findings and exports | Confidential | Operational risk data |
| External credentials and session secrets | Restricted | Account and integration takeover |
| Audit trail | Confidential | Integrity of "who decided" |
| Shared intel snapshots | Internal/Restricted raw | Poisoned feeds distort **priority** |
| Policy definitions | Internal/Confidential | Silent score change |
| Object-storage keys | Restricted | Evidence theft |

## Actors

| Actor | Intent |
| --- | --- |
| Anonymous internet user | Attack exposed HTTP if the operator publishes it |
| Authenticated user in org A | IDOR into org B; raise own privileges |
| Malicious insider in org A | Exfiltrate SBOMs; alter audit if possible; accept risk fraudulently |
| Instance operator | Infrastructure privilege; must not gain a silent app-level cross-org bypass |
| Malicious SBOM author | Parser DoS, SSRF, XSS stored in component names, graph explosion |
| Compromised OSV/KEV path | Wrong correlation, false KEV |
| Compromised CI or dependency | Backdoor in PatchPilot itself |
| Queue attacker (if Redis exposed) | Replay, inject jobs |

## Trust boundaries

See [trust boundaries](../architecture/trust-boundaries.md). Primary HTTP boundary is `apps/api`. Workers trust PostgreSQL more than Redis payloads.

## STRIDE-style findings (v0.1)

Each subsection states the threat, impact, and the **designed mitigation**. Residual risk is in the [risk register](risk-register.md).

### IDOR

**Threat:** Caller supplies another organization's asset, SBOM, finding, export, or credential UUID.

**Impact:** Cross-tenant read or mutate.

**Mitigation:** Deny by default; repository methods require `organizationId` from membership; lookup-by-id is insufficient; tests required ([tenant isolation](../architecture/tenant-isolation.md)).

### Broken tenant isolation

**Threat:** Missing `WHERE organization_id`; global unique hash shared across orgs; job payload org trusted; object key is digest-only.

**Impact:** Systematic data leak.

**Mitigation:** Org-prefixed object keys; org-scoped uniqueness; reload aggregates in workers; ingestion verifies `objectKey` scope against the reloaded **SBOM** row before GET; promote rejects cross-scope keys; no cross-org operator API without ADR.

### Malicious SBOMs

**Threat:** Hostile JSON: unexpected types, huge strings, script-like names, `externalReferences` URLs, prototype keys.

**Impact:** XSS in UI, SSRF if fetched, parser crash, prototype pollution.

**Mitigation:** CycloneDX JSON 1.4–1.6 only; no URL fetch; schema, depth, node, and semantic limits from typed configuration; quarantine poison; treat names as untrusted text; no `eval`. Parser timeout uses worker-thread termination, not `Promise.race`.

### Oversized JSON

**Threat:** Multi-gigabyte body or missing Content-Length stream.

**Impact:** Memory exhaustion (DoS).

**Mitigation:** `SBOM_UPLOAD_MAX_BYTES` default 20 MiB counted while streaming; reject before parse. Ordinary `REQUEST_BODY_LIMIT_BYTES` is independent.

### Deeply nested JSON

**Threat:** Nesting that blows stack or schema walker.

**Impact:** Worker crash, restart loops.

**Mitigation:** Max depth 32 (configurable); wall-clock parse via worker-thread termination; worker exit without a message → `parser_crash`; poison → quarantine not infinite retry. `Promise.race` is not a parser kill switch.

### Dependency explosion

**Threat:** Tens of millions of edges or duplicated bom-refs.

**Impact:** DB fill, correlation hang.

**Mitigation:** Max 10,000 components and 50,000 edges; reject ingestion.

### Package-name confusion

**Threat:** Match `npm/foo` to `PyPI/foo`.

**Impact:** False findings or missed findings presented as fact.

**Mitigation:** Ecosystem required; no fuzzy name match ([OD-15](../architecture/open-decisions.md)).

### Ecosystem confusion

**Threat:** Guess ecosystem when SBOM omitted it.

**Impact:** Wrong OSV queries; false correlation.

**Mitigation:** Do not guess; skip correlation; may contribute to `inconclusive` on compare if identity cannot be formed.

### Version-range manipulation

**Threat:** Attacker-controlled SBOM versions to avoid or force OSV range hits; poisoned intel ranges.

**Impact:** False absence or false presence.

**Mitigation:** Record match method and source record id; version is observed from SBOM; intel ranges come from additive source records; UI separates facts from conclusions. Residual: garbage-in, garbage-out from the uploader's SBOM.

### Poisoned vulnerability feeds

**Threat:** Compromised OSV/KEV content, MITM, or a zip-bomb / hostile archive.

**Impact:** Incorrect future correlation and KEV enrichment; wrong **priority**; parser exhaustion. Session 9 must not turn a poisoned feed into Findings.

**Mitigation:** HTTPS, allowlists, payload hashes, additive versions, retain conflicts, guarded current-projection activation, archive extraction limits, KEV worker-thread termination, no body logging. Residual: public catalogs can be wrong. Finding integration is not implemented.

### Compromised provider credentials

**Threat:** Stolen **ExternalCredential** or instance cloud keys.

**Impact:** Feed or storage abuse; if GitHub were connected, repo access (GitHub is not MVP).

**Mitigation:** Encrypt at rest; decrypt in adapter; no client bundles; rotate/revoke states; OSV/KEV v0.1 typically unauthenticated public HTTP. Storage credentials are operator secrets.

### Webhook forgery

**Threat:** Forged inbound webhook mutates tenant data.

**Impact:** Confused deputy.

**Mitigation:** **No inbound webhooks in v0.1.** Future: signatures required, unsigned denied.

### Webhook replay

**Threat:** Replay a valid signed body.

**Impact:** Duplicate processing or stale commands.

**Mitigation:** Not applicable until webhooks exist; future: delivery id + timestamp window.

### SSRF

**Threat:** Fetch SBOM URLs, license URLs, advisory `references`, KEV notes, user-controlled intel endpoints, or link-local metadata.

**Impact:** Cloud credential theft, internal scan.

**Mitigation:** No SBOM URL fetch; no fetch of provider reference or note URLs; compiled provider allowlist; HTTPS only via `node:https.request`; redirects disabled; proxy environment ignored; reject private, loopback, link-local, metadata-service, and other non-public destinations; DNS lookup pinning plus post-connect verification (not DNSSEC); timeouts and size limits; no arbitrary caller URL. Residual: mis-allowlist; pinning is not DNSSEC.

### SQL injection

**Threat:** String-concatenated SQL on untrusted names.

**Impact:** Database compromise.

**Mitigation:** Prisma parameterized queries; no raw SQL with user strings; Zod at edges.

### XSS

**Threat:** Component name `"><script>` stored and rendered.

**Impact:** Session theft from org users.

**Mitigation:** Default framework escaping; never `dangerouslySetInnerHTML` for SBOM fields; CSP when web is scaffolded; don't dump raw JSON.

### CSRF

**Threat:** Cross-site POST using session cookie.

**Impact:** Upload, accept risk, export as the user.

**Mitigation:** `SameSite=Lax`, exact Origin allowlist, and a synchronizer CSRF token on authenticated mutations ([ADR 0019](../adr/0019-local-password-sessions.md)). Session 6 login/logout/select-organization routes and the Session 8 SBOM upload route implement this. Read routes are exempt from Origin and CSRF because they do not mutate.

### Credential leakage

**Threat:** Secrets in images, docs, client JS, error messages.

**Impact:** Takeover.

**Mitigation:** Config package only; no hardcoded secrets; error taxonomy without stack internals in production.

### Secret logging

**Threat:** Authorization header or SBOM body in Pino/OTel.

**Impact:** Restricted data in log stores.

**Mitigation:** Canonical redaction; tests; no full feed payloads.

### Audit alteration

**Threat:** UPDATE/DELETE audit rows or cascade.

**Impact:** Lost accountability.

**Mitigation:** Insert-only; DB privileges; no cascade; tests.

### Object-storage exposure

**Threat:** Public bucket, guessable keys, list-all.

**Impact:** SBOM theft.

**Mitigation:** Private bucket; `org/{organizationId}/.../sha256/{hash}`; no public URLs; no ACL on any request; no presigner dependency in production code (build-enforced); no application download route. Presigning later needs an ADR. Object keys never appear in API responses, audit payloads, or logs.

### Evidence tampering at rest

**Threat:** Stored SBOM bytes are modified or swapped in the bucket after upload, so the parsed graph no longer reflects the evidence the user submitted.

**Impact:** Inventory that silently disagrees with the recorded digest; forged component sets.

**Mitigation:** The processor re-reads the stored object and verifies byte length and SHA-256 against the **SBOM** row while streaming. A mismatch yields `hash_mismatch`, which quarantines rather than retries, so a corrupted object cannot be reprocessed until it happens to pass. Residual: an attacker with both bucket write and database write can update the recorded digest too.

### Orphan object accumulation

**Threat:** Objects that no **SBOM** row references accumulate after failed finalization.

**Impact:** Disk growth, and Restricted bytes retained with no product-level owner or lifecycle.

**Mitigation:** Bounded by upload rate limits and size limits. Not otherwise mitigated: no reconciliation job exists, so this is an accepted, documented residual until one is built ([retention and deletion](../architecture/retention-and-deletion.md)).

### Stalled ingestion after a retryable failure

**Threat:** A transient storage failure returns the ingestion and job to `queued`, and nothing redelivers the work.

**Impact:** Availability, not integrity: an ingestion silently never completes and a user believes processing is still in progress.

**Mitigation:** State is left consistent and idempotently resumable so an operator replay is safe. Detection depends on watching `queued` **BackgroundJob** rows, not on an automatic retry. Residual: no automatic retry and no lease heartbeat are implemented ([reliability model](../architecture/reliability-model.md)).

### Queue duplication

**Threat:** At-least-once double deliver.

**Impact:** Duplicate findings or audits.

**Mitigation:** Idempotent handlers, unique constraints including organization, replay tests.

### Race conditions

**Threat:** Concurrent ingest and intel refresh; concurrent acceptances.

**Impact:** Lost updates, duplicate findings.

**Mitigation:** Unique finding identity; append-only calculations; acceptance supersede rules; optional finding row version.

### Stale jobs

**Threat:** Worker crash leaves `running`; old job applies after archive.

**Impact:** Corruption or surprise mutation.

**Mitigation:** Visibility timeout; idempotency; reload state; dead-letter missing aggregates.

### Dependency compromise

**Threat:** Malicious npm package in PatchPilot's own tree.

**Impact:** Full instance compromise.

**Mitigation:** Lockfile, future dependency review in CI, minimize deps, no install during this architecture phase. Residual: supply chain.

### CI/CD compromise

**Threat:** Stolen GitHub credentials publish a backdoored image.

**Impact:** Operator runs attacker code.

**Mitigation:** Branch protection when available; no secrets in logs; [SECURITY.md](../../SECURITY.md). Residual: operator verifies images.

### Development adapters enabled in production

**Threat:** Fake auth or unrestricted HTTP selected.

**Impact:** Auth bypass, SSRF.

**Mitigation:** Config gating; tests that production config cannot construct those adapters.

### Backup exposure

**Threat:** Unencrypted dumps, world-readable snapshots.

**Impact:** All tenants on that instance.

**Mitigation:** Operator guidance; Restricted classification; no product-level public backup API.

### Insider threats

**Threat:** Org `owner` exports all SBOMs; instance operator reads Postgres.

**Impact:** Expected privilege, still harmful.

**Mitigation:** Role split; audit exports; no extra bypass; cannot prevent a motivated instance operator with disk access. Document honestly.

### Denial of service

**Threat:** Upload floods, expensive parse, intel refresh storms.

**Impact:** Availability.

**Mitigation:** Rate limits, size/depth/count limits, worker concurrency caps, circuit breaker on feeds.

### Incorrect risk prioritization

**Threat:** Policy bug, poisoned intel, missing factors.

**Impact:** Operators fix the wrong thing; false sense of safety.

**Mitigation:** Versioned policy, full factors, no AI scores, recalc without erasure, distinguish severity vs priority, honest UI copy.

### False remediation

**Threat:** Task `completed` shown as fixed; missing component treated as resolved when compare was `inconclusive`; older SBOM finishing last treated as current; versioned PURL used as finding identity.

**Impact:** Premature closure or duplicate findings that never resolve.

**Mitigation:** Finding `resolved` only with stored evidence (adequate `absent` or out-of-range) on the **current** ingestion (max `receivedAt` among `completed`); UI separates workflow from rescan; incomplete coverage → `inconclusive`; workflow states `risk_accepted`/`mitigated`/`false_positive` are not overwritten by inconclusive compare; identity is `organizationId` + `assetId` + `componentId` + `vulnerabilityId` ([ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md)).

### AI data leakage (if optional AI is introduced later)

**Threat:** SBOM or findings sent to a third-party model; hardcoded keys; model sets scores.

**Impact:** Evidence exfil; unauthorized scoring.

**Mitigation:** AI disabled by default; user-supplied keys only; never authoritative scores; never send originals without explicit future ADR ([ADR 0017](../adr/0017-optional-ai-user-credentials.md)). v0.1 sends nothing to AI providers.

### Privilege escalation

**Threat:** `member` approves risk acceptance or rotates credentials.

**Impact:** Unauthorized residual-risk decisions or credential theft.

**Mitigation:** Role matrix in [tenant-isolation.md](../architecture/tenant-isolation.md); API tests.

### Duplicate or malicious bom-ref

**Threat:** Repeated or colliding `bom-ref` values to confuse the graph.

**Impact:** Wrong dependency edges; parser crash.

**Mitigation:** Duplicate `bom-ref` → `rejected`.

### Concurrent ingestion

**Threat:** Two SBOMs for one asset processed at once.

**Impact:** Races on finding current state.

**Mitigation:** Unique constraints; latest **completed** ingestion wins for compare; append-only calculations.

### Job lease theft / clock skew

**Threat:** Two workers run the same job after lease expiry.

**Impact:** Duplicate side effects if not idempotent.

**Mitigation:** Idempotent handlers; org-scoped unique keys.

### Partial catalog activation

**Threat:** A failed mid-archive import becomes the visible current catalog or applies missing-record semantics.

**Impact:** Silent withdrawal of still-valid advisories, or mixed old/new current state.

**Mitigation:** Activate current projection only after a complete source unit succeeds; staging or generation-based activation; do not advance freshness on partial failure ([ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)). Residual: staging schema is deferred.

### Missing provider data

**Threat:** OSV/KEV gap presented as "not vulnerable."

**Impact:** False safety.

**Mitigation:** Freshness display; no match ≠ proof of safety; KEV absence is not proof of non-exploitation. Session 9 import does not create Findings, so a missing catalog row is not a tenant "all clear."

### Open instance registration

**Threat:** Unauthenticated callers create organizations and upload SBOMs on an internet-exposed instance.

**Impact:** Shared-catalog query abuse, disk fill, unintended multi-tenant hosting.

**Mitigation:** No public registration ([ADR 0019](../adr/0019-local-password-sessions.md)). Existing users only; development seed is production-rejected. Residual: MFA and durable lockout remain [OD-17](../architecture/open-decisions.md).

### Incorrect vulnerability matching

**Threat:** Wrong ecosystem or range evaluation.

**Impact:** False findings or misses.

**Mitigation:** Session 9 must not run matching. Future correlation: adapter-based versions; no fuzzy match; record method; tests with fixtures ([ADR 0010](../adr/0010-osv-correlation.md), [OD-15](../architecture/open-decisions.md)).

### Incomplete SBOM coverage

**Threat:** Smaller new SBOM treated as full remediation.

**Impact:** False `resolved`.

**Mitigation:** Coverage heuristic → `inconclusive`; see [finding-lifecycle.md](../architecture/finding-lifecycle.md). Session 8 `completed` does not imply exhaustive coverage and does not by itself support `resolved`.

## Control table (material threats)

For each row: preventive / detective / recovery / test / residual / owner. Text above remains the narrative if the table is not rendered.

| Threat | Asset | Attack path | Impact | Preventive | Detective | Recovery | Test | Residual | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| IDOR | Findings, SBOMs | UUID in URL without membership | Cross-tenant read | Org predicate, deny default | Authz deny metrics | Isolation incident runbook | Cross-tenant tests | Until code exists | `packages/domain`, API |
| Broken tenancy | All tenant data | Missing WHERE; digest-only keys | Systematic leak | Prefixed keys; promote scope; ingest key check; job reload | Anomalous org access | Isolate, rotate | Isolation + job tamper | Operator disk | Tenancy |
| Privilege escalation | Acceptance, creds | Role not checked | Bad accept / leak | Role matrix | Audit | Revoke session | API authz tests | Insider owner | Authz |
| Malicious SBOM | Parser, UI | Hostile JSON | XSS, crash, SSRF | No fetch, limits, escape | Quarantine metrics | Quarantine runbook | Parser tests | GIGO | `packages/sbom` |
| Oversized JSON | API memory | Huge body | DoS | 20 MiB proposal cap | 413 metrics | Rate limit | Size tests | Volumetric DoS | API |
| Deep JSON | Worker | Nesting | Crash loop | Depth 32 proposal | Quarantine | DLQ | Depth tests | Novel parser bugs | Parser |
| Component explosion | DB | Huge component list | Fill disk | 10k proposal | Reject metrics | Reject | Generated fixture | Tuned limits | Ingest |
| Edge explosion | DB | Huge deps | Hang | 50k proposal | Reject | Reject | Generated fixture | Tuned limits | Ingest |
| Bad bom-ref | Graph | Duplicates | Wrong graph | Reject duplicates | Reject | User re-upload | Fixture | — | Parser |
| Name/ecosystem confusion | Findings | Cross-eco match | False finding | No fuzzy match | Match method | Recalc | Near-miss fixtures | Uploader GIGO | Intel |
| Range manipulation | Findings | Crafted versions | False abs/pres | Record method; adapters | Factors | Recalc | Version fixtures | GIGO | Intel |
| Poisoned feeds | Catalog | MITM/compromise | Wrong priority | HTTPS, hashes, additive | Stale/degraded | Keep last good | Fixture conflicts | Public catalogs lie | Intel |
| Stolen provider/storage creds | Storage, feeds | Leak | Theft | Encrypt, config | Audit creds | Rotate | Redaction tests | Operator keys | Integrations |
| Webhook forgery/replay | Future | Fake callback | Confused deputy | No listeners in v0.1 | — | — | When added | Future | API |
| SSRF | Cloud metadata | URL fetch; advisory references | Cred theft | No SBOM/reference fetch; compiled allowlist; non-public destination rejection; CISA lookup-pin plus post-connect verify | Egress logs | Block | Adapter tests | Mis-allowlist; pinning is not DNSSEC | Integrations |
| Poisoned / hostile intel archive | Shared catalog | MITM, zip bomb, incomplete activation | Wrong future match; DoS | Hashes, additive revisions, extraction limits, guarded activation, zero Findings | Quarantine / failed run | Keep last accepted catalog | Fixture + replay | Public catalogs lie | Intel |
| Partial catalog activation | Current projection | Mid-import failure treated as complete | Silent withdrawal | Staging/generation activation after complete unit | Sync failed/quarantined audit | New run; do not rewrite terminal | Persistence tests later | Staging schema deferred | Intel |
| SQLi | DB | Concat SQL | Takeover | Prisma | — | Restore | — | Raw SQL mistakes | Database |
| XSS | Sessions | Component names | Session theft | Escape, CSP later | — | Rotate | UI tests | New sinks | Web |
| CSRF | Mutations | Cross-site POST | Unwanted upload | SameSite + Origin + token | — | Revoke | API tests | Auth and upload routes enforce all three | API |
| Evidence tampering at rest | SBOM bytes | Bucket write | Forged inventory | Re-read + digest verify | `hash_mismatch` quarantine | Quarantine runbook | Processor tests | Bucket + DB write together | Storage |
| Orphan objects | Storage | Failed finalization | Disk growth, stray Restricted bytes | Rate + size limits | Manual listing | Manual delete after grace | — | No reconcile job exists | Storage |
| Stalled retry | Availability | Transient failure, no redelivery | Ingestion never completes | Idempotent resumable state | `queued` BackgroundJob count | Operator replay | Replay tests | No auto-retry, no heartbeat | Worker |
| Cred/secret logging | Logs | Header in Pino | Restricted leak | Redaction | Log review | Rotate | Redaction tests | Sink bypass | Logger |
| Audit alteration | Accountability | UPDATE audit | Lost history | Insert-only | Integrity runbook | Restore | Update-fail test | Superuser | Audit |
| Public bucket | SBOMs | ACL | Theft | Private + org keys | Cloud alerts | Make private | Adapter tests | Operator ACL | Storage |
| Queue duplication | Findings | At-least-once | Dup rows | Idempotency | Unique violations | No-op | Replay tests | — | Worker |
| Concurrent ingest | Finding state | Two SBOMs | Race | Constraints; completed wins | — | Recalc | Concurrency test | Rare races | Worker |
| Stale jobs / lease | Tenant data | Crash + double run | Dup/corrupt | Lease + idempotency | Stale metric | Replay | Lease tests | Clock skew | Worker |
| Dependency/CI compromise | Instance | Malicious npm/CI | RCE | Lockfile later | — | Rebuild | — | Supply chain | Process |
| Dev adapters in prod | Authn | Misconfig | Bypass | Config gate | Boot fail | Disable | Production-config test | Human error | Config |
| Backup exposure | All | Open dump | Mass leak | Operator encrypt | — | Rotate | — | Accepted operator | Deploy |
| Insider | Tenant data | Privileged user | Expected | Audit, roles | Audit | — | — | Cannot prevent | Product |
| DoS | Availability | Flood/parse | Outage | Limits, rates | Lag alerts | Shed load | Limit tests | Volumetric | API/worker |
| Missing intel | Priority | Gap | False safety | Freshness UI | Stale alert | Retry sync | Fixture | Feeds incomplete | Intel |
| Wrong matching | Findings | Adapter bug | False pos/neg | Adapters, tests | — | Recalc | Fixtures | Residual | Intel |
| Wrong priority | Queue | Policy bug | Wrong work | Versioned policy | Factor UI | New version | Golden tests | Weights arbitrary | Policy |
| False remediation | Finding state | Task complete; stale completion order | Premature close | Evidence rules; current=`receivedAt` | — | Reopen on present | State + race tests | Incomplete SBOMs | Findings |
| Incomplete coverage | Finding state | Sparse SBOM | False resolved | Coverage heuristic | Inconclusive | Re-upload | Coverage test | Heuristic | Findings |
| Open registration | Instance | Unauthenticated org create | Abuse | No public registration (ADR 0019) | Auth metrics | Disable signup | Authn tests | OD-17 lockout | Authn |
| AI leakage (later) | Restricted | Model API | Exfil | Disabled; ADR 0017 | — | Disable | — | If enabled later | Future |

## Related documents

- [Security controls](security-controls.md)
- [Risk register](risk-register.md)
- [SBOM ingestion](../architecture/sbom-ingestion.md)
