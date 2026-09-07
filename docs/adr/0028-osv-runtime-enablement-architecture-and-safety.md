# ADR 0028: OSV Runtime Enablement Architecture and Safety Controls

- Status: Accepted
- Date: 2026-09-06
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted on this feature branch after Runtime Enablement Phase R1-R independent architecture review.
This ADR records the architecture required to move the committed disabled OSV acquisition foundation
toward controlled production operation. It does **not** implement a listing executor, scheduler,
durable OSV job, retry engine, cleanup executor, kill-switch variable, activation command,
parser-host change, retrieval-policy change, storage-policy change, source-license change,
Prisma model, migration, dependency, API, permission, matching, or Finding path.

Accepting this ADR means:

- the runtime architecture is approved for the staged roadmap below
- **R2 may implement exactly one** production GCS listing-page HTTPS adapter (see §1 and
  [Exact R2 authorization boundary](#exact-r2-authorization-boundary))
- later batches R3–R7 remain gated individually and are **not** authorized by this acceptance alone
- production OSV runtime remains disabled
- no provider contact is authorized by ADR acceptance alone
- no canary is authorized by ADR acceptance alone
- no catalog activation is authorized by ADR acceptance alone
- matching is not authorized
- Finding writes are not authorized

`INTELLIGENCE_OSV_ENABLED=true` remains rejected until a later, separately reviewed enablement
decision. This ADR must not be read as implying that OSV will be enabled.

This ADR does **not** supersede [ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md),
[ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md),
[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md), or
[ADR 0027](0027-osv-acquisition-persistence-and-catalog-activation.md). It does not accept ADR 0027.
It builds on the Session 11 acquisition foundation and on ADR 0027's persistence **shape** without
treating that Proposed ADR as accepted, as runtime authorization, or as an R2 prerequisite.
See [ADR 0027 relationship](#adr-0027-relationship).

Architecture identifier: `osv_runtime_enablement_architecture_v1`.

## What this ADR is and is not

| Kind | Meaning in this ADR |
| --- | --- |
| Architecture approval | Binding runtime design for later implementation batches R2–R7 |
| R2 listing-adapter authorization | **Granted only for** one listing-page HTTPS adapter per [Exact R2 authorization boundary](#exact-r2-authorization-boundary). No provider contact in production composition. Synthetic/local tests only |
| Broader implementation authorization | **Not granted.** R3–R5 remain separately gated |
| Canary authorization | **Not granted.** R6 requires kill switch, runbooks, legal revalidation, and explicit operator authorization |
| Catalog-activation authorization | **Not granted.** R7 is a separate gate after a passed canary |
| OSV runtime enablement | **Not granted.** `INTELLIGENCE_OSV_ENABLED=true` remains rejected |
| Matching authorization | **Not granted.** Phases M1–M3 remain later work |
| Finding-write authorization | **Not granted.** Phases F1–F2 remain later work and still require [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) |

No production OSV runtime exists after this ADR. Acceptance is not enablement.

## Context

Session 11 closed the OSV acquisition foundation as implemented and synthetically verified.
Production OSV remains disabled. The committed foundation already contains:

- six-prefix inventory scope `osv_gcs_six_prefix_public_export_v1`
- source-family classification and verified source-license provenance
- compiled GCS listing request description and bounded listing-page parser
- generation-bound retrieval policy `osv_generation_bound_retrieval_policy_v1` (1,048,576 bytes, one HTTP attempt)
- isolated parser worker with pool size 1 and occupancy 1
- PostgreSQL acquisition persistence and immutable object storage
- disabled acquisition orchestration `osv_disabled_acquisition_orchestration_policy_v1`
- atomic active-pointer adapter that disabled orchestration never invokes

The following remain unselected in committed code and would be unsafe to invent during an
implementation batch: production listing execution ownership, pagination and token-cycle limits,
scheduler and job ownership, run leases, retry ownership, parser-host pending capacity, canary
scope, activation authorization, rollback, kill switch, cleanup, observability, and duplicate
JSON-key disposition.

Without those dispositions, a later batch could contact the provider unbounded, persist page
tokens, reuse KEV jobs as silent OSV carriers, activate a candidate automatically, or leak
tokens and bodies through telemetry.

## Decision

Preserve every committed Session 11 policy named in [Preserved committed policies](#preserved-committed-policies).
R1 does not silently alter retrieval, disabled orchestration, storage layout, parser schema pins,
or source-license decisions.

### 1. Production GCS listing execution architecture

Define exactly one future production listing executor.

| Bound | Disposition |
| --- | --- |
| Request and parser contracts | Remain in `@patchpilot/vulnerability-intelligence` (`createOsvGcsListingRequest`, `parseOsvGcsListingPage`, committed port operation `OsvTransportPort.listPage`) |
| HTTPS implementation | `@patchpilot/integrations`, future path `packages/integrations/src/osv-gcs-listing-https-adapter.ts`, factory `createOsvGcsListingHttpsAdapter` |
| Orchestration | Invokes listing only through `OsvTransportPort.listPage` |
| Applications | Must not construct listing URLs, compile query strings, or call `storage.googleapis.com` |
| Database and storage packages | Must not execute provider listing |

The executor, when later implemented in R2, must:

- use the compiled Batch 3C request description (`osv_gcs_json_objects_list_v1`)
- perform **exactly one** HTTPS listing request per adapter invocation
- implement **no** pagination loop, token-cycle store, retry, scheduler, durable job, or runtime composition
- contact only host `storage.googleapis.com` on HTTPS port 443
- use method `GET` and path `/storage/v1/b/osv-vulnerabilities/o`
- use unauthenticated access (`authentication: none`); no caller credentials, no environment endpoint override
- reject redirects (redirect policy `error`)
- use identity content encoding (`Accept-Encoding: identity`)
- accept only `application/json`
- enforce listing response-byte ceiling `1,048,576`
- hand off received bytes to fatal UTF-8 decode and the bounded Batch 3C listing-page parser
- return the bounded Batch 3C listing-page result
- return no raw response body
- expose no raw page token through errors, logs, metrics, traces, or public types
- implement no internal retry
- require no Prisma, object storage, parser worker, scheduler, durable job, tenant context, or environment endpoint override

User-Agent remains owned by the HTTPS adapter, matching the CISA KEV adapter pattern. The executor
is not wired into API, worker, CLI, health, seed, or migration startup by R2. Tests use synthetic
local HTTP seams only and must not contact `storage.googleapis.com` or `osv.dev`.

See [Exact R2 authorization boundary](#exact-r2-authorization-boundary).

### 2. Listing pagination limits

Identifier: `osv_listing_pagination_policy_v1`.

These values are PatchPilot **hard safety ceilings**, not provider guarantees and not catalog
completeness expectations. Hitting a ceiling marks the prefix and run **incomplete**, prevents
retrieval and candidate readiness for that run, produces no internal retry, preserves bounded
evidence, and **never** silently truncates while claiming completeness.

**Per-pass versus per-run (exact arithmetic):**

| Term | Meaning |
| --- | --- |
| Pages / observations / listing bytes **per prefix** | Ceiling for **one prefix pass** (pass A or pass B alone) |
| Pages / observations / listing bytes **per run** | Ceiling across **all authorized prefixes and both A and B passes** for one synchronization attempt |
| Observations | Raw pass-observation counts (listed items encountered), **not** unique provider-object cardinality after convergence |
| Failed or repeated pages | Count against the same ceilings, including pages read before token-cycle detection terminates the pass |

Canary identity (one selected prefix, one A/B pair):

- 8 pages per prefix **per pass** × 2 passes = **16 pages per run**
- 2000 observations per prefix **per pass** × 2 = **4000 observations per run**
- 8,388,608 listing bytes per prefix **per pass** × 2 = **16,777,216 listing bytes per run**

Production fail-closed identity (six prefixes, one A/B pair; **not** six-prefix execution
authorization):

- 500 pages per prefix **per pass** × 6 prefixes × 2 passes = **6000 pages per run**
- 500,000 observations per prefix **per pass** × 6 × 2 = **6,000,000 raw pass-observations per run**
- 524,288,000 listing bytes per prefix **per pass** × 6 × 2 = **6,291,456,000 listing bytes per run**

Split policies because a safely justified six-prefix observation total cannot be selected without
provider measurement.

**Committed page inputs (unchanged):**

| Limit | Value | Origin |
| --- | --- | --- |
| Maximum observations per page | 1000 | Batch 3C `OSV_GCS_JSON_OBJECTS_LIST_MAX_RESULTS` |
| Maximum response bytes per page | 1048576 | Batch 3C `OSV_GCS_LISTING_PAGE_MAX_BYTES` |

**Strict canary limits** (`osv_disabled_first_provider_canary_policy_v1`; first live contact only):

| Limit | Value | Scope |
| --- | --- | --- |
| Maximum pages per prefix | 8 | Per pass |
| Maximum pages per run | 16 | One prefix × two passes |
| Maximum listing bytes per prefix | 8388608 | Per pass |
| Maximum listing bytes per run | 16777216 | One prefix × two passes |
| Maximum object observations per prefix | 2000 | Per pass (raw) |
| Maximum object observations per run | 4000 | One prefix × two passes (raw) |
| Maximum token bytes | 8192 | UTF-8 encoding of the JSON string value |
| Maximum body retrievals | 16 | Per canary run |
| Maximum aggregate body bytes | 16777216 | Per canary run; each object ≤ 1048576 |
| Maximum duration | 1800 seconds | Wall-clock from job start |

**Production fail-closed ceilings** (algorithm bounds; **not** six-prefix execution authorization):

The proposed architecture values of 10,000 pages per prefix and 60,000,000 observations per run are
**rejected** for v1. They imply unbounded run duration, unbounded PostgreSQL inventory growth, and
a completeness claim the repository cannot currently prove.

| Limit | Value | Scope / rationale |
| --- | --- | --- |
| Maximum pages per prefix | 500 | Per pass. Initial unmeasured hard safety ceiling; incomplete if exceeded |
| Maximum pages per run | 6000 | 500 × 6 prefixes × 2 passes. Fail-closed, not a catalog-size promise |
| Maximum listing bytes per prefix | 524288000 | Per pass: 500 × 1,048,576 received; pages are not retained as raw bodies |
| Maximum listing bytes per run | 6291456000 | 6,000 × 1,048,576 received streaming |
| Maximum object observations per prefix | 500000 | Per pass: 500 × 1,000 raw. Incomplete if exceeded |
| Maximum object observations per run | 6000000 | Two-pass six-prefix raw pass-observation ceiling. Incomplete if exceeded |
| Maximum token bytes | 8192 | GCS tokens are opaque; 8 KiB is a conservative UTF-8 ceiling on the JSON string value |

Raising any production ceiling requires a new pagination-policy identifier, recorded measurement,
and review. R1 does not authorize six-prefix production listing. First live listing is the one-prefix
canary. Expanding to remaining approved prefixes is a later authorization after canary review.
R2 does not implement pagination.

**Page-token character policy:** nonempty UTF-8 JSON string value; untrimmed and unnormalized
(Batch 3B opaque-token behavior preserved); UTF-8 byte length of that string value 1 through 8192;
reject NUL, C0 controls (U+0001–U+001F), DEL, and C1 controls. Do not silently trim. Reject rather
than coerce. This ADR adds only the safety byte bound and control-character rejection; it does not
normalize valid token bytes. The 8192 bound is not yet enforced in committed Batch 3B token
construction and becomes an R3 orchestration/admission check.

**Empty-page behavior:** an empty page with a continuation token is non-terminal and counts against
the page ceiling. Continue. Two empty pages do not special-case terminate.

**Terminal-page behavior:** absence of `nextPageToken` is the only terminal signal (Batch 3C
preserved). Mark the prefix pass complete only after a terminal page within limits.

**Cancellation behavior:** `AbortSignal` cancellation ends the current listing request as
non-retryable `cancelled`, marks the prefix pass incomplete, persists the failure reason, and
discards the in-memory token. Do not persist the token. Do not continue the prefix.

### 3. Page-token confidentiality and cycle protection

Raw page tokens:

- remain in memory only during one prefix pass
- are never in a durable job payload
- are never in PostgreSQL
- are never in object storage
- are never in public errors
- are never in operational logs, metrics, or traces
- are never exposed in an API
- are scoped to one provider prefix and one pass
- cannot be reused across runs
- cannot be reused across prefixes or across pass A and pass B
- are sent to the provider exactly as received (no reconstruct-from-digest, no normalize, no trim)
- may yield a SHA-256 digest only for local repetition detection
- digest is never sent to the provider as `pageToken`
- digest is never persisted

**Token-repetition and cycle detection:** retain bounded SHA-256 token digests **in memory only**
for the active prefix pass. Maximum digest set size equals the maximum pages for that policy
(canary 8, production 500). Include the initial continuation lineage correctly. Reject an
immediately repeated token digest. Reject any prior token digest seen within that pass. Treat any
digest collision or repetition as a conservative cycle (fail closed; no raw-token comparison is
required after digest construction). Terminate the prefix as incomplete with failure kind
`listing_token_cycle`. Quarantine the candidate. Never continue into an infinite cycle. Clear the
digest set when the pass ends. Do not reuse the set across prefix or pass boundaries. Do not log
the digest unless an explicitly approved cycle-detection event requires it.

Crash resume does not require persisting digests because the prefix pass restarts from page one.
Do not persist the raw token. Do not persist token digests in v1.

### 4. Two-pass inventory convergence

Production inventory convergence, when later implemented in R3:

1. Complete pass A over every authorized prefix for that run.
2. Complete pass B over every authorized prefix for that run.
3. Compare deterministic immutable observation sets.
4. Require exact convergence.
5. Reject when the inventory changes between passes.
6. Never treat a partial pass as complete.
7. Never retrieve bodies before the required inventory gate permits it.

**Comparison identity (order-independent):** each complete pass produces a deterministic immutable
observation set. Compare sets by validated provider object key + exact provider generation +
declared size + required metadata fields from the committed inventory contracts. Do **not** use
ETag alone, updated timestamp alone, object-order position, page boundaries, or page tokens.
Identical keys with contradictory metadata fail closed before convergence. Pass A and pass B must
agree exactly. One A/B pair per synchronization attempt. Mismatch yields `inventory_not_converged`,
no same-run restart, and no body retrieval.

Selected v1:

| Dimension | Disposition |
| --- | --- |
| Maximum convergence attempts | 1 A/B pair per synchronization attempt |
| Internal convergence restart | Prohibited |
| Mismatch result | Retryable incomplete inventory (`inventory_not_converged`) |
| Next attempt | A future explicit synchronization attempt; new run identity |
| Canary | One A/B pair over the single canary prefix |
| Partial pass | Incomplete; not a completeness input |

This avoids a convergence loop inside one job.

### 5. Inventory progress and resume

Persist, as metadata only:

- run identity
- prefix identity
- pass number (A or B)
- page number
- page count
- object count
- response-byte count
- terminal evidence (complete or incomplete)
- failure reason (bounded catalog code)
- convergence result

Do not persist raw page tokens, provider bodies, parsed documents, or canonical URLs. Do not persist
raw page content.

After a process crash during a prefix pass:

- durable job redelivery or a new durable attempt may resume the synchronization attempt under the
  R4 retry and lease policy
- preserve the previous incomplete pass as immutable append-only evidence
- start a **new** pass-attempt identity for that prefix/pass-number; restart from page one
- do not attempt to reconstruct a token
- do not append new pages onto a stale token chain
- keep the run bounded by the same page, byte, observation, duration, and job-retry ceilings
- identical replay of an already-complete prefix pass is `already_applied`
- a conflicting replacement of immutable complete-pass evidence is `immutable_conflict`
- cancellation preserves incomplete evidence

Replacement of an **incomplete** prefix pass is allowed only by starting a new pass-attempt row for
the same run/prefix/pass-number after crash or cancellation. Historical incomplete rows remain.
Restart cannot exceed job retry and run ceilings.

### 6. Runtime job ownership and payload

Owner: global instance-owned background worker. No tenant owner.

| Item | Disposition |
| --- | --- |
| Job type | `intelligence.osv.sync` (reserved; not added in R1) |
| Outbox event type | `intelligence.osv.sync.requested.v1` (**name reserved**; necessity decided in R4A) |
| Queue | existing `patchpilot` queue when jobs are added |
| KEV job reuse | Prohibited. `intelligence.sync` remains KEV-only |
| Orchestration independence | Orchestration must not import BullMQ. The worker constructs runtime dependencies |
| Provider bodies and tokens | Never enter the queue |

**Outbox necessity (R4A decision):** KEV uses an Outbox event so scheduler/manual requests become
durable and relayed transactionally. R4A must choose one of:

1. emit `intelligence.osv.sync.requested.v1` from scheduler/operator commands into the existing
   Outbox relay (internal event; duplicate delivery is idempotent at job creation), or
2. insert the durable job request transactionally without a separate Outbox type if the existing
   architecture already provides equivalent durability for that command path.

Do not add an Outbox event merely for symmetry. If chosen, the event is internal, carries only the
bounded job-request fields below, cannot trigger tenant behavior, and cannot activate catalogs.
Who emits it, why it exists, and duplicate-delivery handling must be recorded in R4A before any
production composition.

Job payload may contain only:

- job schema version
- requested synchronization scope (`osv_gcs_six_prefix_public_export_v1` or canary subset)
- policy identifiers (architecture, pagination, retrieval, parser, registry, schema, retry, canary)
- explicit operator or scheduler reason (`scheduler`, `operator_canary`, `operator_production`)
- correlation identifier (UUID)
- requested-at timestamp (UTC)
- optional canary policy identifier

Job payload must not contain: provider body, parsed document, page token, raw provider key
inventory, tenant ID, organization ID, package inventory, storage locator, active-pointer
instruction, matching option, Finding option, credentials, or arbitrary URL.

The worker pins the exact version set at job start. The job type is not added in R1.

### 7. Scheduler architecture

| Dimension | Disposition |
| --- | --- |
| Scheduling component | `apps/worker`, a module distinct from the KEV scheduler |
| Default cadence | Disabled. No OSV interval is registered until a later reviewed instance-level policy |
| Suggested later candidate | 86400 seconds UTC, matching KEV's conservative daily default; **not authorized and not encoded in config by R1** |
| Tenant configuration | Prohibited |
| Startup behavior | No immediate run on startup |
| Missed-run behavior | Skip. No catch-up storm |
| Overlapping-run behavior | At most one queued or running job per catalog scope |
| Deployment concurrency | Mutual exclusion is the database lease, not process count |
| Manual trigger | Separate reasons: `operator_canary` and `operator_production`. Manual does not bypass kill switch, enablement, or lease |
| Kill-switch interaction | Halted acquisition rejects new schedule emits and new job starts |
| Clock | UTC |
| Stale-job rejection | Reject if `requestedAt` (or enqueue-equivalent request timestamp) is older than the run-age limit |
| Run-age limit | Canary 1800 seconds. Production ceiling 14400 seconds. Measured from request/enqueue time, **not** from lease TTL |
| Run deadline | Separate from lease duration. A long run keeps the lease alive through heartbeats; a 15-minute lease must not silently terminate a four-hour production run |
| Graceful shutdown | Cancel in-flight listing and retrieval via `AbortSignal`. Do not abort a database transaction mid-commit |
| Observability | Bounded scheduler events only (see §12) |

Cadence remains a runtime configuration selected through a reviewed instance-level policy. R1 does
not add scheduler configuration variables.

### 8. Run lease and mutual exclusion

Transaction-scoped `pg_advisory_xact_lock`, as used by catalog activation, **cannot** cover a
long network synchronization run. Do not hold a PostgreSQL transaction open across listing or
retrieval.

Selected v1 lease (fencing protocol):

| Dimension | Disposition |
| --- | --- |
| Mechanism | Durable PostgreSQL lease row with compare-and-swap revision |
| Identity / scope key | One row per catalog scope (`osv_gcs_six_prefix_public_export_v1`). Canary uses the same scope plus canary policy discriminator so a canary cannot be confused with a six-prefix run |
| Holder token | UUID v4; no tenant identifier |
| Lease revision | Monotonic integer; CAS on every acquire, heartbeat, release, and reclaim |
| Timestamps | `acquiredAt`, `heartbeatAt`, `expiresAt` owned by **database time** (`clock_timestamp()` / equivalent), not the application wall clock |
| Lease duration (TTL) | 900000 ms (15 minutes) from last successful heartbeat |
| Heartbeat interval | 60000 ms (≥3 missed heartbeats before expiration) |
| CAS acquire | Insert or reclaim only when expired; set new holder token + incremented revision |
| CAS heartbeat | Succeeds only when holder token and revision still match; extends `expiresAt` |
| CAS release | Clears holder only for the exact token+revision |
| Stale takeover | Reclaim only after exact expiration **and** CAS of the expired revision with a new holder token |
| Fencing | Before each listing request, each retrieval request, each retry dispatch, each parser dispatch, reconciliation, candidate readiness, and activation, the holder must re-verify its token+revision still owns the lease. Failure halts new external work |
| Prior owner after takeover | Must not continue provider work. An in-flight database transaction may settle; no new provider request without verified ownership; stale holder cannot finalize readiness after losing the lease |
| Process crash | Lease expires; incomplete prefix evidence remains; next holder restarts the crashed prefix pass from page one |
| Database outage | No reclaim, no listing, no retrieval. Inability to confirm lease ownership fails closed |
| Heartbeat pause | Treat as impending expiration; do not start new provider requests without a successful heartbeat confirmation when ownership is uncertain |
| Shutdown release | Best-effort CAS release; otherwise wait for TTL |
| Deployment overlap | Second deployer cannot hold the same scope concurrently |
| Advisory lock | Reserved for short activation compare-and-swap only, never for the listing run |
| Lease vs run duration | Lease TTL is **not** total run duration. Heartbeats keep a long run alive within the separate run-age / run-deadline policy |

A future forward-only migration is an R4B prerequisite. R1 does not create the table. Existing
BackgroundJob leases remain for queue execution; the OSV synchronization lease is a distinct
catalog-scope lock so a KEV `intelligence.sync` job cannot be mistaken for OSV mutual exclusion.

### 9. Retry and backoff policy

Identifier: `osv_runtime_retry_policy_v1`.

Retry owner: durable synchronization worker / job layer. Never the transport adapter, storage
adapter, parser core, or database adapter. Committed retrieval remains one HTTP attempt with no
internal retry.

**Attempt semantics:** every “maximum attempts” value below is **total attempts including the
initial attempt** (initial + at most two retries for a ceiling of 3, except where a tighter rule is
stated). Each attempt has a unique immutable ordinal, retains failure classification and policy
version, never mutates a prior attempt result, and must check cancellation, kill switch, and lease
fencing before dispatch. Revalidate source permission where relevant before a retry that would
contact the provider or retain bytes.

| Dimension | v1 value |
| --- | --- |
| Maximum attempts per listing request | 3 total (including initial) |
| Maximum attempts per retrieval item | 3 total (including initial) |
| Maximum attempts per storage transient | 3 total (including initial) |
| Maximum attempts per database transient | 3 total (including initial) |
| Maximum attempts per parser startup or crash | 3 total (including initial) |
| Maximum attempts per parser timeout | **2 total** (initial + one future explicit retry in a **fresh isolate**). Exhaustion quarantines. Do not run three automatic timeout attempts |
| Maximum synchronization attempts per job delivery | 1 A/B convergence pair. Item/stage retries occur inside that attempt |
| Initial delay | 1000 ms |
| Subsequent delay | 4000 ms |
| Backoff | Exponential with bounded full jitter |
| Maximum delay | 30000 ms |
| Retry-After | Honored only for HTTP 429. Integer seconds preferred; if HTTP-date is present, accept only when parseable and in the future. Cap at 30000 ms. Malformed, negative, past, or non-429 values are ignored. Must not extend beyond job age or run deadline. No provider prose parsed. Full jitter still applies to the chosen delay |
| Attempt persistence | Each attempt is a separately persisted record |
| Cancellation | Ends the current job. No further retry dispatch |
| Exhaustion | Incomplete or quarantined terminal outcome. No hidden extra attempt |
| Backoff vs concurrency | Short stage backoff keeps the one active run; same-scope jobs do not overlap; unrelated KEV work remains separately bounded by shared worker concurrency |

**Potentially retryable:** listing/retrieval transport timeout; temporary DNS failure; connection
reset; HTTP 408, 429, 500, 502, 503, 504; transient object-storage unavailable; transient database
unavailable; parser-worker startup failure; parser-worker crash; parser timeout under the two-attempt
fresh-isolate rule above.

**No retry** for: redirect; oversized object; generation mismatch; immutable conflict; content
integrity mismatch; source ineligible; retention prohibited; legal-review required; schema-invalid
advisory; deterministic structural-limit failure; parser identity mismatch; token cycle; inventory
conflict; policy mismatch; registry mismatch; kill-switch halt; duplicate JSON-key security
exception (when detected later).

Use the committed retrieval failure taxonomy. Listing failures map to the committed transport
failure catalog. Parser timeout/crash exhaustion quarantines the item and marks eligible-body/parser
completeness incomplete; silent omission from a complete generation is forbidden.

Do not implement retries in R1.

### 10. Parser-host pending capacity

Selected v1 **runtime policy**: **parser pending capacity 0**.

| Dimension | Value |
| --- | --- |
| Parser workers | 1 |
| Active parser request | 1 |
| Parser pending capacity | 0 |
| Dynamic scaling | Prohibited |
| Tenant priority | Prohibited |
| Body bytes in a parser queue | Prohibited |

**Current implementation behavior (committed):** the host rejects a second concurrent parse with
`invalid_request` while occupying (occupancy 1). There is no pending queue of body-holding
requests in practice. However, the committed isolation constants remain:

- `OSV_ADVISORY_PARSER_PENDING_QUEUE_SIZE_POLICY = 'unavailable'`
- `OSV_ADVISORY_PARSER_RUNTIME_COMPOSITION_AUTHORIZATION = 'blocked_pending_queue_size_unapproved'`

Pending capacity **0 is therefore selected architecture**, not yet a machine-enforced named
constant. Claiming the constant already equals 0 is false. R4A/R5A must replace those markers with
exact pending capacity `0` and a composition authorization that still requires the other R2–R5
deliverables, with tests proving a second concurrent parse is rejected and that no pending body
bytes are retained. Until that constant change, runtime composition remains blocked.

The orchestrator must dispatch only when the parser host is available. Pending parser requests must
never hold body bytes. Excess work remains in the durable job's metadata plan. R1-R does not modify
the parser host.

Disabled-orchestration pending work (32 metadata-only items) remains a different control and is
unchanged.

### 11. Runtime acquisition concurrency

Preserve the synthetically verified Batch 6B model.

| Dimension | v1 |
| --- | --- |
| Synchronization attempts per scope | 1 |
| Prefixes listed at a time | 1 |
| Page requests at a time | 1 |
| Body items processed at a time | 1 |
| Parser requests at a time | 1 |
| Attachments at a time | 1 |
| Parallel source families | Prohibited |
| Dynamic scaling | Prohibited |
| Candidate-generation concurrency | 1 per scope |
| Catalog-scope concurrency | 1 |

Do not optimize throughput before canary evidence exists.

### 12. Production observability

Identifier: `osv_runtime_observability_contract_v1`.

Logs, metrics, and durable audit records remain distinct. Do not implement observability in R1.

**Event codes:** `sync_requested`, `lease_acquired`, `lease_rejected`, `run_started`,
`prefix_pass_started`, `page_completed`, `prefix_pass_completed`, `convergence_accepted`,
`convergence_failed`, `candidate_created`, `retrieval_completed`, `retrieval_failed`,
`attachment_completed`, `attachment_failed`, `parser_completed`, `parser_failed`,
`quarantine_recorded`, `reconciliation_completed`, `candidate_ready`, `activation_requested`,
`activation_completed`, `activation_failed`, `run_cancelled`, `run_exhausted_retries`,
`run_completed`, `kill_switch_observed`, `cleanup_backlog_observed`.

**Allowed attributes:** event code, run identifier, candidate-generation identifier, prefix, stage,
bounded failure code, retry attempt, count, duration bucket, byte-size bucket, safe provider-key
digest only where required for an item-scoped failure, version identifiers, readiness state.

**Prohibited attributes:** page token, provider body, parsed document, raw provider key, canonical
URL, response headers, provider prose, package name, aliases, affected ranges, S3 keys, credentials,
tenant ID, organization ID, Finding ID, JavaScript stack, Prisma stack.

**Metrics cardinality:** prefix (closed to the six inventory values), stage (closed), failure code
(closed), and version identifiers are the only low-cardinality labels. Do not use provider object
digest, run identifier, or candidate-generation identifier as unbounded metric labels. Digests may
appear on opt-in debug logs for a single correlation identifier, never as metric labels. Size and
duration use buckets. Retry attempt is bounded.

**Sink ownership:** structured operational logs, metrics, and traces are observability sinks.
Immutable activation and security-sensitive transitions also require durable database/audit records
separate from ordinary telemetry. Event-sink failure must not alter acquisition outcome. Logs are
not activation authorization evidence.

### 13. Operational-event confidentiality

Operational events follow the committed retrieval and parser confidentiality rules. Failures omit
body bytes, raw keys, complete URLs, headers, Location, provider prose, stack traces, tenant data,
package data, and Finding data. Token digests are allowed only on cycle-detection events and are
not sent to the provider. Audit payloads use the same prohibition list.

### 14. Cleanup and retention architecture

Identifier: `osv_cleanup_retention_architecture_v1`.

No legal retention duration is invented. Evidence remains until a documented source change, failed
integrity check, scheduled legal review, or a later accepted retention duration. No broad
attached-object deletion is authorized. A cleanup executor remains disabled until separately
reviewed.

| Class | Evidence class | Deletion eligibility | Protections | Cleanup owner / trigger |
| --- | --- | --- | --- | --- |
| Inventory attempts and incomplete prefix passes | Operational evidence | Not eligible in v1 | Append-only | None |
| Provider-body snapshots | Intelligence evidence | Not eligible while referenced or attached | Active and superseded reference protection; license constraints | None in v1 |
| Parsed documents | Intelligence evidence | Same as bodies | Same | None in v1 |
| Parser attempts | Append-only evidence | Not eligible | Immutable | None |
| Candidate generations | Catalog evidence | Not eligible | Quarantine and completeness rows stay | None |
| Reconciliation records | Catalog evidence | Not eligible | Immutable | None |
| Quarantine records | Security evidence | Not eligible | Immutable; not a deletion authorization | None |
| Activation history | Security evidence | Not eligible | Append-only; no rewrite | None |
| Temporary storage objects | Staging | Eligible only for a known staged identity after successful attach (already committed) or a classified orphan past a future reviewed grace period | In-flight staged, attached, referenced, and conflicting objects are not executable cleanup targets | Best-effort delete of known temp after attach (exists). Orphan job is future and disabled |
| Orphaned storage objects | Residual storage | Classification only until a reviewed executor exists | Revalidate references; acquire cleanup lease; never delete active evidence | Future disabled executor |
| Superseded generations | Catalog evidence | Metadata retained. Objects retained | Pointer rollback may need superseded bytes | None |
| Failed candidates | Catalog evidence | Not eligible | Incomplete is evidence | None |
| Operational events | Telemetry | Log/metric retention is operator-owned; not catalog deletion | Confidentiality list | Operator log pipeline |

A future cleanup executor must: use exact immutable identity; revalidate references; acquire a
cleanup lease; never delete active evidence; never interpret provider absence as deletion
authorization; record bounded audit evidence; remain disabled until separately reviewed.

Immediate temporary-object cleanup, orphan reconciliation, failed-candidate cleanup, long-term
evidence retention, and legal erasure or license-revocation action are separate. License revocation
is not automatic deletion.

### 15. First-provider canary policy

Identifier: `osv_disabled_first_provider_canary_policy_v1`.

The canary may contact the provider only in a later explicitly authorized phase (R6). R1 does not
contact the provider and does not select a real advisory ID. **This ADR does not authorize
provider-body retrieval for the canary.** Body retrieval remains gated by source eligibility,
legal revalidation, kill switch, and explicit R6 authorization.

| Dimension | Disposition |
| --- | --- |
| Provider prefix | `crates.io/` (**provisional technical candidate**) |
| Allowed source identifier | `rustsec_advisory_database` (**provisional; not legally authorized by this ADR**) |
| Allowed family | `RUSTSEC` (**provisional**) |
| Inventory | One A/B pair over that prefix only. Six-prefix completeness is not claimed |
| Catalog activation | Prohibited. Resulting candidate is a canary candidate, not a production catalog, and has no active-pointer eligibility |
| Matching | Prohibited |
| Findings | Prohibited |
| Isolated candidate | Required. No production active pointer |
| Operator approval | Required before R6 (named authorization role/mechanism, runbook acknowledgment, kill-switch tested, observability active, provider-rate controls active) |
| Provider rate protection | One page at a time; retry policy v1; halt kills new requests |
| Kill switch | Required and must be implemented before R6 |
| Scheduler | Ordinary scheduler must not start canary; `operator_canary` is distinct from production |
| Runbook | Must be invoked before start |
| Post-run review | Required. Operator review package without body leakage |

**Byte and retrieval budgets (exact):**

| Budget | Value |
| --- | --- |
| Maximum body retrieval count | 16 |
| Maximum body bytes per object | 1048576 |
| Maximum aggregate body bytes | 16777216 |
| Parser / parsed-document bytes | Separate in-process and storage ceilings remain the committed parser (2 MiB output) and snapshot admission (1 MiB) policies; they do **not** expand the 16 MiB aggregate body budget |
| Stop behavior | Reaching any limit stops further retrieval; no silent truncation interpreted as complete inventory; candidate remains nonactive |

Why this family is the provisional technical candidate: verified CC0-1.0 source-level provenance,
parser compatibility already exercised with synthetic RUSTSEC keys, no MAL matching implication,
and `crates.io/` is the smallest approved prefix. Per-advisory license fields may indicate
CC-BY-4.0 for GHSA imports; whether that field is present and binding in the committed OSV
representation must be resolved during legal revalidation, not assumed here. External exposure
remains conservative until post-parse confirmation. **R6 is blocked on explicit legal and
provenance revalidation of `rustsec_advisory_database`**, including per-advisory license-field
handling if applicable. This ADR does not conduct new licensing research and does **not** present
RustSec as finally approved. If revalidation cannot complete, a later ADR amendment or reviewed
canary-policy version may change only the canary prefix/family without redesigning listing, lease,
or retry architecture. Canary source selection does not block R2.

Canary outputs: inventory observations, at most 16 retrieved snapshots totaling ≤ 16 MiB body
bytes, parser outcomes, quarantine outcomes, reconciliation, a candidate that is not activated, and
an operator review package that omits bodies, tokens, raw keys, and URLs.

Canary evidence follows the same retention architecture. It is not a license to delete after
review. Temporary objects follow the committed best-effort temp delete.

### 16. Catalog-activation authorization

Identifier: `osv_catalog_activation_authorization_v1`.

The runtime synchronization job must **not** automatically activate a candidate merely because it
is `ready_for_activation`. `ready_for_activation` is not `active`. Parser success does not
activate a catalog. Accepting this ADR does **not** authorize activation.

Preferred initial production behavior:

- synchronization produces candidate readiness only
- explicit operator or separately reviewed policy requests activation
- activation service revalidates every prerequisite
- active-pointer compare-and-swap remains atomic
- activation history remains immutable (durable database/audit evidence, not mere telemetry)
- matching does not start automatically
- Finding writes do not start automatically

**Required activation inputs:** candidate generation, current pointer revision, expected prior
generation, exact version-set fingerprint, accepted reconciliation, source-license registry
version, legal revalidation result, canary result or production-run approval, activation reason,
operator or system authorization identity, requested timestamp (UTC), kill-switch not engaged,
rollback readiness evidence.

**Preactivation revalidation:** current registry version compatibility; source permissions not
broadened and not newly prohibited; object-storage integrity of referenced attachments; no
blocking quarantine; completeness equations pass; schema and parser versions match the pinned set;
kill switch not engaged; rollback readiness (previous generation still referenced and readable).

**Candidate-age policy:** an exact maximum candidate staging age is **not selected in R1**. It is
an **R7 blocking policy** input. Activation architecture requires the age check to exist before R7
acceptance; do not invent a value without evidence. Explicit revalidation is required regardless of
age.

Do not implement activation invocation in R1. Disabled orchestration continues to omit
`activateReadyGeneration`.

### 17. Rollback and downgrade prevention

Distinguish:

| Action | In scope for acquisition foundation |
| --- | --- |
| Stopping provider acquisition | Yes (enablement + kill switch) |
| Cancelling an active run | Yes (lease + AbortSignal) |
| Preventing activation | Yes (authorization gate) |
| Reverting the active catalog pointer | Yes, as a **new** activation record (exceptional explicitly authorized downgrade) |
| Disabling reads from the new catalog | Later read-path decision; no OSV read API exists |
| Deleting evidence | No |
| Rolling back matching | Out of scope |
| Rolling back Findings | Out of scope |

Pointer reversion is permitted only as an explicit new activation of a previously activated
generation that still exists, is integrity-verified, and is compatible with the current registry,
schema, and parser pins—or carries an explicit emergency exception with named owner. Authorization
is the same activation gate plus reason `rollback`, actor, timestamp, post-rollback monitoring, and
kill-switch consideration. History is never rewritten. No evidence deletion. No automatic Finding
mutation. A prior generation may be operationally older but still safer; treat rollback as an
exceptional authorized downgrade, not a silent history rewrite. Downgrade checks reject a target
whose version-set fingerprint is not in the accepted rollback set or that fails current integrity
or legal checks.

### 18. Emergency kill switch

The kill switch is independent from `INTELLIGENCE_OSV_ENABLED`.

Recommended later variable name: `INTELLIGENCE_OSV_ACQUISITION_HALT`. **Do not add it in R1.**

Defense-in-depth design (selected):

| Dimension | Disposition |
| --- | --- |
| Enablement | `INTELLIGENCE_OSV_ENABLED` defaults false and currently rejects `true`. Enabling OSV does **not** automatically clear halt |
| Halt default | **`true` (halted)** until first explicit operational authorization sets `false` |
| Missing or malformed halt | Fail closed to **halted** |
| Production runtime requires | `enabled = true` **and** `halt = false` |
| Canary | May require a separate signed or bounded authorization rather than general enablement; still observes halt |
| Halt blocks | New listing requests, new retrieval requests, retry dispatch, new parser dispatch, readiness transitions that require further provider work, and candidate activation |
| Does not | Delete immutable evidence; terminate a database transaction mid-commit; itself enable OSV |
| In-flight network | Cancel via `AbortSignal` where safe |
| During backoff/sleep | Next wake must re-read halt before any provider request or retry dispatch |
| Active catalog reads | Separate later decision. No OSV catalog read API exists |
| Matching and Findings | Outside this phase |
| Configuration source | Typed `@patchpilot/config` only, when R5A adds the variable |
| Runtime refresh | Re-read at job acceptance, lease acquisition, before each listing page, before each retrieval, before retry dispatch, before parser dispatch, before readiness transition, and before activation. Not mid-transaction |
| Audit | Bounded `kill_switch_observed` event. No secrets |
| Restart | Not required for halt to take effect on the next attempt boundary |
| Stale worker | Next attempt boundary observes halt; in-flight HTTP is cancelled |
| Precedence | Halt > scheduler emit > manual job start. Enablement `false` also blocks |

Compensating control while the variable is absent: OSV enablement remains rejected and no
production composition exists, so a future default of halted cannot be bypassed by R1–R4 work.

### 19. Duplicate JSON-key disposition

Current state: last-key-wins `secure-json-parse` limitation; prototype-sensitive keys rejected;
adversarial tests show no known bypass of authorization, identity, schema pinning, resource bounds,
normalization eligibility, or top-level ID confirmation; detection is not implemented.

Selected: **Option B.**

- Permit only the tightly bounded **disabled** canary under documented residual risk after kill
  switch, runbooks, and legal revalidation. Canary cannot activate, match, or create Findings.
  Canary results require operator review. If another control detects duplicate keys, quarantine.
- Require duplicate-key detection **or** an explicit security exception **before R7** production
  catalog activation. An exception, if used, must name an owner, acceptance date, and
  expiry/review event. Do **not** accept an indefinite silent exception. The exception does not
  authorize matching or Findings.
- Do not accept the risk silently for production activation.
- Do not add a dependency in R1. A later detection implementation may need a dependency review;
  that review is an R7 prerequisite if detection is chosen instead of an explicit exception.

MAL matching remains prohibited. OSV and ECHO remain fail closed.

### 20. Source-license and provenance revalidation

Revalidate source permission:

- before listing (prefix is inventory context only; listing still requires registry pin and
  inventory-scope approval; listing permission does **not** imply body retrieval)
- before body retrieval (body-retrieval eligibility, exact source classification, complete evidence)
- before private retention
- before parsing (normalization eligibility independently required)
- before candidate readiness (same pinned registry version; included source permissions still
  compatible)
- immediately before activation (current registry compatibility, explicit legal revalidation, no
  newly prohibited source)
- after registry-policy change
- after license-evidence change
- after source archival or ownership change

Body-retrieval prohibition must not prevent metadata inventory when metadata listing is
independently approved by the registry. Listing permission must not imply retrieval.

Registry-version pinning is preserved. If the registry changes during a run:

- the active run retains its immutable version set
- no mutation of the running version set; no new source permission added mid-run
- readiness may complete under the pinned policy
- activation requires current-policy compatibility
- newly prohibited sources block activation
- no source permission is broadened automatically
- historical evidence follows retention policy
- provider absence is not source revocation
- license revocation is not automatic deletion
- future retry or new run uses the new registry version

Evidence remains valid until a documented source change, failed integrity check, or scheduled
legal review. No arbitrary expiry date is invented. First real canary requires explicit
revalidation of every included source. Activation requires a registry compatibility check.

### 21. Operational runbooks

R1 defines minimum outlines. They are **not live procedures**. No OSV runtime exists. Do not treat
this section as authorization to contact the provider or to delete evidence. See
[Operational runbook outlines](#operational-runbook-outlines).

### 22. Continued zero-tenant and zero-Finding boundaries

R1 adds no tenant identifiers, organization identifiers, package inventory, Component query,
Vulnerability write, Finding write, FindingObservation, Evidence, RiskCalculation,
`finding.recalculate`, tenant Outbox event, or tenant AuditEvent. Matching remains unauthorized.
Finding behavior remains unauthorized. Runbook references to Findings describe a **prohibited
unexpected side effect**, not a supported workflow. Session 11 remains zero-Finding. Session 12
remains zero-Finding.

### Version-set pinning during a run

At job start the worker pins this fingerprint and refuses caller overrides:

- inventory scope `osv_gcs_six_prefix_public_export_v1`
- listing protocol `osv_gcs_json_objects_list_v1`
- transport policy `osv_transport_policy_v1`
- retrieval policy `osv_generation_bound_retrieval_policy_v1`
- pagination policy `osv_listing_pagination_policy_v1` or canary policy
- parser protocol `osv_advisory_parser_protocol_v1`
- schema v1.9.0 commit `f3f826310aeca8e324baabd195632f2229952abe` SHA-256 `cdb8292f72945cfdf06d3e044280d7c0867105a3a1ae6d4547c983eba20810a2`
- registry `osv_source_license_registry_v1`
- retry policy `osv_runtime_retry_policy_v1`
- architecture `osv_runtime_enablement_architecture_v1`

Activation requires current-policy compatibility with that fingerprint. A run does not pick up a
new registry or schema mid-flight.

## Preserved committed policies

Do not silently alter:

| Policy | Pin |
| --- | --- |
| Retrieval | `osv_generation_bound_retrieval_policy_v1`; 1048576 bytes; one HTTP attempt; no redirects; no automatic retry; identity encoding; exact generation binding; exact HTTP 200; source and retention preflight |
| Disabled orchestration | `osv_disabled_acquisition_orchestration_policy_v1`; concurrency 1; pending 32; 32 observations per invocation; only the active item may hold body bytes; automatic activation prohibited; automatic retries prohibited |
| Storage | `osv_object_storage_layout_v1`; `advisory_body` and `parsed_advisory`; SHA-256 attached identities; staged UUID temps; no attached overwrite; no provider key in storage paths |
| Parser | schema v1.9.0; commit `f3f826310aeca8e324baabd195632f2229952abe`; SHA-256 `cdb8292f72945cfdf06d3e044280d7c0867105a3a1ae6d4547c983eba20810a2`; isolated worker; one active parse; bounded input/output; duplicate JSON-key detection not implemented |

Also preserve: provider prefix is inventory context only; prefix grants no retrieval permission;
source URL grants no permission; generation is an exact decimal string; latest cannot substitute;
PatchPilot SHA-256 identifies exact bytes; ETag and md5Hash are provider metadata only; retrieval
and private-retention permissions are independent; parser normalization permission is independently
required; PostgreSQL and object storage are not one transaction; evidence attachments are immutable;
parser success does not activate a catalog; `ready_for_activation` is not `active`; MAL matching
remains prohibited; OSV and ECHO remain fail closed; CVE has no eligible default; matching
completeness remains `not_in_scope`; OSV remains intentionally disabled.

## Runtime dependency graph

Adjacency (acyclic):

```text
R1_ADR_accepted -> listing_policy_accepted
listing_policy_accepted -> listing_executor_implemented
listing_executor_implemented -> token_cycle_controls_verified
token_cycle_controls_verified -> listing_pagination_orchestration
R1_ADR_accepted -> lease_mechanism_implemented
R1_ADR_accepted -> retry_policy_implemented
R1_ADR_accepted -> parser_capacity_policy_implemented
R1_ADR_accepted -> observability_implemented
R1_ADR_accepted -> cleanup_retention_controls_accepted
R1_ADR_accepted -> kill_switch_implemented
R1_ADR_accepted -> runbooks_approved
listing_pagination_orchestration -> durable_job_lease_retry
lease_mechanism_implemented -> durable_job_lease_retry
retry_policy_implemented -> durable_job_lease_retry
parser_capacity_policy_implemented -> runtime_worker_implementation
observability_implemented -> runtime_worker_implementation
kill_switch_implemented -> runtime_worker_implementation
durable_job_lease_retry -> runtime_worker_implementation
cleanup_retention_controls_accepted -> disabled_canary_authorized
runbooks_approved -> disabled_canary_authorized
kill_switch_implemented -> disabled_canary_authorized
legal_revalidation_complete -> disabled_canary_authorized
runtime_worker_implementation -> disabled_canary_authorized
disabled_canary_authorized -> disabled_canary_passed
disabled_canary_passed -> activation_authorization_accepted
legal_revalidation_complete -> activation_authorization_accepted
duplicate_json_key_resolved_or_accepted -> activation_authorization_accepted
activation_authorization_accepted -> candidate_synchronization_passed
candidate_synchronization_passed -> explicit_activation_approved
explicit_activation_approved -> catalog_activated
catalog_activated -> ecosystem_normalization_accepted
ecosystem_normalization_accepted -> evaluator_accepted
evaluator_accepted -> matching_implemented
matching_implemented -> match_evidence_verified
match_evidence_verified -> finding_write_gate_accepted
finding_write_gate_accepted -> controlled_finding_implementation
```

Invariants: no canary before kill switch and runbooks; no activation before canary and legal
revalidation; no matching before catalog activation and evaluator approval; no Findings before
matching evidence and ADR 0026 authorization; no tenant node enters acquisition; no source
permission is bypassed. Duplicate JSON-key resolution is required before activation, not before
the disabled canary.

## Runtime loop analysis

| Loop | Owner | Max iterations | Persisted progress | Cancellation | Retry owner | Terminal states | Recovery | Confidentiality |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Listing pagination | Future listing orchestrator | Canary 8 pages/prefix/pass; production 500/prefix/pass; run = prefixes × passes | Page number, counts, terminal flag. No raw token | AbortSignal | Durable job layer, 3 total attempts/page including initial | terminal page, cycle, cap, cancel | Restart prefix from page one under new pass-attempt identity | No token, body, URL |
| Convergence | Future listing orchestrator | 1 A/B pair | Pass result | AbortSignal | New explicit job | converged, inventory_not_converged | New run | Prefix and counts only |
| Retry | Durable job layer | 3 total per retryable unit (parser timeout: 2) | Attempt records | Ends job | Job layer only | success, exhausted, quarantined | No adapter loop | Failure codes only |
| Scheduler | Worker scheduler | 1 queued or running per scope | Job request row | Halt and shutdown | None (no catch-up) | skipped, emitted, halted | Next UTC window | No payload bodies |
| Parser | Parser host | 1 active, pending 0 | Parser attempt row | terminate() | Job layer for crash/timeout (timeout max 2) | success, deterministic failure, exhausted | Recycle on protocol failure | No advisory bytes |
| Storage recovery | Attachment service | `OSV_STORAGE_CALL_BUDGETS` | Staged/attached metadata | N/A | Job layer for transient only | attached, immutable_conflict, staged | No polling loop | No S3 keys in events |
| Cleanup | Future disabled executor | Bounded batch of exact identities | Classification only in v1 | Halt | None | classified, skipped | No bucket-wide scan | No locators in public errors |
| Activation | Persistence adapter | 1 CAS transaction | History row | N/A | None. Stale pointer returned to owner | activated, rejected, scope_mismatch | Reload pointer | No bodies |
| Lease fencing | Sync worker | Continuous while holding lease | Lease revision + holder token | Halt and shutdown | None | owned, expired, reclaimable | Stale holder blocked before next provider request | No tokens in events |

## Implementation roadmap

| Batch | Purpose | Prerequisites | Deliverables | Prohibited | Exit verdict |
| --- | --- | --- | --- | --- | --- |
| R2 | Production GCS listing executor | This ADR accepted | One listing-page HTTPS adapter; exact compiled surface; one request/invocation; synthetic local tests; confidential failures | Pagination loop, token-cycle store, retry, scheduler, jobs, retrieval composition, activation, provider contact in tests | Listing executor implemented; still disabled; no production wiring |
| R3 | Listing pagination and convergence | R2 | Prefix passes; token-cycle detection; page/observation ceilings; restart from page one; inventory metadata persistence | Body retrieval composition, scheduler, activation | Pagination verified without provider contact in tests |
| R4A | Runtime job, lease, and retry **contracts** | R3 | Job/payload/Outbox necessity decision; lease fencing contract; retry-attempt model; parser pending capacity policy constant selection recorded | Prisma migration, enablement, provider contact, activation | Contracts reviewable without schema change |
| R4B | Lease and attempt schema | R4A | Forward-only Prisma migration for lease + attempt persistence | Runtime enablement, provider contact, activation | Migration frozen after apply |
| R4C | Lease and retry-attempt adapters | R4B | PostgreSQL adapters implementing R4A contracts; parser pending-capacity constant `0` | Enablement, provider contact, activation | Adapters exist; enablement still rejected |
| R5A | Disabled production composition and kill switch | R4C | Worker composition behind disabled config; `INTELLIGENCE_OSV_ACQUISITION_HALT` default **true**; scheduler registration that does not emit while disabled/halted | Provider contact, canary execution, activation | Worker exists; OSV remains disabled; halt defaults halted |
| R5B | Observability and operational runbook implementation | R5A | Bounded events/metrics; live runbook procedures derived from outlines | Provider contact unless canary authorization is present | Observability and runbooks ready for canary review |
| R6 | Disabled real-provider canary | R5A+R5B; legal revalidation; explicit operator authorization | Exact canary limits; operator review | Activation, matching, Findings | Canary passed or failed without activation |
| R7 | Catalog-activation authorization | R6 passed; duplicate-key detection or named exception; legal revalidation; candidate-age policy selected | Preactivation checks; explicit authorization; rollback; pointer monitoring | Matching | Activation authorized as a separate command |
| M1 | Matching architecture | Catalog activated; ADR 0025 | Matching design | Finding writes | Architecture only |
| M2 | First ecosystem evaluator | M1 | Evaluator for one reviewed ecosystem | Finding writes | Fail-closed evaluation |
| M3 | Match-evaluation persistence | M2; ADR 0026 | Append-only match evidence | Finding writes | Evidence without Findings |
| F1 | Finding-write architecture | M3; ADR 0026 gates | Write-path design | Production writes | Architecture only |
| F2 | Controlled Finding implementation | F1; explicit authorization | Finding ensure | Cross-tenant writes | Still requires tenant-isolation proof |

## Exact R2 authorization boundary

If and only if this ADR is Accepted, R2 may implement **only**:

- one GCS listing-page HTTPS adapter at
  `packages/integrations/src/osv-gcs-listing-https-adapter.ts` (`createOsvGcsListingHttpsAdapter`)
- exact compiled Batch 3C request surface (`GET`, `storage.googleapis.com`,
  `/storage/v1/b/osv-vulnerabilities/o`, unauthenticated, no redirects, identity encoding,
  `application/json`, 1,048,576-byte response ceiling, 1000-item page policy)
- exactly one HTTPS request per adapter invocation via `OsvTransportPort.listPage`
- fatal UTF-8 and bounded listing-page parser handoff
- confidential failures (no raw body, raw token, URL, headers, or provider prose)
- synthetic and local HTTP tests only; source-boundary tests; package-export absence until exported
  deliberately

R2 must **not** implement: multi-page listing; A/B convergence; token-cycle store; body retrieval
orchestration; production startup registration; scheduler; durable job; Outbox event; retry;
cleanup; canary; catalog activation; matching; Findings; Prisma/migrations; dependencies;
environment endpoint overrides; tenant context; live contact with `storage.googleapis.com` or
`osv.dev` in tests or production composition.

## ADR 0027 relationship

[ADR 0027](0027-osv-acquisition-persistence-and-catalog-activation.md) remains **Proposed**.

R1-R:

- does **not** supersede ADR 0027
- does **not** accept ADR 0027
- does **not** require ADR 0027 acceptance before R2
- builds on Session 11 persistence that already implements much of ADR 0027's shape
- **narrows** activation: `ready_for_activation` is never automatic activation
- provides missing runtime-acceptance inputs that ADR 0027 explicitly left out (listing, lease,
  retry, canary, kill switch, rollback)

ADR 0027 concerns acquisition persistence and catalog-activation **shape**. Session 11 implemented
the persistence foundation. A **separate** persistence-only acceptance review may evaluate ADR 0027
later. Runtime enablement must not falsely accept ADR 0027. Catalog activation remains prohibited
even though the persistence shape exists.

## Alternatives considered

- Reuse `intelligence.sync` for OSV. Rejected: KEV payload and OSV listing/token/lease semantics
  differ. Silent dual-use would hide OSV enablement inside KEV.
- Transaction-scoped advisory lock for the whole sync. Rejected: cannot cover multi-minute HTTPS.
- Pending parser capacity 1. Rejected: a pending request would hold body bytes. Capacity 0 matches
  the occupancy-1 host behavior and prevents hidden memory amplification; the named constant remains
  an R4C/R5A implementation gap.
- 10,000 pages / 60,000,000 observations as v1 production limits. Rejected: unmeasured, unbounded
  duration and database growth. Split canary vs fail-closed ceilings instead.
- Internal convergence restart loop. Rejected: can livelock on a changing provider inventory.
- Automatic activation when `ready_for_activation`. Rejected: Session 11 explicitly forbids it.
- Option A (duplicate-key detection before any canary). Rejected as an R1 blocker: residual risk is
  documented and canary is tiny, disabled, and non-activating. Option C (accept for v1 production)
  is rejected as a silent security exception.
- Kill-switch default `false` (not halted). Rejected by R1-R: once enablement exists, a missing
  operational halt would permit acquisition. Selected default is halted (`true`) with malformed →
  halted.
- Adding kill-switch or scheduler config in R1. Rejected: would create a premature enablement
  surface.

## Consequences

Positive: later batches can implement listing, leases, retries, and canary without redesigning
runtime architecture. Provider contact, activation, matching, and Findings stay gated.

Negative: six-prefix production listing is not authorized until after canary measurement. A lease
migration is required in R4B. Parser pending capacity is selected here but the code constant remains
`unavailable` until R4C/R5A. Duplicate-key detection remains unimplemented and blocks production
activation. Kill-switch default halted requires explicit operational release before any future
acquisition work.

## Security and tenancy

No `organizationId` or other tenant columns enter OSV runtime jobs, leases, payloads, or events.
No Finding, Component, or tenant package inventory is read or written. System audit, when added
later, uses a null organization. Page tokens, bodies, raw keys, URLs, headers, and credentials
must not appear in logs, metrics, traces, or audit payloads. Outbound contact is only the compiled
GCS listing and generation-bound retrieval surfaces, and only after later authorization. ZIP
remains unauthorized. Tenant package query APIs remain rejected.

## Operational failure plan

See [Operational runbook outlines](#operational-runbook-outlines). Until R5–R7 exist, the only
live OSV control is configuration rejection of `INTELLIGENCE_OSV_ENABLED=true` and the absence of
production composition. Do not invent operator SQL that deletes evidence. Do not include secrets
or shell commands that rewrite catalog rows.

## Follow-up

- R2 listing executor within the Exact R2 authorization boundary.
- Parser-host pending-capacity constant change in R4C/R5A.
- Kill-switch variable in R5A with default halted (`true`); not in R1.
- Duplicate-key detection or named security exception with expiry before R7.
- Candidate-age policy selection before R7.
- Legal revalidation of `rustsec_advisory_database` before R6.
- Separate persistence-only acceptance review of ADR 0027 (optional; not an R2 gate).
- Invariant tests proving production runtime remains unreachable and ADR status remains Accepted.

## Operational runbook outlines

Each outline identifies trigger, immediate containment, evidence to collect, forbidden operator
actions, recovery, escalation owner, and closure criteria. No outline authorizes evidence deletion
or Finding mutation. Escalation owner is the instance operator until OD-10 is closed.

1. **First real-provider canary.** Trigger: scheduled R6 after authorization. Containment: confirm
   kill switch implemented and not required-engaged; enablement still not a general production
   enablement. Evidence: run id, prefix `crates.io/`, counts, bounded failure codes. Forbidden:
   activation, matching, pasting bodies or tokens. Recovery: abort via halt if unexpected.
   Closure: operator review recorded; candidate not active.
2. **Provider unavailable.** Trigger: listing or retrieval DNS/timeout/5xx. Containment: stop new
   emits if halt is warranted. Evidence: failure codes, attempt counts. Forbidden: raising ceilings
   or disabling TLS checks. Recovery: durable retry policy; exhaustion incomplete. Closure: later
   explicit job succeeds or remains incomplete without activation.
3. **Listing pagination cycle.** Trigger: `listing_token_cycle`. Containment: terminate prefix;
   quarantine candidate. Evidence: token digest only, page number. Forbidden: persisting or
   injecting a token. Recovery: new run from page one. Closure: cycle absent on next attempt or
   candidate remains quarantined.
4. **Listing does not converge.** Trigger: A/B mismatch. Containment: no body retrieval. Evidence:
   pass counts. Forbidden: forcing completeness. Recovery: new explicit attempt. Closure:
   convergence or abandoned incomplete candidate.
5. **Retrieval object too large.** Trigger: `response_too_large`. Containment: do not retry that
   item. Evidence: declared size bucket. Forbidden: raising 1,048,576 without a new retrieval
   policy. Recovery: item quarantined; generation incomplete. Closure: quarantine recorded.
6. **Generation mismatch.** Trigger: returned generation ≠ requested. Containment: no byte reuse.
   Evidence: requested generation string equality result only. Forbidden: substituting latest.
   Recovery: no retry of mismatched generation. Closure: item failed closed.
7. **Partial response body.** Trigger: short read or interrupt. Containment: discard bytes.
   Evidence: retryability class. Forbidden: concatenating Range retries (unauthorized). Recovery:
   retry only if classified retryable. Closure: exact byte match or exhaustion.
8. **Storage immutable conflict.** Trigger: same identity different SHA-256. Containment: no
   overwrite. Evidence: conflict code. Forbidden: deleting the attached object. Recovery: fail
   closed. Closure: conflict row retained.
9. **Storage and PostgreSQL split-brain.** Trigger: attached object missing or staged metadata
   without object. Containment: recovery inside `OSV_STORAGE_CALL_BUDGETS`. Evidence: attachment
   state. Forbidden: marking attached when GET hash fails; bucket purge. Recovery: committed
   recovery path. Closure: staged, rejected, or verified attached.
10. **Parser timeout.** Trigger: execution timeout. Containment: `worker.terminate()`. Evidence:
    correlation id, attempt. Forbidden: raising timeout via environment. Recovery: at most one
    future explicit retry in a fresh isolate (2 total attempts including initial); then quarantine.
    Closure: success or quarantined incomplete.
11. **Parser crash or malformed output.** Trigger: worker exit or protocol mismatch. Containment:
    recycle worker. Evidence: failure kind. Forbidden: trusting malformed output. Recovery: retry
    startup/crash; deterministic protocol failures do not retry. Closure: recycle plus terminal
    attempt record.
12. **Quarantine accumulation.** Trigger: rising quarantine count. Containment: do not activate.
    Evidence: quarantine codes. Forbidden: deleting quarantine rows. Recovery: fix cause; new
    candidate. Closure: blocking quarantine absent before any activation request.
13. **Reconciliation discrepancy.** Trigger: equation mismatch. Containment: candidate not ready.
    Evidence: dimension counts. Forbidden: waiver. Recovery: new run after cause fixed. Closure:
    exact integer match.
14. **Candidate remains incomplete.** Trigger: ceiling hit or skipped items. Containment: no
    activation. Evidence: which ceiling. Forbidden: treating partial as complete. Recovery:
    measurement review before raising limits. Closure: incomplete recorded.
15. **Activation rejected.** Trigger: CAS miss or prerequisite failure. Containment: pointer
    unchanged. Evidence: rejection code. Forbidden: retry loops; hand SQL pointer writes.
    Recovery: reload pointer; new authorized request. Closure: pointer matches expected revision.
16. **Active-pointer rollback.** Trigger: operator rollback request. Containment: halt new
    activation. Evidence: prior generation id, integrity. Forbidden: rewriting history; deleting
    the failed generation. Recovery: new activation record to previous generation. Closure:
    history shows rollback reason; matching still unauthorized.
17. **Source permission revoked.** Trigger: registry or evidence change. Containment: halt
    retrieval and activation. Evidence: registry versions. Forbidden: automatic deletion.
    Recovery: new registry version; compatibility check. Closure: prohibited sources excluded.
18. **Emergency kill switch.** Trigger: operator halt or observed halt. Containment: no new
    listing, retrieval, retry, parser dispatch, or activation. Evidence: `kill_switch_observed`.
    Forbidden: deleting evidence to "turn it off". Recovery: cancel in-flight HTTP; resume only
    after halt cleared and enablement rules still apply. Closure: no in-flight provider calls.
19. **Retry exhaustion.** Trigger: attempt == 3 failed. Containment: no fourth attempt. Evidence:
    attempt records. Forbidden: manual adapter retries. Recovery: new explicit job if retryable
    class remains. Closure: incomplete or quarantined.
20. **Cleanup backlog.** Trigger: orphan classification count. Containment: executor stays
    disabled until reviewed. Evidence: counts not locators. Forbidden: bucket-wide delete.
    Recovery: future executor with exact identity. Closure: backlog classified, not blindly
    deleted.
21. **Unexpected provider rate response.** Trigger: 429. Containment: honor Retry-After ≤ 30s or
    backoff; halt if storm detected. Evidence: status class. Forbidden: multiplying workers.
    Recovery: retry policy. Closure: rate abates or run incomplete.
22. **Unexpected tenant or Finding side effect.** Trigger: any organizationId, Finding, or
    `finding.recalculate` observed on an OSV path. Containment: halt immediately; stop the job.
    Evidence: process, module, stack **redacted of payloads**. Forbidden: continuing the run;
    "fixing" Findings in place as part of OSV recovery. Recovery: treat as a security incident
    under tenant-isolation and audit runbooks. Closure: proven no tenant mutation; defect fixed;
    OSV remains disabled until review.

## Selected numeric policies

Machine-checkable pins for invariant tests:

- architecture identifier: `osv_runtime_enablement_architecture_v1`
- listing executor future path: `packages/integrations/src/osv-gcs-listing-https-adapter.ts`
- job type: `intelligence.osv.sync`
- outbox event type: `intelligence.osv.sync.requested.v1`
- parser pending capacity: 0
- canary prefix: `crates.io/`
- canary source: `rustsec_advisory_database`
- canary legally authorized: false
- canary maximum pages per prefix: 8
- canary maximum pages per run: 16
- canary maximum observations per prefix: 2000
- canary maximum observations per run: 4000
- canary maximum body retrievals: 16
- canary maximum aggregate body bytes: 16777216
- canary maximum duration seconds: 1800
- production maximum pages per prefix: 500
- production maximum pages per run: 6000
- production maximum observations per prefix: 500000
- production maximum observations per run: 6000000
- pages per prefix scope: per pass
- pages per run identity: prefixes × passes
- maximum token bytes: 8192
- maximum observations per page: 1000
- maximum response bytes per page: 1048576
- listing request attempts: 3
- listing request attempts include initial: true
- retrieval item attempts: 3
- parser timeout attempts: 2
- retry initial delay ms: 1000
- retry subsequent delay ms: 4000
- retry maximum delay ms: 30000
- lease duration ms: 900000
- lease heartbeat ms: 60000
- lease expiration clock: database time
- production run-age limit seconds: 14400
- kill-switch future default: true
- duplicate JSON-key disposition: Option B
- ADR status: Accepted
- OSV enablement: not granted
- `intelligence.sync` remains KEV-only
- Accepting this ADR is **architecture approval** only
- not OSV runtime enablement
- R2 may implement exactly one production GCS listing-page HTTPS adapter
- ADR 0027 remains Proposed; R2 does not require ADR 0027 acceptance

## Implementation note (Session 12 Batch 1)

Session 12 Batch 1 implemented the R2 listing-page HTTPS adapter at
`packages/integrations/src/osv-gcs-listing-https-adapter.ts`
(`createOsvGcsListingHttpsAdapter`). This note does not change the accepted
decision. The adapter remains uncomposed and runtime-unreachable. It performs
one request per invocation, rejects redirects, requires identity encoding,
bounds the page to 1,048,576 bytes, decodes UTF-8 fatally, and reuses the
committed listing-page parser. Listing-specific timeout milliseconds were not
committed in Batch 3B; the adapter reuses `OSV_TIMEOUT_POLICY_V1` because that
policy is the approved GCS HTTPS one-attempt, 1 MiB, four-phase bound. Tests
are synthetic and local only. Pagination, token-cycle detection, retries,
schedulers, catalog activation, matching, Findings, and OSV enablement remain
out of scope. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 3)

Session 12 Batch 3 records framework-independent pagination and two-pass
inventory convergence contracts in
`packages/vulnerability-intelligence/src/osv/listing-pagination/`. This note
does not change the accepted decision, ceilings, or ADR status.

The ADR defined A/B convergence without a named policy identifier. Batch 3
pins that closed policy as `osv_listing_inventory_convergence_policy_v1`.
Pagination policy identifiers remain `osv_listing_pagination_policy_v1` and
`osv_disabled_first_provider_canary_policy_v1`. Exact ADR 0028 ceilings are
preserved, including production 524,288,000 listing bytes per prefix per pass
and 6,291,456,000 listing bytes per run.

Raw continuation tokens remain in memory only. Token digests are in-memory
cycle controls only and are never durable identities. Crash restart begins at
page one. One A/B pair is permitted per synchronization attempt. Incomplete
inventory cannot authorize body retrieval. Pagination is not executed in
Batch 3. The listing HTTPS adapter remains uncomposed. Production OSV runtime
remains disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 4)

Session 12 Batch 4 implements the bounded in-memory pagination and two-pass
inventory-convergence runtime defined by Batch 3, in
`packages/vulnerability-intelligence/src/osv/listing-pagination/`. This note
does not change the accepted decision, ceilings, or ADR status.

The listing HTTPS adapter now exposes exact `responseByteCount` on the
successful one-page transport result: received bytes before UTF-8 decoding,
positive, at most 1,048,576, and not caller-supplied. Pagination passes that
count to `acceptOsvListingPage`. The adapter still performs one request per
invocation and does not paginate.

`createOsvListingPaginationService` is explicitly invoked and is not composed
into worker, API, scheduler, queue, health, seed, or migration runtime. Raw
continuation tokens and token digests remain in memory only. Token cycles fail
closed. Page admission is atomic. Pass A and pass B execute once per prefix
attempt. Canary completeness cannot satisfy production completeness. Incomplete
inventory cannot authorize body retrieval. Retry disposition is recorded and
not executed. Tests do not contact `storage.googleapis.com` or `osv.dev`.
Production OSV runtime remains disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 4-R)

Session 12 Batch 4-R adversarially reviewed the Batch 4 pagination service with
synthetic listing pages and scripted listing-port doubles. This note does not
change the accepted decision, ceilings, or ADR status.

Concrete corrections: rejected pages do not commit candidate counts; only
constructed transport success is admitted; hung listing ports lose to
cancellation; unsafe ceiling arithmetic fails closed; event-sink thenables
cannot become unhandled rejections; canonical convergence checks the exact
algorithm identifier. Raw tokens remain in memory only. Retry disposition is
recorded and not executed. Tests do not contact `storage.googleapis.com` or
`osv.dev`. Production OSV runtime remains disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 5)

Session 12 Batch 5 records framework-independent contracts for the future
`intelligence.osv.sync` job, shared catalog-scope lease, holder token, CAS
row revision, fencing token, database-time expiry, retry policy
`osv_runtime_retry_policy_v1`, parser pending capacity 0, future halt default
halted, and bounded operational events. This note does not change the accepted
decision, numeric policy, or ADR status.

Clarifications that remain compatible with the accepted decision:

- Canary and production acquisition for the same OSV GCS public export share
  one lease so they cannot overlap. Work scopes remain distinct.
- Heartbeat increments lease row revision. Fencing token increments on
  acquire, stale takeover, and release, not on heartbeat.
- Parser timeout remains two total attempts, including the initial attempt.
  Ordinary retryable stages remain three total attempts, including the initial
  attempt.
- HTTP 429 Retry-After is capped at 30 seconds. Malformed and non-429 values
  use bounded full jitter. Full jitter still applies to honored Retry-After
  values and cannot exceed 30 seconds.
- Reserved Outbox name `intelligence.osv.sync.requested.v1` is deferred until
  scheduler and job persistence prove a transaction-bound publication
  requirement. The name remains reserved and is not registered.
- `INTELLIGENCE_OSV_ACQUISITION_HALT` is not added. Parser-host pending-queue
  status remains `unavailable` until a later runtime-composition batch.

No Prisma, migration, lease adapter, retry executor, scheduler, or production
composition is included. Tests do not contact `storage.googleapis.com` or
`osv.dev`. Production OSV runtime remains disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 6 / 6-R)

Session 12 Batch 6 records the schema-only PostgreSQL persistence for the
committed Batch 5 contracts: immutable synchronization request and run, one
current lease projection per shared acquisition scope, holder-token digest
only, separate CAS row revision and fencing token, database timestamps, and
stage attempts. Session 12 Batch 6-R independently reviewed that uncommitted
schema and froze migration
`20260907120000_osv_runtime_coordination_persistence` at SHA-256
`7017b1c4b1d4bcae8bed4bdd0eb43559c0c89fce5b3636e0e889b276013cc3a6`. This note
does not change the accepted decision, numeric policy, or ADR status.

Clarifications that remain compatible with the accepted decision:

- Raw holder tokens are not stored. Only a lowercase SHA-256 digest is durable.
  Digests use TEXT plus an exact 64-character lowercase hex CHECK so
  CHAR/VARCHAR(64) trailing-space truncation cannot admit a padded value.
- Expired is derived from database time and `expiresAt`, not stored as a
  mutable lease state. Stored projection states are `held` and `released`.
- The current lease projection cannot be deleted in ordinary operation.
  Fencing tokens are monotonic for the lease scope. Heartbeat does not change
  the fencing token.
- Request rows are append-only. Duplicate request delivery cannot create a
  second run. Attempt identity is immutable. Planned or running attempts may
  transition once to a terminal state. Attempt ordinal 4 cannot satisfy CHECK
  constraints.
- Parser timeout remains two total attempts. Inventory convergence cannot use
  durable retry rows beyond ordinal 1.

No lease adapter, heartbeat, stale takeover, retry executor, scheduler, or
production composition is included. Tests do not contact
`storage.googleapis.com` or `osv.dev`. Production OSV runtime remains
disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 7)

Session 12 Batch 7 implements `createOsvRuntimeCoordinationPersistence` in
`@patchpilot/database` against the frozen Batch 6 schema. The adapters
establish and inspect durable request, run, lease, fencing, attempt, and
retry-eligibility authority. They do not execute retries, sleep, contact a
provider, or compose production runtime. Holder tokens remain secret; only
SHA-256 digests are stored. Lease and retry timestamps use database
`CURRENT_TIMESTAMP`. Fencing tokens increment on ownership change, release,
and reacquisition, not on heartbeat. This note does not change the accepted
decision, numeric policy, or ADR status.

No scheduler, BackgroundJob routing, Outbox routing, kill-switch variable,
catalog activation, or OSV enablement is included. Tests do not contact
`storage.googleapis.com` or `osv.dev`. Production OSV runtime remains
disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 7-R)

Session 12 Batch 7-R independently reviewed the uncommitted Batch 7 adapters.
Expired holders cannot heartbeat or release. Same-owner acquire after expiry
is a new fencing generation: the Batch 6-R heartbeat trigger cannot increment
fencing on held→held same run and digest, so the adapter bumps generation
through a same-transaction released-then-held pair without a schema change.
Public release still rejects expired holders. Attempt reservation is
transactional and ordinal-contiguous. Retry eligibility remains inspection
only. BIGINT values retain exact precision. This note does not change the
accepted decision, numeric policy, or ADR status.

No schema, migration, scheduler, BackgroundJob routing, Outbox routing,
kill-switch variable, catalog activation, or OSV enablement is included.
Tests do not contact `storage.googleapis.com` or `osv.dev`. Production OSV
runtime remains disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 8)

Session 12 Batch 8 implements `createOsvDisabledRuntimeSynchronization`, an
explicitly constructed disabled composition of committed listing pagination,
inventory convergence, lease/fencing adapters, stage attempts, disabled
acquisition orchestration, and candidate readiness. Construction performs no
I/O. Production startup does not import the factory. Retry disposition is
recorded and not executed. There is no periodic heartbeat loop. Candidate
readiness does not activate a catalog. This note does not change the accepted
decision, numeric policy, or ADR status.

No schema, migration, scheduler, BackgroundJob routing, Outbox routing,
kill-switch variable, catalog activation, or OSV enablement is included.
Tests do not contact `storage.googleapis.com` or `osv.dev`. Production OSV
runtime remains disabled. ADR 0027 remains Proposed.

## Implementation note (Session 12 Batch 8-R)

Session 12 Batch 8-R independently reviewed and hardened the uncommitted
Batch 8 disabled composition. Concrete corrections: the public factory never
honors a caller-supplied execution flag and the verification factory is not a
public package export; late listing, retrieval, parser, and attachment success
after ownership loss is discarded; attempt reservation or start failure prevents
the protected stage; stale owners do not transition the authoritative run to
failed or cancelled and do not release a later holder's lease; post-lease
cancellation terminalizes the run before release; the inventory bridge requires
the exact canary or production prefix plan plus complete pass A and pass B;
membership, quarantine, catalog-lifecycle, body-read, and related acquisition
writes recheck current ownership. This note does not change the accepted
decision, numeric policy, or ADR status.

No schema, migration, scheduler, BackgroundJob routing, Outbox routing,
kill-switch variable, catalog activation, or OSV enablement is included.
Tests do not contact `storage.googleapis.com` or `osv.dev`. Production OSV
runtime remains disabled. ADR 0027 remains Proposed.
