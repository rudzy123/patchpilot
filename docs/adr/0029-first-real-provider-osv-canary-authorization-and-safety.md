# ADR 0029: First Real-Provider OSV Canary Authorization and Safety Controls

- Status: Accepted
- Date: 2026-09-08
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Architecture identifier: `osv_first_real_provider_canary_authorization_v1`.

Accepted on this feature branch after Session 13 Batch 1-R independent architecture
and authorization review. This ADR depends on [ADR 0028](0028-osv-runtime-enablement-architecture-and-safety.md)
and does **not** supersede it. It preserves Session 12 bounds, general production
disablement, halt default true, lease and fencing authority, no automatic retries,
parser pending capacity 0, and the separation of readiness from activation. It
narrows real-provider execution to separately authorized canary phases.

## What this ADR is and is not

Accepting this ADR authorizes **only** later implementation of the reviewed
operational controls: provisional canary operator-identity persistence, one-shot
authorization persistence, one-shot administrative execution boundary, heartbeat
controller, deadline controller, and executable runbooks.

Acceptance does **not** authorize:

- provider contact
- listing-only canary execution
- provider-body retrieval
- production OSV enablement (`INTELLIGENCE_OSV_ENABLED=true` remains rejected)
- recurring synchronization
- scheduler registration
- automatic retry
- catalog activation
- matching
- Finding writes

Architecture approval remains distinct from implementation approval, operator
execution approval, provider-contact approval, body-retrieval approval,
catalog-activation approval, matching approval, and Finding-write approval.
No live canary is authorized by this acceptance.

[ADR 0028](0028-osv-runtime-enablement-architecture-and-safety.md) remains
**Accepted**. [ADR 0027](0027-osv-acquisition-persistence-and-catalog-activation.md)
remains **Proposed**. This ADR does not change those statuses and does not enable
OSV.

## Context

Session 11 closed the synthetically verified OSV acquisition foundation. Session 12
closed the disabled runtime-enablement foundation: fixed-endpoint GCS listing,
bounded pagination, durable request/run/lease/fencing, disabled composition,
fail-safe acquisition halt, and bounded observability. Production OSV remains
disabled. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
`INTELLIGENCE_OSV_ACQUISITION_HALT` defaults halted.

There is no production OSV BackgroundJob route, Outbox route, scheduler, automatic
retry executor, periodic heartbeat loop, cleanup executor, real-provider canary
evidence, or active OSV catalog. Session 12 deliberately deferred the heartbeat
controller (`deferred_to_session_13_or_dedicated_heartbeat_batch`). The Accepted
canary duration ceiling is 1800 seconds. The committed lease TTL is 900000 ms.
A real canary cannot safely run without heartbeat.

Accepted ADR 0028 identifies a **provisional technical candidate**
(`crates.io/` / `rustsec_advisory_database` / `RUSTSEC`) and requires legal and
provenance revalidation before live contact. Session 11 Batch 3A-P captured
source-level evidence in `osv_source_license_registry_v1`. That registry status
is not canary legal authorization. This ADR does not invent a legal conclusion
and does not conduct new internet research.

General instance-operator identity ([OD-10](../architecture/open-decisions.md))
remains open for console, bootstrap, and IntelligenceSource management. This ADR
selects a **canary-scoped provisional identity** sufficient for Batch 2
persistence. A tenant User, Membership, or Organization identity must not become
the canary authority. Anonymous operator canaries are forbidden.

## Decision

Session 13 Batch 1-R accepts the first real-provider OSV canary architecture.
It does not execute the canary, contact a provider, implement an administrative
command, register a job, start a timer, acquire a lease, activate a catalog,
match packages, or write Findings.

### 1. Exact canary purpose

The first real-provider canary exists to validate:

- real GCS listing protocol compatibility
- real response-header behavior
- real listing-page parser compatibility
- continuation-token behavior
- practical page and observation counts
- pass A and pass B convergence behavior
- provider response-size distributions
- source-family classification behavior
- bounded provider-body retrieval compatibility, only in a later separately
  authorized canary phase
- parser compatibility
- object-storage and persistence compatibility
- quarantine behavior
- operator evidence and runbook quality

The canary does **not** validate:

- complete production catalog coverage
- production scheduler behavior
- automatic retries
- production throughput
- matching correctness
- Finding lifecycle
- catalog activation
- SLA or availability
- all six provider prefixes
- every OSV ecosystem

A successful listing-only canary is protocol and control-plane evidence. It is
not production inventory completeness and not activation eligibility.

### 2. Exact canary mode and phase separation

Identifier: `osv_canary_phase_separation_v1`.

The real-provider canary has two independently gated phases. First listing
contact and provider-body retrieval must not share one irreversible
authorization.

| Phase | Identifier | Authorized work | Forbidden work |
| --- | --- | --- | --- |
| Listing-only | `listing_only` | One provisional prefix, one bounded A/B pair, listing HTTPS only | Provider-body retrieval, object attachment, advisory parsing, candidate readiness, activation |
| Bounded-body | `bounded_body` | After listing-only evidence is accepted; deterministic subset; generation-bound retrieval; immutable attachment; parser; parsed-document attachment | Production completeness claim, activation, matching, Findings, listing of additional prefixes |

Each phase requires its own durable authorization record, operator
acknowledgement, and post-phase independent review. Listing-only success does
not authorize bounded-body. Bounded-body success does not authorize activation.

Work scope remains `osv_runtime_canary_scope_crates_io_rustsec_v1`. Production
scope `osv_runtime_production_scope_six_prefix_v1` is forbidden for both
phases. Reason remains `operator_canary`. Scheduler reason remains unauthorized.

### 3. Provisional provider source and prefix

Disposition selected: **retain RustSec as the provisional technical candidate, blocked on legal revalidation.**

| Dimension | Value | Status |
| --- | --- | --- |
| Prefix | `crates.io/` | Provisional technical candidate |
| Source | `rustsec_advisory_database` | Provisional; not legally authorized by this ADR |
| Family | `RUSTSEC` | Provisional |
| Policy | `osv_disabled_first_provider_canary_policy_v1` | Safety ceilings only |
| Registry | `osv_source_license_registry_v1` | Source-level evidence captured; not canary legal authorization |

Why retain this candidate from committed evidence only:

- ADR 0028 already pinned this prefix, family, and work-scope identifier.
- `crates.io/` is the smallest approved inventory prefix.
- Synthetic parser tests already exercise RUSTSEC object-key grammar.
- Source-level registry notes CC0-1.0 with a per-advisory license field that may
  indicate CC-BY-4.0 for GHSA imports.
- Changing family now would require a new work-scope identity. The persisted
  Prisma enum already contains `osv_runtime_canary_scope_crates_io_rustsec_v1`.

Why not select another registry family now:

- MAL matching remains prohibited by product policy.
- GSD is archived.
- OSV and ECHO remain fail-closed.
- GHSA, PYSEC, GO, and EEF-CVE are larger or attribution-bearing and are not
  the committed canary work scope.
- This ADR does not invent a new legal ranking among eligible sources.

Listing object metadata does not imply body-retrieval permission. Listing-only
authorization and provider-body authorization remain separate. The provider
prefix, compiled GCS URL, and source landing URL grant **no** permission by
themselves. This candidate is approved for neither listing nor body retrieval
until the required legal and operator authorization is complete. It is
replaceable through a reviewed ADR amendment or policy version. It is not a
production catalog commitment and not an authorization for all RustSec records.

Source selection does **not** block Session 13 Batch 2 operational-control
implementation. It **does** block listing-only provider contact until legal and
operator gates pass. It **does** block bounded-body retrieval until source and
per-advisory conditions pass.

### 4. Legal and provenance revalidation

Identifier: `osv_canary_legal_provenance_gate_v1`.

No provider contact is authorized until a human **instance legal and provenance
reviewer** (role, not a named person) records a current revalidation package.
Uncertainty is a blocking state. Session 11 Batch 3A-P `legalReviewStatus:
approved` is historical source-level evidence, not this canary's legal gate.
Provider prefix and source URL grant no permission. Provider absence does not
grant deletion permission. A changed registry must not broaden permissions for
an active run: the authorization record pins registry version and legal-decision
version; checkpoints re-evaluate; if the current registry is broader than the
pin, the pin wins; if the current registry is stricter, the run fails closed to
the stricter permission.

**Revalidation event:** before every listing-only authorization issue and,
separately, before every bounded-body authorization issue. Immutable decision
evidence must be retained as a versioned record (identifier, version, UTC
issued-at, role, phase, source, permissions, blocking/permitted states). Events
are not legal approval records.

Required evidence before **any** provider contact:

- source-license registry version (`osv_source_license_registry_v1` or a later
  reviewed successor)
- source evidence record for `rustsec_advisory_database`
- exact requested URL
- final URL policy (must equal requested URL; redirects rejected)
- redirect policy (`error`)
- HTTP status
- media type
- content encoding
- byte count
- SHA-256
- retrieval timestamp (UTC)
- work covered by the evidence
- mutable-URL status
- source ownership or archival status
- body-retrieval permission
- private-retention permission
- parser-normalization permission
- external-exposure permission
- attribution requirement
- per-advisory license requirement

Each permission dimension has evidence source, evidence version, responsible
approval role, blocking and permitted states, revalidation event, and immutable
decision evidence. Permissions are not inferred from one another:

| Permission | Evidence source | Listing-only | Bounded-body | Blocking state | Permitted state |
| --- | --- | --- | --- | --- | --- |
| List object metadata from the compiled GCS JSON API | Legal decision for GCS public-export listing contact | Required | Required and still current | `legal_gate_blocked` | Current listing decision |
| Retrieve advisory bodies | Source-level body-retrieval permission plus current legal decision | Not granted by listing | Required and still current | `legal_gate_blocked` | Current body-retrieval decision |
| Retain privately | Source-level retention plus advisory-level license confirmation | Not applicable to listing JSON pages as catalog bodies | Required before attachment | Reject retrieval until resolved | Confirmed supported license |
| Parse and normalize | After license confirmation | Forbidden | License-inspection parse only before retention; full parse after | `policy_violation` | Confirmed retention |
| Expose externally | Advisory-level confirmation | Forbidden | Conservative; canary review packages omit bodies | Forbidden for canary | Not granted in Session 13 |
| Use for internal matching | Product matching authorization | Forbidden | Forbidden for the canary | Forbidden | Not granted in Session 13 |

Listing-only still requires legal review of contacting
`storage.googleapis.com` for the compiled public-export listing surface. That
review is not a RustSec body-license conclusion.

Responsible approval role: instance legal and provenance reviewer, countersigned
by the instance operator who will execute the one-shot command. No tenant role
is sufficient.

### 5. Per-advisory license-field handling

Identifier: `osv_canary_rustsec_license_field_policy_v1`.

Applies only if RustSec remains the body-canary source after legal
revalidation. Do not implement the parser or storage-flow change in Session 13
Batch 1-R. The committed advisory parser currently **omits** the license field
from success envelopes. The committed disabled orchestrator **attaches** the
provider body before parse. Reusing that attach-then-parse path for bounded-body
would retain content before advisory-level confirmation. That is a **blocking
bounded-body implementation prerequisite**, not a Batch 2 operational-control
blocker.

Preferred fail-closed design:

| Decision | Disposition |
| --- | --- |
| Earliest inspection | After generation-bound retrieval of transient in-memory bytes, before any durable attach |
| Transient in-memory retrieval | Permitted for license evaluation only during bounded-body, after listing-only evidence is accepted and source-level body-retrieval permission is current |
| Durable body or parsed-document attachment before confirmation | **Forbidden** |
| Parser before confirmation | Bounded **license-inspection** parse of transient bytes only. Schema success does not override license policy |
| Two-stage parse | **Required.** Stage 1 inspects the advisory-level license field without durable attachment. Stage 2 full parse and durable attach occur only after retention is permitted |
| Missing field | Quarantine or bounded legal-policy rejection; no retention; no external exposure; no matching |
| Malformed field | Same as missing |
| Unsupported license | Same as missing |
| Contradictory source and advisory license | Fail closed to the stricter permission; no retention if the advisory value is missing, malformed, or unsupported |
| Private retention | Only after the advisory-level decision permits a supported license. Exact supported values come from the current legal decision, not from this ADR inventing a new allowlist |
| External exposure | Forbidden for the canary. Canary evidence review packages omit bodies |
| Internal matching | Forbidden. Canary bodies must not participate in matching |
| Duplicate `license` keys | Last-key-wins **must not** authorize durable legal classification or retention. Duplicate-aware extraction or fail-closed duplicate detection is required before durable legal classification. Do not add a parser dependency in this batch |

Fail closed. License-inspection implementation is a bounded-body (Session 13
Batch 4) prerequisite, not a listing-only prerequisite and not a Batch 2
heartbeat/authorization prerequisite.

### 6. Operator authorization and identity

Identifier: `osv_canary_operator_authorization_v1`.
Identity identifier: `osv_canary_instance_operator_identity_v1`.

The first canary must not be triggered by tenant users, public API, ordinary
authenticated users, scheduler, worker startup, Outbox replay, BackgroundJob
routing, configuration load, health checks, migrations, tests running in
production, or synthetic verification authority
(`createOsvDisabledRuntimeSynchronizationForVerification`).

**Provisional canary-scoped identity (option 3).** OD-10 remains open for a
general instance-operator console, bootstrap user, and IntelligenceSource
management. This ADR does not close OD-10. For canary Batch 2 persistence only,
select a narrowly scoped provisional identity that requires a separate
execution gate before Batch 3:

- Actor kind is the existing audit type `instance_operator`.
- Audit columns: `actorUserId` null, `organizationId` null,
  `actorMembershipId` null.
- `operatorAttestationId` is a UUID v4, instance-scoped, locally configured,
  nonsecret, and not a person name hardcoded in the repository.
- `operatorAttestationLabel` is a bounded nonsecret display string for audit.
- Authentication is local host control of the one-shot administrative command
  process, not Organization membership and not a product permission.
- Distinct from the lease holder token and from process or worker IDs.
- Tenant User IDs are prohibited. Anonymous operator canaries are forbidden.
- A different attestation UUID cannot consume another operator's authorization.

This identity is sufficient for Batch 2A persistence. Listing-only execution
still waits for a configured attestation UUID, legal gate, heartbeat, deadline,
runbooks, and egress proof.

### 6a. Immutable one-shot authorization record

Identifier: `osv_canary_execution_authorization_record_v1`.

Closed required fields (callers cannot add others):

- `authorizationId` (UUID v4)
- `operatorAttestationId` (UUID v4)
- `actorKind` (`instance_operator`)
- `phase` (`listing_only` or `bounded_body`)
- `providerPrefix` (`crates.io/`)
- `sourceIdentifier` (`rustsec_advisory_database`)
- `family` (`RUSTSEC`)
- `canaryPolicyIdentifier` (`osv_disabled_first_provider_canary_policy_v1`)
- `workScope` (`osv_runtime_canary_scope_crates_io_rustsec_v1`)
- `runtimeVersionSetFingerprint` (lowercase SHA-256 of the committed runtime
  version-set)
- `requestBudget` and `resourceBudget` (pinned from the phase ceilings; not
  caller-supplied)
- `issuedAt` (UTC)
- `expiresAt` (`issuedAt` plus 3600 seconds unused TTL)
- `singleUse` (true)
- `reason` (`operator_canary`)
- `runbookAcknowledgement` (true)
- `haltControlAcknowledgement` (true)
- `activationProhibitionAcknowledgement` (true)
- `legalDecisionReference` and `legalDecisionVersion`
- `postcanaryReviewRequired` (true)
- `consumedAt` (null until execution start)
- `terminalDisposition` (null until terminal)

Forbidden fields: arbitrary endpoint, arbitrary numeric bounds, tenant fields,
package inventory, activation option, matching option, Finding option, provider
credentials, page token, holder token.

**Consumption:** consume at successful execution start after durable request and
run ensure. Crash after consume cannot replay execution. Inspection of the
authoritative run result is permitted. Unused authorization expires after 3600
seconds and cannot start work. After execution start, the 1800-second canary
deadline governs, not the unused TTL.

**Persistence:** required in Session 13 Batch 2A as a forward-only Prisma
migration. Do not modify Prisma in Batch 1-R. Until that schema exists,
execution remains unauthorized.

### 7. One-shot execution boundary

Preferred future mechanism: a locally controlled **Node.js instance-operator
administrative command**. It is not the deferred [ADR 0018](0018-go-cli-deferred.md)
Go CLI, not an `apps/cli` product CLI, not a tenant HTTP API, and not a public
route. The command:

- validates one immutable one-shot authorization
- creates or ensures one durable global canary request and run
- uses existing lease, fencing, halt, deadline, and observability controls
- does not expose arbitrary endpoints or limits
- does not bypass halt or durable authorization
- does not publish a general production job type
- does not import `createOsvDisabledRuntimeSynchronizationForVerification`
- executes only the selected phase
- exits with a bounded result
- consumes the authorization exactly once at execution start
- does not activate a catalog

Rejected for the first canary:

- temporary HTTP API
- tenant-authenticated route
- worker startup hook
- scheduler window
- configuration-load execution
- manually inserted general `intelligence.osv.sync` production job
- synthetic verification factory as the production entrypoint
- arbitrary database-insertion instructions that bypass request/run authority

Prefer **direct one-shot execution** after durable authorization because the
canary is a single 1800-second process with lease, heartbeat, and fencing.
A canary-only durable job route is not authorized now. If a later review finds
process isolation insufficient, that route would require a separate reviewed
canary-only discriminant, canary-only payload, authorization identity, no
production profile, no scheduler producer, duplicate-delivery safety, and no
activation authority.

Do not implement the command in this batch.

### 8. Scheduler, BackgroundJob, and Outbox exclusion

Scheduler remains absent or disabled for OSV. No catch-up, recurring
registration, automatic startup run, or tenant scheduling.

The first canary does **not** add:

- a production OSV BackgroundJob discriminant
- a production OSV Outbox discriminant
- a BullMQ OSV processor
- reserved Outbox `intelligence.osv.sync.requested.v1` registration

If a later review finds that process isolation of the administrative command is
insufficient,
a specifically authorized global job route may be designed in a later batch.
That route is not authorized now. Prefer invoking the disabled runtime directly
after durable authorization.

### 9. OSV enablement interaction

`INTELLIGENCE_OSV_ENABLED` remains false and `true` remains rejected in every
environment. The canary must not weaken that rejection. Canary authorization is
a separate durable fact. Enablement true is never a canary permit.

### 10. Acquisition-halt interaction

Preferred defense-in-depth:

1. Production worker, API, and any future scheduler processes keep
   `INTELLIGENCE_OSV_ACQUISITION_HALT=true`. They are never restarted with halt
   released in order to run the canary.
2. Durable one-shot canary authorization is the execution permit
   (`osv_canary_execution_authorization_v1`). Halt release is not authorization.
3. The administrative command process may set halt false **only in its own
   process environment**. That process-local release does not mutate shared
   production env files and does not start worker/API composition.
4. Execution requires **both** a current unconsumed durable authorization **and**
   command-local halt permitted. Neither alone is sufficient. No configuration
   combination creates a canary.
5. `INTELLIGENCE_OSV_ENABLED` remains false.
6. After terminal handling, the authorization is consumed. The command process
   exits. Production services remain halted. Terminal handling does not depend
   solely on restoring an environment variable.
7. Environment refresh remains a process snapshot. Because production services
   are not the canary process, a production restart is not required to restore
   halt. Process-snapshot halt remains valid emergency containment.

Rejected: editing a shared production environment file, restarting worker with
halt false, and restoring halt after the run. That workflow is fragile and can
unintentionally enlarge the halt-release window. Operator control cannot acquire
synthetic verification authority. Authorization cannot silently become
production enablement.

### 11. Egress boundary

Allowed canary destination is the already committed listing surface:

- HTTPS
- host `storage.googleapis.com`
- port 443
- path `/storage/v1/b/osv-vulnerabilities/o`
- bucket `osv-vulnerabilities`
- compiled query grammar (`prefix`, `maxResults`, `fields`, optional `pageToken`)

Bounded-body later adds only the committed generation-bound retrieval surface
for the same host, port, bucket, and `ifGenerationMatch` binding. Redirects
remain rejected.

Prohibited: HTTP, alternate host, regional endpoint, signed URL, `mediaLink`,
`selfLink`, proxy selected from provider data, caller-selected endpoint,
redirects, arbitrary DNS result, private or loopback address, cloud metadata,
unrelated Google APIs, and body retrieval during listing-only.

Application controls already exist (fixed endpoint, DNS pinning, post-connect
verification, redirect rejection). Additional **operational** controls required
before provider contact, and not claimed as currently implemented:

- container or host egress allowlist to that host and port only
- deny cloud-metadata and link-local ranges at the host/network layer
- no outbound HTTP proxy for the canary process
- operator evidence that the deployed binary is the reviewed listing adapter

Do not claim network-level egress isolation exists today.

### 12. DNS and TLS readiness

The deployed canary environment must use the hardened transport controls:

- fixed server name
- TLS certificate verification
- DNS lookup pinning
- prohibited address ranges
- post-connect address verification
- no redirects
- no endpoint fallback
- no custom CA from provider input
- no proxy selected from request input

Operator evidence required before contact: build identity, configuration
snapshot proving no proxy env is honored, and a **synthetic** local TLS/DNS
double rehearsal of the same binary. No real DNS check is performed in this
batch.

### 13. Provider-rate protections

Concurrency remains one. No prefetch. One prefix. One A/B pair.

| Control | Listing-only | Bounded-body |
| --- | --- | --- |
| Active listing requests | 1 | 0 additional listing unless a new listing authorization exists |
| Maximum listing requests | 16 | 0 unless re-authorized |
| Provider-body requests | 0 | at most 16 |
| Parallel retrieval | n/a | 0 |
| Automatic retry | 0 | 0 |
| Scheduler | absent | absent |
| Repeated canary | new authorization required | new authorization required |

HTTP 429, retryable 5xx, and provider timeout: **stop**. Record
`future_explicit_retry_permitted` disposition. Do not retry during the canary.
Require human review before another attempt.

No inter-request delay is selected (`0` ms). Concurrency one and zero retries are
sufficient for the first canary. Do not invent a delay without evidence.
Postcanary review must inspect provider-rate signals (HTTP 429, retryable 5xx,
timeouts) before any later authorization.

### 14. Listing-only ceilings

Confirm ADR 0028 / `osv_disabled_first_provider_canary_policy_v1` without
increase:

| Limit | Value |
| --- | --- |
| Prefixes | 1 (`crates.io/`) |
| Passes | 2 |
| Pages per pass | 8 |
| Pages per run | 16 |
| Observations per pass | 2000 |
| Raw observations per run | 4000 |
| Response bytes per page | 1048576 |
| Response bytes per pass | 8388608 |
| Response bytes per run | 16777216 |
| Token UTF-8 bytes | 8192 |
| Listing concurrency | 1 |
| Retries | 0 |
| Duration | 1800 seconds |

Exact ceilings are allowed. Continuation at the page ceiling yields incomplete.
Incomplete is not success. No silent truncation. No body retrieval follows a
listing-only canary. No candidate becomes activation eligible. Useful evidence
may still be reviewed from a failed or incomplete canary.

### 15. Bounded-body ceilings

Later body-canary maximums. Do not increase without evidence.

| Limit | Value |
| --- | --- |
| Selected observations | 16 |
| Retrievals | 16 |
| Bytes per body | 1048576 |
| Aggregate received body bytes | 16777216 |
| Retrieval concurrency | 1 |
| Parser workers | 1 |
| Parser concurrency | 1 |
| Parser pending | 0 |
| Transport retries | 0 |
| Redirects | 0 |
| Activation calls | 0 |
| Duration | 1800 seconds (separate run; not stacked onto listing-only; not the 900000 ms lease TTL) |

Body-phase deadline budget from committed timeouts, not an unmeasured multi-hour
phase: 16 retrievals × 30 000 ms `totalRequestDeadlineMs` = 480 seconds worst
case; 16 parser executions × (5 000 ms execution + 1 000 ms forced termination)
≈ 96 seconds; remaining margin inside 1800 seconds covers storage, database,
heartbeat, and shutdown grace. The 1800-second total is exact and closed. Batch
2C implements the controller; it does not reopen the number.

Deterministic sample selection (`osv_canary_bounded_body_selection_v1`):

1. Start from the accepted listing-only canonical converged set, or fail closed
   if listing-only did not converge.
2. Filter through current source and legal eligibility for
   `rustsec_advisory_database` under the pinned registry and legal-decision
   versions.
3. Sort with `compareOsvListingCanonicalObservations` (committed canonical
   order: bytewise provider object key, then generation tie-breakers).
4. Take the first 16 eligible observations.
5. Preserve every filter or omission reason.
6. Never use random selection, operator-selected advisory IDs, package-based
   selection, or tenant input.

The selected set must pin listing-only evidence identity, exact object-key
digest, exact generation, declared size, source classification, legal-decision
version, and selection algorithm identifier
`osv_canary_bounded_body_selection_v1`. Changing selection rules requires a new
policy version. The canary tests compatibility, not representativeness. Do not
claim the sample is unbiased coverage of RustSec or crates.io.

### 16. Heartbeat and lease lifecycle

Heartbeat implementation **blocks both canary phases** because 1800 seconds
exceeds the 900000 ms lease TTL. Execution gate:
`heartbeat_controller_required_before_real_provider_canary`. Do not implement
the controller in this batch.

| Decision | Value |
| --- | --- |
| Owner | Canary runtime process after lease acquisition |
| Interval | 60000 ms |
| Lease TTL | 900000 ms |
| Time authority | Database `CURRENT_TIMESTAMP` |
| Row revision | Increments on heartbeat |
| Fencing token | Stable on heartbeat |
| Start | Only after lease acquisition |
| Stop | Before or during guarded release |
| In-flight heartbeats | 1 |
| Failure | Cancel further protected work; attempt guarded release; no retry |
| Halt / cancellation | Stop scheduling further heartbeats; still validate ownership before release |
| Process shutdown | Stop timer; attempt guarded release; preserve immutable evidence |
| Stale owner | Must not heartbeat, release, or continue |
| After release or ownership loss | No heartbeat |
| Overlap | Forbidden |

Heartbeat does not substitute for stage fencing. Every protected stage still
revalidates current ownership. Preferred shape: one runtime-owned bounded
heartbeat controller with timer removal on every terminal path. Do not maintain
a listing-only TTL-only mode. Implement heartbeat before either real-provider
phase.

Resolved races:

| Race | Disposition |
| --- | --- |
| Heartbeat versus release | Stop the controller, then attempt guarded release. Late heartbeat after stop is discarded |
| Heartbeat versus takeover | Heartbeat CAS miss is `ownership_lost`. Do not release another holder's lease |
| Heartbeat versus cancellation or halt | Stop scheduling new heartbeats. Validate ownership before release |
| Callback after stop | Ignored. No unhandled rejection. No timer leak |
| Database failure | `heartbeat_failed`. Stop successor work. Attempt guarded release if still current |
| Delayed event-loop or process suspension longer than TTL | Database expiry wins. Stop. Do not continue as if the lease were current |
| Overlapping timer callbacks | Forbidden. One heartbeat in flight |

A 30-minute canary is blocked until this controller is implemented and
adversarially reviewed.

### 17. Canary deadline

One authoritative monotonic deadline per authorized phase:

- listing-only: 1800 seconds
- bounded-body: 1800 seconds

Distinguish:

| Clock | Authority | Role |
| --- | --- | --- |
| Authorization unused TTL | `issuedAt` + 3600 seconds | Unused authorization expiry |
| Job-request age | Durable request timestamp | Audit identity, not takeover |
| Lease TTL | Database time | Ownership expiry (900000 ms) |
| Heartbeat interval | Runtime timer + database heartbeat | Keep-alive only (60000 ms) |
| Total canary deadline | Monotonic application time | Cancel the run (1800 seconds) |
| Individual request timeouts | Committed `OSV_TIMEOUT_POLICY_V1` | One request (30000 ms total) |
| Parser timeout | Committed parser policy | One parse (5000 ms execution) |
| Shutdown grace | Committed parser/host grace | Termination only |

Deadline owner must: cancel in-flight transport and parser work once, stop new
work, block successor stages, attempt guarded release, preserve immutable
evidence, produce a bounded deadline outcome, clean up timers, and never
trigger retry. Deadline must not replace database lease time. Do not implement
it in this batch. Provider contact remains forbidden until Batch 2C implements
this controller.

### 18. Cancellation, emergency halt, and abort

Ownership loss outranks cancellation. Cancellation outranks halt. Halt does not
create retries, reset fencing, delete the lease row, or activate a catalog.

Abort conditions and required behavior:

| Condition | Containment | Stage / run | Lease | Artifacts | Escalation | Later canary |
| --- | --- | --- | --- | --- | --- | --- |
| Operator cancellation | Stop next protected stage | `cancelled` | Guarded release if current owner | Retain immutable evidence | Instance operator | New authorization |
| Halt engaged | Stop next protected stage | `halted` | Release if current owner | Retain | Instance operator | New authorization after halt review |
| Authorization expired or consumed | Do not start or continue | `authorization_rejected` | No acquire if unused; guarded release if already owner | Retain authorization record | Instance operator | New authorization |
| Ownership lost | Discard late success | Do not fail another holder's run | Do not release another's lease | Retain | Instance operator | Inspect fencing before retry |
| Heartbeat failure | Cancel protected work | `failed` / heartbeat_failed | Guarded release if current | Retain | Instance operator | Heartbeat fix required |
| Total deadline | Cancel in-flight I/O | `failed` / deadline_exceeded | Guarded release if current | Retain | Instance operator | New authorization |
| Listing-page or run-byte limit | Stop listing | Incomplete, not complete | Release if current | Retain counts | Instance operator | Evidence-only; not completeness |
| Token cycle | Fail closed | Incomplete / token_cycle | Release if current | No raw token | Instance operator | New authorization |
| Inventory nonconvergence | No body retrieval | Incomplete | Release if current | Retain both passes | Instance operator | New authorization |
| HTTP redirect / address verify fail | Fail closed | `failed` / transport_failed | Release if current | No Location echo | Security + operator | Block until transport review |
| HTTP 429 / retryable 5xx / timeout | Stop, no retry | `failed` / provider_rate_limited or transport_failed | Release if current | Record disposition | Instance operator | Human review |
| Response too large | Stop that unit | Incomplete or item failure | Release if current | No truncated body success | Instance operator | Do not raise ceiling |
| Generation / integrity mismatch | Fail closed | Item / run failed | Release if current | No attach | Instance operator | New authorization |
| Storage immutable conflict | Fail closed | `failed` / storage_failed | Release if current | No overwrite | Instance operator | Inspect identity |
| Parser timeout / crash / schema failure | Fail closed | parser_failed | Release if current | Attempt row retained | Instance operator | New authorization |
| Source-policy failure | Fail closed | policy_violation | Release if current | Quarantine if required | Legal + operator | Legal review |
| Lease-release uncertainty | Do not loop release; do not delete row | `release_uncertain` | Inspect projection; no fencing reset | Retain | Instance operator | New authorization after inspection |
| Unexpected tenant or Finding side effect | Immediate halt | unexpected_side_effect | Release if current | Preserve for forensics | Security | Must not repeat until root cause |
| Activation attempt | Immediate halt | unexpected_side_effect | Release if current | Pointer snapshot | Security | Must not repeat |
| Telemetry confidentiality violation | Stop emission path | Continue fail-closed domain result | Unchanged | Redact / isolate sink | Security | Review sink before repeat |

No automatic retry.

### 19. Observability and operator evidence

Before provider contact, prove: event sink operational; sink failure does not
block safety; metric labels bounded; provider request counters active; lease and
fencing outcomes visible; page and byte buckets visible; halt and cancellation
visible; deadline visible; parser and storage outcomes visible for body phase;
candidate state visible as nonactive; release result visible.

Operator review package **may** contain: authorization identity, operator
attestation identity (not a secret), request ID, run ID, canary phase, policy
versions, scope, request counts, aggregate byte counts, observation counts,
page counts, provider status families, token-cycle outcome, convergence
outcome, heartbeat outcomes, deadline outcome, stage outcomes, retry
dispositions, body selection count, parser results, quarantine count,
reconciliation result, candidate state, lease-release result, halt restoration
or terminal authorization state, active-pointer unchanged proof, zero-Finding
proof.

Events are not legal approval records. Events are not operator authorization.
Events are not activation evidence.

It **must not** contain: page tokens, holder tokens, provider bodies, parsed
documents, raw keys, URLs, response headers, storage locators, tenant data,
package data, or Findings.

### 20. Evidence classification, retention, and cleanup

No broad deletion is authorized. Provider absence is not deletion
authorization. License change is not automatic deletion authorization.

| Class | Listing-only | Body phase | Mutability | Retention | Cleanup |
| --- | --- | --- | --- | --- | --- |
| Authorization record | Yes | Yes | Immutable one-shot | Retain | Not eligible |
| Synchronization request / run | Yes | Yes | Request immutable; run terminalizes | Retain | Not eligible |
| Lease evidence | Yes | Yes | Projection; no DELETE | Retain | Not eligible |
| Listing observations | Yes | Reused | Immutable observations | Retain | Not eligible |
| Pass / convergence results | Yes | Required input | Immutable | Retain | Not eligible |
| Operational events | Yes | Yes | Append-only telemetry | Operator log retention | Not catalog deletion |
| Provider-body snapshots | No | Yes, after license confirmation | Immutable attached | Only if private retention is currently permitted | Not eligible while referenced |
| Parsed documents | No | Yes, after license confirmation | Immutable | Same as bodies | Not eligible while referenced |
| Parser attempts | No | Yes | Immutable | Retain | Not eligible |
| Candidate generation | No | Isolated canary only | Lifecycle projection | Retain as canary-ineligible | Not eligible |
| Reconciliation / quarantine | No | Yes | Append-only | Retain | Not eligible |
| Postcanary review decision | Yes | Yes | Append-only | Retain | Not eligible |
| Temporary staged objects | No | Known temp only | Staging | Eligible only for known temp after successful attach or failed unreferenced temp | Exact identity only |

**Body-phase retention disposition until legal revalidation resolves it:
reject body retrieval (option 3).** After a current legal review permits
private retention, retain only evidence legally permitted for private
retention (option 2). Do not invent a legal retention duration. A cleanup
executor remains a later separately reviewed work item.

### 21. Duplicate JSON-key residual risk

ADR 0028 Option B remains: residual risk for a tightly bounded disabled canary;
detection or an explicit accepted security exception is required before
activation. This batch does **not** issue a security exception and does not add
a JSON parser dependency.

Listing-only: duplicate keys in listing pages remain undetected
(`last_key_wins_secure_json_parse_limitation`). Hardened constructors still
reject wrong prefix, oversize pages, malformed tokens, and observation
conflicts. Residual risk is accepted for listing-only because no body is
retrieved, no candidate is activation-eligible, and page admission is atomic.
It is not hidden. No security claim says duplicates are detected.

Bounded-body: advisory parser last-key-wins remains for identity, source
classification, schema revision, resource limits, and normalization eligibility
as reviewed in Batch 4D. **Last-key-wins must not authorize durable legal
classification of the per-advisory license field.** Duplicate-aware license
extraction or fail-closed duplicate detection is required before durable
retention based on that field. Catalog activation remains blocked until
duplicate-key detection exists or a separately accepted time-bounded security
exception exists. Matching and Findings remain unauthorized. This batch does
not issue a security exception.

### 22. Candidate-generation disposition

Listing-only: no candidate activation eligibility. The run may produce an
isolated canary inventory result. No production completeness claim.

Bounded-body: may create an isolated candidate generation that is permanently
prevented from production-scope activation. It cannot replace the active
pointer, trigger matching, or create Findings. Source-specific quarantine is
preserved.

**Schema gap (blocking implementation requirement before bounded-body, not a
Prisma change in this batch):** `OsvCatalogGeneration.inventoryScope` is the
production identifier `osv_gcs_six_prefix_public_export_v1`. Runtime canary
work scope is separate and does not currently mark a catalog generation as
canary-ineligible. Before any body canary implementation, a later batch must
introduce a distinct canary catalog/inventory scope or an immutable
canary-ineligible marker that activation predicates reject. Listing-only does
not create a candidate, so this gap does not authorize listing-only execution
by itself and does not require a Batch 1 migration.

### 23. Catalog-activation prohibition

Proof required after every canary:

- `activateReadyGeneration` call count remains zero
- active pointer unchanged before and after
- activation history unchanged
- no activation command in canary input
- no activation route or job
- no automatic successor after readiness
- acquisition halt applies to any future activation request
- duplicate-key gate remains unresolved or explicitly accepted later
- legal compatibility remains current

No canary outcome may authorize activation automatically.

### 24. Postcanary independent review

Mandatory after each real-provider canary. Reviewers must inspect: exact
operator authorization, policy versions, actual request count, actual response
byte counts, actual observation counts, token-cycle behavior, A/B convergence,
provider statuses, provider-rate signals, source classification, retrieval
counts, aggregate body bytes, parser outcomes, quarantine, reconciliation,
candidate state, lease and fencing, halt restoration, resource cleanup, active
pointer unchanged, zero-Finding, telemetry confidentiality, and legal
conditions.

Returns exactly one of:

- `listing_canary_evidence_accepted`
- `listing_evidence_accepted_with_corrections`
- `canary_must_not_be_repeated`
- `blocked_by_legal_issue`
- `blocked_by_transport_issue`
- `blocked_by_provider_rate_issue`
- `blocked_by_lease_or_heartbeat_issue`
- `blocked_by_security_issue`
- `blocked_by_operational_issue`

Only a separate accepted review may authorize the body phase. Only a separate
accepted review after the body phase may allow activation architecture work to
continue. No automatic progression from listing-only to body canary. No
automatic progression to activation.

### 25. Success, failure, and abort criteria

**Listing-only success** requires all of: exact authorization valid; one
approved prefix; request count ≤ 16; response bytes within ceilings; no
endpoint or TLS violation; no token cycle; both passes terminate; A/B
convergence accepted; no automatic retry; lease remained current via heartbeat;
halt/authorization behavior verified; lease release accepted; active pointer
unchanged; zero-Finding; evidence review package created.

A nonconverged inventory is **not** a successful completeness result. Run
outcomes:

- `completed_converged_listing_canary`: all listing-only success conditions
- `completed_incomplete_evidence_only_canary`: authorized run stopped at a
  ceiling or nonconvergence without transport or policy violation; useful
  evidence; not success
- `failed_canary`: abort or failure category below
- `cancelled_canary`: operator cancellation
- `halted_canary`: halt engaged
- `ownership_lost_canary`: fencing or takeover
- `deadline_exceeded_canary`: monotonic deadline
- `legally_blocked_canary`: legal gate
- `release_uncertain_canary`: lease-release CAS uncertainty

Do not label an incomplete or nonconverged listing as successful. A useful
evidence package does not imply success. A successful listing canary does not
imply body compatibility, production completeness, activation readiness, or
matching readiness.

**Bounded-body success** is defined only after listing-only evidence is
accepted and requires: at most 16 retrievals; aggregate body bytes ≤ 16777216;
license confirmation before retention; parser outcomes recorded; candidate
nonactive and canary-ineligible; no activation; zero-Finding; review package
created.

No failure automatically retries. Same-authorization replay after terminal
consumption is forbidden except for safe idempotent result retrieval of the
already-authoritative run. Every outcome defines primary code, phase, retry
disposition (`no_retry` during the first canary), operator consequence, lease
behavior, evidence retention, authorization consumption or expiry behavior, and
whether a new explicit authorization is required.

Closed canary terminal categories:

- `authorization_rejected`
- `legal_gate_blocked`
- `halt_engaged`
- `operator_cancelled`
- `ownership_lost`
- `heartbeat_failed`
- `deadline_exceeded`
- `transport_failed`
- `provider_rate_limited`
- `page_limit_exceeded`
- `inventory_not_converged`
- `policy_violation`
- `body_limit_exceeded`
- `generation_mismatch`
- `integrity_failed`
- `storage_failed`
- `parser_failed`
- `quarantine_blocked`
- `reconciliation_failed`
- `release_uncertain`
- `unexpected_side_effect`
- `internal_failure`

### 26. Runbook readiness

Required outlines live in [osv-canary.md](../runbooks/osv-canary.md). They are
**not** live procedures until implementation and operator rehearsal complete.

### 27. Zero-tenant and zero-Finding

Canary jobs, authorizations, leases, events, and artifacts must not include
organization, tenant, user-as-tenant-authority, asset, component, or Finding
identifiers. No tenant query or write. No matching write. No Finding,
FindingObservation, Evidence, RiskCalculation, `finding.recalculate`, tenant
Outbox, or tenant AuditEvent. Unresolved instance-operator identity must not be
solved with a tenant identity.

### 28. Implementation sequencing

The graph is acyclic:

canary ADR accepted
→ legal and provenance revalidation
→ provisional canary operator identity persisted (Batch 2A)
→ one-shot authorization persistence (Batch 2A)
→ execution boundary accepted and implemented (Batch 2B)
→ heartbeat controller implemented (Batch 2C)
→ deadline controller implemented (Batch 2C)
→ runbooks implemented and locally rehearsed (Batch 2D)
→ egress controls verified
→ halt behavior verified
→ listing-only authorization issued
→ listing-only canary executed (Batch 3)
→ listing evidence independently reviewed (Batch 3-R)
→ bounded-body authorization issued
→ license-inspection and canary-ineligible marker implemented
→ bounded-body canary executed (Batch 4)
→ body evidence independently reviewed (Batch 4-R)
→ duplicate-key activation gate resolved
→ activation architecture reviewed (Batch 5)
→ activation implemented separately (Batch 6, if authorized)
→ activation explicitly authorized
→ catalog activated
→ active catalog independently verified
→ matching architecture
→ evaluator
→ match evidence
→ Finding gate

No body phase before listing review. No provider contact before operator, legal,
egress, heartbeat, deadline, runbook, and halt gates. No activation before
body-canary review and duplicate-key resolution. No matching before verified
active catalog. No Findings before match evidence and
[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md).

## Alternatives considered

- Combine listing and body into one authorization. Rejected: irreversible
  retrieval before listing evidence exists.
- Treat Session 11 registry `approved` as canary legal authorization. Rejected:
  ADR 0028 requires revalidation; evidence URLs are mutable; per-advisory field
  is unresolved.
- Select GHSA or PYSEC instead. Rejected without new legal research and without
  a work-scope identity change.
- Temporary HTTP API. Rejected: enlarges the trigger surface.
- Release production halt by restarting worker. Rejected: fragile and can start
  a future composed runtime.
- Depend on 15-minute lease without heartbeat. Rejected: 1800 s exceeds TTL.
- Automatic retry during canary. Rejected: rate and safety risk.
- Invent an inter-request delay. Rejected: no evidence.
- Close OD-10 with a tenant user. Rejected: tenant contamination.
- Leave canary operator identity unspecified until OD-10 closes. Rejected:
  Batch 2 cannot persist an authorization record without a canary-scoped
  identity. Provisional identity is selected; OD-10 remains open.
- Use last-key-wins as legal authority for the RustSec license field. Rejected:
  duplicate keys could retain disallowed content.
- Reuse the committed attach-then-parse orchestrator for body canary. Rejected:
  it attaches before advisory-level confirmation.
- Issue a duplicate-key security exception. Rejected: activation remains gated.
- Claim network egress isolation. Rejected: only application controls exist.
- Combine Batch 2 identity, command, heartbeat, and runbooks in one batch.
  Rejected: schema and runtime work should be separately reviewable.

## Consequences

Positive: later Session 13 batches can implement operator authorization,
heartbeat, deadline, and runbooks against a closed canary policy without
enabling OSV or activating a catalog. Acceptance authorizes those operational
controls only.

Negative: legal revalidation, configured operator attestation, heartbeat,
deadline, runbook rehearsal, egress verification, license-inspection parse,
duplicate-aware license classification, and a canary-ineligible catalog marker
remain execution blockers. Listing-only cannot retrieve bodies. Body canary
cannot proceed on unresolved retention. OD-10 remains open for general operator
console work.

Session 13 sequence:

1. **Batch 1** (this ADR's original design): architecture and authorization
   design.
2. **Batch 1-R** (this acceptance): independent architecture and authorization
   review and narrow design corrections.
3. **Batch 2A:** operator identity and authorization persistence.
4. **Batch 2B:** one-shot administrative command and canary-only execution
   boundary.
5. **Batch 2C:** heartbeat and deadline controllers.
6. **Batch 2D:** executable runbooks and preflight.
7. **Batch 2-R:** combined operational-control adversarial review (this
   checkpoint). The listing-only execution bridge does not yet exist.
8. **Batch 3A:** listing-only execution bridge and final operator-confirmation
   contract, implemented and tested against a scripted provider port only.
   No real provider contact.
9. **Batch 3A-R:** execution-bridge adversarial review.
10. **Batch 3B:** explicitly authorized listing-only real-provider canary
    execution, only after legal revalidation, configured operator attestation,
    the reviewed Batch 3A bridge, heartbeat, runbooks, and egress proof.
11. **Batch 3B-R:** listing-canary evidence review.
12. **Batch 4:** bounded provider-body canary execution, only after listing
    evidence accepted, license-field gate, retention disposition, duplicate-aware
    license classification, and canary-ineligible candidate marker.
13. **Batch 4-R:** body, parser, storage, and legal evidence review.
14. **Batch 5:** catalog-activation architecture and authorization review.
15. **Batch 6:** explicit activation implementation, if authorized.
16. **Batch 6-R:** activation and rollback adversarial review.
17. **Session 13 closure:** session-wide review and PR.

Batch 1-R permitted changes: documentation, this Accepted ADR, narrow
contracts, invariant tests. Forbidden: CLI, job route, heartbeat controller,
deadline timer, canary execution, provider contact, activation, Prisma,
migrations, dependencies.

## Security and tenancy

No organization or tenant column enters canary authorization, jobs, leases, or
events. No Finding write. Outbound contact remains the compiled GCS surfaces
after later authorization. Page tokens, bodies, raw keys, URLs, headers, and
credentials must not appear in logs, metrics, traces, or review packages.
Synthetic verification authority remains nonpublic. Halt false in production
configuration still starts nothing.

Threat review (architecture; no runtime code in this batch):

| Threat | Disposition |
| --- | --- |
| Accidental production enablement | Enablement true remains rejected; no production composition |
| Unsafe halt release | Production services stay halted; durable one-shot + command-local halt |
| Operator spoofing | Provisional canary-scoped `instance_operator` attestation UUID; no tenant User; host-controlled command; OD-10 remains open for general console |
| Authorization replay | Consume at execution start; 3600 s unused TTL; single-use |
| Halt as authorization | Halt false alone starts nothing; durable unused authorization also required |
| Scheduler / job replay | Scheduler and OSV routes remain unregistered |
| Arbitrary endpoint / proxy / DNS rebinding / TLS confusion / redirects | Committed adapter controls; operational egress required before contact |
| Provider-rate excess | Concurrency 1, max 16 listing requests, zero retries, no inter-request delay, postcanary rate review |
| Token leakage / persistence | In-memory only; omitted from evidence |
| Unbounded pages | Exact canary ceilings |
| Lease expiry / missed heartbeat | Heartbeat required before execution; races closed in §16 |
| Stale-owner continuation | Committed fencing; late success discarded |
| Automatic retry | Prohibited for first canary |
| Legal-policy drift / per-advisory mismatch / unauthorized retention | Legal gate; retain-before-confirm forbidden; registry cannot broaden an active run |
| Parser duplicate keys | Option B documented for listing-only; last-key-wins must not authorize license-based retention; activation blocked |
| Evidence leakage | Closed review-package prohibition list |
| Activation bypass | Call count zero; pointer snapshot; canary-ineligible marker required before body phase |
| Tenant / matching / Finding implication | Zero-tenant and zero-Finding invariants |

## Operational failure plan

See [osv-canary.md](../runbooks/osv-canary.md). Until Batch 2 implements
controls and Batch 3 is authorized, the live OSV controls remain: reject
`INTELLIGENCE_OSV_ENABLED=true`, default halt, and absence of production
composition. Do not invent operator SQL that deletes evidence. Do not include
secrets.

## Session 13 Batch 2A implementation note

Session 13 Batch 2A implements framework-independent contracts only in
`@patchpilot/vulnerability-intelligence` (`src/osv/canary-authorization/`).
This note does not change the Accepted status of this ADR and does not
authorize provider contact, listing-only execution, body retrieval,
production enablement, scheduler registration, automatic retry, catalog
activation, matching, or Finding writes.

The original Batch 2 sequence named operator-identity and authorization
persistence as Batch 2A. Closer implementation splits that work the same
way Session 12 split Batch 5 contracts from Batch 6 persistence:

- Batch 2A: operator-identity and single-use authorization **contracts**.
- Batch 2B: canary authorization **persistence**.
- Batch 2C: one-shot administrative command and canary-only execution
  boundary.
- Batch 2D: heartbeat and deadline controllers.
- Batch 2E: executable runbooks and preflight.

Batch 2A does **not** implement operator authentication, authorization
persistence, CLI, API, scheduler, heartbeat, deadline, or provider contact.
Legal-decision issuance remains a blocking preexecution dependency. Halt
release and synthetic verification grant no authority. Prisma is unchanged.
OD-10 remains open for general console identity.

## Session 13 Batch 2B implementation note

Session 13 Batch 2B adds schema-only persistence for the committed Batch 2A
contracts in `@patchpilot/database`. Migration
`20260908120000_osv_canary_authorization_persistence` (frozen SHA-256
`321ac38a02090470aa5f09661cb0e29562327c16c9e341b44bc99516bd7fbd99`) is the
fifteenth frozen catalog entry. All fourteen prior migrations remain
byte-for-byte unchanged. Later SQL corrections require another forward-only
migration.

This note does not change the Accepted status of this ADR and does not
authorize provider contact, listing-only execution, body retrieval,
production enablement, scheduler registration, automatic retry, catalog
activation, matching, or Finding writes.

Batch 2B persists:

- instance-scoped operator identity (`osv_canary_instance_operator_identity`)
- one-shot phase-specific authorization (`osv_canary_authorization`)

Operator identity is instance owned. No tenant User or Organization relation
exists. Anonymous operator identity cannot persist. Listing-only and
bounded-body remain distinct rows. Authorization policy and budget bindings
are immutable. Bounded-body requires accepted listing-review evidence bound
to a completed listing-only authorization whose consumed request and run
match. Database time owns consumption, revocation, and expiration
transitions. One authorization is consumable once. Restrictive
`ON DELETE RESTRICT` relationships preserve evidence. No issuance,
consumption, or revocation adapter exists. No operator CLI, heartbeat, or
deadline implementation exists. Schema existence does not issue or consume
an authorization. OD-10 remains open. Session 13 remains zero-Finding.

## Session 13 Batch 2B-R implementation note

Session 13 Batch 2B-R independently reviewed the uncommitted Batch 2B schema
with disposable PostgreSQL and direct SQL. It did not contact
`storage.googleapis.com` or `osv.dev`. The same uncommitted migration
`20260908120000_osv_canary_authorization_persistence` was corrected and
frozen (SHA-256
`321ac38a02090470aa5f09661cb0e29562327c16c9e341b44bc99516bd7fbd99`).
Fifteen frozen migrations. All fourteen prior migrations remain
byte-for-byte unchanged. Later SQL corrections require another forward-only
migration.

This note does not change the Accepted status of this ADR and does not
authorize provider contact, listing-only execution, body retrieval,
production enablement, scheduler registration, automatic retry, catalog
activation, matching, or Finding writes.

Concrete schema corrections:

- operator identity must be inserted as active
- authorization must be inserted as issued
- bounded-body listing review requires a completed listing_only row
- listing request, run, and version-set fingerprint must match the consumed
  listing authorization
- one listing authorization may authorize one bounded-body row
- consume, revoke, and expire transitions compare against database time

Legal-decision and inventory-evidence UUIDs remain opaque references. Session
13 Batch 2C implements persist-and-compare adapters that verify locally
available immutable fields and completed listing-review evidence. Those
adapters do not authenticate operators, execute the canary, or contact a
provider. Session 13 Batch 2C-R independently reviewed those adapters.
Next checkpoint is Session 13 Batch 2D one-shot operator command boundary.

## Session 13 Batch 2C implementation note

Session 13 Batch 2C implements `createOsvCanaryAuthorizationPersistence` in
`@patchpilot/database` against the frozen Batch 2B schema. Operator and
authorization ensure are insert-once with immutable replay comparison.
Consumption is a database-time CAS that binds one request and one run.
Same-run replay is distinguishable from a second execution. Production
composition does not construct the factory. No CLI, heartbeat, deadline,
scheduler, or provider contact is included.

This note does not change the Accepted status of this ADR and does not
authorize provider contact, listing-only execution, body retrieval,
production enablement, scheduler registration, automatic retry, catalog
activation, matching, or Finding writes.

## Session 13 Batch 2C-R implementation note

Session 13 Batch 2C-R independently reviewed the uncommitted Batch 2C
adapters. Operator identity replay cannot overwrite immutable authority.
Revoked operators cannot issue new authorizations or consume unconsumed
authorizations. Authorization replay cannot overwrite immutable bindings.
Listing-only cannot escalate to bounded-body. Legal-decision and
listing-review substitution fail closed. Database time controls issuance,
expiration, consumption, revocation, and terminalization. Exactly one
concurrent consumer can win. Same-run replay is status reuse, not second
execution. Different-run replay is rejected. Terminal authorization
outcomes are immutable. Production composition does not construct the
factory. No CLI, heartbeat, deadline, scheduler, or provider contact is
included. Authorization consumption alone does not execute the canary.

This note does not change the Accepted status of this ADR and does not
authorize provider contact, listing-only execution, body retrieval,
production enablement, scheduler registration, automatic retry, catalog
activation, matching, or Finding writes.

## Session 13 Batch 2D implementation note

Session 13 Batch 2D implements `createOsvCanaryOneShotCommandService` in
`@patchpilot/vulnerability-intelligence`. The command authenticates an
instance operator through an injected port, loads one existing
authorization, evaluates acquisition halt independently, ensures one
canary synchronization request and run, consumes the authorization once,
and returns `authorized_preflight_required`. It does not create operator
identity or authorization. Production authentication is not operational.
There is no public CLI. The command does not acquire a lease, start
heartbeat or deadline, contact a provider, or enable OSV. Same-run replay
is status reuse. Different-run replay is rejected. Default halt does not
consume an issued authorization. Production composition does not construct
the factory. Session 13 Batch 2D-R independently reviewed and hardened this
command boundary: halt is re-evaluated immediately before consumption,
same-run replay compares consumed request/run bindings, authentication
proofs are bounded and redacted, and listing-only cannot escalate to
bounded-body. Next checkpoint is Session 13 Batch 2E heartbeat and deadline
controllers.

This note does not change the Accepted status of this ADR and does not
authorize provider contact, listing-only execution, body retrieval,
production enablement, scheduler registration, automatic retry, catalog
activation, matching, or Finding writes.

## Session 13 Batch 2E implementation note

Session 13 Batch 2E implements `createOsvCanaryLeaseHeartbeatController` and
`createOsvCanaryDeadlineController` in `@patchpilot/vulnerability-intelligence`
(`src/osv/canary-runtime-controls/`). Heartbeat cadence is exactly 60000 ms and
lease TTL remains 900000 ms. Both listing-only and bounded-body deadlines are
the committed 1800 seconds (1800000 ms) of monotonic elapsed time and are not
the lease TTL. At most one heartbeat is in flight. Successful heartbeat
replaces the row revision and keeps the fencing token unchanged. Delayed
callbacks revalidate ownership and fail closed at or beyond lease TTL without
catch-up. Stop blocks dispatch, cancels the timer, awaits one in-flight
heartbeat or the abort signal, and yields a private latest-revision proof for
later guarded release outside the controller. Deadline arms once, settles
once, and ignores late callbacks after completion or cancellation. Construction
performs no I/O. Production composition does not construct the factories. The
controllers do not acquire a lease, contact a provider, register a CLI, or
enable OSV. The closer Session 13 Batch 2 split used on this branch is 2A
contracts, 2B schema, 2C adapters, 2D command, 2E heartbeat and deadline
controllers, and 2F executable preflight. Provider-facing execution remains
later.

## Session 13 Batch 2E-R implementation note

Session 13 Batch 2E-R independently reviewed the uncommitted Batch 2E heartbeat
and deadline controllers. Heartbeat cadence remains exactly 60000 ms and lease
TTL remains 900000 ms. Both phase deadlines remain 1800000 ms of monotonic
elapsed time. Callers cannot override cadence, TTL, lateness, or duration.
Synchronous schedule callbacks fail closed and cannot resurrect terminal
state. Stale callbacks after reschedule cannot heartbeat. Halt during an
in-flight heartbeat prevents reschedule. Row revision must be the exact
successor; fencing changes fail closed. Already-aborted stop still awaits the
in-flight heartbeat so the latest accepted revision is retained. Early
deadline callbacks fail closed and cancel the timer. Event-sink failure cannot
change controller state. Construction still starts no timer. Production
composition still does not construct the factories. The controllers do not
acquire a lease, contact a provider, register a CLI, or enable OSV. Session
13 Batch 2F later added uncomposed executable preflight.

## Session 13 Batch 2F implementation note

Session 13 Batch 2F implements uncomposed `createOsvCanaryPreflightService`.
Preflight accepts one existing consumed authorization bound to the exact
request and run. Halt must be separately released and is rechecked immediately
before success. Lease scope is inspected without acquisition. Heartbeat and
deadline policies are validated without starting timers. Egress readiness
evaluates committed deployment policy without provider DNS or HTTP.
Listing-only skips storage and parser readiness; bounded-body requires them.
Active-pointer and zero-Finding baselines are captured and not modified.
Success is `canary_execution_preflight_passed_provider_contact_not_authorized`
and is not permission to contact a provider. Production composition does not
construct the factory. No public CLI, scheduler, job route, lease acquisition,
provider contact, activation, matching, or Finding writes.

## Session 13 Batch 2F-R implementation note

Session 13 Batch 2F-R independently reviewed the uncommitted Batch 2F
preflight. Halt is re-evaluated at each protected checkpoint and immediately
before success, including after authorization validation so request/run
inspection does not start under halt. Public fake-ready committed ports are
not package exports. Event-sink reentry cannot start a nested preflight.
Egress distinguishes application-verified controls from deployment controls
that are declared but not externally proven. Active-pointer and
activation-history reads share one read-only Repeatable Read transaction.
Zero-Finding baseline captures bounded counts and canary-attributed write
proofs; global Finding absence is not required. Success still does not
authorize provider contact. Next checkpoint was Session 13 Batch 2-R
combined operational-controls review.

## Session 13 Batch 2-R implementation note

Session 13 Batch 2-R independently reviewed the combined operational-control
chain. Authentication establishes identity only. Authorization remains
distinct from halt and lease ownership. One authorization is consumed once.
The command stops at `authorized_preflight_required`. Preflight success is
`canary_execution_preflight_passed_provider_contact_not_authorized` and is
not permission to contact a provider. Lease inspection remains read-only.
Heartbeat and deadline readiness start no timers. No production CLI, API,
scheduler, or job route is registered. At this Batch 2-R checkpoint the
listing-only execution bridge did not exist. Next checkpoint was Session 13
Batch 3A listing-only execution bridge against a scripted provider port.

## Session 13 Batch 3A implementation note

Session 13 Batch 3A implements uncomposed
`createOsvCanaryListingOnlyExecutionBridge` in
`@patchpilot/vulnerability-intelligence`. It requires a fresh
instance-operator execution confirmation, reloads consumed listing-only
authorization plus exact request/run and accepted preflight evidence,
rechecks halt and egress, acquires the global OSV lease, starts heartbeat,
arms the listing-only deadline, and then executes one scripted prefix with
exact pass A and pass B. Ownership is revalidated before every page.
Continuation tokens remain in memory only. Body retrieval, parser, storage,
activation, matching, and Finding writes remain zero. Automatic retries
remain zero. Controllers stop, then the run and authorization are
terminalized under current ownership, then guarded release uses the latest
row revision. Success is
`listing_only_scripted_inventory_converged` with
`executionMode=scripted_provider_only` and
`realProviderContactAuthorized=false`. Preflight evidence alone cannot
authorize provider contact. The scripted listing-capability constructor and
verification factory are not public package exports. No real-provider
capability exists. Production composition does not construct the factory.
No public CLI, API, scheduler, or job route is added. Session 13 Batch 3A-R independently reviewed this bridge. This note does not change the Accepted status of this ADR and does not
authorize real provider contact, body retrieval, production enablement,
scheduler registration, automatic retry, catalog activation, matching, or
Finding writes.

## Session 13 Batch 3A-R review note

Session 13 Batch 3A-R independently reviewed the uncommitted Batch 3A
listing-only execution bridge. Concrete corrections: held-by-other does
not terminalize the authorization or run; accepted preflight evidence must
wrap a constructed preflight success; legal revalidation uses inspect
observed-at against the recorded boundary; halt and scripted egress are
rechecked before every page; halt during listing remains `halt_engaged`
and still releases a current lease; a generic listing `policy_violation`
is not classified as ownership loss. Fresh operator confirmation remains
mandatory. Real-provider capability remains absent. Production composition
does not construct the factory. Next checkpoint relative to this
Batch 3A-R note was Session 13 Batch 3B listing-only provider-contact
authorization.

This note does not change the Accepted status of this ADR and does not
authorize real provider contact.

## Session 13 Batch 3B implementation note

Session 13 Batch 3B implements uncomposed
`createOsvListingProviderContactAuthorizationService` in
`@patchpilot/vulnerability-intelligence`
(`src/osv/canary-provider-contact-authorization/`). The operation is
`evaluateOsvListingProviderContactAuthorization`. Fresh instance-operator
confirmation remains mandatory. Only an existing consumed listing-only
canary authorization bound to the exact request and run may proceed.
Accepted provider-free preflight evidence must keep
`providerContactAuthorized=false`. Current listing-metadata legal approval
is required; body retrieval remains prohibited. Versioned egress and
deployment evidence are fail-closed; generic `ready: true` is insufficient.
Heartbeat and deadline policies are validated without starting timers.
Acquisition halt is observed and not cleared. Existing
`osv_canary_authorization` cannot represent this without phase and
lifecycle ambiguity. After other gates pass, evaluation fails closed with
`persistence_required` and does not return an in-memory authorization
package. Session 13 Batch 3B-P later added the distinct schema. Durable
issuance adapters remain later. No real-provider capability exists.
Production composition does not construct the factory. No public CLI, API,
scheduler, or job route is added. Batch 3B-R is deferred until durable
issuance exists. Batch 3C remains blocked until durable issuance exists.

This note does not change the Accepted status of this ADR and does not
authorize real provider contact, body retrieval, production enablement,
scheduler registration, automatic retry, catalog activation, matching, or
Finding writes.

## Session 13 Batch 3B-P implementation note

Session 13 Batch 3B-P adds schema-only persistence for a distinct
listing-only OSV provider-contact authorization. Existing
`osv_canary_authorization` is not reused. Migration
`20260909120000_osv_listing_provider_contact_authorization_persistence`
(frozen SHA-256
`8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`).
Sixteen frozen migrations. All fifteen prior migrations remain
byte-for-byte unchanged. Tables `osv_canary_provider_free_preflight_attestation`
and `osv_listing_provider_contact_authorization` are global and instance
owned. One provider-contact authorization binds one consumed listing-only
source canary authorization, one request, one run, and one accepted
provider-free preflight attestation. Listing-only is the only representable
phase. Body retrieval remains prohibited. Database time owns issuance,
expiration, consumption, revocation, and terminalization. DELETE is
forbidden. Schema existence does not issue or consume an authorization.
No issuance or consumption adapter existed in Batch 3B-P. Session 13 Batch 3B
evaluation still fails closed with `persistence_required`. Production
composition does not construct the evaluation factory. No public CLI, API,
scheduler, or job route is added. Session 13 Batch 3B-P-R independently
reviewed and hardened that uncommitted schema before freeze. Next checkpoint
relative to this note was Session 13 Batch 3B-A durable issuance.

This note does not change the Accepted status of this ADR and does not
authorize real provider contact, body retrieval, production enablement,
scheduler registration, automatic retry, catalog activation, matching, or
Finding writes.

## Session 13 Batch 3B-P-R implementation note

Session 13 Batch 3B-P-R independently reviewed the uncommitted Batch 3B-P
schema with disposable PostgreSQL and direct SQL. It did not contact
`storage.googleapis.com` or `osv.dev`. Migration
`20260909120000_osv_listing_provider_contact_authorization_persistence`
(frozen SHA-256 after review
`8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`).
Sixteen frozen migrations. Concrete corrections: future `issued_at` is
rejected; `issued_at` cannot precede preflight `captured_at`; future
preflight timestamps and future `consumed_at` are rejected; consumption
rechecks an active operator, a still-consumed source canary authorization,
a current legal revalidation boundary, and the bound preflight still
attesting unauthorized provider contact; a consumed source cannot leave
consumed while a child grant is issued or
`consumed_for_listing_execution`; insert matches source provider, prefix,
family, policy, and listing budget. Schema existence still does not issue or consume an
authorization. No issuance or consumption adapter exists in Batch 3B-P-R.
Batch 3B evaluation still fails closed with `persistence_required`. Next
checkpoint relative to this note was Session 13 Batch 3B-A.

This note does not change the Accepted status of this ADR and does not
authorize real provider contact, body retrieval, production enablement,
scheduler registration, automatic retry, catalog activation, matching, or
Finding writes.

## Session 13 Batch 3B-A implementation note

Session 13 Batch 3B-A implements uncomposed PostgreSQL adapters
(`createOsvListingProviderContactAuthorizationPersistence` in
`@patchpilot/database`) against the frozen Batch 3B-P schema. Issuance
validates the consumed listing-only source canary authorization, exact
request and run, accepted provider-free preflight evidence, operator,
legal, egress, deployment, and closed listing-only policy bindings, then
inserts with database-owned `issued_at` and
`expires_at = issued_at + 3600 seconds`. Identical issued replay is
`already_applied`. Immutable disagreement is `immutable_conflict`.
Inspection is read-only and uses database time so
`databaseNow >= expiresAt` is expired. Consumption is one
compare-and-swap from `issued` with exact bindings and
`CURRENT_TIMESTAMP < expires_at`. Same-run replay is status only.
Different-run replay fails closed without revealing the other run.
Revocation is from `issued` only. There is no row-revision column; CAS
uses issued state, bindings, and database time. Adapters perform no
provider, lease, timer, activation, matching, or Finding work. Production
composition does not construct the factory. Session 13 Batch 3B evaluation
still fails closed with `persistence_required`. Successful consumption
remains necessary but insufficient for provider contact. Session 13 Batch
3B-A-R independently reviewed and hardened those adapters: issuance replay
compares legal evidence-set identity, legal issued-at, and acknowledgement
timestamps; time-expired issued rows are `immutable_conflict`; insert
requires current legal revalidation at database time; consume after
operator revocation is `operator_revoked`; inspect omits the record on
`consumed_other_run`. Schema and migration remain unchanged. Next
checkpoint is Session 13 Batch 3B-R combined provider-contact
authorization review. Batch 3C remains blocked until reviewed consumption
composition exists.

This note does not change the Accepted status of this ADR and does not
authorize real provider contact, body retrieval, production enablement,
scheduler registration, automatic retry, catalog activation, matching, or
Finding writes.

Remaining Session 13 execution gates after this combined review:

- Legal and provenance revalidation of listing contact and, separately, RustSec
  body permissions.
- Session 13 Batch 2C: persist-and-compare adapters implemented and
  adversarially reviewed in Batch 2C-R.
  Do not close OD-10.
- Session 13 Batch 2D: one-shot Node.js administrative command boundary
  implemented and uncomposed. Authentication remains an injected port.
  Session 13 Batch 2D-R independently reviewed that command. Production CLI
  remains later. Do not close OD-10.
- Session 13 Batch 2E: heartbeat and deadline controllers implemented and
  uncomposed. Session 13 Batch 2E-R independently reviewed those controllers.
- Session 13 Batch 2F: executable preflight and operator runbooks implemented
  and uncomposed. Success does not authorize provider contact. Session 13
  Batch 2F-R independently reviewed that preflight.
- Session 13 Batch 2-R: combined operational-control adversarial review
  complete.
- Session 13 Batch 3A: listing-only execution bridge against a scripted
  provider port implemented and uncomposed. Real-provider capability does
  not exist. Session 13 Batch 3A-R independently reviewed that bridge.
- Session 13 Batch 3B: listing-only provider-contact authorization
  evaluation implemented and uncomposed. After other gates pass,
  evaluation fails closed with `persistence_required` and does not mint
  in-memory authority.
- Session 13 Batch 3B-P: schema-only distinct listing-only provider-contact
  authorization persistence implemented. Session 13 Batch 3B-P-R independently
  reviewed and froze that schema.
- Session 13 Batch 3B-A: uncomposed listing-only provider-contact
  authorization issuance, inspection, consumption, and revocation adapters
  implemented. Production composition does not construct the factory.
  Successful consumption does not authorize provider contact. Session 13
  Batch 3B-A-R independently reviewed those adapters. Next is Session 13
  Batch 3B-R combined provider-contact authorization review. Batch 3C
  remains blocked until reviewed consumption composition exists.
- Canary-ineligible catalog/inventory marker before bounded-body (Batch 4
  prerequisite; schema only if contracts cannot distinguish safely).
- Per-advisory license-inspection parse and duplicate-aware license
  classification before bounded-body. Do not reuse attach-then-parse as-is.
- Duplicate-key detection or named exception with expiry before activation.
- Invariant tests that this ADR remains Accepted, that acceptance does not
  authorize provider contact, and that production runtime remains unreachable.
