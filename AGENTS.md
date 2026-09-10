# PatchPilot agent and contributor guide

This is the central navigation document for coding agents and human contributors.

PatchPilot is a production-minded, self-hosted platform for software asset inventory, CycloneDX SBOM processing, vulnerability correlation, explainable environmental risk, remediation tracking, and audit-preserving evidence. The product must remain fully useful without an AI provider.

This paragraph states the product direction, not current feature completion. The authoritative current project status below identifies which product capabilities are implemented, disabled, or not yet implemented.

Read this file before editing. Then read the Cursor rules and documents that apply to the files you will change.

## Rule precedence

1. Repository-wide security, tenancy, and authorization rules in this file and in [`.cursor/rules/security.mdc`](.cursor/rules/security.mdc) always apply.
2. Instructions closer to a file (narrower Cursor rules, directory guides, or file-level comments) may **add** constraints.
3. Closer instructions **must not silently weaken** repository-wide security, tenancy, authorization, secret handling, or audit rules.
4. If two instructions conflict, keep the stricter security and tenancy interpretation and record the conflict in the change description or an ADR.

Do not treat product, styling, or convenience guidance as permission to bypass deny-by-default authorization, organization scoping, input validation, or secret handling.

## Authoritative current project status

Last verified checkpoint: Session 13 Batch 3C (one operator-controlled listing-only real-provider GCS canary; halt restored; lease released; Session 13 Batch 3C-R evidence review is mandatory).
Current session: Session 13.
Current checkpoint: Session 13 Batch 3C implemented uncomposed `createOsvBoundedListingCanaryService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-bounded-listing/`) and the nonpublic operator entry `scripts/run-osv-listing-canary.mjs`. After local gates and explicit operator invocation, exactly one listing HTTPS request was sent to the committed `storage.googleapis.com` GCS JSON Objects listing path for prefix `crates.io/`. Outcome `listing_canary_one_page_classified`: one request attempted, one HTTP 200 listing page accepted, 320143 response bytes, 1000 observations, continuation token present and not followed, retries 0, pagination follow-ups 0, body requests 0. Halt restoration `restored`. Deadline stopped. Heartbeat stopped. Guarded lease release `released`. Active pointer unchanged. Zero Finding operations. Raw response bytes and continuation tokens were not persisted. No provider fixture was committed. Production worker, API, scheduler, queue, health, seed, and migration composition do not import the factory or run the operator command. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Next checkpoint is Session 13 Batch 3C-R listing-canary evidence review.
Current branch: `feat/osv-provider-canary`.

PatchPilot currently provides authentication, organization selection, asset inventory, SBOM upload and ingestion, local graph persistence, local CISA KEV synchronization, sanitized provider status, canonical CVE identity, a disabled synthetically verified OSV acquisition foundation, an uncomposed, adversarially reviewed Session 12 Batch 1 GCS listing-page HTTPS executor, Session 12 Batch 3 framework-independent listing pagination and two-pass inventory convergence contracts, an explicitly invoked Session 12 Batch 4 in-memory pagination and convergence service, the Session 12 Batch 4-R adversarial review of that service, Session 12 Batch 5 framework-independent durable synchronization job, lease, retry, parser-capacity, halt, cancellation, and operational-event contracts, Session 12 Batch 6 schema-only OSV runtime coordination persistence, Session 12 Batch 7 uncomposed PostgreSQL runtime-coordination adapters, the Session 12 Batch 7-R adversarial review of those adapters, Session 12 Batch 8 disabled runtime composition (`createOsvDisabledRuntimeSynchronization`), Session 12 Batch 9 typed acquisition halt and bounded operational observability, the Session 12 Batch 10 runtime-enablement foundation closure review, Session 13 Batch 2E-R adversarially reviewed uncomposed canary lease-heartbeat and monotonic-deadline controllers, Session 13 Batch 2F uncomposed executable canary preflight, Session 13 Batch 2F-R adversarial review of that preflight, Session 13 Batch 2-R combined operational-controls review, Session 13 Batch 3A uncomposed listing-only execution bridge against a scripted provider port (`createOsvCanaryListingOnlyExecutionBridge`), the Session 13 Batch 3A-R adversarial review of that bridge, Session 13 Batch 3B uncomposed listing-only provider-contact authorization evaluation (`createOsvListingProviderContactAuthorizationService`), Session 13 Batch 3B-A uncomposed listing-only provider-contact authorization PostgreSQL adapters (`createOsvListingProviderContactAuthorizationPersistence`), adversarially reviewed in Session 13 Batch 3B-A-R, Session 13 Batch 3B-R combined provider-contact authorization review, Session 13 Batch 3C-Auth uncomposed listing-canary execution-authorization (`createOsvListingCanaryExecutionAuthorizationService`), adversarially reviewed and hardened in Session 13 Batch 3C-Auth-R, and Session 13 Batch 3C uncomposed operator-controlled bounded listing canary (`createOsvBoundedListingCanaryService`) that executed exactly one real GCS listing request. The pagination service, Batch 5 contracts, Batch 6 tables, Batch 7 adapters, Batch 8 composition, Batch 9 halt/observability controls, Batch 2E controllers, Batch 2F preflight, the one-shot command, the Batch 3A execution bridge, the Batch 3B provider-contact authorization service, the Batch 3B-P provider-contact authorization tables, the Batch 3B-A persistence factory, the Batch 3C-Auth execution-authorization service, and the Batch 3C bounded listing-canary service remain production-unreachable. The operator script is not registered in worker, API, or application startup. General OSV runtime remains disabled. Session 13 Batch 3C-R listing-canary evidence review is mandatory.

PatchPilot does not yet provide the primary end-user vulnerability workflow: authoritative package normalization, affected-version evaluation, component-to-advisory matching, OSV-derived Findings, explainable production risk scores, remediation workflows, dashboards, or reports.

### Product state

Implemented:

- Local password authentication, opaque sessions, CSRF, organization selection, and the Session 6 web login shell.
- Tenant-scoped asset inventory.
- CycloneDX JSON SBOM upload, object storage, outbox-driven ingestion, worker-thread parse, and graph persistence.
- CISA KEV synchronization and authenticated sanitized provider-status GETs.
- Canonical CVE identity persistence and read-only active-catalog KEV membership derivation.
- Disabled, synthetically verified OSV acquisition foundation (classification, one-attempt retrieval adapter, immutable storage, isolated parser worker, persistence, disabled orchestrator).
- Session 12 Batch 1 uncomposed GCS listing-page HTTPS executor (`createOsvGcsListingHttpsAdapter` in `@patchpilot/integrations`), adversarially reviewed and hardened in Session 12 Batch 2. Successful one-page results expose exact `responseByteCount`.
- Session 12 Batch 3 framework-independent OSV listing pagination and two-pass inventory convergence contracts in `@patchpilot/vulnerability-intelligence` (`src/osv/listing-pagination/`).
- Session 12 Batch 4 explicitly invoked in-memory listing pagination and two-pass inventory-convergence service (`createOsvListingPaginationService`) using an injected one-page listing port. One prefix, one pass, and one page at a time. No production composition and no provider contact in tests. Session 12 Batch 4-R adversarially reviewed and hardened that service with synthetic listing pages and scripted ports only.
- Session 12 Batch 5 framework-independent OSV durable synchronization job, lease, fencing, retry, parser-capacity, halt, cancellation, restart, and bounded operational-event contracts in `@patchpilot/vulnerability-intelligence` (`src/osv/runtime-coordination/`). No lease adapter, retry execution, scheduler, or production composition.
- Session 12 Batch 6 schema-only OSV runtime coordination persistence in `@patchpilot/database`, adversarially reviewed and hardened in Session 12 Batch 6-R: immutable synchronization request, one run per request, current lease projection (holder-token digest only, separate BIGINT row revision and fencing token, DELETE forbidden so fencing cannot reset), and identity-immutable stage attempts that may transition once from planned or running to a terminal state. Migration `20260907120000_osv_runtime_coordination_persistence` (frozen SHA-256 `7017b1c4b1d4bcae8bed4bdd0eb43559c0c89fce5b3636e0e889b276013cc3a6`).
- Session 12 Batch 7 uncomposed PostgreSQL adapters (`createOsvRuntimeCoordinationPersistence` in `@patchpilot/database`) for request/run ensure, database-time lease acquire/heartbeat/release/stale takeover, fencing CAS, immutable stage-attempt reservation and terminal recording, and retry-eligibility inspection. Session 12 Batch 7-R adversarially reviewed those adapters: expired owners cannot heartbeat or release, attempt reservation is transactional and ordered, BIGINT values retain exact precision, and retry inspection is not dispatch authority. No retry execution, scheduler, or production composition.
- Session 12 Batch 8 disabled runtime composition (`createOsvDisabledRuntimeSynchronization` in `@patchpilot/vulnerability-intelligence`). Explicitly constructed. Assembles committed listing pagination, inventory convergence, lease/fencing, stage attempts, disabled acquisition orchestration, and candidate readiness. Construction performs no I/O. Worker, API, scheduler, queue, health, seed, and migration composition do not import the factory. No periodic heartbeat loop. Retry disposition is recorded and not executed. Candidate readiness never activates a catalog. Session 12 Batch 8-R adversarially reviewed that composition: the public factory cannot be enabled by a request field or package subpath; listing late-success is discarded after ownership loss; attempt reservation failure prevents stage execution; stale owners do not fail the authoritative run; inventory-to-acquisition conversion requires exact prefix plans; and cross-layer rehearsal cleans test-owned MinIO and PostgreSQL rows.
- Session 12 Batch 9 typed acquisition halt (`intelligence.osvAcquisitionHalt` from `INTELLIGENCE_OSV_ACQUISITION_HALT` in `@patchpilot/config`) and bounded operational observability for the disabled composition. Default, missing, and empty values are halted. Explicit `false` releases halt only and does not enable OSV. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt is re-evaluated synchronously at protected checkpoints. Environment refresh is a process snapshot (restart required). Operational events use `osv_runtime_operational_event_catalog_v1`. Event-sink failure cannot change the domain result. No scheduler, production job route, retry executor, heartbeat loop, or provider contact. Session 12 Batch 9-R independently reviewed and hardened that halt and observability work: prototype-derived halt values cannot release halt; the public halt-state port is observation only; pass B and next-prefix listing stops are named checkpoints; the first blocking halt checkpoint is preserved; event emission is bounded per invocation; metric labels are closed per metric name.
- Session 12 Batch 10 independently reviewed the committed Batches 1 through 9-R runtime-enablement foundation. Listing transport, pagination, token confidentiality, lease fencing, disabled composition, halt defaults, and bounded observability remain consistent with the committed policies. Production OSV remains disabled and uncomposed.
- Session 13 Batch 1 defines [ADR 0029](docs/adr/0029-first-real-provider-osv-canary-authorization-and-safety.md) (`osv_first_real_provider_canary_authorization_v1`) for the first real-provider OSV canary. Session 13 Batch 1-R independently reviewed and **Accepted** that ADR. Acceptance authorizes only later operational-control implementation. RustSec / `crates.io/` remains the provisional technical candidate, blocked on legal revalidation. Listing-only and bounded-body phases are separately gated. No CLI, scheduler, job route, heartbeat controller, deadline timer, provider contact, activation, matching, or Findings are included.
- Session 13 Batch 2A defines framework-independent canary-scoped instance-operator identity and single-use authorization contracts in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-authorization/`). Authentication is contract-only and not implemented. Halt release and synthetic verification grant no authority.
- Session 13 Batch 2B adds schema-only canary authorization persistence in `@patchpilot/database`: global `osv_canary_instance_operator_identity` and `osv_canary_authorization` tables, migration `20260908120000_osv_canary_authorization_persistence` (frozen SHA-256 `321ac38a02090470aa5f09661cb0e29562327c16c9e341b44bc99516bd7fbd99`). Session 13 Batch 2B-R independently reviewed and froze that uncommitted schema. Fifteen frozen migrations.
- Session 13 Batch 2C implements uncomposed PostgreSQL adapters (`createOsvCanaryAuthorizationPersistence` in `@patchpilot/database`) for insert-once operator and authorization ensure, immutable replay comparison, operator revocation and authority inspection, database-time validity inspection, atomic single-use consumption with request/run binding, same-run consumed replay, different-run rejection, pre-consumption revocation and cancellation, durable expiration, and consumed terminal disposition. Session 13 Batch 2C-R independently reviewed those adapters: revoked-operator replay cannot recreate authority, unconsumed authorizations cannot be consumed after operator revocation, legal-decision revalidation is database-time fail-closed, listing-review substitution fails closed, unique consume bindings are not treated as identity replay, and mappers fail closed on malformed rows. Production composition does not construct the factory. No CLI, heartbeat, deadline, scheduler, or provider contact. Session 13 remains zero-Finding.
- Session 13 Batch 2D-R independently reviewed and hardened `createOsvCanaryOneShotCommandService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-operator-command/`). Framework-independent. Injected instance-operator authentication port. Loads one existing authorization. Does not create operator identity or authorization. Evaluates halt independently before request/run ensure and again immediately before consumption, and does not consume under default halt or after a later halt engagement. Ensures one canary request and one run, consumes the authorization once, and returns `authorized_preflight_required`. Same-run replay is status reuse. Different-run replay is rejected. Stops before lease, heartbeat, deadline, and provider contact. Production authentication is not operational. No public CLI. Production composition does not construct the factory.
- Session 13 Batch 2E implements uncomposed `createOsvCanaryLeaseHeartbeatController` and `createOsvCanaryDeadlineController` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-runtime-controls/`). Heartbeat cadence is exactly 60000 ms and lease TTL remains 900000 ms; callers cannot override either. At most one heartbeat is in flight. Successful heartbeat replaces the row revision and must keep the fencing token unchanged. Halt, cancellation, ownership loss, expiry, timing violation, and stop are terminal and schedule nothing further. Delayed callbacks revalidate ownership and fail closed at or beyond lease TTL without catch-up bursts. Both listing-only and bounded-body deadlines are the committed 1800000 ms monotonic duration, not the lease TTL. Stop blocks dispatch, cancels the timer, awaits one in-flight heartbeat or the abort signal, and yields a private release proof for later guarded release outside the controller. Construction performs no I/O. Production composition does not construct the factories. No lease acquisition, provider contact, retry, CLI, or OSV enablement.
- Session 13 Batch 2E-R independently reviewed those uncommitted controllers with scripted ports, fake clocks, hostile schedulers, and disposable PostgreSQL. Concrete corrections: synchronous schedule callbacks cannot resurrect terminal state; stale callbacks after reschedule are ignored; halt during an in-flight heartbeat prevents reschedule; row revision must be the exact successor; monotonic clock values must be integers; already-aborted stop still awaits the in-flight heartbeat so the latest accepted revision is retained; early deadline callbacks fail closed; event-sink `stop()` during emit cannot deadlock. Production composition still does not construct the factories. No lease acquisition, CLI, or provider contact.
- Session 13 Batch 2F implements uncomposed `createOsvCanaryPreflightService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-preflight/`). It loads one existing consumed authorization bound to the exact request and run, rechecks halt before local work and immediately before success, inspects lease scope without acquisition, validates heartbeat and deadline policies without starting timers, validates egress without provider DNS or HTTP, checks listing-only database and observability readiness, requires object storage and parser readiness only for bounded-body, captures read-only active-pointer and zero-Finding baselines, and returns `canary_execution_preflight_passed_provider_contact_not_authorized`. Same-run replay is status inspection. Production composition does not construct the factory. No CLI, lease acquisition, provider contact, activation, matching, or Finding writes.
- Session 13 Batch 2F-R independently reviewed that preflight. Session 13 Batch 2-R independently reviewed the combined operational-control chain. Preflight success does not authorize provider contact.
- Session 13 Batch 3A implements uncomposed `createOsvCanaryListingOnlyExecutionBridge` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-listing-execution/`). Fresh instance-operator execution confirmation. Reloads consumed listing-only authorization, exact request/run, and accepted preflight evidence. Rechecks halt and egress. Acquires the global OSV lease, starts heartbeat, arms the listing-only deadline, then executes one scripted prefix with exact pass A and pass B. Ownership is revalidated before every page. Tokens remain nondurable. Body, parser, storage, activation, matching, and Finding calls remain 0. Automatic retries remain 0. Controllers stop, then the run and authorization are terminalized under current ownership, then guarded release uses the latest row revision. Success is `listing_only_scripted_inventory_converged`. Real-provider capability does not exist. Production composition does not construct the factory. No public CLI. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 3A-R independently reviewed and hardened that uncommitted bridge. Held-by-other does not terminalize authorization or run. Constructed preflight success is required. Legal, halt, and egress freshness are rechecked. Halt during listing releases a current lease. No real-provider capability. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 3B implements uncomposed `createOsvListingProviderContactAuthorizationService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-provider-contact-authorization/`). Fresh identity-only instance-operator confirmation. Reloads consumed listing-only canary authorization, exact request/run, and accepted provider-free preflight evidence. Validates current listing-metadata legal approval, versioned egress evidence, deployment approval, heartbeat and deadline policies, runbook, containment, independent postcanary reviewer assignment, retention disposition, and active-pointer plus zero-Finding baselines. Observes halt without clearing it. Existing `osv_canary_authorization` cannot represent a distinct single-use provider-contact grant. After other gates pass, evaluation fails closed with `persistence_required` and does not return an in-memory authorization package. No real-provider capability. Production composition does not construct the factory. No public CLI. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 3B-P adds schema-only persistence for a distinct listing-only provider-contact authorization in `@patchpilot/database`. Migration `20260909120000_osv_listing_provider_contact_authorization_persistence` (frozen SHA-256 `8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`). Sixteen frozen migrations. Tables `osv_canary_provider_free_preflight_attestation` and `osv_listing_provider_contact_authorization` are global and instance owned. One provider-contact authorization binds one consumed listing-only source canary authorization, one request, one run, and one accepted provider-free preflight attestation. Listing-only is the only representable phase. Body retrieval remains prohibited. Database time owns issuance, expiration, consumption, revocation, and terminalization. DELETE is forbidden. Schema existence does not issue or consume an authorization. Session 13 Batch 3B-P-R independently reviewed and froze that schema.
- Session 13 Batch 3B-A implements uncomposed PostgreSQL adapters (`createOsvListingProviderContactAuthorizationPersistence` in `@patchpilot/database`) for insert-once listing-only provider-contact issuance with transactional prerequisite validation, immutable replay comparison, exact identity and run-bound inspection, atomic single-use consumption with request/run/preflight/source binding, same-run consumed replay, different-run rejection, issued-only revocation, and database-time expiry (`databaseNow >= expiresAt` is expired). Production composition does not construct the factory. No CLI, lease, heartbeat, deadline, scheduler, or provider contact. Session 13 remains zero-Finding. Session 13 Batch 3B-A-R independently reviewed those adapters.
- Session 13 Batch 3B-A-R independently reviewed the uncommitted Batch 3B-A adapters with disposable PostgreSQL, synthetic identities, and database-time SQL. Concrete corrections: issuance replay compares legal evidence-set identity, legal issued-at, and acknowledgement timestamps; time-expired issued rows are `immutable_conflict` rather than silent reissue; insert requires current legal revalidation at database time; consume after operator revocation is `operator_revoked`; inspect omits the record on `consumed_other_run`. Schema and migration remain unchanged.
- Session 13 Batch 3B-R independently reviewed the complete provider-contact authorization chain. No authority substitutes for another. Preflight evidence still states provider contact is unauthorized. Halt and lease remain independent. Consumption does not execute a provider operation. Consume results qualify `consumed` and `already_consumed_same_run` with `providerOperationExecuted=false`, `remainingRuntimeGatesRequired=true`, and `executionPermitted=false`. Production composition does not construct the factories. No real provider contact has occurred. Session 13 Batch 3C-Auth later added the uncomposed listing-canary execution-authorization boundary.
- Session 13 Batch 3C-Auth implements uncomposed `createOsvListingCanaryExecutionAuthorizationService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-listing-execution-authorization/`). Fresh ephemeral operator execution confirmation is mandatory and distinct from authentication, canary-authorization consumption, preflight success, and provider-contact issuance. The service consumes or verifies same-run consumed listing-only provider-contact authorization, rechecks halt, acquires the guarded OSV lease, starts heartbeat, arms the listing-only deadline, revalidates egress without DNS/TLS/HTTP, revalidates ownership, and prepares one private one-use listing-attempt permit. Success is `listing_canary_execution_authority_prepared_provider_attempt_not_executed`. Automatic retries remain 0. Body, activation, matching, and Finding authority remain prohibited. Production composition does not construct the factory. No public CLI. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 13 Batch 3C-Auth-R independently reviewed and hardened that boundary.
- Session 13 Batch 3C implements uncomposed `createOsvBoundedListingCanaryService` and the nonpublic operator command `scripts/run-osv-listing-canary.mjs`. After synthetic rehearsal and explicit operator invocation, exactly one listing HTTPS request was sent to the committed GCS JSON Objects listing endpoint for `crates.io/`. Outcome `listing_canary_one_page_classified` with one request, one accepted page, 320143 bytes, 1000 observations, continuation token present and unused, retries 0, pagination 0, and body requests 0. Halt was restored. Deadline and heartbeat stopped. The lease was guardedly released. Active pointer unchanged. Zero Finding operations. No provider response fixture was retained. Production composition does not construct the factory. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 13 Batch 3C-R listing-canary evidence review is mandatory.

Disabled:

- Production OSV runtime. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Catalog activation is not invoked. No production OSV catalog is active.
- The listing executor is exported and is not imported by worker, API, scheduler, queue, health, seed, or migration composition.
- Session 12 Batch 3 pagination contracts, Session 12 Batch 4 `createOsvListingPaginationService`, the Session 12 Batch 4-R hardened pagination service, Session 12 Batch 5 runtime-coordination contracts, Session 12 Batch 7 `createOsvRuntimeCoordinationPersistence`, Session 12 Batch 8 `createOsvDisabledRuntimeSynchronization`, Session 13 Batch 2C `createOsvCanaryAuthorizationPersistence`, Session 13 Batch 2D `createOsvCanaryOneShotCommandService`, Session 13 Batch 2E `createOsvCanaryLeaseHeartbeatController`, Session 13 Batch 2E `createOsvCanaryDeadlineController`, Session 13 Batch 2F `createOsvCanaryPreflightService`, Session 13 Batch 2F `createOsvCanaryPreflightReadiness`, Session 13 Batch 3A `createOsvCanaryListingOnlyExecutionBridge`, Session 13 Batch 3B `createOsvListingProviderContactAuthorizationService`, Session 13 Batch 3B-A `createOsvListingProviderContactAuthorizationPersistence`, Session 13 Batch 3C-Auth `createOsvListingCanaryExecutionAuthorizationService`, and Session 13 Batch 3C `createOsvBoundedListingCanaryService` are exported and are not imported by worker, API, scheduler, queue, health, seed, or migration composition. The operator script `scripts/run-osv-listing-canary.mjs` is not registered in `dev`, `start`, `test`, or `build`. Session 12 Batch 6 tables exist and are unused by production runtime. Session 13 Batch 2B canary authorization tables exist and are unused by production runtime. Session 13 Batch 3B-P provider-contact authorization tables exist and are unused by production runtime. The future job type `intelligence.osv.sync` is not registered in production worker routing.

Not yet implemented:

- Full product dashboard, registration, invitation, password reset, session listing, and remote revoke.
- Package normalization and affected-version evaluation. The implemented ecosystem registry is empty.
- Component-to-advisory matching, match-evaluation persistence, and OSV-derived Finding writes.
- Explainable production risk scoring and complete remediation workflows.
- Durable OSV job registration, retry execution, scheduler wiring, catalog activation, matching, and Finding writes. Token-cycle detection and A/B convergence execute only inside the uncomposed Batch 4 in-memory service, the disabled Batch 8 composition, and the uncomposed Batch 3A scripted listing-only bridge. Session 13 Batch 3C executed one operator-controlled listing-only real-provider canary; Session 13 Batch 3C-R listing-canary evidence review is mandatory. Production operator authentication, public CLI, legal issuance, body canary, catalog activation, matching, and Finding writes remain later gates.

Repository integrity:

- Sixteen frozen Prisma migrations. Do not edit them; any SQL correction requires another forward-only migration.
- ADRs 0001–0026 are **Accepted**. [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains **Proposed**. [ADR 0028](docs/adr/0028-osv-runtime-enablement-architecture-and-safety.md) is **Accepted**. [ADR 0029](docs/adr/0029-first-real-provider-osv-canary-authorization-and-safety.md) is **Accepted**. Acceptance of ADR 0029 does not authorize provider contact.
- Session 12 remains zero-Finding. Session 13 Batch 3A remains zero-Finding. Generic Finding schema exists and is unused by intelligence import.
- No ZIP dependency. Tests must not contact `storage.googleapis.com` or `osv.dev`.

### Current OSV runtime status

- Session 12 implements Accepted ADR 0028 incrementally while OSV remains disabled. ADR phase labels (R1–R7) are historical ADR references; contributor checkpoints use Session 12 batch names.
- Session 12 Batch 1 implemented one listing-page HTTPS request per `OsvTransportPort.listPage` invocation. It is uncomposed and runtime-unreachable.
- Session 12 Batch 2 adversarially reviewed and hardened the Batch 1 listing executor. Scheduling, retries, runtime enablement, activation, matching, and Findings remain out of scope.
- Session 12 Batch 3 defines pure pagination and two-pass inventory convergence contracts. It does not persist raw tokens, retrieve advisory bodies, or enable OSV.
- Session 12 Batch 4 implements bounded in-memory pagination and two-pass inventory convergence through an injected one-page listing port. It is explicitly invoked and production-unreachable. Raw tokens and token digests remain in memory only. No same-attempt restart, no automatic retry, no body retrieval, no persistence, and no activation. Durable jobs, retries, scheduler wiring, canary execution, and activation remain later gates.
- Session 12 Batch 4-R adversarially reviewed that pagination service with synthetic pages and scripted ports. Concrete corrections: rejected pages do not commit candidate counts; only constructed transport success is admitted; hung listing ports lose to cancellation; unsafe ceiling arithmetic fails closed; async event-sink rejections cannot become unhandled.
- Session 12 Batch 5 defines framework-independent contracts for future job type `intelligence.osv.sync`, one immutable payload and version-set fingerprint, one catalog-scope lease shared by canary and production, holder-token plus row-revision plus fencing-token fencing, database-time expiry, three total attempts including the initial attempt, parser-timeout maximum two attempts, bounded full jitter, HTTP 429 Retry-After capped at 30 seconds, parser pending capacity 0, future halt default halted, cancellation and redelivery, and bounded operational events. No runtime job is registered. No lease is acquired. No retry executes. Reserved Outbox name `intelligence.osv.sync.requested.v1` remains deferred until scheduler and job persistence prove a transaction-bound publication requirement.
- Session 12 Batch 6 adds the persistence schema for those contracts: one immutable request, one run per request, one current lease projection per shared acquisition scope, holder-token SHA-256 digest only, separate positive BIGINT row revision and fencing token, database timestamps for acquisition/heartbeat/expiry/release, and stage attempts with ordinals 1–3 (parser timeout 1–2). Session 12 Batch 6-R forbids lease-row deletion so fencing tokens cannot reset, keeps fencing monotonic on UPDATE, and allows planned or running attempts to transition once to a terminal state.
- Session 12 Batch 7 implements uncomposed PostgreSQL adapters for those tables: insert-once request and run ensure with immutable replay comparison, database-time lease acquire/heartbeat/release, expired-lease takeover with one CAS winner, holder-digest fencing, immutable stage-attempt reservation and guarded terminal recording, database-time retry-not-before, and retry-eligibility inspection without executing retries. Production composition does not construct the factory.
- Session 12 Batch 7-R independently reviewed those adapters with disposable PostgreSQL. Concrete corrections: expired holders cannot heartbeat or release; same-owner acquire after expiry is a new fencing generation; non-owners do not observe expiry as a distinct heartbeat outcome; attempt reservation is transactional, bounded, and ordinal-contiguous; planned attempts cannot skip to retryable failure; BIGINT mapping rejects unsafe Number conversion; unique-conflict and restrict-violation translation remains bounded. Retry inspection is not dispatch authority.
- Session 12 Batch 8 implements `createOsvDisabledRuntimeSynchronization` in `@patchpilot/vulnerability-intelligence`. Explicitly constructed and production-unreachable. Request and run authority precede work. Lease and fencing checks guard stages. Inventory must converge before acquisition. Canary completeness cannot substitute for production completeness. Pagination tokens remain nondurable. Retry disposition is persisted and not executed. There is no periodic heartbeat loop (`deferred_to_session_13_or_dedicated_heartbeat_batch`). Candidate readiness never invokes activation. No scheduler, BackgroundJob route, or Outbox route is added. Tests use scripted listing and retrieval only. Session 12 Batch 8-R reviewed and hardened that composition.
- Session 12 Batch 8-R independently reviewed the uncommitted Batch 8 composition with scripted listing, scripted retrieval, disposable PostgreSQL, disposable MinIO, and the isolated parser worker. It did not contact `storage.googleapis.com` or `osv.dev`. Concrete corrections: the public factory never honors a caller-supplied execution flag and the test-only verification factory is not a package export; late listing and retrieval success after ownership loss is discarded; attempt reservation or start failure prevents the protected stage; stale owners do not transition the authoritative run to failed; the inventory bridge requires the exact canary or production prefix plan plus complete pass A and pass B; membership, quarantine, catalog-lifecycle, and related acquisition writes recheck current ownership; cross-layer rehearsal deletes test-owned MinIO objects and PostgreSQL rows in FK-safe order.
- Session 12 Batch 9 adds typed `INTELLIGENCE_OSV_ACQUISITION_HALT` and bounded operational observability for the disabled composition. Default, missing, and empty values are halted. Explicit `false` releases halt only. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt is rechecked at protected checkpoints without polling. Environment refresh is process-bound. Operational events use `osv_runtime_operational_event_catalog_v1`. Event-sink failure is non-authoritative. No scheduler, production job route, retry executor, heartbeat loop, activation, matching, or Findings. Session 12 Batch 9-R independently reviewed and hardened that work.
- Session 12 Batch 9-R independently reviewed the uncommitted Batch 9 halt and observability controls with synthetic listing, scripted ports, and hostile configuration, halt-state, sink, metric, and envelope attacks. Tests do not contact `storage.googleapis.com` or `osv.dev`. Concrete corrections: halt configuration uses own-property lookup and rejects non-string values; the public halt-state factory copies closed control/source only and cannot grant synthetic or production authority; legacy halt authorization without a typed evaluation fails closed even if `osvEnabled` is true; listing wrappers name `before_pass_b` and `before_next_prefix` from tokenless prefix/pass transitions; the first blocking halt checkpoint is preserved; event emission is capped at 64 per invocation with per-call-stack reentrancy suppression; metric labels are closed per metric name with documented cardinality upper bounds. Halt false still does not enable OSV. A current owner may release under halt; a stale owner cannot. Session 12 Batch 10 later closed the runtime-enablement foundation without adding a heartbeat loop, scheduler, or production composition.
- Session 13 Batch 1-R independently reviewed and Accepted ADR 0029 canary architecture. Listing-only and bounded-body phases are separately gated. RustSec remains provisional and blocked on legal revalidation. Heartbeat is required before either phase. Production worker/API remain halted. Acceptance does not authorize provider contact. No CLI, job route, provider contact, or activation is added.
- Session 13 Batch 2A defines canary-scoped instance-operator identity and single-use authorization contracts. Listing-only and bounded-body require separate authorizations. One authorization is consumable once. Halt release and synthetic verification grant no authority. Legal-decision issuance remains a blocking preexecution dependency.
- Session 13 Batch 2B persists those contracts as schema only. Operator identity is instance owned. No tenant User or Organization relation. Listing-only and bounded-body remain distinct rows. One authorization is consumable once. Database time owns consumption and expiration. Schema existence does not issue or consume an authorization. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 2B-R independently reviewed that uncommitted schema with disposable PostgreSQL and direct SQL. Concrete corrections: authorizations and operators must be inserted as issued/active; bounded-body review requires a completed listing_only row whose consumed request and run match; one listing authorization authorizes at most one bounded-body row; consume, revoke, and expire transitions use database time. The migration is frozen. Later SQL corrections require another forward-only migration.
- Session 13 Batch 2C implements `createOsvCanaryAuthorizationPersistence` against that frozen schema. Operator ensure is insert-once with immutable replay comparison. Revoked operators cannot receive new authorizations. Authorization ensure uses database-owned issuance and expiration. Consume is a guarded CAS that binds one request and one run. Same-run replay returns the consumed state without a second execution. A different run cannot reuse the authorization. Expired, revoked, cancelled, and terminal rows cannot be consumed. Production composition does not construct the factory. No CLI, heartbeat, deadline, scheduler, or provider contact. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 2C-R independently reviewed those uncommitted adapters with disposable PostgreSQL, synthetic operator identities, and database-time SQL. Tests do not contact `storage.googleapis.com` or `osv.dev`. Concrete corrections: revoked-operator ensure replay is `operator_revoked` rather than `already_applied`; unconsumed consumption after operator revocation is `operator_revoked` rather than `identity_mismatch`; already-consumed same-run replay remains status reuse; legal-decision revalidation uses database time at ensure and consume; listing-review unique conflicts are not authorization-identity replay; consume unique bindings are `request_run_mismatch`; mappers fail closed on foreign prefixes, listing-only body fields, invalid TTL, and unknown states. Authorization consumption alone does not execute the canary. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 2D-R independently reviewed the uncommitted Batch 2D one-shot command with scripted authentication, synthetic authorizations, and disposable PostgreSQL. Authentication remains an injected instance-operator port and is not a production implementation. The command loads one existing authorization, evaluates halt independently before request/run ensure and again immediately before consumption, consumes the authorization once, and returns `authorized_preflight_required`. Same-run replay is status reuse. Different-run replay is rejected. Default halt and later halt engagement do not consume an issued authorization. The command does not acquire a lease, start heartbeat or deadline, contact a provider, or enable OSV. Production composition does not construct the factory. No public CLI. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 2E implements uncomposed `createOsvCanaryLeaseHeartbeatController` and `createOsvCanaryDeadlineController`. Heartbeat cadence is 60000 ms with pending capacity 0 and max in-flight 1. Lease TTL remains 900000 ms. Both canary deadlines are 1800000 ms of monotonic elapsed time and are not the lease TTL. Delayed callbacks revalidate ownership and fail closed at or beyond TTL without catch-up. Stop yields a private latest-revision proof for later guarded release outside the controller. The controllers do not acquire a lease, contact a provider, register production timers, or enable OSV. Production composition does not construct the factories. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 2E-R independently reviewed those controllers. Synchronous schedule callbacks fail closed without overwriting terminal state. Stale callbacks after reschedule cannot heartbeat. Halt during in-flight work prevents the next schedule. Row revision must increase by exactly one. Already-aborted stop still awaits the in-flight heartbeat. Early deadline callbacks fail closed. Event-sink failure and reentrant stop cannot change ownership or restart scheduling. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 2F implements uncomposed `createOsvCanaryPreflightService`. It accepts one existing consumed authorization bound to the exact request and run, rechecks halt before local work and immediately before success, inspects lease scope without acquisition, validates heartbeat and deadline policies without starting timers, validates egress without provider DNS or HTTP, checks listing-only database and observability readiness, requires object storage and parser readiness only for bounded-body, captures read-only active-pointer and zero-Finding baselines, and returns `canary_execution_preflight_passed_provider_contact_not_authorized`. Same-run replay is status inspection. Different-run reuse fails. Halt release alone is insufficient. Production composition does not construct the factory. No CLI, lease acquisition, provider contact, activation, matching, or Finding writes. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 2F-R independently reviewed that preflight. Halt is re-evaluated at each protected checkpoint and immediately before success. Public fake-ready committed ports are not package exports. Egress distinguishes application-verified controls from deployment controls declared but not externally proven. Success still does not authorize provider contact.
- Session 13 Batch 2-R independently reviewed the combined operational-control chain. Authentication, authorization, halt, request/run, consumption, preflight, lease inspection, controller policy readiness, and runbooks form one fail-closed path. Session 13 Batch 3A later added the uncomposed listing-only execution bridge against a scripted provider port. Real-provider capability does not exist. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 3A implements uncomposed `createOsvCanaryListingOnlyExecutionBridge`. Fresh execution confirmation, consumed listing-only authorization reload, accepted preflight evidence, halt and egress rechecks, guarded lease acquisition, heartbeat start, listing-only deadline arm, scripted one-prefix A/B pagination, ownership checkpoints, zero automatic retries, zero body retrievals, controller stop, and guarded release. Success is `listing_only_scripted_inventory_converged`. No real-provider capability. Production composition does not construct the factory. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 3A-R independently reviewed that uncommitted bridge. Concrete corrections: held-by-other does not terminalize the authorization or run; constructed preflight success is required; legal revalidation uses inspect observed-at against the recorded boundary; halt and egress are rechecked before every page; halt during listing remains `halt_engaged` and still releases a current lease; a generic `policy_violation` listing failure is not treated as ownership loss. Real-provider capability remains absent. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 3B implements uncomposed `createOsvListingProviderContactAuthorizationService`. Fresh confirmation, consumed listing-only canary authorization, exact request/run, accepted provider-free preflight evidence, current listing-metadata legal approval, versioned egress and deployment evidence, heartbeat and deadline policy versions, runbook, containment, independent reviewer assignment, retention disposition, and baselines are evaluated. Halt is observed and not cleared. After other gates pass, evaluation fails closed with `persistence_required` and does not return an in-memory authorization package. Existing `osv_canary_authorization` cannot represent this grant. Session 13 Batch 3B-P adds the distinct forward-only schema. No DNS, HTTP, lease, timer, provider, activation, matching, or Finding activity. Production composition does not construct the factory. `INTELLIGENCE_OSV_ENABLED=true` remains rejected.
- Session 13 Batch 3B-P adds schema-only `osv_canary_provider_free_preflight_attestation` and `osv_listing_provider_contact_authorization` (`20260909120000_osv_listing_provider_contact_authorization_persistence`, frozen SHA-256 `8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`). Sixteen frozen migrations. Provider-contact authorization is listing-only, expiring, and single use. It binds exact request, run, preflight, legal, egress, deployment, controller, runbook, reviewer, and retention evidence. Database time can govern issuance, expiration, consumption, revocation, and terminalization. Exactly one concurrent consumer can win. Same-run replay is distinguishable. Different-run reuse is rejected. Deletion cannot reset single-use authority. Session 13 Batch 3B-P-R independently reviewed and froze that schema.
- Session 13 Batch 3B-A implements `createOsvListingProviderContactAuthorizationPersistence` against that frozen schema. Issuance is insert-once with transactional prerequisite validation. Identical issued replay is `already_applied`. Immutable mismatch is `immutable_conflict`. Inspection is read-only. Consumption is one CAS winner. Same-run replay returns `already_consumed_same_run` without a second execution. Different-run replay is `already_consumed_other_run`. Expired, revoked, cancelled, completed, and failed rows cannot be consumed. Revocation is issued-only and uses database time. Production composition does not construct the factory. No CLI, heartbeat, deadline, scheduler, or provider contact. Successful consumption remains necessary but insufficient for provider contact. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 13 Batch 3B-A-R independently reviewed those adapters. Session 13 Batch 3B-R independently reviewed the complete chain. Session 13 Batch 3C-Auth later added the uncomposed listing-canary execution-authorization boundary.
- Session 13 Batch 3C-Auth implements uncomposed `createOsvListingCanaryExecutionAuthorizationService`. Fresh ephemeral operator execution confirmation is required. Issued listing-only provider-contact authorization is consumed once; same-run consumed replay is status inspection and does not mint a second permit. Halt is rechecked before lease, after controllers, immediately before permit creation, after permit preparation, and immediately before claim. Lease acquisition rejects held-by-other and stale-takeover. Heartbeat starts and the listing-only deadline arms before egress revalidation. Ownership is revalidated immediately before one private one-use permit and again before claim. Success is `listing_canary_execution_authority_prepared_provider_attempt_not_executed` with provider, DNS, TLS, HTTP, body, retry, activation, matching, and Finding counts 0. Cleanup is deadline stop, heartbeat stop, then guarded release of current ownership. Production composition does not construct the factory. No public CLI. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 13 Batch 3C-Auth-R independently reviewed and hardened that boundary. Session 13 Batch 3C later executed one operator-controlled listing-only real-provider canary.
- Session 13 Batch 3C implements uncomposed `createOsvBoundedListingCanaryService` and the nonpublic operator command `scripts/run-osv-listing-canary.mjs`. After synthetic rehearsal and explicit operator invocation, exactly one listing HTTPS request was sent to the committed GCS JSON Objects listing endpoint for `crates.io/`. Outcome `listing_canary_one_page_classified` with one request, one accepted page, 320143 bytes, 1000 observations, continuation token present and unused, retries 0, pagination 0, and body requests 0. Halt restoration `restored`. Deadline and heartbeat stopped. Guarded lease release `released`. Active pointer unchanged. Zero Finding operations. No provider response fixture was retained. Production composition does not construct the factory. The operator script is not registered in worker, API, or application startup. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 13 Batch 3C-R listing-canary evidence review is mandatory.
- Parser pending capacity: ADR 0028 selects runtime parser pending capacity **0**. Batch 5 represents that selected value. The current parser host already has occupancy 1 and rejects a second concurrent parse (`invalid_request`). The historical isolation-policy status constant still reports pending-capacity policy as `unavailable`. A later runtime-composition batch (Session 13 or dedicated) must reconcile that machine-readable status before production composition. No body-bearing parser queue is authorized. The disabled orchestrator's metadata pending capacity 32 is a separate policy.
- Finding writes are not authorized in Session 12 or Session 13 Batch 3C. They remain blocked until an active authoritative catalog, package normalization, a reviewed ecosystem evaluator, a deterministic `affected` result, persisted immutable match evidence, [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) gates, tenant-isolation proof, and explicit Finding-write authorization are complete. Architectural gates are authoritative, not the assigned session number. The current roadmap places that work no earlier than Session 16.

### Current roadmap (gates remain authoritative)

- Session 12: runtime-enablement foundation closed and reviewed (listing executor and pagination contracts implemented; Batch 4 in-memory pagination implemented and uncomposed; Batch 4-R adversarial review committed; Batch 5 job/lease/retry contracts committed; Batch 6 lease and retry persistence schema implemented; Batch 6-R persistence and migration review committed; Batch 7 PostgreSQL adapters implemented and uncomposed; Batch 7-R adversarial review committed; Batch 8 disabled runtime composition implemented and uncomposed; Session 12 Batch 8-R disabled composition adversarial review completed; Session 12 Batch 9 typed halt and bounded operational observability implemented; Session 12 Batch 9-R kill-switch and observability adversarial review completed; Session 12 Batch 10 runtime closure review completed; production composition remains gated).
- Session 13: Batch 1-R accepted ADR 0029 canary architecture (execution unauthorized; no real provider contact). Batch 2A defines operator-identity and authorization contracts. Batch 2B adds canary authorization persistence schema. Batch 2B-R persistence adversarial review is complete. Batch 2C uncomposed authorization adapters are implemented. Batch 2C-R adapter adversarial review is complete. Session 13 Batch 2D one-shot operator command boundary is implemented and uncomposed. Session 13 Batch 2D-R command adversarial review is complete. Session 13 Batch 2E heartbeat and deadline controllers are implemented and uncomposed. Session 13 Batch 2E-R heartbeat and deadline adversarial review is complete. Session 13 Batch 2F executable canary preflight and operator runbooks are implemented and uncomposed. Session 13 Batch 2F-R independently reviewed that preflight. Session 13 Batch 2-R independently reviewed the combined operational-control chain. Session 13 Batch 3A listing-only execution bridge against a scripted provider port is implemented and uncomposed. Session 13 Batch 3A-R independently reviewed and hardened that bridge. Session 13 Batch 3B listing-only provider-contact authorization evaluation is implemented and uncomposed; it fails closed with `persistence_required` after other gates pass and does not start execution or contact a provider. Session 13 Batch 3B-P adds schema-only provider-contact authorization persistence. Session 13 Batch 3B-P-R independently reviewed and froze that schema. Session 13 Batch 3B-A implements uncomposed listing-only provider-contact authorization issuance, inspection, consumption, and revocation adapters. Session 13 Batch 3B-A-R independently reviewed those adapters. Session 13 Batch 3B-R independently reviewed the complete provider-contact authorization chain. Session 13 Batch 3C-Auth implements uncomposed listing-canary execution authorization that prepares one private one-use listing-attempt permit and does not contact a provider. Session 13 Batch 3C-Auth-R independently reviewed and hardened that boundary. Session 13 Batch 3C executed one operator-controlled listing-only real-provider canary (`listing_canary_one_page_classified`; one HTTPS listing request; continuation token unused; halt restored; lease released). Session 13 Batch 3C-R listing-canary evidence review is mandatory. Body canary and later catalog-activation work remain. General OSV runtime remains disabled.
- Session 14: package normalization and matching architecture.
- Session 15: first ecosystem evaluator and match evidence.
- Session 16: earliest current roadmap candidate for controlled Finding lifecycle.

## Session 12 current state

Session 12 implements the Accepted ADR 0028 runtime architecture in small gated batches while OSV remains disabled. Session 12 remains zero-Finding.

### Session 12 Batch 1 (committed)

Session 12 Batch 1 implements `createOsvGcsListingHttpsAdapter` at `packages/integrations/src/osv-gcs-listing-https-adapter.ts` in `@patchpilot/integrations`. Verified from committed code and tests:

- Exactly **one** GCS JSON Objects listing-page HTTPS request per `OsvTransportPort.listPage` invocation.
- Request construction is the committed Batch 3C surface: `GET` `https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o`, unauthenticated, HTTPS port 443.
- Redirects are rejected. Identity encoding is required (`Accept-Encoding: identity`). Successful responses must be `application/json`.
- Response consumption is bounded to 1,048,576 bytes. UTF-8 decoding is fatal.
- After transport success, bytes are handed to the committed Batch 3C parser `parseOsvGcsListingPage`.
- Raw continuation tokens remain opaque and are omitted from errors, events, JSON, and inspection. Continuation-token UTF-8 bytes above 8192 are rejected at request construction. This is not pagination or cycle detection.
- Timeouts reuse committed `OSV_TIMEOUT_POLICY_V1`.
- No retry, pagination loop, token-cycle store, A/B convergence, provider-body retrieval, persistence, storage, parser-worker invocation, catalog activation, matching, Finding write, API, permission, Prisma, or dependency change.
- The production factory is exported from `@patchpilot/integrations`. The test factory is not. Worker, API, scheduler, queue, health, seed, and migration composition do not import the adapter.
- Tests use synthetic local HTTPS and DNS doubles only. They do not contact `storage.googleapis.com` or `osv.dev`.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 2 (committed)

Session 12 Batch 2 adversarially reviewed the Batch 1 listing executor with synthetic request and response doubles only. Tests do not contact `storage.googleapis.com` or `osv.dev`. Concrete transport corrections:

- Duplicate or empty `Location` on HTTP 200 fails closed (arrays are not ignored).
- `Transfer-Encoding` other than absent/`chunked`, compressed transfer encodings, and `Content-Length` plus `Transfer-Encoding` fail closed.
- Shared Content-Length parsing rejects leading zeros and multi-value arrays instead of coalescing duplicates.
- Shared Content-Encoding parsing accepts only absent or `identity` (empty and whitespace-only values are rejected).
- DNS answers are copied before pin selection. Socket listeners are one-shot and removed on terminal cleanup. Non-byte body chunks are rejected.
- Continuation tokens remain opaque. One invocation remains zero or one HTTPS request. Pagination, token-cycle detection, and A/B convergence remain absent.

The adapter remains uncomposed. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 3 (committed)

Session 12 Batch 3 adds framework-independent listing pagination and two-pass inventory convergence contracts in `@patchpilot/vulnerability-intelligence` at `packages/vulnerability-intelligence/src/osv/listing-pagination/`. Verified from committed code and tests:

- Closed policy profiles `disabled_canary` and `production_fail_closed` pin Accepted ADR 0028 identifiers and ceilings. Callers cannot supply numeric limits.
- Per-page limits remain 1000 observations, 1,048,576 response bytes, and 8192 continuation-token UTF-8 bytes.
- Canary ceilings: 8 pages / 2000 observations / 8,388,608 bytes per prefix per pass; 16 pages / 4000 observations / 16,777,216 bytes per run.
- Production fail-closed ceilings: 500 pages / 500,000 observations / 524,288,000 bytes per prefix per pass; 6000 pages / 6,000,000 observations / 6,291,456,000 bytes per run.
- Raw continuation tokens remain in-memory opaque handles. Token-digest cycle detection is in-memory only, bounded by max pages per pass, and treats digest collision as `listing_token_cycle`.
- Canonical pass-set identity is SHA-256 over length-prefixed observation fields. Pass A and pass B comparison uses digest plus exact ordered equality.
- Incomplete inventory, canary completeness, and even recorded production-scope completeness still block body retrieval, candidate readiness, and catalog activation from these contracts.
- One A/B pair per synchronization attempt. Crash restart begins at page one with a new pass-attempt identity. Retry disposition is recorded and never executed.
- Batch 3 itself has no pagination loop, no HTTPS, no provider contact, no Prisma or migration change, and no production composition. Session 12 Batch 4 later added in-memory execution of these contracts. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 4 (committed)

Session 12 Batch 4 implements bounded in-memory listing pagination and two-pass inventory convergence in `@patchpilot/vulnerability-intelligence` via `createOsvListingPaginationService`. Verified from committed code and tests:

- Explicitly invoked. Injected one-page listing port. Does not import or instantiate `createOsvGcsListingHttpsAdapter`.
- One prefix, one pass, and one page at a time. Pass A then pass B. No parallel requests, no third pass, no same-attempt restart, no automatic retry.
- Exact `responseByteCount` is counted by the listing HTTPS adapter during bounded body consumption and exposed on the one-page transport success result. Pagination passes that count to `acceptOsvListingPage`.
- Raw tokens and token digests remain in memory only. Token cycles fail closed. Page admission is atomic. Exact policy ceilings are enforced.
- Canary and production completeness remain separate. No body retrieval, persistence, scheduler, job, activation, matching, Finding, Prisma, or dependency change.
- Tests use scripted ports and synthetic local HTTPS doubles only. They do not contact `storage.googleapis.com` or `osv.dev`.
- Production composition does not construct the service. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 4-R (committed)

Session 12 Batch 4-R adversarially reviewed the committed Batch 4 pagination service with synthetic listing pages and scripted listing-port doubles only. Tests do not contact `storage.googleapis.com` or `osv.dev`. Concrete corrections:

- Rejected pages no longer commit candidate page, observation, or byte counts. Duplicate, conflict, cycle, and ceiling failures leave prior accepted totals intact.
- Pagination admits only constructed `createOsvListingPageTransportSuccess` results and still validates `responseByteCount` defensively. Unconstructed or malformed port output fails closed as `listing_transport_failure`.
- In-flight listing-port calls race `AbortSignal`. A port that never settles cannot hang the pass. Late success after cancellation is ignored. `listingInFlight` is cleared.
- Ceiling evaluators reject unsafe integers instead of comparing `NaN` as capacity remaining. Direct `acceptOsvListingPage` rejects non-positive byte counts.
- Event-sink thenables are forwarded and swallowed so a rejected Promise cannot become an unhandled rejection or alter control flow.
- Canonical convergence also checks the exact algorithm identifier. Equal digest with different observations, and different digest with equal observations, fail closed as `internal_validation_failure`.

No durable jobs, retries, schedulers, body retrieval, persistence, activation, matching, Findings, Prisma, or dependency change is included. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 5 (committed)

Session 12 Batch 5 adds framework-independent OSV durable synchronization job, lease, fencing, retry, parser-capacity, halt, cancellation, restart, and bounded operational-event contracts in `@patchpilot/vulnerability-intelligence` at `src/osv/runtime-coordination/`. Verified from committed code and tests:

- Future job type is exactly `intelligence.osv.sync`. It is distinct from KEV `intelligence.sync` and SBOM `sbom.ingest`. It is not registered in worker routing, BackgroundJob production discriminants, or Outbox production discriminants.
- One immutable payload pins committed version-set identifiers. Callers cannot supply fingerprints, retry limits, lease timing, concurrency, activation, matching, Finding, tenant, token, body, URL, or credential fields.
- Closed reasons are `scheduler`, `operator_canary`, and `operator_production`. Canary and production work scopes are distinct and share one catalog-scope lease so they cannot overlap. KEV uses a separate scope.
- One run belongs to one job request. Duplicate delivery reuses the authoritative run. Redis job IDs are not authority. Incomplete prefix passes restart at page one. One A/B pair remains one synchronization attempt.
- Lease fencing separates holder token (secret UUID v4), compare-and-swap row revision (PostgreSQL BIGINT-safe decimal string, increments on every mutation including heartbeat), and fencing token (increments on acquire, stale takeover, and release, not on heartbeat). Expiry uses database-owned time. Takeover is permitted when `databaseNow >= expiresAt`.
- Retry policy `osv_runtime_retry_policy_v1` allows three total attempts including the initial attempt (ordinals 1–3). Parser timeout is restricted to two total attempts. Adapter-level retry remains prohibited. Nominal backoff is 0/1000/4000 ms with inclusive full jitter `[0, nominal]` and a 30 000 ms maximum. HTTP 429 Retry-After uses unsigned delta-seconds or a parseable IMF-fixdate, capped at 30 seconds; malformed and non-429 values use normal bounded backoff.
- Parser pending capacity is represented as 0. The parser-host occupancy-1 rejection behavior is unchanged. The historical pending-queue marker remains `unavailable` until a later runtime-composition batch.
- Future halt name `INTELLIGENCE_OSV_ACQUISITION_HALT` is documented only. Default, missing, and malformed values are halted. The environment variable is not added. Enablement does not clear halt.
- Reserved Outbox name `intelligence.osv.sync.requested.v1` remains deferred until scheduler and job persistence prove a transaction-bound publication requirement.

`INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 6 (committed)

Session 12 Batch 6 adds the minimum forward-only Prisma and PostgreSQL persistence schema for the committed Batch 5 contracts. Session 12 Batch 6-R independently reviewed that uncommitted schema before freeze.

- Exactly one new migration: `20260907120000_osv_runtime_coordination_persistence`. Frozen SHA-256 `7017b1c4b1d4bcae8bed4bdd0eb43559c0c89fce5b3636e0e889b276013cc3a6` after Batch 6-R corrections. Fourteen frozen migrations. All thirteen prior migrations remain byte-for-byte unchanged.
- Four global, instance-owned, tenant-independent tables: `osv_runtime_synchronization_request`, `osv_runtime_synchronization_run`, `osv_runtime_lease_projection`, `osv_runtime_stage_attempt`. No Organization, User, Asset, Component, Vulnerability-matching, Finding, Evidence, or RiskCalculation relation.
- Immutable request identity with closed job type `intelligence.osv.sync`, closed reasons and work scopes, lowercase SHA-256 version-set fingerprint, operator UUID or scheduler-window idempotency, and append-only trigger. Canary reason requires canary scope and canary policy. Scheduler and production reasons prohibit canary policy.
- One run per request (`UNIQUE request_id`). Composite foreign key pins scope, reason, fingerprint, and lease scope to the request. Run states match the committed graph. No active or activated catalog state.
- One current lease projection keyed by exact lease scope. Stored states are `held` and `released`. Absent is no row. Expired is derived from database time and `expiresAt`. Holder token is stored only as lowercase SHA-256 digest. Row revision and fencing token are separate positive BIGINTs. No `@updatedAt` application-clock default.
- Stage-attempt identity is unique on `(run_id, stage, attempt_ordinal)` when target digest is absent, and unique on `(run_id, stage, target_identity_digest, attempt_ordinal)` when a target digest is present. Ordinals 1–3; parser timeout 1–2; inventory convergence ordinal 1 only. Exhaustion is `state = exhausted` plus `retry_exhausted = true` plus `retry_disposition = retry_exhausted` with the exact failure code preserved. Retry-not-before is present only for retryable failure with attempts remaining.
- All new foreign keys are `ON DELETE RESTRICT`. Request rows are append-only. Attempt DELETE is forbidden. No seed rows. No JSON payload. No raw holder token, page token, token digest, provider body, or URL column.
- No lease adapter, heartbeat, release, takeover, fencing check, retry executor, scheduler, BackgroundJob discriminant, Outbox discriminant, BullMQ processor, kill-switch variable, or production composition.

`INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 6-R (committed)

Session 12 Batch 6-R independently reviewed, adversarially tested, and hardened the uncommitted Batch 6 schema and migration before freeze. Concrete corrections:

- Lease projection DELETE is forbidden. Deleting and recreating a scope row can no longer reset `fencing_token` to 1.
- Lease UPDATE requires a strictly increasing `row_revision`. Same-owner held mutations (heartbeat) cannot change `fencing_token`. Ownership change, release, and reacquisition must increment `fencing_token`. Decreasing `fencing_token` fails closed.
- Stage-attempt UPDATE is permitted only for planned or running rows transitioning according to the Batch 5 graph. Identity fields and terminal rows are immutable. DELETE remains forbidden.
- Completed runs cannot carry `durable_retry`. Released leases require `released_at >= heartbeat_at`. Retryable failure `retry_not_before` cannot exceed `terminal_at + 30 seconds`. Cancelled attempts cannot store a failure catalog without a failure code.
- Concurrent stale-takeover CAS (`WHERE row_revision` and `fencing_token` plus `CURRENT_TIMESTAMP >= expires_at`) admits exactly one winner on disposable PostgreSQL.

No lease adapter, heartbeat adapter, stale-takeover adapter, retry executor, scheduler, BackgroundJob routing, Outbox routing, kill-switch variable, or production composition is included. Tests do not contact `storage.googleapis.com` or `osv.dev`. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 7 later added PostgreSQL adapters.

### Session 12 Batch 7 (completed, awaiting Batch 7-R commit together)

Session 12 Batch 7 implements `createOsvRuntimeCoordinationPersistence` in `@patchpilot/database` against the frozen Batch 6 schema and committed Batch 5 contracts. Verified from code and tests:

- Request ensure is insert-once. Unique conflict reloads the natural key and compares every immutable field. Identical replay is `already_applied`. Any immutable mismatch is `immutable_conflict`. P2002 is never treated as success.
- Run ensure is one run per request. Duplicate delivery reuses the authoritative run. Redis job IDs are not authority. Ensure does not change run state.
- First lease acquisition uses `CURRENT_TIMESTAMP` and TTL `900000` milliseconds. Holder tokens are stored only as lowercase SHA-256 digests. Same-owner replay returns `already_held_by_same_owner` without incrementing the fencing token. Held-by-other returns bounded observations without digest or token.
- Heartbeat is CAS on holder digest, row revision, fencing token, held state, and `CURRENT_TIMESTAMP < expires_at`. Heartbeat increments row revision and does not change fencing. An expired owner cannot heartbeat.
- Explicit release is guarded, increments fencing, leaves the row durable, and is idempotent for the same terminal reason. Reacquisition after release increments fencing.
- Expired-lease takeover is one guarded UPDATE. Concurrent contenders sharing the expected revision and fencing token admit exactly one winner. The prior owner cannot heartbeat, release, validate ownership, or complete a protected run.
- Stage attempts reserve as planned, start to running with database `started_at`, and record terminals with database `terminal_at`. Attempt 4 cannot be reserved. Parser-timeout ordinal 3 is rejected. Retry-not-before is `CURRENT_TIMESTAMP + selectedDelayMs` and exists only when another attempt remains. Exhaustion preserves the exact failure code and blocks another ordinal.
- Retry eligibility is inspection only. Adapters do not sleep, poll, enqueue, or execute retries.
- Production worker, API, scheduler, queue, health, seed, and migration composition do not import the factory. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 7-R reviewed these adapters before commit.

### Session 12 Batch 7-R (committed)

Session 12 Batch 7-R independently reviewed the Batch 7 adapters with disposable PostgreSQL, synthetic holder proofs, and database-time SQL. It did not contact `storage.googleapis.com` or `osv.dev`. Concrete corrections:

- Release CAS requires `CURRENT_TIMESTAMP < expires_at`. An expired holder cannot release. A non-owner heartbeat against an expired row returns `ownership_lost`, not `expired`.
- Same-owner acquire after expiry is stale takeover (new fencing generation), not idempotent replay. The Batch 6-R trigger treats held→held same run and digest as a heartbeat, so that acquire bumps fencing through a same-transaction released-then-held pair. Public `release()` still rejects expired holders.
- Attempt reservation runs in one transaction, bounds prior-row reads (`take: 4`), requires contiguous ordinals, and rejects attempt 2 while attempt 1 is still planned or running. Cancellation and success are not labeled exhaustion.
- Terminal attempt commands reject planned-to-retryable-failed at the port. Adapters recheck the Batch 5 graph before UPDATE.
- BIGINT mapping keeps exact decimal strings above `Number.MAX_SAFE_INTEGER` and fails closed on unsafe Number conversion. Heartbeat increment stays in SQL.
- Unique-conflict reload remains compare-after-reload. Restrict-violation and integer overflow translate to bounded codes with no SQL, digest, or Prisma leakage.
- Retry eligibility remains inspection only. Session 12 Batch 8 rechecks ownership before protected stages.

No schema or migration change. No scheduler, BackgroundJob routing, Outbox routing, retry timer, kill-switch variable, or production composition. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 8 (completed)

Session 12 Batch 8 implements `createOsvDisabledRuntimeSynchronization` in `@patchpilot/vulnerability-intelligence` at `src/osv/runtime-coordination/disabled-runtime-synchronization.ts`. Verified from code and tests:

- Explicitly constructed. Factory construction performs no I/O, starts no timer, and acquires no lease.
- Public synchronize halt-closes after persisting request and run. Test-only execution is confined to `createOsvDisabledRuntimeSynchronizationForVerification`, which is not a public package export.
- Scheduler reason cannot run even on the verification path.
- Durable request ensure and one run per request precede work. Duplicate delivery reuses the authoritative run.
- Lease acquisition uses Batch 7. Held-by-other returns without waiting or listing.
- Current fencing is revalidated before listing, each later listing page, inventory acceptance, acquisition, parser/storage dispatch wrappers, reconciliation/readiness, run completion, and release.
- Inventory uses Batch 4 pagination. Tokens remain in memory. Canary completeness cannot satisfy production completeness.
- Acquisition uses the Session 11 disabled orchestrator after a fail-closed inventory bridge. Candidate readiness never activates a catalog.
- Stage attempts reserve ordinal 1 only. Retry disposition is recorded. No same-invocation retry, sleep, poll, or queue publication.
- No periodic heartbeat loop. Heartbeat scheduling remains `deferred_to_session_13_or_dedicated_heartbeat_batch`.
- Worker, API, scheduler, queue, health, seed, and migration composition do not import the factory. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 8-R reviewed this composition.

## Current repository state

The following paragraph is a chronological implementation ledger. Statements that a capability was absent apply to the checkpoint being described and must not override the Authoritative current project status section above.

The Session 3 **development foundation** and Session 4 CI/governance are in place. Session 5 adds the PostgreSQL tenant schema, repository adapters, migrations, and database integration tests. Session 6 Batch 1 accepts [ADR 0019](docs/adr/0019-local-password-sessions.md) (local passwords, opaque sessions, CSRF, interim permissions) and typed auth configuration. `packages/auth` installs `argon2@0.45.1`. Session 6 Batch 2 persists `LocalCredential`, opaque `Session` rows (digest-only), and audit actor columns (`anonymous`, restored `actorUserId`). Hashing, session use cases, and fail-closed login abuse control exist in `packages/auth` (Redis adapter in `apps/api`). Session 6 Fastify authentication routes are implemented: `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`, `GET /auth/organizations`, and `POST /auth/select-organization` (cookies, Origin, CSRF, JSON-only mutations, no-store, audit, login limiter). Session 6 minimal web authentication is implemented: `/login`, client session bootstrap, organization selection, logout, expired-session, and access-denied. CSRF stays in React memory only; the session cookie remains HttpOnly. Session 7 persists asset inventory. Session 8 Batch 1 accepts [ADR 0020](docs/adr/0020-sbom-ingestion-graph-completion.md) (graph-complete ingestion semantics) and typed SBOM ingestion limits in `packages/config`. Session 8 Batch 2 vendors CycloneDX JSON schemas 1.4–1.6 (specification tag `1.6.1`) and installs parser/storage dependencies (`ajv@8.20.0`, `ajv-formats@3.0.1`, `packageurl-js@2.0.1`, `secure-json-parse@4.1.0`, `@aws-sdk/client-s3@3.1120.0`). Session 8 Batch 3 adds SBOM HTTP contracts, the Session 8 ingestion state machine, known/unknown component versions, normalized graph DTOs, and provider-neutral persistence/storage/job ports. Session 8 Batch 4 adds the forward-only migration `20260830120000_sbom_ingestion_graph_persistence` and Prisma adapters for SBOM metadata, ingestion, upload idempotency, outbox claim, BackgroundJob execution, and insert-once graph persistence. The Session 8 graph-persistence migration is **frozen**. Do not edit it; any SQL correction requires another forward-only migration. Session 8 Batch 5 implements private streaming S3-compatible SBOM object storage (`S3SbomObjectStorage` in `@patchpilot/integrations`, MinIO-compatible, no public ACL, no signed URLs). Session 8 Batch 6 implements the framework-independent authorized and idempotent SBOM upload use case (`createUploadSbomUseCase` in `@patchpilot/domain`): hashed Idempotency-Key reservation, streaming put/promote outside PostgreSQL, duplicate-evidence reuse, atomic metadata/audit/outbox/idempotency finalization, and best-effort temporary cleanup. Session 8 Batch 7 implements Fastify SBOM routes (`POST /assets/:assetId/sboms`, `GET /assets/:assetId/sboms`, `GET /assets/:assetId/sboms/:sbomId`, `GET /assets/:assetId/sbom-ingestions/:ingestionId`): session authentication, active Organization, `sbom:upload`/`sbom:read`, tenant-safe not-found, archived Asset conflict, exact Origin, synchronizer CSRF, required `Idempotency-Key`, raw-body streaming, approved UTF-8 JSON content types, per-route upload size, direct peer-IP and Organization rate limits, `trustProxy=false`, outbox-only (no request-path queue publication), and `Cache-Control: private, no-store`. Public responses omit object keys, filenames, worker IDs, lease fields, parser details, and audit payloads. Session 8 Batch 8 implements the worker outbox relay (PostgreSQL `SKIP LOCKED` claim, commit lease, BullMQ.add with deterministic job ID, mark `OutboxEvent` processed, create or reuse `BackgroundJob`). Session 8 Batch 9 implements the worker-thread CycloneDX parser in `@patchpilot/sbom`: `worker.terminate()` wall-clock timeout, secure JSON parse, prototype-key rejection, depth/node/string limits, offline CycloneDX 1.4–1.6 schemas, semantic limits, PURL normalization, explicit unknown versions, duplicate bom-ref rejection, unknown dependency-ref rejection, self-edge omission with `self_dependency_skipped`, cycle retention, bounded normalized results, and graph completeness. Persistence continues to reject DTO-invalid graphs (including remaining self-edges) and does not add self-edge warning behavior. Session 8 Batch 10 implements the ingestion processor in `apps/worker`: BullMQ `sbom.ingest` jobs, ids-only payload validation, BackgroundJob lease claim, authoritative tenant reload, stored-object GET with size and SHA-256 verification, worker-thread parse, transactional graph persist (no storage or Redis in that transaction), Asset pointer update, system audit, and terminal job marking. Session 8 Batch 11 completes the ingestion documentation set: the raw upload contract, storage behavior and failure categories, idempotency layers, orphan handling, outbox relay constants, job leases, parser timeout and quarantine, and the closed safe-failure catalog in [docs/architecture/sbom-ingestion.md](docs/architecture/sbom-ingestion.md), with matching updates to the reliability model, audit catalog, retention, threat model, risk register, local MinIO setup, and the ingestion, outbox, background-job, and local-infrastructure runbooks. The SBOM upload-to-graph path is therefore runnable end to end against local Compose infrastructure. Session 9 Batch 1B accepts [ADR 0021](docs/adr/0021-vulnerability-intelligence-import-foundation.md): global, instance-owned, import-only vulnerability intelligence from OSV GCS bulk export (`all.zip` completeness baseline) and the CISA KEV JSON snapshot, with an explicit zero-Finding boundary. Session 9 Batch 2C adds typed KEV-first intelligence configuration in `@patchpilot/config`. Session 9 Batch 3B vendors the official CISA KEV JSON Schema under `packages/vulnerability-intelligence/vendor/cisa-kev-schema/` and adds offline Ajv draft-07 compilation in `@patchpilot/vulnerability-intelligence` (`ajv@8.20.0`, `ajv-formats@3.0.1`, `secure-json-parse@4.1.0`). Session 9 Batch 4A adds KEV intelligence public status contracts, global domain records, sync-run transition rules, safe failure taxonomy, provider-neutral ports, outbox payload types, parser-thread DTOs, and system audit command types. Session 9 Batch 4C adds the forward-only migration `20260901120000_kev_intelligence_persistence`, domain snapshot/generation/audit corrections, and PostgreSQL adapters for SyncRun, snapshots, generations, atomic activation, scheduler request, not-modified, failure, and freshness. The Session 9 KEV persistence migration is **frozen**. Do not edit it; any SQL correction requires another forward-only migration. OSV runtime remains disabled (`INTELLIGENCE_OSV_ENABLED=true` fails validation). Session 9 Batch 5B adds restricted CISA KEV HTTPS transport (`node:https.request`, no redirects, no proxies, lookup-pin plus post-connect verification) and private S3-compatible intelligence snapshot storage in `@patchpilot/integrations`, reusing the existing Session 8 bucket. Snapshot keys are `intelligence/cisa_kev/cisa_kev_json_catalog/tmp/{uuid}` and `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/{sha256}`. Session 9 Batch 6B adds secure CISA KEV parsing, deterministic normalization, and one-shot worker-thread execution in `@patchpilot/vulnerability-intelligence` (`worker.terminate()` wall-clock timeout, strict UTF-8, secure JSON parse, iterative structural limits, offline official-schema validation, PatchPilot semantic checks, and a 16 MiB serialized-result ceiling). Session 9 Batch 7B adds the framework-independent CISA KEV synchronization service in `@patchpilot/domain` (`createCisaKevSynchronizationService`): authoritative job/outbox/SyncRun prechecks, crash-safe persisted-stage resume, provider fetch and snapshot orchestration, content-hash not-modified, catalog-regression quarantine, dense-prefix staging, atomic activation, BackgroundJob-only lease heartbeat, and pre-snapshot `retry_wait` versus post-snapshot job retry. Session 9 Batch 8B adds the worker KEV scheduler (UTC schedule windows, PostgreSQL dedupe), Outbox mapping of `intelligence.sync.requested.v1` to `intelligence.sync`, a shared `patchpilot` BullMQ Worker with concurrency 2, PostgreSQL-backed retry reconciliation, IntelligenceSource enablement reconciliation, and graceful shutdown. Session 9 Batch 9B accepts [ADR 0022](docs/adr/0022-intelligence-provider-status-authorization.md) and implements authenticated sanitized provider-status GETs (`GET /intelligence/providers`, `GET /intelligence/providers/:provider/status`) with `intelligence:read` for viewer, member, admin, and owner. Active Organization is product-access context, not a data-scope predicate on global intelligence rows. No web UI, dashboard, ZIP dependency, production catalog body, OSV runtime, manual synchronization, manual retry, detailed SyncRun API, or Finding integration exists. [ADR 0010](docs/adr/0010-osv-correlation.md) remains the future correlation ADR, not the Session 9 import mechanism. Generic Finding persistence exists and stays unused by Session 9. Web UI is **not** implemented. Registration, invitation, password reset, session listing, remote revoke, dashboards, and product UIs are **not** implemented. Live vulnerability-provider calls occur only from the worker intelligence processor after authoritative claim, never during configuration load or status GETs. Risk-scoring logic is **not** implemented. Session 10 Batch 1B accepts [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) and adds provider-neutral canonical CVE identity domain boundaries in `@patchpilot/domain` (`CveIdentity`, `VulnerabilityCveIdentityLink`, ensure commands, and persistence ports). Session 10 Batch 3A added the forward-only migration `20260902120000_canonical_cve_identity` with global append-only `cve_identity` and `vulnerability_cve_identity` tables, a canonical CVE CHECK, and exact canonical-only backfill from `vulnerability.cve_id`. Session 10 Batch 3B applied that migration to the persistent development database (eleven finished migrations) and froze it (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Session 10 Batch 4B adds `createCveIdentityPersistence` in `@patchpilot/database` (`identities` and `links`): insert-once ensure, unique-conflict reload of the authoritative row, database-generated identity `createdAt`, caller-supplied immutable link `linkedAt`, bounded batch lookup, and bounded keyset listing. The factory does not query KEV, does not take tenant arguments, and does not write Findings. Session 10 Batch 5B adds read-only active-catalog membership derivation (`createQueryActiveKevMembershipUseCase`, `createActiveKevMembershipPersistence`) for one exact canonical CVE against the accepted active CISA KEV generation. Results are `unavailable`, `absent`, or `listedInActiveKev` with `current`, `stale`, or `disabled_with_history` freshness. No CveIdentity or link row is required or created. No Finding query or write, tenant input, API, worker, Outbox, permission, or web UI is included. Session 10 Batch 6B hardens identity persistence (root Prisma client only; P2002 replay when target metadata is absent) and adds activation-race, corruption-path, and isolation tests. Session 10 remains zero-Finding. `Vulnerability.osvId` remains required and unique. KEV membership remains a global exploitation signal, not proof of tenant exposure. v0.1 architecture, security design, and operational runbooks exist under `docs/architecture/`, `docs/security/`, and `docs/runbooks/`. ADRs 0001–0026 are **Accepted**. [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains **Proposed**. [ADR 0028](docs/adr/0028-osv-runtime-enablement-architecture-and-safety.md) is **Accepted**. Session 11 Batch 1A found the repository unable to authoritatively match versions. Session 11 Batch 1B accepts [ADR 0024](docs/adr/0024-authoritative-affected-version-source-and-osv-acquisition.md): OSV is the future affected-version authority; tenant package query APIs are rejected; instance-owned catalog acquisition is the approved direction. Exact object/listing transport remains unreviewed. ZIP remains absent and unauthorized. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 Batch 1C accepts [ADR 0025](docs/adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md): ecosystem-aware package identity, a closed fail-closed registry, and the future evaluator result model. The implemented ecosystem set is empty. No first ecosystem is selected. Session 11 Batch 1D accepts [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md): Finding natural key `organizationId` + `assetId` + `componentId` + `vulnerabilityId`, future append-only match evaluation, observation semantics, and the first Finding-write gate. Session 11 Batch 3A implements OSV metadata contracts, source-license registry, and fail-closed classification in `@patchpilot/vulnerability-intelligence`. Nine sources with fail-closed registry (MAL Apache-2.0, GHSA CC-BY-4.0, PYSEC CC-BY-4.0, GO CC-BY-4.0 vulnerability data, RUSTSEC CC0-1.0, GSD archived, EEF-CVE CC-BY-4.0, OSV ambiguous fail-closed, ECHO proprietary fail-closed). Session 11 Batch 3A-P incorporates verified provenance so seven sources are body-retrieval eligible; OSV and ECHO remain fail-closed. Session 11 Batch 3B adds framework-independent OSV transport contracts. Session 11 Batch 3C adds a compiled GCS JSON Objects list request builder and a bounded listing-page parser using synthetic fixtures. Session 11 Batch 4A vendors the official OSV advisory schema (v1.9.0) with immutable provenance. Session 11 Batch 4B defines the isolated OSV advisory parser protocol. Session 11 Batch 4B-P closes parser resource-policy v1 and authorizes synthetic bounded reference-parser requests. Session 11 Batch 4C implements an in-process reference parser for one bounded synthetic OSV advisory. Session 11 Batch 4D adversarially reviews that parser with synthetic hostile inputs and hardens identity whitespace/control rejection, abort checks, and unexpected-exception mapping. Session 11 Batch 4E closes the production isolation design (`worker_threads`, exact timeouts, pinned schema load inside the isolate, one-request-at-a-time Ajv, pool size 1, sequential reuse) without implementing a worker. Session 11 Batch 4F implements the isolated OSV advisory parser worker and parent-side adapter, aligning with the committed Batch 4E isolation architecture. Session 11 Batch 4F-R verified that implementation under Node.js 24: the worker loads only compiled `dist/osv/advisory-parser-worker.js`, verifies the pinned schema, compiles one Ajv instance, and parses one synthetic advisory at a time; the host enforces occupancy 1 with no pending queue, catalog failure kinds, idempotent shutdown, correlation matching, and parent validation of worker output. `worker_threads` is not an operating-system sandbox. No HTTP adapter, provider-object retrieval, scheduler, or OSV runtime exists. Session 11 Batch 5B adds framework-independent OSV persistence contracts. Session 11 Batch 5C adds Prisma models and the forward-only migration `20260904120000_osv_acquisition_persistence_foundation` (frozen SHA-256 `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`). Session 11 Batch 5C-R adds `20260904180000_osv_parsed_revision_id_check_correction` (thirteen finished migrations; frozen SHA-256 `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`) which replaces only the unsatisfiable parsed OSV ID CHECK. Session 11 Batch 5D adds `createOsvAcquisitionPersistence` in `@patchpilot/database`: PostgreSQL adapters for inventory, provider identity, snapshot/attachment metadata, parser attempts, parsed revisions, catalog-generation transitions, deterministic reconciliation, append-only quarantine and provider presence, and atomic active-pointer compare-and-swap with immutable activation history. The Batch 5C and Batch 5C-R migrations are unchanged. Session 11 Batch 5E adds an immutable S3-compatible object-storage adapter (`S3OsvAdvisoryObjectStorage` in `@patchpilot/integrations`) and staged-attachment orchestration (`createOsvArtifactAttachmentService` in `@patchpilot/vulnerability-intelligence`) for provider-body snapshots and parsed structural documents. Locators are `intelligence/osv/advisory_body/{tmp|sha256}/…` and `intelligence/osv/parsed_advisory/{tmp|sha256}/…`. Provider keys are never storage paths. PostgreSQL and object storage are not one transaction. Bytes are locally supplied synthetic test bytes only. Session 11 Batch 5F adversarially reviews and hardens that storage path (write-once GET hashing, bounded recovery, cleanup eligibility, and error confidentiality) without authorizing provider retrieval. Session 11 Batch 6A-P closes `osv_generation_bound_retrieval_policy_v1` and OD-8 at 1,048,576 received bytes. Session 11 Batch 6A implements one-attempt generation-bound HTTPS retrieval (`createOsvGenerationBoundRetrievalHttpsAdapter` in `@patchpilot/integrations`) with source and retention preflight, `ifGenerationMatch` binding, identity encoding, redirect rejection, and bounded streaming SHA-256. The adapter returns a validated retrieval result only. It does not attach snapshots, invoke the parser, retry, list GCS inventory, synchronize, or enable OSV. Tests use synthetic local streams and an injected HTTP seam. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 Batch 6B implements a disabled bounded acquisition orchestrator that is explicitly invoked and never activates a catalog. Session 11 Batch 6C executes a disabled synthetic end-to-end rehearsal with disposable MinIO, disposable PostgreSQL, and the isolated parser worker; ineligible items terminate at `retrieval_skipped`. Session 11 Batch 6D closes the acquisition-foundation review: the foundation is implemented and synthetically verified; production OSV acquisition remains disabled; at Session 11 closure, listing execution, scheduler, durable jobs, and automatic retries remained absent; catalog activation is not invoked; matching and Finding writes remain unauthorized. Runtime Enablement Phase R1-R accepts [ADR 0028](docs/adr/0028-osv-runtime-enablement-architecture-and-safety.md) for staged runtime architecture without enabling OSV. Session 11 remains zero-Finding. Session 12 remains zero-Finding. Finding writes are not authorized in Session 12; gates, not a session number, are authoritative (current roadmap: no earlier than Session 16). Generic Finding schema exists and is unused. No match-evaluation model, comparator, evaluator, or OSV-derived Finding write path exists. The layout below is the modular monolith. Do not invent a different topology without an accepted ADR.

### Known Session 8 gaps

These are deliberate, documented gaps. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- No SBOM web UI, retry API, or quarantine-release API. Requeueing a `failed` ingestion and releasing a `quarantined` one are operator database work.
- No object-storage orphan reconciliation job. `SBOM_ORPHAN_GRACE_SECONDS` is a validated policy floor with no consumer.
- No BackgroundJob lease heartbeat. `renewLease` exists on the port and adapter and is never called, so the lease must exceed the worst-case run.
- No BullMQ `attempts`/`backoff` on `sbom.ingest` and no BackgroundJob requeue poller. A retryable failure leaves resumable state and stops until an operator replays the job.
- `sbom.upload_rejected`, `sbom.ingestion.released_from_quarantine`, and `sbom.reprocessed` are specified in the audit model and not yet emitted.
- Ingestion limit values in `packages/config` are unmeasured proposals (risk R31).
- Idempotency reservation renewal during a slow client upload is not implemented (risk R43).

### Known Session 9 gaps (after Batch 9B)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Official CISA KEV JSON Schema is vendored with checksums and provenance. Offline Ajv compiles it. Re-vendoring is maintainer-only (`scripts/vendor-cisa-kev-schema.mjs --execute`). Install, build, test, CI, and runtime do not download the schema.
- The framework-independent CISA KEV synchronization service exists in `@patchpilot/domain`. `apps/worker` schedules, relays, and processes KEV work. `apps/api` exposes sanitized provider-status GETs only; it does not start synchronization.
- Authenticated `GET /intelligence/providers` and `GET /intelligence/providers/:provider/status` exist (`intelligence:read`). Manual sync, manual retry, detailed SyncRun, generation-history, snapshot, and KEV CVE list APIs do not. There is no OpenAPI document and no web dashboard.
- PostgreSQL KEV persistence exists and is frozen. Do not edit `20260901120000_kev_intelligence_persistence`; any SQL correction requires another forward-only migration.
- Restricted CISA KEV HTTPS transport and private intelligence snapshot storage exist in `@patchpilot/integrations`. Configuration loading, API status GETs, and worker startup do not contact CISA. The processor fetches only after authoritative PostgreSQL validation and BackgroundJob claim.
- The production KEV catalog body is not stored in the repository.
- KEV-first typed configuration includes scheduler poll, startup delay, and retry-reconcile settings. Loading configuration does not start timers or Redis.
- OSV runtime remains disabled. `INTELLIGENCE_OSV_ENABLED=true` must fail configuration validation. Public OSV status is always deferred and is not loaded from PostgreSQL.
- Worker `resourceLimits` are not set in v0.1. Bounding is the 8 MiB input ceiling, 16 MiB serialized output ceiling, configured wall-clock timeout, and actual `worker.terminate()`. Duplicate JSON object keys are not detected; last-key-wins remains a documented limitation. Sub-millisecond `dateReleased` fractional digits are not retained in `catalogReleasedAt`.
- Snapshot object-key layout is closed: `intelligence/cisa_kev/cisa_kev_json_catalog/tmp/{uuid}` and `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/{sha256}` ([OD-20](docs/architecture/open-decisions.md)).
- No advisory-to-component matching, version-range evaluation, Finding writes, KEV enrichment of Findings, risk scoring, or `finding.recalculate`.
- Existing required unique `osvId` is unchanged. [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) accepts canonical CVE identity. Batch 3B applied and froze `20260902120000_canonical_cve_identity`. Batch 4B ships `createCveIdentityPersistence`. Batch 5B adds read-only active-catalog membership derivation. Full provider-neutral Vulnerability advisory identity remains open ([OD-19](docs/architecture/open-decisions.md)).
- Delivery remains at-least-once. PostgreSQL uniqueness and BackgroundJob leases are authority; Redis job IDs are not exact-once.
- Instance-operator identity remains unresolved ([OD-10](docs/architecture/open-decisions.md)).
- Session 9 did not receive a separate formal closure checkpoint. Its implemented KEV capabilities remain current. These gaps remained after Session 9 Batch 9B; they are historical Session 9 boundaries and do not imply that the repository is currently executing Session 9. Unresolved product gaps remain tracked independently.

### Session 10 Batch 1B

These were the Batch 1B gaps. Later Session 10 batches added the frozen migration, persistence adapters, and read-only membership derivation. Do not treat this list as current state:

- [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) is accepted on this feature branch. Canonical CVE identity and advisory-to-CVE links began as domain records, commands, and provider-neutral ports only.
- The current application has no production Finding creation path. The policy engine remains without production scoring.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, or Finding-adjacent command is added.
- `Vulnerability.osvId` remains required and unique. No Vulnerability rows are merged by CVE. No OSV identifier is manufactured.
- Canonical CVE identity persistence and the forward-only identity migration remained future relative to Batch 1B. Do not treat Batch 1B types as the shipped adapter story.
- KEV membership remains a global exploitation signal, not proof of tenant exposure. Read-only active-KEV derivation was not implemented in Batch 1B.
- No API route, worker, Outbox event, permission, or web UI was added in Batch 1B.

### Session 10 Batch 3B

These were the Batch 3B gaps after the freeze. Later batches added adapters and membership derivation. Do not treat the adapter/derivation sentences as current state:

- Migration `20260902120000_canonical_cve_identity` was applied to the persistent development database. That catalog now has eleven finished migrations.
- The migration is **frozen**. Frozen SHA-256: `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`. Do not edit it; any SQL correction requires another forward-only migration.
- Two global append-only tables exist: `CveIdentity` (`createdAt` only) and `VulnerabilityCveIdentityLink` (`linkedAt` only, source-free). Canonical-only backfill completed. Malformed legacy `cveId` values remain unchanged and unlinked.
- No CveIdentity persistence adapter, mapper, repository factory, or runtime service existed in Batch 3B.
- Read-only active-KEV derivation was not implemented in Batch 3B. `KevEntry` is unchanged.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, Outbox, BackgroundJob, API, worker, permission, risk, or web UI change is included. No fan-out runtime was added.
- `Vulnerability.osvId` remains required and unique. `Vulnerability.cveId` remains nullable `VARCHAR(32)` and unchanged. No Vulnerability merge occurred. OSV remains deferred.

### Session 10 Batch 4B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `createCveIdentityPersistence` exposes `identities` and `links`. Ensure is insert-once. Unique conflicts reload the stored row. The database generates identity `createdAt`. Link `linkedAt` is supplied by the command and is never overwritten. Source-free links are unchanged. Batch lookup and keyset listing are bounded (1–100). Invalid keyset limits are rejected, not clamped.
- Global identity tables remain instance-owned. The adapters take no tenant arguments and do not query KEV entries or generations.
- The migration remains frozen and unchanged. Frozen SHA-256: `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`.
- Read-only active-KEV derivation is not implemented in Batch 4B. `KevEntry` is unchanged.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, Outbox, BackgroundJob, API, worker, permission, risk, or web UI change is included. No fan-out runtime was added.
- `Vulnerability.osvId` remains required and unique. `Vulnerability.cveId` remains nullable `VARCHAR(32)` and unchanged. No Vulnerability merge occurred. OSV remains deferred. ZIP processing remains absent.

### Session 10 Batch 5B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `createQueryActiveKevMembershipUseCase` answers active-catalog membership for **one exact canonical CVE** against the currently accepted CISA KEV generation. Statuses are `unavailable` (`no_active_generation` only), `absent`, and `listedInActiveKev`. Freshness is `current`, `stale`, or `disabled_with_history` on absent and listed results only.
- Absence is relative to the accepted active snapshot, not live CISA. Listed means membership in that snapshot. Disablement stops refresh but does not erase accepted history. Stale results remain snapshot-relative. A future risk or Finding workflow must explicitly decide whether stale or disabled-with-history absence is usable.
- No provider prose is returned. Structured calendar dates and the normalized ransomware enum are the only listed attributes besides catalog metadata and freshness. No CveIdentity or advisory-link row is required or created. A KEV CVE may be listed without an identity row.
- The read port and Prisma adapter take no tenant, organization, provider, generation, or identity arguments. The query is bounded to one IntelligenceSource, the nested active generation, and at most two `KevEntry` rows (`take: 2`). Staging, complete, superseded, and abandoned generations are invisible.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, Component, Outbox, BackgroundJob, API, worker, scheduler, permission, risk, or web UI change is included. No fan-out or `finding.recalculate` event exists. The use case is not wired into `apps/api` or `apps/worker`.
- All eleven migrations remain frozen and unchanged. `Vulnerability.osvId` remains required and unique. OSV remains deferred. ZIP processing remains absent. KEV membership remains an exploitation signal, not proof of tenant exposure.

### Session 10 current state (after Batch 6B)

- The canonical CVE identity migration exists and is frozen.
- Identity and link persistence adapters exist.
- Read-only active-catalog KEV membership derivation exists.
- No Finding enrichment exists.
- No tenant join exists.
- No risk integration exists.
- No API or worker wiring exists.
- Zero-Finding remains enforced.

### Session 11 Closure State (after Batch 6D)

Session 11 acquisition foundation is **CLOSED** and synthetically verified. Verdict: Session 11 acquisition foundation closed; ready for runtime-enablement architecture.

- Production OSV acquisition remains disabled. `INTELLIGENCE_OSV_ENABLED=true` is rejected.
- At Session 11 closure, provider listing execution was absent. Session 12 Batch 1 later added the uncomposed listing adapter; it remains runtime-unreachable.
- Runtime scheduler and durable OSV jobs are absent.
- Automatic retries are absent.
- Catalog activation is not invoked. No production OSV catalog is active.
- Matching and Finding writes remain unauthorized.
- Parser pending capacity: ADR 0028 selects **0**. The parser host occupancy is 1 and a second concurrent parse is rejected. The historical isolation-policy constant remains `unavailable` until a later Session 12 runtime-composition batch reconciles it. No body-bearing parser queue is authorized.
- Duplicate JSON-key detection is not implemented. ADR 0028 Option B: residual risk for a later disabled canary; detection or explicit exception before activation.
- Operational runbook **outlines** live in ADR 0028. They are not live procedures.
- Cleanup executor and retention deletion remain absent.
- Canary policy is defined and not executed (Session 13 / ADR 0028 R6).
- Package normalization and version evaluation remain out of scope for Session 12 runtime-enablement batches.

Session 12 Batch 1 implements the uncomposed GCS listing-page HTTPS executor. Pagination, schedulers, jobs, and OSV enablement remain later gates. Session 12 remains zero-Finding. Matching is later Session 14+ architecture. Finding writes remain gate-blocked (current roadmap: no earlier than Session 16).

### Runtime Enablement Phase R1 (ADR 0028, Accepted)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0028](docs/adr/0028-osv-runtime-enablement-architecture-and-safety.md) is **Accepted**. Architecture identifier `osv_runtime_enablement_architecture_v1`. Acceptance authorizes only the staged roadmap and the listing-adapter boundary later implemented as Session 12 Batch 1 (ADR 0028 R2). It is not canary, activation, matching, Finding-write, or OSV enablement authorization.
- R1 did not implement a listing executor, scheduler, `intelligence.osv.sync`, lease table, retry executor, cleanup executor, kill-switch variable, or observability emitters. Session 12 Batch 1 later added the uncomposed listing adapter; it remains runtime-unreachable. Scheduler, jobs, leases, retries, cleanup, kill-switch, and observability emitters are **not implemented**.
- Parser-host pending capacity is selected at **0**. The committed isolation constant remains `unavailable` until a later Session 12 runtime-composition batch (ADR 0028 R4/R5). Occupancy is already 1; a second concurrent parse is rejected. No body-bearing parser queue is authorized.
- First-provider canary is `crates.io/` / `rustsec_advisory_database` with exact caps. It is not authorized to execute. Legal revalidation is required before Session 13 canary work (ADR 0028 R6).
- Duplicate JSON-key disposition is Option B: residual risk for a disabled canary; detection or explicit exception before catalog activation.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 12 Batch 1 (listing-page HTTPS executor)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 1 implements `createOsvGcsListingHttpsAdapter` at `packages/integrations/src/osv-gcs-listing-https-adapter.ts`. It performs **one** GCS JSON Objects listing-page HTTPS request per invocation via `OsvTransportPort.listPage`.
- The compiled Batch 3C surface is fixed: `GET` `https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o`, unauthenticated, redirects rejected, `Accept-Encoding: identity`, `application/json`, 1,048,576-byte page ceiling, fatal UTF-8, committed listing-page parser.
- Timeouts reuse committed `OSV_TIMEOUT_POLICY_V1` (listing-specific milliseconds were not committed; semantics match the approved GCS HTTPS one-attempt 1 MiB policy). Continuation-token UTF-8 bytes are rejected above 8192 at request construction. ADR 0028 pagination ceilings, token-cycle detection, and A/B convergence are **not** implemented.
- The adapter is exported from `@patchpilot/integrations` and is **not** imported by worker, API, scheduler, queue, health, seed, or migration composition. Tests use synthetic local HTTPS/DNS doubles only and do not contact `storage.googleapis.com` or `osv.dev`.
- No retry, body retrieval, persistence, storage, parser-worker, catalog activation, matching, Finding write, API, permission, Prisma, or dependency change is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 2 later adversarially reviewed this executor. Batch 1 and Batch 2 do not implement pagination or convergence.

### Session 12 Batch 2 (listing-executor adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 2 adversarially reviewed the Batch 1 listing executor with synthetic doubles only. It did not contact `storage.googleapis.com` or `osv.dev`.
- Transport hardening: HTTP 200 `Location` presence including arrays fails closed; `Transfer-Encoding` ambiguity and compressed transfer encodings fail closed; shared Content-Length rejects leading zeros and multi-value arrays; shared Content-Encoding accepts only absent or `identity`; DNS answers are copied before pin selection; socket listeners are one-shot with cleanup; non-byte body chunks are rejected.
- Continuation tokens remain confidential and are encoded once in `pageToken`. One invocation remains zero or one HTTPS request.
- Pagination, token-cycle detection, A/B convergence, retries, schedulers, durable jobs, catalog activation, matching, Findings, and production composition remain absent.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Next checkpoint relative to this Batch 2 checkpoint was Session 12 Batch 3 pagination and convergence contracts.

### Session 12 Batch 3 (listing pagination and convergence contracts)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 3 implements pure pagination and two-pass inventory convergence contracts in `@patchpilot/vulnerability-intelligence`. It does not execute a pagination loop, call `createOsvGcsListingHttpsAdapter`, contact `storage.googleapis.com` or `osv.dev`, persist raw tokens or token digests, retrieve advisory bodies, compose production runtime, enable OSV, or write Findings.
- Policy profiles are closed: `disabled_canary` (`osv_disabled_first_provider_canary_policy_v1`) and `production_fail_closed` (`osv_listing_pagination_policy_v1`). Convergence policy identifier is `osv_listing_inventory_convergence_policy_v1`. Callers cannot supply numeric limits.
- Raw continuation tokens remain in memory only. In-memory SHA-256 token-digest cycle detection is bounded by max pages per pass. Crash restart begins at page one with a new pass-attempt identity.
- Canary completeness cannot satisfy production completeness. Incomplete inventory cannot authorize body retrieval. These contracts never authorize candidate readiness or catalog activation.
- Pagination execution, two-pass I/O orchestration, durable jobs, retries, schedulers, catalog activation, matching, and Findings remain absent from Batch 3. Session 12 Batch 4 later added in-memory pagination execution without production composition.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 4 (listing pagination and convergence implementation)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 4 implements `createOsvListingPaginationService` in `@patchpilot/vulnerability-intelligence` at `src/osv/listing-pagination/pagination-service.ts`. It is explicitly invoked. Worker, API, scheduler, queue, health, seed, and migration composition do not import it.
- One immutable policy profile, one prefix, one pass, and one page are processed at a time. Pass A runs before pass B. There is no third pass and no same-attempt convergence restart.
- Closed profiles remain `disabled_canary` and `production_fail_closed`. Callers cannot supply numeric limits, endpoints, tokens, or prefix reordering.
- The injected `OsvListingPageExecutorPort` performs one listing-page call per requested page. The production HTTPS adapter is not imported. Tests use scripted in-memory ports only and do not contact `storage.googleapis.com` or `osv.dev`.
- Successful one-page transport results expose exact `responseByteCount` (received bytes before UTF-8 decoding). Pagination passes that count to `acceptOsvListingPage`. Failures do not return a successful byte count.
- Raw continuation tokens and token digests remain in memory only. At most one raw token is retained for the active pass. Token cycles fail closed (`listing_token_cycle`, `quarantine_required`). Detector state is not reused across passes, prefixes, or attempts.
- Page admission is atomic in memory. Exact per-page, per-pass, per-prefix, and per-run ceilings are enforced. Exact ceiling is accepted; one over fails closed.
- After the first terminal nonconverged prefix, later prefixes are accounted without further listing I/O so Batch 3 inventory completeness still receives every planned prefix. Production completeness still requires all six prefixes to converge.
- Canary completeness cannot satisfy production completeness. Incomplete inventory cannot authorize body retrieval. These results never authorize candidate readiness or catalog activation.
- Cancellation is checked at prefix, pass, page, token, convergence, and inventory boundaries. Interruption returns bounded incomplete progress with no durable token. Retry disposition is recorded and never executed.
- No Prisma, migration, dependency, scheduler, BackgroundJob, Outbox, body retrieval, object storage, parser, matching, Finding, or OSV-enablement change is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 4-R later adversarially reviewed this implementation.

### Session 12 Batch 4-R (listing pagination adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 4-R adversarially reviewed `createOsvListingPaginationService` with synthetic pages and scripted ports only. It did not contact `storage.googleapis.com` or `osv.dev`.
- Page admission is atomic: candidate arithmetic is calculated and discarded on rejection. Exact ceilings succeed; one over fails closed. Unsafe integers fail closed.
- Only constructed transport success is trusted. Malformed port output, extra fields, and unconstructed success objects fail closed. Hung ports lose to cancellation. One listing call remains in flight.
- Raw tokens remain ephemeral and confidential. Token cycles, digest collisions, and cross-pass token reuse fail closed. Detector state cannot exceed the pass page maximum.
- Canonical sets remain length-prefixed and order-independent. Convergence requires digest plus exact observation equality plus the committed algorithm identifier. Canary completeness cannot satisfy production completeness.
- Retry disposition is recorded and never executed. There is no prefetch, third pass, same-attempt restart, body retrieval, scheduler, job, lease, or production composition.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 5 later added framework-independent job, lease, and retry contracts without registering a runtime job.

### Session 12 Batch 5 (runtime job, lease, and retry contracts)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 5 implements pure job, lease, fencing, retry, parser-capacity, halt, cancellation, restart, and operational-event contracts in `@patchpilot/vulnerability-intelligence` at `src/osv/runtime-coordination/`. It does not persist leases, acquire leases, execute retries, parse environment variables, contact a provider, or compose production runtime.
- Future job type `intelligence.osv.sync` is a design contract only. Worker routing still recognizes `sbom.ingest` and `intelligence.sync` only.
- Canary and production share one OSV GCS public-export lease scope and remain distinct work scopes. KEV synchronization remains a separate job and lease domain.
- Holder token, lease row revision, and fencing token are separate. Database time is the takeover authority. Heartbeat does not substitute for stage fencing.
- Three total attempts include the initial attempt. Parser timeout is two total attempts. Retry-After is HTTP 429 only and is capped at 30 seconds. Exhaustion is terminal and does not create attempt 4.
- Parser pending capacity is contracted as 0. The parser-host pending-queue status constant remains `unavailable` until a later runtime-composition batch. No body-bearing parser queue is authorized.
- Future halt defaults halted. `INTELLIGENCE_OSV_ACQUISITION_HALT` is not added. Enablement does not clear halt.
- Reserved Outbox event `intelligence.osv.sync.requested.v1` is deferred, not registered.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 6 later added schema-only persistence without adapters.

### Session 12 Batch 6 (runtime coordination persistence schema)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 6 implements Prisma models and exactly one forward-only migration: `20260907120000_osv_runtime_coordination_persistence`. Frozen SHA-256 after Batch 6-R: `7017b1c4b1d4bcae8bed4bdd0eb43559c0c89fce5b3636e0e889b276013cc3a6`. Fourteen finished migrations. Do not edit it; any SQL correction requires another forward-only migration.
- Tables are global and instance-owned. They have no tenant foreign key and no Finding relation. Raw holder tokens, page tokens, token digests, provider bodies, URLs, and arbitrary JSON are absent.
- Current lease projection stores holder-token digest only. Row revision and fencing token are separate positive BIGINTs. Expired is not a stored state. Database timestamps support `databaseNow >= expiresAt` without application-clock authority.
- Stage-attempt identity is immutable. Ordinal 4 cannot satisfy CHECK constraints. Parser timeout cannot use ordinal 3. Retry exhaustion preserves the exact failure code.
- The schema existing does not make `intelligence.osv.sync` executable. Session 12 Batch 7 later added uncomposed PostgreSQL adapters without production composition.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 6-R later reviewed this schema before freeze.

### Session 12 Batch 6-R (persistence and migration review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 6-R independently reviewed the uncommitted Batch 6 schema with disposable PostgreSQL and direct SQL. It did not contact `storage.googleapis.com` or `osv.dev`.
- Version-set fingerprints, holder-token digests, and target-identity digests are TEXT with exact `char_length = 64` lowercase SHA-256 CHECKs. CHAR/VARCHAR(64) would silently truncate extra trailing spaces and accept a padded digest.
- Lease projection DELETE is forbidden so an ordinary cleanup cannot recreate the scope row with `fencing_token = 1`. UPDATE requires strictly increasing `rowRevision`. Heartbeat cannot change `fencingToken`. Ownership change, release, and reacquisition must increment `fencingToken`.
- Concurrent stale-takeover CAS against the same revision and fencing token admits exactly one winner. The prior owner cannot subsequently satisfy ownership fields.
- Planned or running stage attempts may transition once to a terminal state. Terminal attempts and attempt identity fields are immutable. DELETE remains forbidden.
- Completed runs cannot claim `durable_retry`. Retry-not-before is capped at `terminal_at + 30 seconds`. Batch 7 computes retry-not-before from database time plus selected delay.
- Session 12 Batch 7 later added uncomposed PostgreSQL adapters. Retry execution, scheduler, BackgroundJob routing, Outbox routing, kill-switch variable, and production composition remain absent.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 7 later added PostgreSQL adapters. Session 12 Batch 7-R reviewed those adapters.

### Session 12 Batch 7 (runtime coordination adapters)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 7 implements `createOsvRuntimeCoordinationPersistence` in `@patchpilot/database`. Worker, API, scheduler, queue, health, seed, and migration composition do not import it.
- Adapters establish and inspect durable authority only. They do not execute retries, sleep, poll, parse live Retry-After headers, contact a provider, invoke storage or the parser, activate a catalog, or enable OSV.
- Holder tokens remain in WeakMap proofs. PostgreSQL stores lowercase SHA-256 digests only. Public projections omit digest and raw token.
- Lease time and retry-not-before use database `CURRENT_TIMESTAMP`. Application clocks are not takeover or retry authority.
- Fencing tokens increment on acquire after absence/release, stale takeover, and release. Heartbeat does not change fencing. Lease rows are never deleted.
- Attempt ordinal 4 is impossible. Parser timeout remains two total attempts. Exhaustion is queryable and does not replace the root failure code.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 7-R later reviewed these adapters.

### Session 12 Batch 7-R (runtime coordination adapter review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 7-R independently reviewed the uncommitted Batch 7 adapters with disposable PostgreSQL. It did not contact `storage.googleapis.com` or `osv.dev`.
- Expired holders cannot heartbeat or release. Database time owns that boundary (`CURRENT_TIMESTAMP < expires_at` remains valid; `>=` is expired). Same-owner acquire after expiry is a new fencing generation via a same-transaction released-then-held pair, because the Batch 6-R trigger treats held→held same run and digest as a heartbeat.
- Attempt reservation is transactional and ordered. Inspection of retry eligibility is not dispatch authority. Session 12 Batch 8 rechecks ownership before protected stages.
- No schema or migration change. No scheduler, BackgroundJob routing, Outbox routing, retry timer, kill-switch variable, or production composition.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Session 12 Batch 8 later added disabled runtime composition.

### Session 12 Batch 8 (disabled runtime composition)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 8 implements `createOsvDisabledRuntimeSynchronization` in `@patchpilot/vulnerability-intelligence`. It is explicitly constructed. Worker, API, scheduler, queue, health, seed, CLI, and migration composition do not import it.
- Synthetic execution is confined to `createOsvDisabledRuntimeSynchronizationForVerification`, which is not exported from the public package. It cannot be enabled by `INTELLIGENCE_OSV_ENABLED`, environment variables, queue payloads, JSON flags, or a package subpath. Public synchronize halt-closes after persisting request and run.
- Request and run authority precede listing. Listing requires current lease ownership. Fencing is revalidated at committed checkpoints. Ownership loss does not release another holder's lease.
- Inventory convergence precedes acquisition. Canary completeness cannot satisfy production completeness. Raw tokens and token digests remain in memory only.
- Retry disposition is persisted. Batch 8 does not sleep, poll, enqueue, or execute attempt 2.
- No periodic heartbeat loop. Heartbeat scheduling remains deferred to Session 12 Batch 9 or a dedicated heartbeat batch. Synthetic tests complete well inside the 900000 ms lease TTL and do not prove a four-hour run is safe.
- Candidate readiness does not activate the catalog, replace the active pointer, invoke matching, or create Findings.
- No production BackgroundJob discriminant, Outbox discriminant, BullMQ processor, scheduler, or acquisition-halt environment variable.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding.

### Session 12 Batch 8-R (disabled composition adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 8-R independently reviewed the uncommitted Batch 8 composition with scripted listing pages, scripted retrieval, disposable PostgreSQL, disposable MinIO, and the isolated parser worker. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- The public factory never honors a caller-supplied execution flag. The verification factory is not a public package export and is not imported by worker, API, scheduler, queue, health, seed, or migration composition. The worker rehearsal imports that unexported factory from the compiled package dist so constructed payload and holder-token identity matches Batch 7 adapters. Worker `tsconfig.json` excludes that integration test from production typecheck.
- Late listing, retrieval, parser, and attachment success after ownership loss is discarded and cannot authorize the next protected stage. Attempt reservation or start failure prevents the stage. Stale owners do not transition the authoritative run to failed or cancelled and do not release a later holder's lease. Post-lease cancellation terminalizes the run before release.
- The inventory-to-acquisition bridge requires the exact canary or production prefix plan and complete pass A and pass B. Canary completeness cannot satisfy production completeness. Source authorization remains independent of inventory completeness.
- Retry disposition is recorded. There is no automatic retry, sleep, polling, delayed dispatch, periodic heartbeat loop, scheduler, BackgroundJob route, or Outbox route.
- Candidate readiness never activates a catalog. Results and events omit holder tokens, page tokens, provider bodies, and tenant fields. Cross-layer rehearsal deletes test-owned MinIO objects and PostgreSQL rows in FK-safe order.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 12 remains zero-Finding. Next checkpoint is Session 12 Batch 9 typed halt and observability, later reviewed in Session 12 Batch 9-R.

### Session 12 Batch 9 (acquisition halt and observability)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 9 adds typed `INTELLIGENCE_OSV_ACQUISITION_HALT` in `@patchpilot/config` (`intelligence.osvAcquisitionHalt`). Default, missing, and empty values are `halted`. Explicit `true` is halted. Explicit `false` is `permitted_by_halt_control` only. Malformed values fail configuration validation. Whitespace-padded `true`/`false` follow the existing typed boolean contract. `1`, `yes`, `on`, and similar aliases are rejected.
- Enablement and halt are independent. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt false does not make enablement valid and does not start production composition, a scheduler, a job route, a lease, or provider contact.
- Halt evaluation accepts only typed trusted state. It does not read `process.env`. Production callers cannot select synthetic authority. The verification factory remains unexported. Work continues only for `permitted_for_synthetic_disabled_execution`.
- Halt is re-evaluated synchronously at protected checkpoints (request/run authority, lease, listing, retrieval, attachment, parser, reconciliation, readiness, and successful completion). There is no polling loop, watcher, or timer. Production environment refresh is a process snapshot; restart is required to pick up a new environment value. A test halt port may change between checkpoints.
- Halt before lease records request and run, then terminalizes without listing, retrieval, parser, retry, or readiness. Halt after lease begins no next protected stage, retains immutable evidence, and releases only if current ownership remains valid. Halt does not create retries, reset fencing, delete the lease row, or activate a catalog.
- Operational events use closed catalog `osv_runtime_operational_event_catalog_v1`. Logs, metrics, and traces remain distinct. Metric labels are closed and exclude run, request, correlation, tenant, Finding, URL, and provider-key identifiers. Event-sink failure cannot change the domain result.
- No production BackgroundJob discriminant, Outbox discriminant, BullMQ processor, scheduler, automatic retry, periodic heartbeat loop, or provider contact. Session 12 remains zero-Finding. Session 12 Batch 9-R reviewed this work.

### Session 12 Batch 9-R (kill-switch and observability adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 9-R independently reviewed the uncommitted Batch 9 halt and observability controls. Tests use synthetic listing pages, scripted ports, and hostile configuration, halt-state, sink, metric, and envelope doubles only. They do not contact `storage.googleapis.com` or `osv.dev`.
- Missing, empty, whitespace, tab, newline, and Unicode-whitespace halt values remain halted by default. Prototype-inherited properties cannot supply the setting. Non-string, mixed-case, numeric, and alias values fail closed without echoing the raw value.
- Explicit `false` remains `permitted_by_halt_control` only. `INTELLIGENCE_OSV_ENABLED=true` remains rejected in every environment. Halt false does not construct production runtime, acquire a lease, or contact a provider.
- `createOsvRuntimeHaltStatePort` is a trusted-state observation factory. Extra properties, enablement flags, and synthetic-authority fields cannot enter the snapshot. Legacy `authorizeOsvRuntimeHaltCheckpoint` without a typed evaluation fails closed even when `osvEnabled` is true. The verification factory remains unexported.
- Halt is re-evaluated at each protected checkpoint. The first blocking checkpoint identity is preserved. Pass B page one is named `before_pass_b` and the first page of a later prefix is named `before_next_prefix`; later pages of the same pass remain `before_listing_request`. Those named checks occur in the listing ownership wrapper before the inner listing call.
- Ownership loss still wins over cancellation and halt. Cancellation still wins over halt. A current owner may release under halt. A stale owner cannot. Halt does not overwrite a prior ownership-loss primary result.
- Event sinks remain non-authoritative. Reentrancy is suppressed on the current invocation call stack. At most 64 emissions are accepted per invocation. Thenables are fire-and-isolate: late rejection, double settlement, and `then` throws cannot alter the domain result or become unhandled.
- Metric labels are closed per metric name. High-cardinality identifiers cannot become labels. Documented per-metric combination upper bounds remain finite. Logs and traces use closed bindings and omit prohibited markers. There is no OpenTelemetry SDK in `@patchpilot/vulnerability-intelligence`.
- No scheduler, production job route, Outbox route, retry executor, heartbeat loop, cleanup executor, catalog activation, matching, Finding write, Prisma change, migration, or dependency change is included. Session 12 remains zero-Finding. Session 12 Batch 10 later closed the runtime-enablement foundation.

### Session 12 Batch 10 (runtime-enablement foundation closure)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 Batch 10 independently reviewed listing transport, pagination, token confidentiality, runtime coordination, lease fencing, retry evidence without execution, disabled composition, halt defaults, bounded observability, production exclusion, provider-contact exclusion, catalog-activation exclusion, and zero-Finding boundaries.
- Production OSV remains disabled. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt false does not enable OSV.
- No production BackgroundJob discriminant, Outbox discriminant, BullMQ processor, scheduler, automatic retry executor, periodic heartbeat loop, cleanup executor, real-provider canary, catalog activation, matching, or Finding write is added.
- Heartbeat scheduling remains `deferred_to_session_13_or_dedicated_heartbeat_batch`. Session 13 Batch 1 later defined canary architecture without implementing the heartbeat controller and must not begin with a live provider call.
- Fourteen frozen migrations remain unchanged. No dependency or lockfile change is included. ADR 0028 remains Accepted. ADR 0027 remains Proposed. Session 12 remains zero-Finding.

### Session 13 Batch 1 (canary architecture and authorization design)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 12 is closed and merged. Session 13 has begun. Batch 1 was design only. No real provider contact has occurred.
- [ADR 0029](docs/adr/0029-first-real-provider-osv-canary-authorization-and-safety.md) defines `osv_first_real_provider_canary_authorization_v1`. Session 13 Batch 1-R Accepted it. Architecture approval is not operator execution, provider-contact, body-retrieval, activation, matching, or Finding-write approval. Acceptance authorizes only later operational-control implementation.
- Exact canary purpose is protocol and control-plane compatibility, not production coverage, scheduler, retries, matching, Findings, activation, or SLA.
- Phases are independently gated: `listing_only` then `bounded_body`. Listing does not grant body retrieval.
- Provider source remains `crates.io/` / `rustsec_advisory_database` / `RUSTSEC` as the provisional technical candidate, blocked on legal revalidation. Session 11 registry evidence is not canary legal authorization.
- Operator authorization is a one-shot instance-operator administrative command after a durable authorization record. A canary-scoped provisional `instance_operator` attestation UUID is selected. OD-10 remains open for general console work. Tenant identity is prohibited.
- Scheduler, production OSV BackgroundJob, and OSV Outbox remain unregistered. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Production services remain halted. Halt false in a shared production configuration must not start the canary.
- Listing-only ceilings remain ADR 0028 canary limits (8/16 pages, 2000/4000 observations, 8,388,608 / 16,777,216 listing bytes, 1800 seconds, 0 body requests, 0 retries). Heartbeat is required before either phase because 1800 s exceeds the 900000 ms lease TTL. The controller is not implemented in Batch 1-R.
- Catalog activation, matching, and Findings remain prohibited. Bounded-body candidates must be canary-ineligible; current catalog-generation inventory scope cannot mark canary, which blocks body-canary implementation until a later batch. Last-key-wins must not authorize durable license classification.
- Runbook outlines live in [docs/runbooks/osv-canary.md](docs/runbooks/osv-canary.md) and are not live procedures.
- No CLI, Prisma, migration, dependency, lockfile, provider artifact, or Session completion report is included.

### Session 13 Batch 1-R (independent canary architecture review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 1-R independently reviewed the uncommitted Batch 1 canary architecture. It did not contact `storage.googleapis.com` or `osv.dev`.
- ADR 0029 is **Accepted**. Acceptance authorizes only Batch 2 operational-control implementation. It does not authorize provider contact, listing-only execution, body retrieval, production enablement, scheduler, automatic retry, catalog activation, matching, or Finding writes.
- Corrections: closed canary-scoped operator identity; closed one-shot authorization record with consume-on-start and 3600 s unused TTL; two-stage license inspection without attach-before-confirm; last-key-wins must not authorize license-based retention; legal gate pins registry version so an active run cannot broaden; heartbeat races closed; body deadline 1800 s budgeted from committed timeouts; Batch 2 split into 2A–2D.
- Next checkpoint is Session 13 Batch 2A operator identity and authorization contracts. Prisma is unchanged in Batch 1-R.

### Session 13 Batch 2A (operator identity and canary authorization contracts)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2A defines framework-independent canary-scoped instance-operator identity and single-use authorization contracts in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-authorization/`).
- Operator identity is instance scoped, non-tenant, UUID v4 attestation, actor kind `instance_operator`. Anonymous, tenant User, organization membership, session cookie, lease holder token, worker ID, process ID, Redis job ID, and synchronization run ID cannot grant canary authority.
- Authentication source is `local_host_control_of_one_shot_administrative_command` and remains `contract_only_not_implemented`. Batch 2A does not implement authentication.
- Authorization binds exactly one phase (`listing_only` or `bounded_body`), the committed `crates.io/` prefix, source, policy, version-set fingerprint, and frozen budget profile. Callers cannot supply numeric limits, endpoints, activation, matching, or Finding options.
- Listing-only authorization cannot permit body retrieval. Bounded-body authorization requires accepted listing-review evidence plus a body legal-decision reference. Legal issuance remains a blocking preexecution dependency (`recorded_reference_not_execution_authority`).
- Lifecycle: issued → consumed → completed | failed | cancelled; issued may also become revoked, expired, or cancelled. One authorization is consumable once. Same-run redelivery reloads the consumed result. Different run is rejected. Unused TTL is 3600 seconds. `databaseNow >= expiresAt` means expired. Consumed authorization does not become expired merely because unused TTL passes.
- Halt release alone grants no authority. Synthetic verification grants no authority. Authorization alone does not release halt. Execution remains unauthorized in this batch.
- Persistence intent documents Batch 2B tables (`osv_canary_instance_operator_identity`, `osv_canary_authorization`). Prisma is unchanged in Batch 2A. No CLI, API, scheduler, job route, Outbox route, heartbeat, deadline timer, provider contact, activation, matching, or Findings.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 2B later added schema-only persistence.

### Session 13 Batch 2B (canary authorization persistence schema)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2B adds the minimum forward-only Prisma and PostgreSQL persistence for the committed Batch 2A contracts: `osv_canary_instance_operator_identity` and `osv_canary_authorization`.
- Migration `20260908120000_osv_canary_authorization_persistence`. Frozen SHA-256 `321ac38a02090470aa5f09661cb0e29562327c16c9e341b44bc99516bd7fbd99`. Fifteen frozen migrations. All fourteen prior migrations remain byte-for-byte unchanged. Later SQL corrections require another forward-only migration.
- Operator identity is global and instance owned. No Organization, tenant User, password, API key, bearer token, cookie, certificate, session, lease-holder token, or Finding relation. Anonymous identity cannot persist. Authentication remains unimplemented; the row is a durable identity authority contract, not proof that authentication is operational. No operator identity is seeded.
- One authorization row authorizes exactly one phase. Listing-only cannot store body-selection or listing-review fields. Bounded-body requires accepted listing-review evidence plus a body legal-decision reference. Policy, budget-profile, version-set fingerprint, runbook, halt, activation-prohibition, and retry-prohibition identifiers are immutable and constrained to committed values. Callers cannot store numeric limits, endpoints, activation, matching, or Finding options.
- Unused TTL is 3600 seconds (`expires_at = issued_at + 3600 seconds`). `databaseNow >= expiresAt` means expired before initial consumption. Consumed authorization does not become expired merely because unused TTL passes.
- Lifecycle matches Batch 2A: issued → consumed → completed | failed | cancelled; issued may also become revoked, expired, or cancelled. DELETE is forbidden. Same-run redelivery can reload the consumed binding. A different run cannot reuse a consumed authorization. Partial unique indexes bind one consumed request and one consumed run to one authorization.
- Listing-review evidence is columns plus a restrictive self-FK to a `listing_only` row. Batch 2B-R requires that target to be completed and to match the consumed listing request, run, and version-set fingerprint. One listing authorization may authorize one bounded-body row.
- No issuance, consumption, revocation, or CLI adapter in this batch. No heartbeat or deadline controller. No scheduler, BackgroundJob route, Outbox route, or production composition. Schema existence does not issue or consume an authorization. Session 13 Batch 2C later added uncomposed PostgreSQL adapters. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding.

### Session 13 Batch 2B-R (canary authorization persistence adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2B-R independently reviewed the uncommitted Batch 2B schema with disposable PostgreSQL and direct SQL. It did not contact `storage.googleapis.com` or `osv.dev`.
- Migration `20260908120000_osv_canary_authorization_persistence` remains the single new forward-only migration. Frozen SHA-256 after review: `321ac38a02090470aa5f09661cb0e29562327c16c9e341b44bc99516bd7fbd99`. Fifteen frozen migrations. All fourteen prior migrations remain byte-for-byte unchanged. Do not edit it; any later SQL correction requires another forward-only migration.
- Operator identity remains global and instance owned. Anonymous identity cannot persist. Tenant User and Organization cannot grant operator authority.
- Listing-only cannot persist body authority. Bounded-body requires accepted listing-review evidence against a completed listing_only authorization whose consumed request and run match. Policy and safety budgets cannot be caller overridden. Legal decisions remain phase specific. Opaque legal-decision and inventory-evidence UUIDs still require Batch 2C transactional verification of the referenced issuance.
- Authorization expiration and initial consumption are enforceable with database time (`CURRENT_TIMESTAMP`). Exactly one concurrent consumer can win. Same-run replay is distinguishable from a second execution. Different-run reuse is rejected. Revoked, expired, cancelled, and terminal authorizations cannot be consumed. Deletion cannot reset single-use authority.
- No issuance, consumption, revocation, or CLI adapter in this batch. No heartbeat or deadline controller. No scheduler, BackgroundJob route, Outbox route, or production composition. Session 13 Batch 2C later added uncomposed PostgreSQL adapters. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding.

### Session 13 Batch 2C (canary authorization adapters)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2C implements `createOsvCanaryAuthorizationPersistence` in `@patchpilot/database` against the frozen Batch 2B schema and committed Batch 2A contracts.
- Operator identity ensure is insert-once. Unique conflict reloads by attestation identity and compares immutable fields. Identical replay is `already_applied`. Any immutable mismatch is `immutable_conflict`. P2002 is never treated as success.
- Operator authority inspection returns `current`, `revoked`, `absent`, `malformed_authority`, or `database_unavailable`. A current identity does not grant canary authorization.
- Operator revocation uses database time, keeps the row durable, and is idempotent for an already-revoked identity. A revoked operator cannot receive a new authorization through the adapter.
- Authorization ensure validates a current operator, exact phase, prefix, budget, policy, version-set fingerprint, phase-specific legal-decision fields, and bounded-body listing-review evidence against a completed listing_only row. Issued-at and expires-at are database owned (`CURRENT_TIMESTAMP` and plus 3600 seconds).
- Consume is one guarded UPDATE (`state = issued` and `CURRENT_TIMESTAMP < expires_at`) that binds one synchronization request and run. Exactly one concurrent consumer can win. Same-run replay returns `already_consumed_same_run`. A different run returns `already_consumed_other_run`.
- Pre-consumption revocation and cancellation, durable expiration from issued, and consumed terminal disposition (`completed`, `failed`, `cancelled`) use expected-state CAS and database timestamps. Terminal rows are immutable.
- Production worker, API, scheduler, queue, health, seed, and migration composition do not import the factory. No CLI, heartbeat controller, deadline timer, scheduler, BackgroundJob route, Outbox route, retry executor, or provider contact. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding.

### Session 13 Batch 2C-R (canary authorization adapter adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2C-R independently reviewed the uncommitted Batch 2C adapters with disposable PostgreSQL and synthetic identities only. It did not contact `storage.googleapis.com` or `osv.dev`.
- Operator ensure remains insert-once. Identical replay is `already_applied`. Immutable mismatch is `immutable_conflict`. Revoked-operator identical replay is `operator_revoked` and does not recreate the row.
- A revoked operator cannot receive a new authorization. Unconsumed authorizations cannot be consumed after operator revocation (`operator_revoked`). Already consumed same-run replay remains status reuse and is not a second execution. Prior attribution remains durable.
- Legal-decision revalidation uses database time at ensure and consume. Expired or substituted legal references fail closed. Listing-only cannot escalate to bounded-body. Listing-review evidence must target a completed listing_only authorization whose consumed run and version bindings match.
- Consumption is one CAS winner. `databaseNow >= expiresAt` rejects initial consumption. Same-run replay returns `already_consumed_same_run` without minting execution permission. Different-run replay is `already_consumed_other_run`. Unique consume-request or consume-run bindings are `request_run_mismatch`, not identity replay.
- Terminal authorization outcomes are immutable. Zero-row CAS reloads and classifies authoritative state. Mappers fail closed on malformed rows. Public results omit SQL, Prisma, credentials, tokens, legal prose, tenant fields, and Findings.
- No schema or migration change. No operator authentication, CLI, heartbeat, deadline, scheduler, BackgroundJob route, Outbox route, retry executor, or provider contact. Authorization consumption alone does not execute the canary. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 2D later added the uncomposed one-shot command boundary.

### Session 13 Batch 2D (one-shot instance-operator command boundary)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2D implements `createOsvCanaryOneShotCommandService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-operator-command/`). Framework-independent. Production composition does not construct the factory.
- Authentication is an injected `OsvCanaryInstanceOperatorAuthenticationPort`. Production authentication remains unimplemented. Tenant User, Organization membership, session cookies, lease holder tokens, worker IDs, and anonymous identity cannot authenticate as an instance operator.
- The command authenticates, confirms durable current operator authority, loads exactly one existing authorization, and does not create operator identity or authorization.
- Halt is evaluated independently after authorization validation and before request/run ensure and consumption. Default halt returns `halt_engaged` and leaves the authorization issued. Halt release is not authorization. Authorization does not release halt.
- When halt is released through trusted state, the command ensures one canary synchronization request and one run, then consumes the authorization once against those identities.
- Successful outcome is `authorized_preflight_required`. `executionPermitted` is false. Remaining gates include heartbeat, deadline, egress preflight, operational runbook, phase-execution authorization, and postcanary review. No lease is acquired. Provider-call count is 0.
- Same-run consumed replay is status reuse and does not execute another stage. Different-run replay is `authorization_consumed_other_run`. Cancellation before consumption leaves the authorization issued. Cancellation after committed consumption reports the consumed status and does not reset the row.
- No public CLI, API route, scheduler, BackgroundJob route, Outbox route, or BullMQ processor. Scripted authentication lives in a test-only harness excluded from the production build. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint relative to this Batch 2D checkpoint was Session 13 Batch 2D-R one-shot command adversarial review.

### Session 13 Batch 2D-R (one-shot command adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2D-R independently reviewed the uncommitted Batch 2D one-shot command with scripted authentication ports, synthetic authorizations, and disposable PostgreSQL. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- Authentication remains an injected identity-only port. Anonymous and tenant identities cannot pass. Authentication proof material is WeakMap-backed, bounded, omitted from JSON/inspect/results/events, and is not a public package export. The command cannot ensure or issue operator identity or authorization.
- Halt is independent from authorization. Halt is re-evaluated after authorization validation and again immediately before consumption. Default halt and later halt engagement leave an issued authorization unconsumed. Halt release is not authorization. Same-run replay remains status reuse and does not authorize a second execution. Different-run replay is rejected without a second consume. Hostile inspect substitution of another request or run fails closed.
- Successful outcome remains `authorized_preflight_required` with `executionPermitted=false`, provider and lease call counts 0. No production CLI, API, scheduler, BackgroundJob route, Outbox route, heartbeat, deadline, or provider contact. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 2E later added uncomposed heartbeat and deadline controllers without wiring them into the command.

### Session 13 Batch 2E (heartbeat and deadline controllers)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2E implements `createOsvCanaryLeaseHeartbeatController` and `createOsvCanaryDeadlineController` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-runtime-controls/`). Framework-independent. Production composition does not construct the factories.
- Heartbeat cadence is exactly 60000 milliseconds. Lease TTL remains exactly 900000 milliseconds. Pending heartbeat capacity is 0. Maximum in-flight heartbeats is 1. Callers, environment, authorization records, and Retry-After cannot override cadence or TTL. There is no jitter and no catch-up burst.
- The first heartbeat is scheduled one interval after successful start. Construction performs no I/O and starts no timer. Start requires a protected ownership context (lease scope, run identity, holder proof, row revision, fencing token, cancellation). Inspection omits that context.
- Each successful heartbeat replaces the current row revision and must return the same fencing token. A changed fencing token fails closed and does not adopt takeover. Expired or replaced ownership cannot be resurrected. The controller does not acquire, take over, or release a lease.
- Halt is evaluated from trusted state before every dispatch. Halt does not release the lease inside the controller. Cancellation is checked before start, before scheduling, when the timer fires, before heartbeat, after heartbeat, and during stop.
- Delayed callbacks measure monotonic lateness. Lateness above zero revalidates current ownership. Delay at or beyond lease TTL fails closed without attempting heartbeat. Overlap is `heartbeat_timing_violation`.
- Stop is idempotent: it blocks dispatch, cancels the timer, awaits the one in-flight heartbeat or the abort signal, and returns a private latest-revision proof for later guarded release outside the controller. No heartbeat begins after stop commits.
- Deadline controllers arm from the committed phase only. Listing-only and bounded-body both use 1800000 milliseconds of monotonic elapsed time. The deadline is not the lease TTL and is not wall-clock elapsed authority. Arm once. One timer. Complete or cancel removes the timer. Late callbacks cannot change a terminal state. First terminal signal wins.
- No public CLI, API route, scheduler, BackgroundJob route, Outbox route, or BullMQ processor. No lease acquisition, provider contact, retry, activation, matching, or Finding write. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 2E-R independently reviewed these controllers.

### Session 13 Batch 2E-R (heartbeat and deadline adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2E-R independently reviewed the uncommitted Batch 2E heartbeat and deadline controllers with scripted ports, fake clocks, hostile schedulers, and disposable PostgreSQL. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- Synchronous `schedule()` callbacks fail closed and cannot overwrite a terminal state back to scheduled or armed. Stale callbacks from a prior schedule epoch cannot start a second heartbeat. Overlapping callbacks are `heartbeat_timing_violation`.
- Successful heartbeat adopts only the exact row-revision successor. Skipped, unchanged, or decreasing revisions fail closed. Fencing token changes fail closed and are not adopted as takeover.
- Halt is re-evaluated after an accepted in-flight heartbeat and does not reschedule. Already-aborted stop still awaits the one in-flight heartbeat so the latest accepted revision is retained for later guarded release. Late results after stop or generation change cannot mutate terminal state.
- Deadline uses integer monotonic milliseconds. Wall-clock `Date.now` is not elapsed authority. Early callbacks fail closed as `malformed_scheduler` and cancel the timer. Duplicate deadline or cancellation settlement is ignored. Terminal result is assigned before cancellation notify.
- Event-sink failure, hostile thenables, and reentrant `stop()` during emit cannot authorize successor work, restart scheduling, or deadlock. Public results omit holder proofs, digests, revisions, fencing tokens, and timer handles. The release constructor is not a public package export.
- Controllers remain uncomposed. Construction starts no timer. Production worker, API, scheduler, queue, health, seed, and migration composition do not import the factories. No CLI, lease acquisition, provider contact, retry, activation, matching, or Finding write. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 2F later added uncomposed executable preflight without wiring it into production runtime.

### Session 13 Batch 2F (executable canary preflight and runbooks)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2F implements `createOsvCanaryPreflightService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-preflight/`). Framework-independent. Production composition does not construct the factory. Construction performs no I/O, starts no timer, acquires no lease, and does not contact a provider.
- Preflight accepts one existing consumed authorization bound to the exact request and run. It does not create operator identity, authorization, request, or run. Issued, expired, revoked, cancelled, completed, failed, and different-run bindings fail closed. Same-run replay is status inspection only and does not authorize execution.
- Halt must be `permitted_by_halt_control` from trusted state. Default and explicit halt block preflight. Halt release alone is not authorization. Halt is re-evaluated before local work and immediately before success. Process environment is not parsed in this package.
- Lease scope is inspected without acquire, takeover, heartbeat, or release. Held-by-another blocks success. An expired projection is later guarded takeover, not acquired authority. Heartbeat and deadline policies are validated without starting timers.
- Egress readiness validates committed deployment policy only. It does not perform provider DNS, TLS, HTTP, proxy, or firewall probes. Missing required deployment controls fail closed and are not reported as proven.
- Listing-only checks PostgreSQL, event-sink, and metric/log/trace binding readiness. It must not require object storage or parser capacity. Bounded-body additionally requires object-storage, parser active capacity 1, parser pending capacity 0, and acquisition-persistence readiness.
- Required observability sink readiness failure blocks preflight as an operational gate. Domain event emission remains nonauthoritative. Active-pointer and activation-history baselines are captured and not modified. Zero-tenant and zero-Finding baselines are proven without writing Findings.
- Successful outcome is `canary_execution_preflight_passed_provider_contact_not_authorized`. Remaining gates include guarded lease acquisition, heartbeat start, deadline arm, final egress confirmation, operator execution confirmation, separately authorized provider contact, and postcanary review. Provider, lease-mutation, timer, activation, matching, and Finding call counts remain 0.
- Operator runbooks in [docs/runbooks/osv-canary.md](docs/runbooks/osv-canary.md) cover preflight, halt, lease, heartbeat, deadline, egress, provider, listing, cancellation, pointer, Finding, postcanary, and retention procedures. Provider-facing execution steps remain unavailable until Batch 3 is separately authorized.
- No public CLI, API route, scheduler, BackgroundJob route, Outbox route, or BullMQ processor. `createOsvCanaryPreflightReadiness` in `@patchpilot/database` is unused by production runtime. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint was Session 13 Batch 2F-R executable preflight adversarial review.

### Session 13 Batch 2F-R (executable preflight adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2F-R independently reviewed the uncommitted Batch 2F preflight with scripted ports, hostile halt sources, malformed dependency results, and disposable local infrastructure. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- Halt is re-evaluated at each protected checkpoint and immediately before success. Halt after authorization validation prevents request/run inspection. A halt change after lease inspection prevents heartbeat, deadline, egress, local, observability, and baseline checks. Result construction after the final halt sample cannot authorize provider contact.
- Public `createCommittedOsvCanary*` fake-ready factories are not package exports. Recursive event-sink invocation cannot start a nested successful preflight.
- Egress distinguishes application-verified controls from deployment controls declared but not externally proven. Cloud-metadata denial is not claimed as independently verified. DNS lookup count, TLS count, and provider call count remain 0.
- Active-pointer and activation-history reads share one read-only Repeatable Read transaction. A present pointer with zero history fails closed. Zero-Finding baseline proves no canary-attributed Finding writes and does not require globally zero Finding rows.
- Successful outcome remains `canary_execution_preflight_passed_provider_contact_not_authorized` with `executionPermitted=false`, `providerContactAuthorized=false`, `leaseAcquired=false`, `heartbeatStarted=false`, `deadlineArmed=false`, and `activationAuthorized=false`. Production composition does not construct the factory. No CLI, lease acquisition, provider contact, activation, matching, or Finding write. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint was Session 13 Batch 2-R combined operational-controls review.

### Session 13 Batch 2-R (combined operational-controls review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 2-R independently reviewed Batches 1 through 2F-R as one operational-control chain. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- Authentication establishes instance-operator identity only. Anonymous and tenant identities fail. Authorization remains distinct from authentication, halt, and lease ownership. Listing-only and bounded-body remain independently authorized. One authorization is consumed once. Same-run replay is status reuse. Different-run replay is rejected.
- The one-shot command stops at `authorized_preflight_required` with `executionPermitted=false`. Preflight requires the exact consumed authorization, request, and run. Preflight success does not authorize provider contact. Halt release alone starts nothing. Lease inspection remains read-only. Heartbeat and deadline readiness start no timers.
- At this Batch 2-R checkpoint no listing-only execution bridge existed. Session 13 Batch 3A later added the uncomposed scripted listing-only bridge. Batch 3B remains the first real-provider listing-only authorization after Batch 3A-R review.
- Production composition does not construct the command, preflight, heartbeat, deadline, or authorization factories. No public CLI, API, scheduler, BackgroundJob route, or Outbox route. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint was Session 13 Batch 3A listing-only execution bridge against a scripted provider port.

### Session 13 Batch 3A (listing-only execution bridge, scripted provider only)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3A implements uncomposed `createOsvCanaryListingOnlyExecutionBridge` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-listing-execution/`). Framework-independent. Production composition does not construct the factory. Construction performs no I/O, starts no timer, and does not contact a provider.
- A fresh identity-only instance-operator execution confirmation is required. It contains no tenant identity, canary authorization, or lease authority. Confirmation is used once per invocation and is confidential.
- The bridge reloads consumed listing-only authorization, exact request and run bindings, current legal authority, and accepted preflight evidence. Bounded-body cannot enter. Preflight `providerContactAuthorized` must remain false. Preflight evidence alone cannot authorize provider contact.
- Halt and egress are rechecked before lease acquisition, after lease, before heartbeat start, before deadline arm, before every page, before convergence, before success, and before release preparation. Batch 3A egress remains `realProviderContactAuthorized=false` and `scriptedProviderExecutionOnly=true`. No DNS, TLS, HTTP, or proxy probes.
- Lease acquisition uses the committed Batch 7 adapter against the global OSV acquisition scope. Heartbeat starts and the listing-only deadline arms before any listing page. Current ownership and fencing are validated before every page. A late page result after ownership loss, deadline, halt, or cancellation cannot authorize the next page.
- Listing uses committed pagination and convergence: one approved prefix, exactly two passes, canary ceilings (8/16 pages, 2000/4000 observations, 1,048,576 / 8,388,608 / 16,777,216 bytes), concurrency 1, retries 0, body retrievals 0. Continuation tokens and token digests remain in memory only. Scripted deterministic listing responses only.
- Controllers stop, then the run and authorization are terminalized under current ownership, then guarded release uses the latest row revision. Batch 7 requires current ownership to enter `completed`, so release cannot precede run completion. Stale owners cannot release. Terminal run and authorization outcomes remain consistent. Same-run consumed replay is status inspection. Different-run reuse is rejected. Automatic retries remain zero.
- Successful outcome is `listing_only_scripted_inventory_converged` with `executionMode=scripted_provider_only`. Remaining gates include separately authorized provider contact and postcanary review. No candidate readiness, catalog activation, matching, or Finding writes.
- The scripted listing-capability constructor and verification factory are not public package exports. No real-provider capability exists. No public boolean, environment switch, or caller-controlled mode can substitute real transport.
- No public CLI, API route, scheduler, BackgroundJob route, Outbox route, or BullMQ processor. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 3A-R independently reviewed this bridge.

### Session 13 Batch 3A-R (listing execution bridge adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3A-R independently reviewed the uncommitted Batch 3A listing-only execution bridge with scripted listing ports, fake clocks, hostile confirmation and evidence objects, and disposable PostgreSQL rehearsals. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- Fresh identity confirmation remains mandatory and is consumed once. Anonymous, tenant, and malformed authentication results cannot proceed. Confirmation failure acquires no lease and starts no controller.
- Only an existing consumed listing-only authorization bound to the exact request and run may proceed. Issued, expired, revoked, failed, cancelled, bounded-body, and different-run bindings fail closed. Terminal authorization cannot execute again. Same-run completed replay remains status inspection.
- Accepted preflight evidence must wrap a constructed preflight success. Caller-created structural forgeries fail closed. Evidence bindings must match current authority pins. Prior `providerContactAuthorized=false` cannot substitute for fresh halt, egress, lease, or ownership checks. Legal revalidation uses the inspect observed-at timestamp against the recorded revalidation boundary.
- Halt and scripted egress are rechecked after lease acquisition and before every listing page. Halt during listing is `halt_engaged` and releases a current lease. A generic listing `policy_violation` is not classified as ownership loss and therefore cannot skip guarded release.
- Held-by-other blocks listing and does not terminalize the authorization or run, so same-run redelivery remains possible after the other holder releases. Same-owner acquire replay does not mint a new fencing token. Stale owners cannot release.
- The scripted listing-capability constructor remains unpublished. A structurally forged capability object cannot supply a listing port. Production composition still does not construct the factory. No real-provider capability exists. No public CLI, API, scheduler, BackgroundJob route, or Outbox route. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint relative to this Batch 3A-R checkpoint was Session 13 Batch 3B listing-only provider-contact authorization.

### Session 13 Batch 3B (listing-only provider-contact authorization gate)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3B implements uncomposed `createOsvListingProviderContactAuthorizationService` at `packages/vulnerability-intelligence/src/osv/canary-provider-contact-authorization/`. Framework-independent. Production composition does not construct the factory. Construction performs no I/O, starts no timer, and does not contact a provider.
- The operation is `evaluateOsvListingProviderContactAuthorization`. A fresh identity-only instance-operator confirmation is required and consumed once per invocation. Anonymous, tenant, and revoked operators cannot authorize provider-contact. Authentication proves identity only.
- Provider-contact authorization is distinct from consumed listing-only canary authorization, provider-free preflight, and scripted Batch 3A execution. Only an existing consumed listing-only canary authorization bound to the exact request and run may proceed. Issued, expired, revoked, failed, cancelled, bounded-body, and different-run bindings fail closed.
- Accepted preflight evidence must wrap a constructed preflight success whose `providerContactAuthorized` remains false. Preflight success does not authorize provider contact. Current listing-metadata legal approval is required; body retrieval, private body retention, parsing, and matching remain prohibited. Legal prose is not stored or emitted.
- Egress evidence is versioned and fail-closed. Generic `ready: true` is insufficient. Application controls must be implemented and tested. Deployment DNS, TLS, redirect, proxy, and prohibited-address controls must be at least configured. Provider connectivity is not exercised. The evaluation does not resolve DNS, open a socket, or send HTTP.
- Heartbeat cadence remains 60000 ms, lease TTL remains 900000 ms, and the listing-only deadline remains 1800000 ms of monotonic elapsed time. Policies are validated without starting controllers. Acquisition halt is observed and not cleared. Halt false alone starts nothing. Halt procedure acknowledgement is required; missing acknowledgement is `halt_procedure_not_ready`.
- Independent postcanary review is required. The issuing operator may not review in v1. Evidence-retention disposition binds listing-only classes and forbids raw tokens, token digests, and provider-body snapshots. Unused provider-contact authorization validity reuses committed unused TTL 3600 seconds from this package `issuedAt`; it is not the consumed canary unused window, lease TTL, heartbeat cadence, listing deadline, or transport timeout.
- Existing `osv_canary_authorization` cannot represent this without phase and lifecycle ambiguity. Batch 3B does not modify Prisma. Evaluation is side-effect free except bounded operational events. After other gates pass, evaluation fails closed with `persistence_required` and does not return an in-memory authorization package. Batch 3C must reload and consume durable authority and must not trust an in-memory package as execution permission.
- No real-provider capability exists. No public CLI, API, scheduler, BackgroundJob route, Outbox route, or BullMQ processor. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint relative to this Batch 3B checkpoint was Session 13 Batch 3B-P provider-contact authorization persistence.

### Session 13 Batch 3B-P (listing-only provider-contact authorization persistence)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3B-P adds the minimum forward-only Prisma and PostgreSQL persistence for a distinct listing-only OSV provider-contact authorization. Existing `osv_canary_authorization` is not reused: it is already consumed by the one-shot command, its phase is listing_only or bounded_body, and its lifecycle represents canary-phase authorization rather than external provider-contact authority.
- Exactly one new migration: `20260909120000_osv_listing_provider_contact_authorization_persistence`. Frozen SHA-256 `8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`. Sixteen frozen migrations. All fifteen prior migrations remain byte-for-byte unchanged. Later SQL corrections require another forward-only migration.
- Two global, instance-owned, tenant-independent tables: `osv_canary_provider_free_preflight_attestation` and `osv_listing_provider_contact_authorization`. No Organization, User, Asset, Component, Vulnerability-matching, Finding, Evidence, or RiskCalculation relation. No credential, provider token, page token, lease token, body, URL, or arbitrary JSON column.
- Provider-free preflight attestation is insert-once and immutable. It records that accepted provider-free preflight evidence stated `providerContactAuthorized=false` and was accepted for provider-contact authorization evaluation. It is not execution permission.
- Provider-contact authorization is listing_only only. Body retrieval, parser, retry, activation, matching, and Finding writes are CHECK-prohibited. One row binds one consumed listing-only source canary authorization, one request, one run, one preflight attestation, the issuing instance operator, and closed legal, egress, deployment, heartbeat, deadline, runbook, containment, reviewer, and retention identifiers.
- Cardinality is at most one provider-contact authorization per source canary authorization, per request, per run, and per preflight attestation. Failed or cancelled future provider attempts do not automatically mint a replacement. A later attempt requires a new source canary authorization or an explicitly reviewed policy.
- Lifecycle: issued → consumed_for_listing_execution → completed | failed | cancelled; issued may also become revoked or expired. Unused TTL is 3600 seconds (`expires_at = issued_at + 3600 seconds`). `databaseNow >= expiresAt` means not consumable. Database time owns issuance, expiration, consumption, revocation, and terminalization. DELETE is forbidden.
- Schema existence does not issue or consume an authorization. No issuance or consumption adapter exists. No CLI, heartbeat, deadline, scheduler, BackgroundJob route, Outbox route, or production composition. Session 13 Batch 3B evaluation still fails closed with `persistence_required`. Next checkpoint relative to this Batch 3B-P checkpoint was Session 13 Batch 3B-P-R. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding.


### Session 13 Batch 3B-P-R (provider-contact authorization persistence adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3B-P-R independently reviewed the uncommitted Batch 3B-P schema with disposable PostgreSQL and direct SQL. It did not contact `storage.googleapis.com` or `osv.dev`.
- Migration `20260909120000_osv_listing_provider_contact_authorization_persistence` remains the single new forward-only migration. Frozen SHA-256 after review: `8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`. Sixteen frozen migrations. All fifteen prior migrations remain byte-for-byte unchanged. Do not edit it; any later SQL correction requires another forward-only migration.
- Persistence remains instance-owned and tenant-independent. Tenant, installation, and repository identity are not part of this grant; OSV listing contact is global catalog acquisition, not a tenant GitHub installation. Unknown schema versions, unknown providers, unknown operations, and mutation-shaped permissions fail closed.
- Loading a row does not authorize provider contact. No issuance or consumption adapter exists. Batch 3B evaluation still fails closed with `persistence_required` and inserts no row. Direct SQL insert of a well-formed issued row is inert evidence until a later adapter revalidates and consumes it.
- Concrete corrections: future `issued_at` is rejected so unused TTL cannot extend past database now; `issued_at` cannot precede preflight `captured_at`; future preflight timestamps and future `consumed_at` are rejected; consumption rechecks an active operator, a still-consumed source canary authorization, a current legal revalidation boundary, and the bound preflight still attesting unauthorized provider contact; a consumed source cannot leave consumed while a child grant is issued or `consumed_for_listing_execution`; insert matches source provider, prefix, family, policy, and listing budget and requires an active operator.
- Concurrent consume admits exactly one winner. Same-run replay is distinguishable. Different-run reuse is rejected. DELETE cannot reset single-use authority. Halt, kill-switch, and runtime composition remain consumption-time adapter and service checks; schema cannot encode them.
- No issuance, consumption, revocation, or CLI adapter in this batch. No scheduler, BackgroundJob route, Outbox route, or production composition. Next checkpoint relative to this Batch 3B-P-R checkpoint was Session 13 Batch 3B-A durable issuance. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding.

### Session 13 Batch 3B-A (listing-only provider-contact authorization adapters)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3B-A implements `createOsvListingProviderContactAuthorizationPersistence` in `@patchpilot/database` against the frozen Batch 3B-P schema. Construction performs no I/O. The `ForClient` helper is not a public package export.
- Issuance validates the consumed listing-only source canary authorization, exact request and run, accepted provider-free preflight evidence (`providerContactAuthorized=false`), active operator, current legal revalidation, and closed listing-only policy, budget, prefix, provider, fingerprint, activation-prohibition, retry-prohibition, and body-prohibition bindings. Insert uses database-owned `issued_at` and `expires_at = issued_at + 3600 seconds`. Callers cannot supply issuance or expiry timestamps.
- Identical issued replay is `already_applied`. Unique conflicts reload the natural identity and compare immutable fields. Terminal, expired, revoked, and consumed rows are `immutable_conflict`, not silent reissue. Different source, request, run, preflight, provider, prefix, policy, budget, legal, or version-set bindings are not identical.
- Inspection (`findById`, `inspectForRun`) is read-only. Database time distinguishes issued from expired (`databaseNow >= expiresAt` is expired). Inspection does not consume, extend expiry, or authorize provider contact.
- Consumption is one compare-and-swap from `issued` with exact bindings, `CURRENT_TIMESTAMP < expires_at`, current legal revalidation, and an active operator. There is no row-revision column; CAS uses issued state, bindings, and database time. PostgreSQL triggers recheck a still-consumed source and preflight still attesting unauthorized provider contact. Same-run replay is `already_consumed_same_run` without mutating `consumed_at`. Different-run replay is `already_consumed_other_run` without revealing the other run identity.
- Revocation is from `issued` only, uses database time, and is idempotent for the already-revoked issuing operator. Consumed authority cannot be revoked retroactively. DELETE remains forbidden.
- Production composition does not construct the factory. Session 13 Batch 3B evaluation still fails closed with `persistence_required`. Successful consumption remains necessary but insufficient for provider contact. No CLI, lease, heartbeat, deadline, scheduler, BackgroundJob route, Outbox route, or provider contact. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 3B-A-R independently reviewed those adapters.

### Session 13 Batch 3B-A-R (provider-contact authorization adapter adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3B-A-R independently reviewed the uncommitted Batch 3B-A adapters with disposable PostgreSQL, synthetic identities, and database-time SQL. It did not contact `storage.googleapis.com` or `osv.dev`.
- Schema and migration `20260909120000_osv_listing_provider_contact_authorization_persistence` remain frozen and byte-for-byte unchanged. Frozen SHA-256 `8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`. Sixteen frozen migrations.
- Concrete corrections: issuance replay compares legal evidence-set identity, legal issued-at, and acknowledgement timestamps so conflicting authority is not labeled `already_applied`; time-expired issued rows are `immutable_conflict` rather than silent reissue; insert requires `CURRENT_TIMESTAMP` still before the legal revalidation boundary; consume after operator revocation is `operator_revoked` rather than a generic state conflict; inspect omits the persisted record on `consumed_other_run`; unique consume conflicts reload and classify rather than mislabeling uniqueness as a run mismatch.
- Inspection remains read-only. Database time owns consumption eligibility (`databaseNow >= expiresAt` is expired). Atomic consumption still admits exactly one winner. Same-run replay does not mutate `consumed_at`. Different-run replay fails closed without revealing the other run. Revocation remains issued-only and uses database time.
- Production composition still does not construct the factory. No CLI, lease, heartbeat, deadline, scheduler, BackgroundJob route, Outbox route, or provider contact. Successful consumption remains necessary but insufficient for provider contact. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint relative to this Batch 3B-A-R checkpoint was Session 13 Batch 3B-R combined provider-contact authorization review.

### Session 13 Batch 3B-R (combined provider-contact authorization review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3B-R independently reviewed the complete listing-only OSV provider-contact authorization chain: operator authentication, consumed listing-only canary authorization, exact synchronization request and run, provider-free preflight evidence, and uncomposed issuance, inspection, revocation, and atomic single-use consumption. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- Authorities remain strictly separated. Operator identity cannot substitute for canary authorization. Canary authorization cannot substitute for provider-contact authorization. Preflight success, halt release, and lease ownership cannot authorize provider contact. Provider-contact consumption does not acquire a lease, start heartbeat or deadline, or contact a provider.
- Listing-only is the only representable provider-contact phase. Body retrieval, activation, matching, and Finding authority cannot be represented. Preflight evidence remains immutable and still states `providerContactAuthorized=false`. Issuance and consumption remain distinct operations. Database time owns expiry (`databaseNow >= expiresAt` is expired). Same-run replay is status reuse only. Different-run replay fails closed. Concurrent consumers admit exactly one winner.
- Consume results qualify `consumed` and `already_consumed_same_run` with `providerOperationExecuted=false`, `remainingRuntimeGatesRequired=true`, and `executionPermitted=false`. Session 13 Batch 3B evaluation still fails closed with `persistence_required`. Production composition does not construct the factories. No public CLI, API, scheduler, BackgroundJob route, or Outbox route. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint relative to this Batch 3B-R checkpoint was Session 13 Batch 3C-Auth listing-canary execution authorization.

### Session 13 Batch 3C-Auth (listing-canary execution authorization)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3C-Auth implements uncomposed `createOsvListingCanaryExecutionAuthorizationService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-listing-execution-authorization/`). Framework-independent. Production composition does not construct the factory. Construction performs no I/O, starts no timer, acquires no lease, and does not contact a provider.
- A distinct ephemeral instance-operator execution confirmation is required (`osv_listing_canary_execution_confirmation`). ADR 0029 permits an ephemeral WeakMap-backed confirmation for this manual canary; no confirmation persistence or migration is added. Confirmation is consumed once per invocation and cannot authorize body retrieval, activation, retry, or endpoint selection. Prior authentication, canary-authorization consumption, preflight success, provider-contact issuance, halt release, and lease availability are not confirmation.
- Provider-contact authorization must be listing-only and bound to the exact request, run, preflight, provider, prefix, policy, budget, and version-set fingerprint. Issued rows are consumed once. Same-run consumed replay is status inspection (`executionPermitEstablishedClassification: not_established`) and does not acquire a lease or mint a second permit. Different-run, expired, revoked, failed, completed, and body-oriented rows fail closed.
- Halt is evaluated from trusted state before lease acquisition, after controller startup, immediately before permit creation, after permit preparation, and immediately before any claim. Default halt blocks. Halt release is necessary but insufficient. Process environment is not parsed. Halt after lease acquisition creates no permit, stops deadline then heartbeat, and guardedly releases current ownership. Halt after permit preparation invalidates an unclaimed permit and fails the invocation.
- Lease acquisition uses the committed Batch 7 adapter against `osv_runtime_lease_scope_osv_gcs_public_export_v1`. Held-by-other is `lease_unavailable`. Stale takeover is `lease_state_ambiguous` and is not adopted. Heartbeat cadence remains 60000 ms, lease TTL remains 900000 ms, and the listing-only deadline remains 1800000 ms of monotonic elapsed time. Callers cannot override those timings. Heartbeat and deadline start no public timer handles.
- Final egress validation occurs after lease, heartbeat, and deadline exist. It performs zero DNS, TLS, and HTTP. Generic `ready: true` is insufficient. Ownership is revalidated immediately before creating one private, nonserializable, one-use listing-attempt permit. Maximum provider attempts is 1. Pending attempts are 0. Automatic retries are 0. The permit is not returned through JSON, events, logs, metrics, traces, or inspection.
- Successful outcome is `listing_canary_execution_authority_prepared_provider_attempt_not_executed` with remaining gate `bounded_real_provider_listing_canary_not_authorized`. Provider, DNS, TLS, HTTP, body, retry, activation, matching, and Finding counts remain 0. Cleanup order is deadline stop, heartbeat stop, then guarded release using the latest accepted row revision. Stale owners do not release. Consumed provider-contact authorization is not reset to issued.
- The verification factory and permit constructor are not public package exports. No public CLI, API route, scheduler, BackgroundJob route, or Outbox route. No real-provider capability exists. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Session 13 Batch 3C-Auth-R independently reviewed this boundary.

### Session 13 Batch 3C-Auth-R (listing-canary execution-authorization adversarial review)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3C-Auth-R independently reviewed the uncommitted Batch 3C-Auth execution-authorization boundary with scripted ports, fake clocks, hostile confirmation and evidence objects, concurrent claim races, and disposable PostgreSQL rehearsal. Tests do not contact `storage.googleapis.com` or `osv.dev`.
- Concrete corrections: halt, heartbeat, deadline, cancellation, and ownership are rechecked after permit preparation and immediately before claim; halt after permit preparation invalidates an unclaimed permit and fails the invocation rather than returning success; the verification claim path fails closed on a live-guard rejection without attempting a second claim; cancellation during shutdown is terminal; hostile duplicate scheduler callbacks that terminalize a controller fail closed; abort listeners are detached on every `executeProtected` path; controller stop throws cannot skip cleanup; fencing generation is validated as a lease integer without `Number` conversion.
- Exact confirmation remains mandatory and one-shot. Forged or mismatched confirmation fails before lease acquisition. Same-run consumed provider-contact replay remains status inspection and does not mint a second permit. Different-run reuse fails closed.
- At most one permit can exist. At most one caller can claim it. Permit reuse fails closed. The permit is WeakMap-backed, omitted from JSON, events, logs, metrics, traces, and inspection, and is not a public package export.
- Shutdown remains idempotent. Deadline stops before heartbeat. Heartbeat stops before guarded release. Uncertain ownership produces no release of another holder's lease. Automatic retries remain 0. Body, activation, matching, and Finding authority remain unrepresentable.
- Production composition still does not construct the factory. No public CLI, API, scheduler, BackgroundJob route, or Outbox route. No real-provider capability existed at this checkpoint. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Halt defaults true. Session 13 remains zero-Finding. Next checkpoint relative to this Batch 3C-Auth-R checkpoint was Session 13 Batch 3C first bounded real-provider listing canary.

### Session 13 Batch 3C (bounded real-provider listing canary)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 13 Batch 3C implements uncomposed `createOsvBoundedListingCanaryService` in `@patchpilot/vulnerability-intelligence` (`src/osv/canary-bounded-listing/`) and the nonpublic operator entry `scripts/run-osv-listing-canary.mjs`. Production worker, API, scheduler, queue, health, seed, and migration composition do not import the factory or run the operator command. Construction performs no I/O. Tests, build, lint, typecheck, and application startup do not send a real provider request.
- Dry-run validates command input, identity references, local dependencies, egress policy without DNS or HTTP, halt inspection, and lease availability without acquire. Dry-run makes no authorization or lease mutation, starts no controller, creates no permit, and contacts no provider. Outcome is `listing_canary_dry_run_validated_provider_uninvoked` with `executionAuthorityFromDryRun=false`.
- Execute requires the exact argv `execute-one-listing-request --i-understand-this-sends-one-real-provider-listing-request`. Unknown arguments and `--retry`, `--body`, `--paginate`, `--activate`, `--match`, `--finding`, and `--enable-osv` are rejected. Environment-derived execution authority is rejected.
- After synthetic rehearsal and one explicit operator invocation, exactly one listing HTTPS request was sent to the committed `storage.googleapis.com` GCS JSON Objects listing path for prefix `crates.io/`. Outcome `listing_canary_one_page_classified`: provider requests attempted 1, responses accepted 1, transport `http_200_listing_page`, response bytes 320143 (ceiling 1,048,576), observations 1000, continuation token present and not followed, retries 0, pagination follow-ups 0, body requests 0, storage writes 0, parser executions 0, activation 0, matching 0, Finding writes 0, tenant operations 0.
- Halt restoration `restored`. Deadline stopped. Heartbeat stopped. Guarded lease release `released`. Active pointer unchanged. Activation history unchanged. Raw response bytes and continuation tokens were not persisted. No provider fixture was committed.
- Automatic retries remain 0. Body retrieval, catalog activation, matching, and Finding writes remain unauthorized. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 13 remains zero-Finding. Session 13 Batch 3C-R listing-canary evidence review is mandatory. Do not retry the real-provider request. Do not request a second page.

## Historical checkpoint record

The following sections describe repository state at the end of individual historical checkpoints. Statements that a capability was absent apply only to that checkpoint and must not override the Authoritative current project status section above.

When historical and current-state language differ, the authoritative current-state section and the latest Accepted ADR control. Agents must not remove current capabilities because a historical section says they did not yet exist.

### Session 11 Batch 1A (Historical)

Session 11 Batch 1A found the repository unable to authoritatively match versions. Current `VulnerabilitySourceRecord` normalized JSON is insufficient for affected-version evaluation. OSV is the recommended affected-package and affected-version source. CISA KEV remains an independent exploitation signal. Tenant SBOMs remain inventory, not advisory authority. Tenant package inventory must not be sent to an external provider without an explicit ADR. Current OSV query APIs must not be used with tenant package identities. OSV catalog ingestion must exist before authoritative matching. Session 11 remains zero-Finding. Finding writes are deferred beyond Session 11. Package identity and fail-closed evaluation belong to [ADR 0025](docs/adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md). Finding evidence and lifecycle belong to [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md).

### Session 11 Batch 1B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0024](docs/adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) is accepted on this feature branch. OSV is the future affected-version authority. Tenant package query APIs are rejected. Instance-owned catalog acquisition is the approved direction.
- Exact provider object/listing transport, host, path, licensing, removal semantics, and limits remain to be reviewed. Implementation is not authorized until that review completes.
- ZIP remains absent and unauthorized. `all.zip` is not the first-implementation assumption.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. No OSV runtime, transport, parser, snapshot schema, scheduler, or worker exists.
- Session 11 remains zero-Finding. No matching exists. No Finding write exists.
- [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) (Finding evidence and lifecycle) is accepted as architecture in Batch 1D. It does not implement writes.
- Matching was future work at this checkpoint. Finding writes remained blocked by architectural gates including the [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) four-condition gate. The assigned future session number was not itself authorization.
- Current `VulnerabilityNormalizedJson.affectedPackages` is not an approved matching authority.
- Full provider-neutral Vulnerability advisory identity remains open. `Vulnerability.osvId` remains required and unique.

### Session 11 Batch 1C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0025](docs/adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md) is accepted on this feature branch. Package identity is ecosystem-aware. There is no generic name matcher and no generic lexical or universal-semver comparator.
- The implemented ecosystem registry is **empty**. npm, PyPI, Maven, Go, NuGet, and crates.io are candidates to evaluate, not currently supported ecosystems.
- No first ecosystem is selected. Selection waits for OSV catalog measurements and a separate dependency and evaluator design review. npm is the preferred candidate to evaluate first after those measurements.
- Future evaluation is fail-closed. Unsupported, unknown, malformed, and withdrawn cases must not become `not_affected`. Only a deterministic `affected` result may eventually contribute to Finding creation.
- Evaluation remains read-only and zero-Finding in Session 11 and Session 12. No evaluator, comparator, PURL matching conversion, or version parser exists.
- GIT ranges, Linux distribution ecosystems, CPE identity, and plugin or environment-variable registries are rejected or deferred as specified in ADR 0025.
- Finding writes remain blocked until OSV acquisition, at least one reviewed registry entry, deterministic evaluation, match-evaluation persistence, Finding ensure semantics, the [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) gates, explicit authorization, and tenant-isolation proof all exist. ADR 0026 acceptance does not authorize writes.

### Session 11 Batch 1D

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) is accepted on this feature branch. Finding natural key is `organizationId` + `assetId` + `componentId` + `vulnerabilityId`. Future match evidence is tenant-owned append-only `VulnerabilityMatchEvaluation`. FindingObservation is one summarized result per Finding per completed ingestion.
- Only a deterministic `affected` result may eventually create a Finding. KEV, CVE, unknown versions, unsupported evaluation, and withdrawn advisories do not create Findings and do not automatically resolve them.
- The first Finding-write gate is recorded. Session 11 remains zero-Finding. Session 12 remains zero-Finding. Finding writes were not authorized; gates, not a session number, are authoritative.
- No Finding repositories or lifecycle code is added. No match-evaluation model, observation ensure, risk, API, worker, Outbox, or matching runtime is added.
- OSV runtime remains disabled. ZIP remains absent. The implemented ecosystem set remains empty.

### Session 11 Batch 3A-P

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 3A implements OSV metadata contracts in `@patchpilot/vulnerability-intelligence`: source identifiers, inventory scope, source-license registry, object-key parser, family-candidate extraction, permission enums, evidence provenance contracts, pre-retrieval classification, and post-parse confirmation.
- The immutable versioned source-license registry (`osv_source_license_registry_v1`) defines 9 sources: MAL, GHSA, PYSEC, GO, RUSTSEC, GSD, EEF-CVE, OSV, ECHO.
- **Session 11 Batch 3A-P incorporates verified source-license provenance.** Seven sources (MAL, GHSA, PYSEC, GO, RUSTSEC, GSD, EEF-CVE) now have complete evidence and are **eligible for body retrieval**.
- MAL: Apache-2.0. Body retrieval eligible. Internal matching prohibited (malicious-package semantics not approved by ADR 0025).
- GHSA: CC-BY-4.0. Attribution required.
- PYSEC: CC-BY-4.0. Attribution required.
- GO: CC-BY-4.0 for /data/ directory. Attribution required.
- RUSTSEC: CC0-1.0 source-level with per-advisory license field. External exposure conservative until post-parse confirmation.
- GSD: CC0-1.0 public domain dedication. Archived status independent from licensing permission.
- EEF-CVE: CC-BY-4.0. Attribution required. Dynamic HTML evidence.
- OSV family fails closed (ambiguous aggregator provenance). ECHO fails closed (proprietary, no public license).
- Evidence provenance contracts define required fields: requested URL, final URL, redirects, HTTP status, media type, content encoding, byte count, SHA-256, retrieval timestamp, work covered, mutable-URL indicator.
- No OSV HTTP adapter, object retrieval, advisory parser, persistence, scheduler, worker, API, or runtime exists. Body retrieval implementation remains future work. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding.

### Session 11 Batch 3C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 3B added OSV-specific transport contracts (listing request, opaque continuation token, listing page, generation-bound retrieval request, failure taxonomy). Listing-request `pageSizePolicy` remains `unavailable` so callers cannot supply a numeric page size. Continuation-token and provider-object body byte bounds remain unavailable.
- Session 11 Batch 3C implements a compiled GCS JSON Objects list request builder and a bounded listing-page parser in `@patchpilot/vulnerability-intelligence`. Neither performs I/O.
- Compiled listing surface: HTTPS GET `storage.googleapis.com` `/storage/v1/b/osv-vulnerabilities/o`, unauthenticated, redirects described as `error`, `maxResults` 1000, field projection `kind,nextPageToken,items(name,generation,metageneration,size,etag,md5Hash,contentType,updated)`, listing-page cap 1,048,576 bytes.
- User-Agent is omitted from the request description; the future HTTP adapter owns it.
- The parser accepts supplied page bytes only. It does not fetch. Terminal state follows `nextPageToken` presence only. Listed observations reuse Batch 3A key parsing and Batch 3B classification.
- Duplicate JSON object keys are not detected. Last-key-wins remains the existing `secure-json-parse` limitation. Do not describe Batch 3C as rejecting duplicate keys. A later parser-hardening decision is required before duplicate-key detection exists.
- No HTTP client, provider-object retrieval, advisory parsing, snapshots, object storage, persistence, Prisma, migrations, workers, schedulers, Outbox, BackgroundJob, API, permissions, or OSV enablement is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4A

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4A vendors the official OSV advisory JSON Schema (v1.9.0) with immutable provenance and integrity verification. The schema is self-contained with local-only reference closure.
- **Upstream repository**: `https://github.com/ossf/osv-schema` (OpenSSF)
- **Version tag**: `v1.9.0`
- **Exact commit SHA**: `f3f826310aeca8e324baabd195632f2229952abe`
- **Byte length**: 16,816 bytes
- **SHA-256**: `cdb8292f72945cfdf06d3e044280d7c0867105a3a1ae6d4547c983eba20810a2`
- **Local path**: `packages/vulnerability-intelligence/vendor/osv-schema/schema.json`
- **Schema license**: Apache-2.0 (schema/software license, distinct from advisory content licenses)
- All `$ref` references are local fragments (`#/$defs/...`). No remote HTTP/HTTPS references. No external schema dependencies.
- Vendored artifacts include: `schema.json`, `PROVENANCE.json`, `SHA256SUMS`, `LICENSE`, `NOTICE`.
- Deterministic integrity tests verify: file existence, byte counts, SHA-256 checksums, valid JSON structure, local reference closure, no remote $ref, provenance immutability, no path traversal, no runtime network capability, zero-Finding enforcement.
- `@patchpilot/vulnerability-intelligence` exports immutable schema provenance constants and deterministic path helpers. No tenant input, no network I/O, no Findings.
- **Critical distinction**: Vendoring the OSV schema (Apache-2.0) does NOT license all OSV advisory bodies, change Batch 3A-P source-license registry decisions, make OSV or ECHO retrieval eligible, authorize provider-body retrieval, normalization, matching, external exposure, or Finding creation. The schema is a validation tool. Advisory content licensing remains per-source. OSV and ECHO remain fail-closed.
- No advisory parser implementation, validation runtime, HTTP transport, object-storage snapshots, persistence, Prisma, migrations, worker, scheduler, Outbox, BackgroundJob, API, permissions, package normalization, version comparison, matching, Finding creation, or OSV enablement (`INTELLIGENCE_OSV_ENABLED=true` remains rejected).
- Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4B defines the isolated OSV advisory parser protocol in `@patchpilot/vulnerability-intelligence` (`advisory-parser-protocol.ts`, `advisory-parser-policy.ts`): protocol identity `osv_advisory_parser_protocol_v1`, metadata-only request envelope, success/failure envelopes, resource-policy contract, execution-state transitions, cancellation/termination semantics, source-confirmation handoff, and worker-output validation.
- The protocol pins Batch 4A schema revision `v1.9.0` / commit `f3f826310aeca8e324baabd195632f2229952abe`, registry `osv_source_license_registry_v1`, and eligible-body scope `osv_eligible_body_scope_registry_v1`.
- Input payload representation remains deferred **for provider-object retrieval**. Parser resource-policy v1 is closed by Batch 4B-P. Executable *reference-parser* request construction is authorized only for locally supplied bounded bytes (`synthetic_bounded_reference_parser_authorized`). The parser port, production worker isolation, and provider retrieval remain deferred.
- Parser resource-policy v1 selects exact PatchPilot ceilings (1 MiB input, 2 MiB output, depth 32, and related collection/string bounds). They are not provider guarantees. Overflow fails closed. No environment or caller override. Worker timeouts were `unavailable` in this batch; Batch 4E later selected exact values without implementing a worker.
- Normalization eligibility is required; body-retrieval permission alone is insufficient. OSV and ECHO remain rejected. MAL may normalize while internal matching remains prohibited.
- Parser success never activates intelligence, authorizes matching, or creates Findings. Worker output is untrusted and must match the originating request correlation/protocol/schema/registry/digest/generation/hash.
- No advisory JSON parsing, AJV compilation, worker_threads, child_process, HTTP, provider retrieval, snapshots, persistence, Prisma, migrations, schedulers, Outbox, BackgroundJob, API, permissions, package normalization, version comparison, matching, or Finding path is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4B-P

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4B-P closes `osv_advisory_parser_resource_policy_v1` with exact PatchPilot v1 numeric ceilings and authorizes `synthetic_bounded_reference_parser_authorized` executable requests for locally supplied bounded bytes and synthetic fixtures.
- Input representation is `immutable_defensive_uint8array_copy`. The factory copies a `Uint8Array`, validates length against the policy, and never exposes the internal typed array. JSON, inspect, toString, and errors omit payload bytes.
- Values are PatchPilot security policy, not provider guarantees. Oversize records fail closed and must prevent later generation activation. Silent omission from a complete generation is forbidden.
- Provider-object body retrieval remains `unavailable` on the transport contract. Production worker isolation remained unauthorized in this batch; timeouts stayed `unavailable` until Batch 4E selected exact values. Parser implementation remained absent until Batch 4C.
- The parser port after Batch 4E is `deferred_isolated_worker_not_implemented`. No HTTP, provider retrieval, workers, snapshots, persistence, matching, or Findings.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4C implements `parseOsvAdvisoryWithInProcessReferenceParser` in `@patchpilot/vulnerability-intelligence`. It accepts one Batch 4B executable request with locally supplied bounded bytes and synthetic fixtures only.
- Input identity is verified (byte count and SHA-256) before fatal UTF-8 decoding and `secure-json-parse`. Prototype-pollution keys are rejected. Duplicate JSON object keys are **not** detected; last-key-wins remains a documented `secure-json-parse` limitation.
- Validation uses the pinned Batch 4A OSV schema (v1.9.0) compiled offline with Ajv 2020-12. Remote `$ref` loaders are not configured. PatchPilot structural bounds from parser resource-policy v1 fail closed without truncation.
- Success returns the Batch 4B envelope (structural counts, confirmed top-level OSV id, source confirmation). Affected data is counted, not interpreted. `database_specific` and URLs remain untrusted and are omitted from output. MAL may parse structurally while `authorizesMatching` stays false. OSV and ECHO cannot construct normalization-eligible requests.
- This is an in-process reference parser (`in_process_reference_parser_synthetic_only`). Production worker isolation is not implemented. Parser success does not activate intelligence, authorize matching, or create Findings.
- No provider retrieval, snapshots, object storage, persistence, Prisma, migrations, workers, schedulers, Outbox, BackgroundJob types, APIs, permissions, version comparison, matching, or Finding path is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4D

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4D is an adversarial security, resource-exhaustion, confidentiality, and protocol-compliance review of the committed Batch 4C parser. It does not add parser features, broaden the parsed advisory model, retrieve provider objects, implement HTTP, workers, snapshots, persistence, matching, or Findings, or enable OSV.
- Synthetic hostile inputs only. No live OSV advisories, copied provider records, real GHSA/CVE identifiers, real package names, tenant data, or megabyte-scale committed fixtures.
- Duplicate JSON object keys remain undetected (`last_key_wins_secure_json_parse_limitation`). Adversarial tests show last-key-wins cannot bypass identity confirmation, source classification, schema revision, resource limits, or normalization eligibility. Detection without a new dependency remains a parser-hardening follow-up.
- Parser isolation readiness after Batch 4D was `in_process_core_reviewed_worker_isolation_not_authorized`. Batch 4E supersedes that marker. Duplicate-key detection without a new dependency remains a follow-up before OSV runtime enablement.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4E

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4E closes `osv_advisory_parser_isolation_design_v1` in `@patchpilot/vulnerability-intelligence`. The selected mechanism is `worker_threads`. Isolation readiness is `production_isolation_design_closed_worker_not_implemented`.
- Exact v1 timeouts: 5,000 ms initialization, 5,000 ms per-request execution, 250 ms cancellation grace, 1,000 ms forced termination. These are PatchPilot security policy, not performance guarantees, and are not environment-configurable.
- Future worker entrypoint and parent adapter belong in `@patchpilot/vulnerability-intelligence`. Domain stays free of `worker_threads`. Applications must not construct parser workers. Integrations must not own parser lifecycle. Those files are not created in this batch.
- Schema loading is worker-internal from the pinned vendor path with byte-length and SHA-256 verification before compile. The protocol must not carry schema paths or schema bytes. One Ajv instance per isolate; one request at a time; sequential reuse of a healthy worker is authorized. Recycle follows `terminationRequired`, plus `worker_start_failed`.
- v1 pool size is 1. Pending-queue size remains `unavailable`, so runtime composition is `blocked_pending_queue_size_unapproved`. Duplicate JSON keys remain undetected and do not block worker implementation; they must be resolved or explicitly accepted before OSV enablement.
- This batch does not implement a worker, timers, message channels, provider retrieval, persistence, matching, or Findings. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4F / 4F-R

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4F implements `advisory-parser-worker.ts` and `advisory-parser-host.ts` in `@patchpilot/vulnerability-intelligence`. Batch 4F-R verified the host and worker under Node.js 24 with synthetic bounded fixtures only.
- The parent resolves the worker from compiled `dist/osv/advisory-parser-worker.js` (same pattern as the KEV parser host). Vitest does not load the TypeScript worker source. Missing dist fails closed as `worker_start_failed`.
- Correlation IDs remain caller-supplied UUIDs on the executable request. Production does not generate them and does not accept a public arbitrary generator. Tests use deterministic UUID v4 fixtures. `crypto.randomUUID()` is valid under Node.js 24 and was not the Batch 4F failure cause.
- The worker reconstructs a branded executable request inside the isolate from transferred bytes plus request metadata. The public envelope still omits the raw provider key; a WeakMap handoff exists only for isolate reconstruction and is omitted from JSON, inspect, and events.
- Occupancy is exactly one in-flight parse. Pending-queue size remains `unavailable`, so a second concurrent parse is rejected with `invalid_request`. Sequential reuse of a healthy worker is authorized.
- Host failures use the closed parser failure catalog (`cancelled`, `timeout`, `worker_terminated`, `worker_start_failed`, `malformed_worker_output`, and related kinds). Shutdown is idempotent. Late messages are discarded. Raw advisory bytes never enter errors or events.
- `worker_threads` is not an OS-level sandbox, container isolation, or filesystem/network denial. Compensating controls remain as in Batch 4E.
- No HTTP adapter, provider-object retrieval, snapshots, persistence, Prisma, migrations, schedulers, durable queues, APIs, matching, Findings, or OSV enablement (`INTELLIGENCE_OSV_ENABLED=true` remains rejected).
- Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4G

Session 11 Batch 4G adversarially hardens the committed Batch 4F/4F-R isolated OSV parser worker and parent adapter. These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Comprehensive adversarial worker lifecycle tests cover initialization attacks, correlation attacks, timeout races, cancellation races, malformed messages, worker crashes, Ajv state isolation, input ownership attacks, backpressure attacks, worker recycle attacks, shutdown attacks, observability confidentiality, worker-construction security, and sandbox-claim review.
- Hardening corrections applied: timer cleanup in `terminateWorker` (forced-termination timeout cleared in finally block), explicit listener removal (`removeAllListeners()` for message/error/exit before termination), array index safety (undefined checks for `noUncheckedIndexedAccess`).
- Lifecycle verification: exactly one terminal response per request, stale/duplicate messages safely ignored, no second promise resolution, wrong-worker messages cannot complete request, no recycled worker messages accepted, timers cleared after resolution, no dangling promises or workers, every accepted request settles exactly once, no request runs twice, bounded queue maintained, capacity deterministic, shutdown idempotent, no active worker after successful shutdown.
- Duplicate JSON object keys remain undetected. Adversarial tests prove last-key-wins cannot bypass security gates. Detection without new dependency remains parser-hardening follow-up before OSV enablement.
- No provider retrieval, HTTP, snapshots, persistence, Prisma, migrations, schedulers, durable queues, APIs, matching, Findings, or OSV enablement (`INTELLIGENCE_OSV_ENABLED=true` remains rejected).
- Worker lifecycle hardening is complete. Pending-queue size approval and runtime composition remain blocked. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 5B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Framework-independent OSV persistence contracts exist in `@patchpilot/vulnerability-intelligence` (`src/osv/persistence/`). Identities, inventory, snapshots, parser attempts, parsed revisions, candidate generations, completeness, reconciliation, quarantine, presence, idempotency, activation, and repository ports are contracts only.
- Provider-generation identity is immutable and content-addressed. Body snapshots remain outside PostgreSQL. Object attachment is staged then attached; locators never contain a provider key.
- Parser attempts are immutable. Parser success does not activate a catalog. Matching completeness remains `not_in_scope`. MAL matching remains prohibited.
- Completeness dimensions stay separate. Reconciliation equations are exact integers with no waiver. Quarantine is append-only and blocks activation.
- The active catalog pointer is a contract for later atomic old-to-new replacement. No Prisma, migration, adapter, object storage, provider retrieval, synchronization, Outbox, BackgroundJob, API, permission, matching, or Finding path is included.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) is Proposed, not Accepted. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 5C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Prisma models and exactly one forward-only migration exist: `20260904120000_osv_acquisition_persistence_foundation`. Frozen SHA-256: `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`. Do not edit it; any SQL correction requires another forward-only migration. The persistent development database has twelve finished migrations.
- Global, instance-owned OSV acquisition tables store identities, inventory observations, snapshot/attachment metadata, parser attempts, parsed-revision metadata, candidate generations, separate completeness dimensions, reconciliation counts, append-only quarantine, provider-presence observations, a separate active catalog pointer, and immutable activation history.
- Provider object keys are persisted as bounded validated keys plus SHA-256 digests for generation-bound retrieval. They are never object-storage paths. Body bytes remain outside PostgreSQL. Staged object attachment is metadata only.
- Parser attempts and parsed revisions are immutable rows. Parser success does not activate a catalog. Matching completeness remains `not_in_scope`.
- No active OSV generation is seeded. No object storage, provider retrieval, synchronization, catalog-activation execution against production data, Outbox, BackgroundJob type, API, permission, matching, or Finding path is included.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 5C-R

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Forward-only migration `20260904180000_osv_parsed_revision_id_check_correction` replaces only `osv_parsed_advisory_revision_osv_id_chk`. Frozen SHA-256: `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`. The Batch 5C migration is unchanged. The catalog now has thirteen finished migrations.
- The intended identifier grammar is preserved: nonempty, maximum 512 characters, first character `A-Z` or `0-9`, remaining characters `A-Z0-9._+-`. The CHECK uses `char_length` plus a grammar regular expression without a POSIX counted repetition above 255.
- Parsed-revision rows can now be inserted. The Batch 5C-R migration includes no adapter. Object storage, provider retrieval, synchronization, matching, and Findings remain absent. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding.

### Session 11 Batch 5D

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `createOsvAcquisitionPersistence` in `@patchpilot/database` implements the committed Batch 5B ports against the frozen Batch 5C schema and the Batch 5C-R CHECK correction. Adapters live in the database package; `@patchpilot/vulnerability-intelligence` remains Prisma-free.
- Unique conflicts are reloaded and compared on immutable fields. Identical content is `already_applied`. Conflicting content is `immutable_conflict`. There is no generic upsert and no last-write-wins.
- Catalog-generation, attachment, and activation-prerequisite graphs are explicit adjacency sets. Transitions use `updateMany` compare-and-swap. Active has only a supersede edge.
- Parser success and parsed-revision attachment are coordinated in one PostgreSQL transaction. Failed attempts cannot reference a revision. After uniqueness abort, the adapter reloads the existing revision by natural key and compares immutable fields. Batch 5C-R makes a successful parsed-revision persist possible. Do not edit the frozen Batch 5C migration.
- Reconciliation uses the committed integer equations with no tolerance. Matching completeness remains `not_in_scope`. MAL matching does not participate in acquisition completeness.
- Quarantine and provider-presence observations are append-only. Absence is not withdrawal, source-license revocation, retrieval `generation_not_found`, parser failure, or catalog exclusion.
- Active-pointer replacement and activation history share one Serializable transaction. Cross-scope previous generations fail closed (`scope_mismatch`) without writing history or mutating the pointer. No production OSV generation is seeded.
- Object storage, provider retrieval, synchronization, schedulers, Outbox, BackgroundJob types, APIs, matching, and Findings remain absent. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed.

### Session 11 Batch 5E

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `S3OsvAdvisoryObjectStorage` in `@patchpilot/integrations` stores two artifact categories only: provider-body snapshots and parsed structural documents. It reuses the existing private MinIO/S3-compatible bucket, static credentials, `forcePathStyle`, and no public ACL. There is no presigned URL, no caller-selected bucket or endpoint, and no filesystem fallback.
- Attached identity is `intelligence/osv/{advisory_body|parsed_advisory}/sha256/{sha256}`. Staged identity is `intelligence/osv/{advisory_body|parsed_advisory}/tmp/{uuid}`. Provider object keys, advisory IDs, package names, and tenant IDs are never storage paths.
- Write-once uses `If-None-Match: *` plus HEAD compare. Same identity and same SHA-256 is `already_applied`. Same identity and different bytes is `immutable_conflict`. Storage ETag is not content identity. PatchPilot SHA-256 is verified on read-back.
- `createOsvArtifactAttachmentService` in `@patchpilot/vulnerability-intelligence` coordinates Batch 5D PostgreSQL reservation and finalization with object storage. PostgreSQL and object storage are **not** one transaction. Failed storage work cannot create false attached metadata. Cleanup eligibility is determined only; there is no destructive cleanup service except best-effort deletion of a known staged duplicate after successful attach.
- Size policy is the committed snapshot ceiling `OSV_SNAPSHOT_MAX_BYTE_COUNT` (1 MiB) for both categories. Parser output remains 2 MiB, but coordinated attachment rejects above 1 MiB. Transport body-byte policy stays `unavailable` (OD-8 retrieval limit).
- Parsed documents use the committed compact `JSON.stringify` UTF-8 rule and identifier `osv_parsed_advisory_document_v1`. Provider-body retention fails closed for OSV, ECHO, incomplete evidence, legal-review, and ineligible sources.
- Tests use locally generated synthetic bytes only. No live OSV advisory, copied GHSA/CVE body, GCS response, or catalog dump is stored.
- No provider retrieval, HTTP adapter, GCS listing client, synchronization, scheduler, Outbox, BackgroundJob type, API, permission, matching, or Finding path is included. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed.

### Session 11 Batch 5F

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Batch 5F adversarially reviews the committed Batch 5E object-storage adapter, staged attachment protocol, recovery, read-back integrity, PostgreSQL coordination, concurrency, and cleanup eligibility. Production changes are defect corrections only.
- Write-once idempotency hashes stored bytes. HEAD metadata, storage ETag, and spoofed checksums are not content identity. 409 and 412 compare rather than overwrite.
- Recovery stays inside `OSV_STORAGE_CALL_BUDGETS`. Transient storage failures leave staged metadata. Integrity conflicts may reject. Orphaned and rejected rows cannot become attached. False attached state is not accepted when the deterministic object is missing or corrupt.
- Cleanup remains classification-only except the committed best-effort delete of a known temporary identity after successful attachment. In-flight staged objects, attached evidence, referenced objects, and conflicting objects are not executable cleanup targets.
- Layer tests cover the in-memory orchestrator, disposable MinIO, and disposable PostgreSQL attachment adapters. Session 11 Batch 6B adds the composed MinIO-plus-PostgreSQL disabled-acquisition rehearsal in `apps/worker` integration tests.
- The 1 MiB snapshot ceiling is an object-storage admission limit. Session 11 Batch 6A-P closed OD-8 retrieval bytes at 1 MiB. Session 11 Batch 6A implements one-attempt generation-bound HTTPS retrieval. Do not treat Batch 5F as synchronization readiness.
- No provider retrieval, synchronization, matching, Findings, or OSV enablement existed in Batch 5F. Synthetic bytes only. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed.

### Session 11 Batch 6A

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 6A implements one generation-bound OSV provider-object HTTPS retrieval adapter in `@patchpilot/integrations` (`createOsvGenerationBoundRetrievalHttpsAdapter`). It enforces committed `osv_generation_bound_retrieval_policy_v1`. The injectable `https.request` test seam is not part of the package public export.
- Authorization, GCS get-media request compilation, and the validated result contract live in `@patchpilot/vulnerability-intelligence`. The adapter performs at most one HTTP attempt. Redirects are rejected. There is no retry, backoff, HEAD preflight, Range continuation, listing execution, storage attachment, parser invocation, catalog activation, scheduler, Outbox, BackgroundJob type, API, or permission change.
- Declared-size preflight, source eligibility, and private retention are enforced before HTTP. Generation is an ASCII decimal string bound with `ifGenerationMatch`. Response `x-goog-generation` must equal the requested generation. Received bytes must equal the declared listing size and cannot exceed 1,048,576.
- Streaming SHA-256 is computed over exact received bytes. Identity encoding only. Successful HTTP status is exactly 200. Failures omit body, raw key, URL, headers, Location, provider prose, stack, tenant, package, and Finding data.
- Tests use synthetic local byte streams and injected `node:https.request` / DNS seams only. They do not contact `storage.googleapis.com`. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed. Disabled acquisition orchestration is Batch 6B. Listing execution, scheduling, and OSV enablement remain absent.

### Session 11 Batch 6A-R

Session 11 Batch 6A-R adversarially reviews and hardens the committed Batch 6A generation-bound retrieval adapter, resolving the HTTP 500/502/504 retryability inconsistency. These are deliberate:

- Batch 6A-R adds three dedicated orchestration-retryable failure kinds to `osv_generation_bound_retrieval_policy_v1`: `http_500`, `http_502`, and `http_504`. These statuses were declared `orchestration_retryable` in the policy but mapped to non-retryable `unexpected_http_status` at runtime. Now each has an exact dedicated kind with `orchestration_retryable` classification.
- The `mapHttpStatus` function in the HTTPS adapter now maps HTTP 500 to `http_500`, HTTP 502 to `http_502`, and HTTP 504 to `http_504`. HTTP 503 remains `service_unavailable`. HTTP 408 and 429 remain distinct with their own kinds. Unmapped statuses remain `unexpected_http_status` with `non_retryable` classification.
- Comprehensive retryability taxonomy tests verify: (1) HTTP 500/502/504 have dedicated kinds, (2) all three are `orchestration_retryable`, (3) HTTP 503 remains `service_unavailable`, (4) HTTP 408 and 429 remain distinct, (5) `unexpected_http_status` is `non_retryable`, (6) internal consistency between policy and catalog.
- The retrieval adapter performs exactly one HTTP attempt regardless of status (retryable or non-retryable). No internal retry loop exists. Session 11 Batch 6B records retry disposition only and does not execute retries, backoff, or automatic redispatch.
- Endpoint compilation remains fixed to `storage.googleapis.com`, HTTPS port 443, exact path prefix `/storage/v1/b/osv-vulnerabilities/o/`, and query parameters `alt=media` and `ifGenerationMatch`. Object names are URI-encoded exactly once. Generation is an ASCII decimal string with no Number conversion.
- Redirects (301, 302, 303, 307, 308) remain rejected with dedicated `redirect_rejected` kind. No redirect target is followed. Response generation must exactly equal requested generation (string equality).
- Compressed responses (gzip, br, deflate) remain rejected. Request sends `Accept-Encoding: identity`. Response must be `identity` or absent.
- Received body bytes are bounded to exactly 1,048,576 (1 MiB). First byte above policy terminates consumption immediately with `response_too_large`. Declared listing size, Content-Length, and received size must reconcile exactly. Partial bodies never succeed.
- Streaming incremental SHA-256 is computed over exact received bytes. ETag and md5Hash are informational only and cannot become PatchPilot content identity.
- Confidential failure taxonomy: body bytes, raw provider object key, complete URL, response headers, provider prose, stack traces, tenant data, package data, and Finding data remain omitted from all failures and events.
- Quality gates pass: 168 integrations tests pass (including 33 retryability tests and 72 retrieval tests with the fix), 753 vulnerability-intelligence tests pass, formatting passes, linting passes, typecheck passes.
- Batch 6A-R does not implement retry execution, backoff, storage attachment, parser invocation, synchronization orchestration, pending-work queue, scheduler, Outbox, BackgroundJob types, APIs, permissions, matching, Findings, or OSV enablement. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 6B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 6B implements a **disabled, bounded OSV acquisition orchestrator** in `@patchpilot/vulnerability-intelligence` (`createOsvDisabledAcquisitionOrchestrator`, policy `osv_disabled_acquisition_orchestration_policy_v1`). It is explicitly invoked. It does not start at worker boot, does not schedule work, and does not enable OSV.
- Input is a bounded batch of already-validated listed-object observations (maximum 32). Raw listing pages, continuation tokens, live endpoints, tenant fields, and policy overrides are rejected. GCS listing is not executed.
- Conservative capacity: active concurrency 1, pending work 32 metadata-only items, one retrieval attempt per item per invocation. Only the active item may hold retrieved body bytes (at most 1 MiB). Pending items do not retain body bytes, streams, or client objects.
- The orchestrator composes committed classification, one-attempt generation-bound retrieval, immutable attachment, isolated parsing, parser-attempt and revision persistence, catalog membership, append-only quarantine, deterministic reconciliation, and candidate readiness. Parser success and candidate readiness never activate a catalog.
- Retry disposition is recorded only (`no_retry`, `future_explicit_retry_permitted`, `permanent_failure`, `quarantine_required`). There is no retry loop, backoff, Retry-After execution, delayed task, or durable retry job.
- HTTP retrieval remains in `@patchpilot/integrations`. Object storage remains in `@patchpilot/integrations`. Prisma adapters remain in `@patchpilot/database`, including read-only `createOsvAcquisitionResumeInspection`. Attached-body resume read-back is required (`createOsvAttachedBodyReadPort` over SHA-256-verified storage bytes). The orchestrator depends on injected ports only.
- One authorized MinIO-plus-PostgreSQL composition rehearsal lives in `apps/worker` as an integration test. It uses synthetic GHSA bytes and a fake retrieval port. It does not add worker production OSV startup, Outbox events, BackgroundJob types, or BullMQ jobs.
- Matching completeness remains `not_in_scope`. MAL may be retrieved and parsed where committed permission allows and never acquires matching authorization. OSV and ECHO remain fail-closed. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 6C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 6C is a **disabled end-to-end rehearsal** of the committed acquisition pipeline. It uses synthetic complete-inventory evidence under a test-only contract. It does not represent the real OSV inventory.
- Rehearsal composition lives in `apps/worker` integration tests. Production runtime does not import or invoke it. No scheduler, cron, Outbox event, BackgroundJob type, or BullMQ job is added.
- Retrieval uses an authorized scripted seam. Tests do not contact `storage.googleapis.com`, `osv.dev`, or any external provider. `https.request` is forbidden during the rehearsal suite.
- Ineligible and unknown observations terminate at `retrieval_skipped`. Legal-review observations remain quarantined. They issue zero retrieval attempts.
- Happy-path eligible items reach `ready_for_activation`. The orchestrator never calls `activateReadyGeneration`. The active catalog pointer and activation history remain unchanged.
- Identical replay is idempotent. Conflicting replay fails closed. Resume after interruption reuses attached SHA-256 bodies and persisted parser success without a second revision.
- Rehearsal-owned MinIO objects and PostgreSQL rows are inventoried and removed by test teardown. Storage deletion is a development-gated, compiled-key helper (`deleteDevelopmentOwnedObject`) denied in production. It is not a catalog cleanup job and not a broad bucket purge.
- Parser-worker pending-queue size remains unselected and is not the orchestrator's 32-item metadata queue. Occupancy remains 1. Matching completeness remains `not_in_scope`. MAL may parse and never authorizes matching. OSV and ECHO remain fail-closed. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding.

### Session 11 Batch 6D

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 6D is the acquisition-foundation **closure review**, not a runtime-enablement batch. The foundation is implemented and synthetically verified.
- Production OSV acquisition remains disabled. Provider listing execution, runtime scheduler, durable OSV jobs, and automatic retries remain absent.
- Catalog activation is not invoked. No production OSV catalog is active.
- Matching and Finding writes remain unauthorized. External exposure remains source-specific and is not implied by acquisition.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains **Proposed**. Session 11 closure does not accept it and does not authorize runtime enablement.
- OD-8 generation-bound retrieval bytes remain closed at 1,048,576 by Batch 6A-P. Batch 6D verifies that closure and does not introduce the decision again.
- At this checkpoint, the next work after Session 11 closure and ADR 0028 acceptance was the production GCS listing executor, later implemented as Session 12 Batch 1. Session 11 remains zero-Finding. Session 11 acquisition foundation is **CLOSED**.

## Target repository layout

```text
apps/
  web/                         # Next.js App Router (landing, Session 6 auth UI, /health)
  api/                         # Fastify TypeScript API (health, auth, assets, SBOM upload, intelligence status)

  worker/                      # Node.js TypeScript workers (outbox relay, SBOM ingest, KEV sync)
packages/
  config/                      # typed configuration; only place that may read process.env
  auth/                        # argon2 hashing, session use cases, permissions
  contracts/
  database/                    # Prisma adapters, tenant schema, repository implementations
  domain/                      # Result/error taxonomy; persistence ports; CISA KEV sync service; provider-status query; canonical CVE identity; active-catalog KEV membership; no Prisma types
  integrations/                # Object-storage S3 adapters; restricted CISA KEV HTTPS; OSV generation-bound retrieval and uncomposed GCS listing HTTPS; Redis ports
  logger/
  observability/
  policy-engine/               # empty boundary
  sbom/                        # vendored CycloneDX JSON schemas; worker-thread parser
  test-utils/
  vulnerability-intelligence/  # provider-neutral intelligence contracts; CISA KEV and OSV schemas/parsers; OSV source, transport, persistence, storage, and disabled-orchestration contracts; runtime-enablement invariants
  eslint-config/
  typescript-config/
docs/
  adr/
  architecture/
  product/
  runbooks/
  security/
deploy/
  compose/
  containers/
examples/
  sample-sboms/
  vulnerable-apps/
```

Begin as a modular monolith with separately deployable `web`, `api`, and `worker` applications. Do not introduce microservices without a measured need and an accepted ADR.

## Document map

| Topic | Document |
| --- | --- |
| Product vision and MVP | [docs/product/vision.md](docs/product/vision.md), [docs/product/mvp-scope.md](docs/product/mvp-scope.md), [docs/product/non-goals.md](docs/product/non-goals.md) |
| Users and language | [docs/product/target-users.md](docs/product/target-users.md), [docs/product/glossary.md](docs/product/glossary.md) |
| Definition of done | [docs/development/definition-of-done.md](docs/development/definition-of-done.md) |
| Local setup | [docs/development/local-setup.md](docs/development/local-setup.md), [environment variables](docs/development/environment-variables.md), [testing](docs/development/testing.md), [troubleshooting](docs/development/troubleshooting.md) |
| Git, reviews, releases | [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/commit-guidelines.md](docs/development/commit-guidelines.md), [docs/development/review-checklist.md](docs/development/review-checklist.md), [docs/development/pull-request-process.md](docs/development/pull-request-process.md), [docs/development/release-principles.md](docs/development/release-principles.md), [docs/development/release-strategy.md](docs/development/release-strategy.md) |
| CI and repository governance | [docs/development/ci.md](docs/development/ci.md), [docs/development/dependency-management.md](docs/development/dependency-management.md), [docs/development/branch-protection.md](docs/development/branch-protection.md), [docs/development/repository-settings.md](docs/development/repository-settings.md), [docs/development/artifact-retention.md](docs/development/artifact-retention.md) |
| Architecture | [docs/architecture/README.md](docs/architecture/README.md) |
| Security design | [docs/security/README.md](docs/security/README.md) |
| Operational runbooks | [docs/runbooks/README.md](docs/runbooks/README.md) |
| Architecture decisions | [docs/adr/README.md](docs/adr/README.md) |
| Open architecture decisions | [docs/architecture/open-decisions.md](docs/architecture/open-decisions.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Vulnerability disclosure | [SECURITY.md](SECURITY.md) |
| Conduct | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| License | [LICENSE](LICENSE) (Apache License 2.0) |

## Cursor rules

| Rule | When it applies |
| --- | --- |
| [architecture.mdc](.cursor/rules/architecture.mdc) | Always: layering, dependencies, identifiers, time, transactions |
| [security.mdc](.cursor/rules/security.mdc) | Always: the ten security-sensitive areas (canonical) |
| [git-workflow.mdc](.cursor/rules/git-workflow.mdc) | Always: branches, commits, pull requests |
| [testing.mdc](.cursor/rules/testing.mdc) | Tests and fixtures |
| [database.mdc](.cursor/rules/database.mdc) | Prisma, migrations, persistence |
| [api.mdc](.cursor/rules/api.mdc) | Fastify API |
| [frontend.mdc](.cursor/rules/frontend.mdc) | Next.js web app |
| [workers.mdc](.cursor/rules/workers.mdc) | Workers, queue, outbox |
| [integrations.mdc](.cursor/rules/integrations.mdc) | External providers and feeds |
| [documentation.mdc](.cursor/rules/documentation.mdc) | Docs, ADRs, runbooks |

## Security-sensitive areas

Treat these as in-scope for threat modeling and review on every related change. Canonical rules: [architecture.mdc](.cursor/rules/architecture.mdc) and [security.mdc](.cursor/rules/security.mdc). Terms: [docs/product/glossary.md](docs/product/glossary.md).

1. Tenant isolation
2. SBOM handling
3. Vulnerability-intelligence provenance
4. External integrations
5. Background-job idempotency
6. Sensitive log redaction
7. Credential storage
8. Risk-score explainability
9. Audit integrity
10. Development versus production configurations

## Architectural invariants

Do not copy or weakly restate `security.mdc` here. If this file and a rule disagree, keep the stricter security and tenancy interpretation.

- Modular monolith only (`web`, `api`, `worker` share packages/schema). No microservices without an accepted ADR.
- Application **layer** (use cases) lives in `packages/`. Fastify handlers and Next.js are presentation. Next.js is not a second API.
- Deny by default. Tenant-owned data is scoped to the authorized organization, not a client-supplied id.
- Untrusted: SBOMs, archives, webhooks, feeds, headers, URLs, files, external API responses. Validate with Zod at boundaries.
- `process.env` only in `packages/config`. No hardcoded secrets. Canonical log redaction is in `security.mdc`.
- Outbox for durable work; at-least-once; idempotent handlers and relays, org-scoped for tenant work.
- Intelligence is versioned with provenance. Priorities are explainable and policy-versioned. AI must not set authoritative scores.
- Append-only audit for security- and remediation-sensitive operations. No cascade-delete of evidence.

AI features, if added later, are optional explanation and drafting aids. Users must supply their own API key or local compatible endpoint at runtime. API keys must never be hardcoded. The first usable release must work with AI disabled. GitHub and other source-control integrations are not MVP.

## Agent workflow

Before editing:

1. Read this file and applicable files under [`.cursor/rules/`](.cursor/rules/).
2. Inspect the existing repository. Application shells exist; do not assume product features exist.
3. Summarize current state, assumptions, plan, security-sensitive changes, expected files, and ambiguities.
4. Stay inside the requested scope.

During implementation:

1. Work in small coherent batches. Do not rewrite unrelated files.
2. Add or update tests with implementation.
3. Create new database migrations rather than editing applied migrations.
4. Do not add dependencies without explaining why they are required.
5. Prefer established standards and libraries over custom security mechanisms.
6. Run appropriate checks after each coherent batch.
7. Do not scaffold applications or product functionality unless the task explicitly asks for them.

After implementation:

1. List created and modified files.
2. Explain important decisions.
3. Report executed commands and their actual results. Do not claim that commands passed unless they were executed.
4. Identify untested areas, remaining risks, and follow-up work.
5. Suggest one focused Conventional Commit message.
6. Do not describe work as production-ready merely because tests pass.

## Git and reviews

Use short-lived feature branches and [Conventional Commits](docs/development/commit-guidelines.md). Open a pull request. Do not push directly to `main`. Required checks and review expectations are defined in [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/ci.md](docs/development/ci.md), and [docs/development/review-checklist.md](docs/development/review-checklist.md).

Do not file security vulnerabilities as public issues. Follow [SECURITY.md](SECURITY.md).
