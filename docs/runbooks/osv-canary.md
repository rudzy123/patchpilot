# OSV first real-provider canary operator procedures

These procedures support Accepted
[ADR 0029](../adr/0029-first-real-provider-osv-canary-authorization-and-safety.md).
Session 13 Batch 2-R independently reviewed the combined operational-control
chain: instance-operator identity, injected authentication, durable
authority inspection, phase-specific single-use authorization, the one-shot
command, halt ordering, request/run ensure, executable preflight, read-only
lease inspection, heartbeat and deadline policy readiness, and operator
runbooks. Preflight success remains
`canary_execution_preflight_passed_provider_contact_not_authorized`.
That outcome is evidence only. It does not authorize provider contact,
lease acquisition, heartbeat start, deadline arming, catalog activation,
matching, or Finding writes.

Distinguish these states; they are not interchangeable:
- authorization prepared (`authorized_preflight_required`)
- preflight passed
- provider contact separately authorized
- canary executed
- canary evidence reviewed

Halt is rechecked at each protected command and preflight checkpoint.
Lease inspection remains read-only. Controller readiness starts no timer.
Egress readiness performs no external DNS or HTTP. Observability sink
readiness is an operational gate and is not workflow authority.
Zero-Finding baseline proves no canary Finding writes; it does not
require the platform to contain zero Finding rows.

Do not contact `storage.googleapis.com` or `osv.dev` from this document.
Do not enable OSV. Do not treat halt release as canary authorization.
Do not include secrets or destructive commands.

No production operator CLI is registered. The one-shot command, preflight,
and listing-only execution-bridge factories remain uncomposed. The Batch 3A
bridge supports **scripted provider execution only** and was independently
reviewed in Batch 3A-R. Real-provider capability does not exist.
Provider-facing execution steps remain **unavailable until Batch 3B**.
Escalation owner is the instance operator until
[OD-10](../architecture/open-decisions.md) is closed. Legal questions
escalate to the instance legal and provenance reviewer. Security incidents
escalate to the instance security reviewer. No procedure authorizes
evidence deletion, catalog activation, matching, or Finding mutation.

## 1. Canary authorization preparation

- **Purpose:** Authenticate one instance operator, load one existing
  issued authorization, evaluate halt independently, ensure one canary
  request and run, and consume the authorization once.
- **Prerequisites:** Durable issued authorization already exists. The
  command does not create operator identity or authorization. Production
  authentication remains unimplemented. No public CLI.
- **Trigger:** Operator intends to prepare listing-only (or a later
  bounded-body) canary work after legal issuance and before preflight.
- **Immediate containment:** Do not start a CLI, scheduler, lease, timer,
  or provider request. Default halt must remain engaged in production
  worker and API processes.
- **Evidence to collect:** Outcome `authorized_preflight_required`;
  authorization, request, and run identities; halt decision;
  `executionPermitted` false; provider and lease call counts 0.
- **Forbidden actions:** Treating command success as execution
  permission; creating authorization through the command; using a tenant
  User, Organization role, or anonymous identity; logging authentication
  proof; acquiring a lease; starting heartbeat or deadline; contacting a
  provider; resetting a consumed authorization to issued.
- **Recovery:** Same-run replay is status reuse only and does not start
  a second execution. Different-run replay is rejected. If halt blocked
  consumption, leave the authorization issued, restore halt, and retry
  preparation only after halt is released in a dedicated process.
- **Escalation role:** Instance operator.
- **Closure criteria:** Outcome is `authorized_preflight_required` with
  `executionPermitted=false`, or a closed failure with provider calls 0.
  Preflight remains required.

## 2. Canary authorization preflight

- **Purpose:** Prove whether one consumed canary authorization and its
  authoritative request and run are ready for a later separately
  authorized provider-facing phase.
- **Prerequisites:** Durable consumed authorization bound to the exact
  request and run; halt independently released through trusted state;
  production OSV remains disabled; no public operator CLI.
- **Trigger:** Operator intends to evaluate listing-only or bounded-body
  readiness after `authorized_preflight_required`.
- **Immediate containment:** Do not start a CLI, scheduler, or provider
  request. Keep production acquisition halt restored after the check.
- **Evidence to collect:** Preflight outcome identifier; authorization,
  request, and run identities; halt result; lease-inspection status
  without holder secrets; heartbeat and deadline policy readiness;
  egress application-control evidence; local dependency result;
  active-pointer baseline; zero-Finding counts; remaining closed gates.
- **Forbidden actions:** Treating preflight success as provider
  permission; contacting a provider; acquiring a lease; starting
  heartbeat or deadline timers; releasing halt as a substitute for
  authorization; copying listing continuation handles.
- **Recovery:** Close the named failure, restore halt if it was
  temporarily released in a dedicated process, and re-run preflight.
- **Escalation role:** Instance operator.
- **Closure criteria:** Outcome is
  `canary_execution_preflight_passed_provider_contact_not_authorized`
  or a closed failure with provider calls 0. No provider request issued.

## 3. Halt release and restoration

- **Purpose:** Release acquisition halt only for a dedicated command or
  preflight process snapshot, then restore it.
- **Prerequisites:** An issued authorization exists for command
  preparation, or a consumed authorization exists for preflight. Halt
  release is not authorization and does not enable OSV.
- **Trigger:** Command or preflight reports `halt_engaged` under default
  or explicit halt.
- **Immediate containment:** Do not start worker or API with halt
  released. Do not change shared production environment files.
- **Evidence to collect:** Halt control and source; authorization state;
  no lease mutation; no provider calls.
- **Forbidden actions:** Using halt release as execution permission;
  leaving halt released in production worker or API processes.
- **Recovery:** Restore halt to default halted. Re-run command
  preparation or preflight only in the dedicated process that explicitly
  released halt.
- **Escalation role:** Instance operator.
- **Closure criteria:** Production processes remain halted. Dedicated
  command preparation either reached `authorized_preflight_required` or
  stopped at `halt_engaged`. Dedicated preflight either passed with halt
  rechecked or stopped at `halt_engaged`.

## 4. Lease unavailable or ambiguous

- **Purpose:** Interpret a read-only lease-scope inspection without
  acquiring, taking over, heartbeating, or releasing.
- **Prerequisites:** Preflight reached lease inspection. Scope is the
  shared OSV public-export lease.
- **Trigger:** Preflight reports `lease_unavailable` or
  `lease_state_ambiguous`, or inspection is `held_by_another`,
  `ownership_ambiguous`, or `database_unavailable`.
- **Immediate containment:** Do not acquire. Do not take over an expired
  projection. Do not heartbeat or release.
- **Evidence to collect:** Inspection status; later acquisition action
  identifier; run identity expected by preflight; database availability.
  Do not collect holder secrets or digests.
- **Forbidden actions:** Creating a lease row from preflight; treating
  an expired projection as acquired authority; resetting fencing.
- **Recovery:** Wait for the other holder to finish, or stop. Later
  guarded acquisition remains a Batch 3 concern, unavailable until
  Batch 3.
- **Escalation role:** Instance operator.
- **Closure criteria:** Preflight remains failed closed. Lease row
  revision and fencing are unchanged by preflight.

## 5. Heartbeat startup failure

- **Purpose:** Handle heartbeat policy that is not ready without starting
  a timer.
- **Prerequisites:** Preflight validates cadence 60000 ms, lease TTL
  900000 ms, one in-flight heartbeat, pending capacity 0.
- **Trigger:** `heartbeat_policy_not_ready` or a Batch 3A controller start
  failure. Real-provider start remains unavailable until Batch 3B.
- **Immediate containment:** Do not call heartbeat start. Do not
  schedule catch-up.
- **Evidence to collect:** Policy identifier; interval; TTL; in-flight
  and pending capacities; timer-started false.
- **Forbidden actions:** Overriding cadence or TTL; starting a
  production timer; inspecting holder proofs.
- **Recovery:** Correct policy composition. Re-run preflight. Do not
  start the controller.
- **Escalation role:** Instance operator.
- **Closure criteria:** Heartbeat remains unstarted. Provider calls 0.

## 6. Heartbeat ownership loss

- **Purpose:** Contain ownership loss after a later heartbeat start.
  Real-provider execution remains unavailable until Batch 3B.
- **Prerequisites:** A later guarded owner exists. Preflight itself does
  not start heartbeat.
- **Trigger:** Ownership lost, fencing changed, or expiry observed during
  a future heartbeat loop.
- **Immediate containment:** Stop dispatch. Do not adopt takeover. Do
  not contact a provider.
- **Evidence to collect:** Terminal heartbeat reason; run identity;
  fencing unchanged-vs-changed flag without token values.
- **Forbidden actions:** Catch-up bursts; resurrecting a lost owner;
  releasing another holder's lease.
- **Recovery:** Terminalize the canary attempt. Preserve immutable
  evidence. Restore halt.
- **Escalation role:** Instance operator.
- **Closure criteria:** No further heartbeat. Lease not mutated by
  preflight. Review opened.

## 7. Canary deadline exceeded

- **Purpose:** Contain an exceeded 1800000 ms monotonic phase deadline.
  Batch 3A arms the listing-only deadline before scripted listing.
  Real-provider arming remains unavailable until Batch 3B.
- **Prerequisites:** Deadline policy ready during preflight. Timer not
  armed by preflight.
- **Trigger:** `deadline_policy_not_ready` now, or a later armed timer
  firing at or beyond 1800000 ms.
- **Immediate containment:** Do not arm a replacement timer. Do not
  continue provider work.
- **Evidence to collect:** Phase; duration 1800000 ms; monotonic clock
  availability; timer-armed false during preflight.
- **Forbidden actions:** Using wall-clock elapsed time; using lease TTL
  as the deadline; restarting the deadline.
- **Recovery:** Stop the phase. Preserve evidence. Restore halt.
- **Escalation role:** Instance operator.
- **Closure criteria:** Deadline remains unarmed after preflight, or a
  later Batch 3 run is terminal with no provider retry.

## 8. Egress-policy failure

- **Purpose:** Fail closed when application or declared deployment
  egress controls are missing. No provider DNS or HTTP.
- **Prerequisites:** Fixed host, HTTPS, port 443, GCS listing path,
  bucket, redirect rejection, DNS-pinning policy, prohibited-address
  policy, TLS verification, post-connect peer verification, cloud
  metadata denial, no caller-selected proxy.
- **Trigger:** `egress_policy_not_ready` or missing operational evidence.
- **Immediate containment:** Do not resolve provider DNS. Do not open
  TLS. Do not send HTTP.
- **Evidence to collect:** Evidence class per control
  (`application_control_verified`,
  `deployment_control_declared_but_not_externally_proven`, or
  `missing_operational_evidence`). DNS, TLS, and provider call counts
  remain 0.
- **Forbidden actions:** Claiming network-level enforcement that is not
  configured; disabling certificate verification; selecting a proxy.
- **Recovery:** Restore missing controls. Re-run preflight without
  external probes.
- **Escalation role:** Instance security reviewer.
- **Closure criteria:** Required controls are present. Missing evidence
  still blocks success.

## 9. Provider unavailable

- **Purpose:** Contain a later provider outage. Real-provider contact remains
  unavailable until Batch 3B.
- **Prerequisites:** Preflight succeeded or failed without provider
  calls. Production remains halted.
- **Trigger:** A later Batch 3 listing or retrieval cannot complete.
- **Immediate containment:** Stop the phase. Do not retry automatically.
- **Evidence to collect:** Closed failure kind; provider call count;
  reached stage. No response bodies or headers.
- **Forbidden actions:** Automatic retry; polling; backoff loops;
  copying provider prose.
- **Recovery:** Terminalize. Restore halt. Re-issue a new authorization
  only after review.
- **Escalation role:** Instance operator.
- **Closure criteria:** No automatic retry. Authorization remains
  consumed. Provider calls remain bounded to the later Batch 3 attempt.

## 10. HTTP 429 or provider-rate concern

- **Purpose:** Treat rate limiting as terminal for the first canary.
  Retry-After execution remains prohibited for canary retries (retry count 0).
  Batch 3A records HTTP 429 and does not retry.
- **Prerequisites:** Canary retry prohibition acknowledgement.
- **Trigger:** HTTP 429 or operator suspicion of rate limiting during a
  later Batch 3 attempt.
- **Immediate containment:** Stop. Do not sleep on Retry-After. Do not
  enqueue a retry.
- **Evidence to collect:** Closed 429 failure kind; no header dump; no
  token material.
- **Forbidden actions:** Automatic retry; interpreting Retry-After as
  dispatch authority; looping.
- **Recovery:** Terminalize. Restore halt. Schedule a new authorization
  only after operator review.
- **Escalation role:** Instance operator.
- **Closure criteria:** Retry disposition is `no_automatic_retry`.

## 11. Listing token cycle

- **Purpose:** Fail closed on listing continuation-cycle detection.
  Listing execution against a scripted port exists in uncomposed Batch 3A.
  Real-provider listing remains unavailable until Batch 3B.
- **Prerequisites:** In-memory cycle detection policy from Session 12
  Batch 3/4.
- **Trigger:** `listing_token_cycle` during a later listing-only phase.
- **Immediate containment:** Stop pagination. Do not persist raw
  continuation handles.
- **Evidence to collect:** Cycle failure code; page counts; no raw
  continuation handle; no digest in logs.
- **Forbidden actions:** Inspecting continuation handles; restarting the
  same pass; contacting the provider again.
- **Recovery:** Terminalize. Quarantine as required by listing policy.
  Restore halt.
- **Escalation role:** Instance operator.
- **Closure criteria:** No further listing I/O. Evidence omits
  continuation handles.

## 12. Inventory nonconvergence

- **Purpose:** Stop when pass A and pass B do not converge. Scripted listing
  execution exists in uncomposed Batch 3A. Real-provider listing remains
  unavailable until Batch 3B.
- **Prerequisites:** Two-pass inventory policy. Canary completeness
  cannot satisfy production completeness.
- **Trigger:** Nonconvergence during a later listing-only phase.
- **Immediate containment:** Do not retrieve bodies. Do not activate.
- **Evidence to collect:** Convergence failure code; prefix; pass
  identifiers. No observation payloads in operator notes.
- **Forbidden actions:** Waiving convergence; using canary completeness
  as production completeness; body retrieval.
- **Recovery:** Terminalize. Restore halt. Re-authorize only after
  review.
- **Escalation role:** Instance operator.
- **Closure criteria:** Body retrieval remains 0. Activation remains
  prohibited.

## 13. Listing ceiling reached

- **Purpose:** Stop at exact canary listing ceilings. Scripted Batch 3A
  enforces those ceilings. Real-provider execution remains unavailable
  until Batch 3B.
- **Prerequisites:** Canary ceilings 8/16 pages, 2000/4000 observations,
  8,388,608 / 16,777,216 listing bytes.
- **Trigger:** Ceiling exceeded by one during a later listing-only phase.
- **Immediate containment:** Admit no further pages. Do not raise
  ceilings.
- **Evidence to collect:** Which ceiling; exact counts; no page bodies.
- **Forbidden actions:** Caller-selected limits; continuing after
  overflow; treating exact ceiling overflow as success.
- **Recovery:** Terminalize. Restore halt.
- **Escalation role:** Instance operator.
- **Closure criteria:** Counts remain exact. No provider retry.

## 14. Operator cancellation

- **Purpose:** Stop preflight or a later phase at the next cancellation
  boundary without resetting authorization or mutating the lease.
- **Prerequisites:** Abort signal available to preflight.
- **Trigger:** Operator aborts, or preflight reports
  `cancellation_observed`.
- **Immediate containment:** Do not start successor checks. Do not
  contact a provider. Do not acquire or release a lease.
- **Evidence to collect:** Cancellation boundary; reached stage;
  authorization still consumed if consumption already occurred;
  `authorizationReset` false.
- **Forbidden actions:** Resetting authorization to issued; starting
  controllers; activating; deleting evidence.
- **Recovery:** Leave consumed authorization consumed. Restore halt.
  Issue a new authorization only after review if a new run is required.
- **Escalation role:** Instance operator.
- **Closure criteria:** One bounded result. Provider calls 0. Retry
  disposition `no_automatic_retry`.

## 15. Lease release uncertainty

- **Purpose:** Handle uncertainty about whether a later owner still
  holds the lease. Preflight does not release.
- **Prerequisites:** Stop proof from a later heartbeat controller, if
  any. Preflight yields no release.
- **Trigger:** Operator cannot confirm a later guarded release.
- **Immediate containment:** Do not delete the lease row. Do not guess
  fencing. Do not release without current ownership.
- **Evidence to collect:** Inspection status; whether later acquisition
  action is `none`, `exact_acquire`, or `guarded_stale_takeover`.
- **Forbidden actions:** DELETE of the lease projection; fencing reset;
  releasing another holder's lease.
- **Recovery:** Inspect read-only. If expired, later guarded takeover
  remains unavailable until Batch 3B.
- **Escalation role:** Instance operator.
- **Closure criteria:** Lease row remains durable. Preflight mutation
  count 0.

## 16. Unexpected active-pointer mutation

- **Purpose:** Detect unauthorized catalog-pointer change. Preflight
  captures a read-only baseline and must not modify the pointer.
- **Prerequisites:** Active-pointer baseline policy
  `osv_canary_active_pointer_baseline_v1`.
- **Trigger:** Baseline capture fails, pointer count changes during
  preflight, or activation history appears unexpectedly.
- **Immediate containment:** Do not activate. Do not repair by writing
  the pointer. Stop canary work.
- **Evidence to collect:** Present vs absent; activation-history count;
  captured-at; activation call count 0; `activePointerModified` false.
- **Forbidden actions:** Calling activation; swapping the pointer;
  deleting history.
- **Recovery:** Preserve rows. Open a security review. Restore halt.
- **Escalation role:** Instance security reviewer.
- **Closure criteria:** Pointer unchanged by preflight. Activation
  remains prohibited.

## 17. Unexpected tenant or Finding activity

- **Purpose:** Prove zero-tenant and zero-Finding baselines and contain
  unexpected Finding or tenant-scoped activity.
- **Prerequisites:** Aggregate Finding and FindingObservation counts
  only. No tenant identity in preflight results.
- **Trigger:** `zero_finding_baseline_failed`, tenant context present,
  or Finding counts change during preflight.
- **Immediate containment:** Do not write Findings. Do not emit
  recalculation events. Do not process assets or components.
- **Evidence to collect:** Finding count; observation count;
  `findingWritePlanned` false; `tenantContextPresent` false.
- **Forbidden actions:** Selecting tenant rows by organization identity
  in operator notes; creating Findings; matching.
- **Recovery:** Preserve counts. Open a security review. Restore halt.
- **Escalation role:** Instance security reviewer.
- **Closure criteria:** Counts unchanged by preflight. Session remains
  zero-Finding for canary work.

## 18. Postcanary evidence review

- **Purpose:** Require postcanary review after any later phase.
  Review is mandatory even if preflight passed.
- **Prerequisites:** Remaining gate `postcanary_review_required`.
  Provider contact remains separately authorized.
- **Trigger:** Preflight success or any later terminal canary result.
- **Immediate containment:** Do not proceed to activation, matching, or
  Findings. Do not treat Batch 3A scripted success as Batch 3B authorization.
- **Evidence to collect:** Authorization identity; request and run;
  phase; remaining gates; halt restored; lease inspection; baselines.
- **Forbidden actions:** Treating review as execution permission;
  enabling OSV; copying provider bodies into tickets.
- **Recovery:** Record the review verdict. Issue a new authorization
  only for a new run after accepted review.
- **Escalation role:** Instance canary evidence reviewer, countersigned
  by the instance operator.
- **Closure criteria:** Review recorded. Activation still prohibited.

## 19. Evidence retention and cleanup

- **Purpose:** Keep immutable canary evidence and bound cleanup so
  fencing and single-use authority cannot reset.
- **Prerequisites:** Authorization DELETE forbidden. Lease projection
  DELETE forbidden. Frozen migrations remain unchanged.
- **Trigger:** Operator wants to remove test rows or expired unused
  authorizations after review.
- **Immediate containment:** Do not edit frozen migrations. Do not
  reset fencing by recreating the lease row. Do not purge Findings
  because none should exist from this preflight.
- **Evidence to collect:** Authorization state; lease presence;
  object-storage locators omitted from notes; retention identifiers.
- **Forbidden actions:** Destructive database reset; migration edits;
  deleting lease rows; deleting consumed authorization rows to mint a
  second use; copying provider responses.
- **Recovery:** Leave production evidence durable. Remove only
  test-owned disposable database rows in FK-safe order after a test
  rehearsal.
- **Escalation role:** Instance operator.
- **Closure criteria:** Production evidence retained. Test rehearsal
  cleanup, if any, does not contact a provider and does not alter the
  active catalog pointer.
