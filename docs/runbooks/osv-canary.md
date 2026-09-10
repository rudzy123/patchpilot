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

1. Canary phase authorization (`authorized_preflight_required` after
   consume).
2. Provider-free preflight
   (`canary_execution_preflight_passed_provider_contact_not_authorized`).
3. Provider-contact authorization evaluation (`persistence_required` until
   a later reviewed consumption composition constructs issuance after
   Session 13 Batch 3B-R).
4. Independent provider-contact authorization review.
5. Durable provider-contact authorization issuance and consumption
   (schema exists after Session 13 Batch 3B-P; uncomposed adapters exist
   after Session 13 Batch 3B-A and were independently reviewed in Session
   13 Batch 3B-A-R; the complete chain was independently reviewed in
   Session 13 Batch 3B-R; production composition remains later).
6. Uncomposed listing-canary execution authorization
   (`listing_canary_execution_authority_prepared_provider_attempt_not_executed`
   after Session 13 Batch 3C-Auth; Session 13 Batch 3C-Auth-R independently
   reviewed that boundary; production composition remains later).
7. Operator-controlled bounded listing canary
   (`listing_canary_one_page_classified` after Session 13 Batch 3C;
   Session 13 Batch 3C-R independently reviewed that evidence;
   candidate-selection evidence unavailable; Batch 4-P blocked; do not retry).
8. Protected listing-observation evidence policy
   (`osv_protected_listing_observation_evidence_policy_v1` after Session 13
   Batch 3D-P-R; provider-free; durable persistence required and not
   implemented; encryption-policy checkpoint required before schema; a new
   listing request is not authorized).
9. Provider contact.
10. Postcanary review.

Batch 3B evaluates listing-only provider-contact prerequisites and fails
closed with `persistence_required`. **Batch 3B does not authorize the operator to
execute the provider call.** It does not mint in-memory authorization. Batch 3B-P
persists the distinct listing-only schema only. Session 13 Batch 3B-A adds
uncomposed issuance, inspection, consumption, and revocation adapters.
Session 13 Batch 3B-A-R independently reviewed those adapters.
Session 13 Batch 3B-R independently reviewed the complete authorization
chain. Production composition does not construct them. Successful
consumption does not authorize provider contact. Consume results state
that the provider-contact record was consumed and that remaining runtime
gates are still required.

Session 13 Batch 3C-Auth implements uncomposed listing-canary execution
authorization. Explicit operator execution confirmation is required.
Provider-contact authorization consumption is necessary but insufficient.
Halt is freshly checked. Lease acquisition is guarded. Heartbeat must
start and the listing-only deadline must arm before permit creation.
Final egress validation performs no DNS, TLS, or HTTP. Ownership is
revalidated immediately before one private one-use listing-attempt
permit. Pending provider-attempt capacity is zero. Automatic retries
are zero. Cleanup order is deadline stop, heartbeat stop, then guarded
release. Body retrieval, activation, matching, and Findings remain
unauthorized. OSV remains generally disabled. Production composition
does not construct the factory. Session 13 Batch 3C-Auth-R independently
reviewed that boundary.

Session 13 Batch 3C implements the nonpublic operator command
`scripts/run-osv-listing-canary.mjs`. Dry-run contacts no provider.
After synthetic rehearsal and one explicit operator invocation, exactly
one listing HTTPS request was sent to the committed GCS JSON Objects
listing endpoint for prefix `crates.io/`. Outcome
`listing_canary_one_page_classified`: one request attempted, one HTTP
200 listing page accepted, 320143 response bytes, 1000 observations,
continuation token present and unused, retries 0, pagination follow-ups
0, body requests 0. Halt restoration `restored`. Deadline stopped.
Heartbeat stopped. Guarded lease release `released`. Active pointer
unchanged. Zero Finding operations. Raw response bytes and continuation
tokens were not persisted. Do not retry that request. Do not request a
second page. Session 13 Batch 3C-R independently reviewed that listing
canary. Candidate-selection evidence is unavailable, so Batch 4-P is
blocked. That classification does not authorize another request.

Halt is rechecked at each protected command and preflight checkpoint.
Lease inspection remains read-only. Controller readiness starts no timer.
Egress readiness performs no external DNS or HTTP. Observability sink
readiness is an operational gate and is not workflow authority.
Zero-Finding baseline proves no canary Finding writes; it does not
require the platform to contain zero Finding rows.

Do not copy provider response bodies, continuation tokens, or object
keys into this document. Do not enable OSV. Do not treat halt release as
canary authorization. Do not include secrets or destructive commands.

No production operator CLI is registered. The one-shot command, preflight,
listing-only execution-bridge, provider-contact authorization,
listing-canary execution-authorization, and bounded listing-canary
factories remain uncomposed. The Batch 3A bridge supports **scripted
provider execution only** and was independently reviewed in Batch 3A-R.
The Batch 3C operator script is not registered in worker, API, `dev`,
`start`, `test`, or `build`. Do not retry the Batch 3C listing request.
Body retrieval, catalog activation, matching, and Finding writes remain
unauthorized.

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
  legal-decision identity and listing-metadata permission only;
  deployment egress-evidence identity and control classes;
  DNS, TLS, redirect, proxy, and prohibited-address evidence classes
  without hostnames, addresses, or certificates;
  operator runbook version;
  emergency-containment acknowledgement;
  postcanary reviewer assignment (independent of the issuing operator);
  evidence-retention disposition;
  active-pointer baseline; zero-Finding counts; remaining closed gates.
  Provider-rate budget remains the committed listing-only profile
  (retries 0). Postrun halt restoration remains required after any later
  dedicated process.
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

## 2A. Provider-contact authorization evaluation

- **Purpose:** Evaluate whether listing-only real-provider contact
  prerequisites are satisfied. This is not execution and is not durable
  authorization.
- **Prerequisites:** Durable consumed listing-only canary authorization
  bound to the exact request and run; accepted provider-free preflight
  evidence with `providerContactAuthorized=false`; current listing-metadata
  legal approval; versioned egress and deployment evidence; heartbeat and
  deadline policy versions; runbook, containment, independent reviewer,
  and retention acknowledgements; active-pointer and zero-Finding
  baselines. Halt procedure acknowledgement is required. Halt is not
  cleared.
- **Trigger:** Operator intends to evaluate listing-only provider-contact
  authorization after provider-free preflight.
- **Immediate containment:** Do not construct a real-provider capability.
  Do not resolve DNS. Do not send HTTP. Do not acquire a lease. Do not
  start heartbeat or deadline timers. Do not consume the original canary
  authorization again.
- **Evidence to collect:** Closed failure `persistence_required` after
  other gates pass, or an earlier named failure; source canary
  authorization identity; request and run; halt observed and not cleared;
  provider, DNS, HTTP, lease, and timer counts 0.
- **Forbidden actions:** Treating evaluation as Batch 3C execution
  permission; minting in-memory authorization to skip durable issuance;
  contacting a provider; enabling OSV; using halt false as
  authorization; substituting bounded-body or body-retrieval legal
  approval; using generic `ready: true` as egress evidence; self-review
  by the issuing operator.
- **Recovery:** Close the named failure. Restore halt if it was
  temporarily released in a dedicated process. Re-evaluate after the
  missing evidence is current. Do not invent a replacement authorization.
- **Escalation role:** Instance operator. Independent postcanary
  reviewer assignment is required and is not the issuing operator.
- **Closure criteria:** Evaluation remains `persistence_required` after
  other gates pass, or a named earlier failure. `providerContactStarted`
  is false. Schema existence after Batch 3B-P still issues nothing.
  Batch 3C later consumed durable issuance after Batch 3B-A. No
  additional provider request is authorized from this evaluation.

## 2B. Bounded listing-canary execution

- **Purpose:** Execute exactly one listing-only real-provider HTTPS
  request after local gates, consumed provider-contact authorization,
  halt release in a dedicated process, guarded lease, heartbeat,
  listing-only deadline, egress revalidation, and one-use permit claim.
- **Prerequisites:** Session 13 Batch 3C-Auth-R reviewed execution
  authorization. Synthetic rehearsal passed. Dry-run succeeded with
  provider calls 0. Explicit operator confirmation
  `--i-understand-this-sends-one-real-provider-listing-request`.
- **Trigger:** Operator intends the first listing-only canary after
  all local gates. Tests, build, lint, typecheck, and startup must not
  invoke this command.
- **Immediate containment:** Maximum provider requests 1. Maximum
  in-flight 1. Pending 0. Automatic retries 0. Pagination follow-ups 0.
  Body requests 0. Do not follow a continuation token. Restore halt.
  Stop deadline then heartbeat. Guardedly release the lease.
- **Evidence to collect:** Outcome identifier; request and run
  identities; command execution identity; provider request count;
  HTTP result classification; response-byte count; observation count;
  continuation-token-present Boolean; halt restoration; deadline stop;
  heartbeat stop; lease release; active-pointer unchanged; zero-Finding
  operations. Omit raw bodies, tokens, URLs with query, headers, object
  keys, holder proofs, and Finding data.
- **Forbidden actions:** Retry; second page; body retrieval; GCS media
  download; parser worker; storage write; activation; matching; Finding
  writes; enabling `INTELLIGENCE_OSV_ENABLED`; committing provider
  fixtures.
- **Recovery:** If the request failed safely, collect bounded evidence.
  Session 13 Batch 3C-R has independently reviewed the committed listing
  canary. Do not retry. If halt restoration cannot be proven, treat that
  as a critical operational outcome.
- **Escalation role:** Instance operator. Independent postcanary
  reviewer is required and is not the issuing operator.
- **Closure criteria:** One explicit invocation. One listing request.
  Halt restored. Controllers stopped. Lease released or release
  uncertainty contained. Session 13 Batch 3C-R independently reviewed
  that evidence. Do not retry.

## 3. Halt release and restoration

- **Purpose:** Release acquisition halt only for a dedicated command or
  preflight process snapshot, then restore it. Provider-contact
  authorization evaluation observes halt and does not clear it.
- **Prerequisites:** An issued authorization exists for command
  preparation, or a consumed authorization exists for preflight. Halt
  release is not authorization and does not enable OSV. Batch 3B
  evaluation must fail closed under default halt when the halt procedure
  is acknowledged (`persistence_required` after other gates, or
  `halt_procedure_not_ready` if acknowledgement is missing).
- **Trigger:** Command or preflight reports `halt_engaged` under default
  or explicit halt.
- **Immediate containment:** Do not start worker or API with halt
  released. Do not change shared production environment files. Do not
  treat halt false as provider-contact authorization.
- **Evidence to collect:** Halt control and source; authorization state;
  no lease mutation; no provider calls.
- **Forbidden actions:** Using halt release as execution permission;
  leaving halt released in production worker or API processes; clearing
  halt from Batch 3B evaluation.
- **Recovery:** Restore halt to default halted. Re-run command
  preparation or preflight only in the dedicated process that explicitly
  released halt. Halt restoration after the Batch 3C listing attempt
  completed as `restored`. Do not leave halt released in production
  worker or API processes.
- **Escalation role:** Instance operator.
- **Closure criteria:** Production processes remain halted. Dedicated
  command preparation either reached `authorized_preflight_required` or
  stopped at `halt_engaged`. Dedicated preflight either passed with halt
  rechecked or stopped at `halt_engaged`. Batch 3B evaluation either
  failed `persistence_required` after observing halt or failed
  `halt_procedure_not_ready`.

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
  failure. Real-provider start remains unavailable until durable
  provider-contact authorization is issued and consumed after Batch 3B-P.
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
  Real-provider execution remains unavailable until durable
  provider-contact authorization is issued and consumed after Batch 3B-P.
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
  Real-provider arming remains unavailable until durable
  provider-contact authorization is issued and consumed after Batch 3B-P.
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
- **Trigger:** `egress_policy_not_ready`, `egress_evidence_missing`,
  `egress_evidence_stale`, or missing operational evidence.
- **Immediate containment:** Do not resolve provider DNS. Do not open
  TLS. Do not send HTTP.
- **Evidence to collect:** Evidence class per control
  (`application_control_implemented_and_tested`,
  `deployment_control_configured`,
  `deployment_control_independently_verified`,
  `provider_connectivity_not_exercised`, or
  `missing_required_evidence`). Generic `ready: true` is insufficient.
  DNS, TLS, and provider call counts remain 0. Hostnames, IP addresses,
  proxy values, and certificate material are omitted.
- **Forbidden actions:** Claiming network-level enforcement that is not
  configured; disabling certificate verification; selecting a proxy;
  probing the provider to mint evidence.
- **Recovery:** Restore missing controls. Re-run preflight and Batch 3B
  evaluation without external probes.
- **Escalation role:** Instance security reviewer.
- **Closure criteria:** Required controls are present. Missing evidence
  still blocks success.

## 9. Provider unavailable

- **Purpose:** Contain a later provider outage. Session 13 Batch 3C
  already executed one listing-only request. Do not retry that request.
  Body retrieval remains unauthorized.
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
  enqueue a retry. Do not retry the Batch 3C listing request.
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
  Real-provider listing remains unavailable until durable provider-contact authorization is issued and consumed after Batch 3B-P.
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
  unavailable until durable provider-contact authorization is issued and consumed after Batch 3B-P.
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
  until durable provider-contact authorization is issued and consumed after Batch 3B-P.
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
  remains unavailable until durable provider-contact authorization is issued and consumed after Batch 3B-P.
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

- **Purpose:** Require postcanary review after the Batch 3C listing
  canary. Review is mandatory even if the listing page was accepted.
- **Prerequisites:** Remaining gate `postcanary_review_required`.
  Body retrieval remains separately unauthorized.
- **Trigger:** Batch 3C terminal canary result
  (`listing_canary_one_page_classified` or a contained failure).
- **Immediate containment:** Do not proceed to activation, matching,
  Findings, pagination, or body retrieval. Do not retry the listing
  request. Do not treat Batch 3A scripted success as additional
  provider-contact permission.
- **Evidence to collect:** Authorization identity; request and run;
  phase; provider request count; HTTP classification; response-byte
  count; observation count; continuation-token-present Boolean; halt
  restored; deadline stop; heartbeat stop; lease release; active-pointer
  unchanged; zero-Finding operations.
- **Forbidden actions:** Treating review as a second execution;
  enabling OSV; copying provider bodies or continuation tokens into
  tickets.
- **Recovery:** Record the review verdict. Issue a new authorization
  only for a new run after accepted review. Do not retry Batch 3C.
- **Escalation role:** Instance canary evidence reviewer, countersigned
  by the instance operator.
- **Closure criteria:** Review recorded. Activation still prohibited.
  Session 13 Batch 3C-R independently reviewed the listing canary.
  Candidate-selection evidence is unavailable. Session 13 Batch 3D-P-R
  independently reviewed protected listing-observation evidence
  requirements. A new listing request is not currently authorized.
  Schema work waits on an encryption-policy checkpoint. Batch 4-P is
  blocked.

## 19. Evidence retention and cleanup

- **Purpose:** Keep immutable canary evidence and bound cleanup so
  fencing and single-use authority cannot reset. Session 13 Batch 3D-P-R
  additionally requires durable protected listing-observation evidence
  for a future separately authorized listing (`osv_protected_listing_observation_evidence_retention_v1`).
- **Prerequisites:** Authorization DELETE forbidden. Lease projection
  DELETE forbidden. Frozen migrations remain unchanged. Prisma is
  unchanged; no protected observation rows exist yet. Encryption-policy
  checkpoint required before schema.
- **Trigger:** Operator wants to remove test rows or expired unused
  authorizations after review. Future protected-observation cleanup
  additionally requires independent review recorded, dependent
  authorizations terminal, no legal hold, and a distinct cleanup grant.
- **Immediate containment:** Do not edit frozen migrations. Do not
  reset fencing by recreating the lease row. Do not purge Findings
  because none should exist from this preflight. Do not retain raw
  listing responses or continuation tokens. Do not print protected
  object keys.
- **Evidence to collect:** Authorization state; lease presence;
  object-storage locators omitted from notes; retention identifiers;
  public evidence-set digest and counts only.
- **Forbidden actions:** Destructive database reset; migration edits;
  deleting lease rows; deleting consumed authorization rows to mint a
  second use; copying provider responses; treating candidate-selection
  eligibility as body authority; reusing Batch 3C authorization.
- **Recovery:** Leave production evidence durable. Remove only
  test-owned disposable database rows in FK-safe order after a test
  rehearsal. Future protected-identity erasure is a controlled redaction
  of one encrypted-envelope column, then an append-only purge row without
  the raw object key or a bare key digest. No
  TTL worker and no automatic cleanup loop.
- **Escalation role:** Instance operator.
- **Closure criteria:** Production evidence retained. Test rehearsal
  cleanup, if any, does not contact a provider and does not alter the
  active catalog pointer. Batch 3D-P-R did not persist real observations.
