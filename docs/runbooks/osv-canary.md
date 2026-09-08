# OSV first real-provider canary runbook outlines

These outlines support Accepted [ADR 0029](../adr/0029-first-real-provider-osv-canary-authorization-and-safety.md).
They are **not** live procedures. Do not contact `storage.googleapis.com` or
`osv.dev` from this document. Do not enable OSV. Do not release production
acquisition halt as a canary trigger. Do not include secrets or destructive
commands.

Escalation owner is the instance operator until [OD-10](../architecture/open-decisions.md)
is closed. Legal questions escalate to the instance legal and provenance
reviewer role. Security incidents escalate to the instance security reviewer
role. No outline authorizes evidence deletion, catalog activation, matching, or
Finding mutation.

## 1. Canary preflight

- **Trigger:** Operator intends to request listing-only or bounded-body
  authorization.
- **Containment:** Do not start the CLI. Confirm production halt remains true
  and `INTELLIGENCE_OSV_ENABLED` remains false.
- **Evidence:** Durable authorization absent or unconsumed; no active OSV
  lease; active-pointer snapshot; zero-Finding baseline; parser readiness;
  database and object-storage health; egress control evidence; telemetry sink
  proof; legal gate current for the requested phase. Session 13 Batch 2A
  defines identity and authorization contracts only; they are not a live
  authorization store and do not make this outline operational.
- **Forbidden:** Releasing worker halt; registering a scheduler; using a tenant
  user; contacting a provider.
- **Recovery:** Close gaps, then re-run preflight.
- **Escalation:** Instance operator.
- **Closure:** Preflight checklist recorded; no provider request issued.

## 2. Canary execution

- **Trigger:** Independent architecture review accepted; legal gate current;
  canary-scoped operator attestation configured; heartbeat and deadline
  implemented; runbooks rehearsed. ADR 0029 acceptance alone is not this
  trigger.
- **Containment:** One-shot CLI only. One phase. One prefix. Stop on first
  retryable provider failure.
- **Evidence:** Request ID, run ID, authorization identity, policy versions,
  counts, buckets, stage outcomes. No tokens, bodies, URLs, or headers.
- **Forbidden:** Automatic retry; activation; second phase without review;
  shared env-file halt edits.
- **Recovery:** Terminalize; consume authorization; verify production remains
  halted.
- **Escalation:** Instance operator.
- **Closure:** Bounded result recorded; lease released or recovery inspected.

## 3. Emergency halt

- **Trigger:** Unexpected side effect, activation attempt, confidentiality
  violation, or operator judgment.
- **Containment:** Cancel in-flight work. Do not start successor stages.
  Production halt remains true. Consume canary authorization if present.
- **Evidence:** First blocking checkpoint, run state, lease observation without
  digest, pointer snapshot, zero-Finding proof.
- **Forbidden:** Retry; deleting evidence; weakening TLS or ceilings.
- **Recovery:** Guarded release if current owner; preserve immutable evidence.
- **Escalation:** Instance security reviewer.
- **Closure:** No active work; halt restored/consumed; review opened.

## 3a. Authorization expired or consumed

- **Trigger:** Unused authorization past 3600 seconds, or consume-at-start
  already recorded.
- **Containment:** Do not start work. Do not replay the same authorization.
- **Evidence:** Authorization identity, issued-at, expires-at, consumed-at.
- **Forbidden:** Extending TTL in place; reusing a consumed record.
- **Recovery:** Issue a new authorization after review if still appropriate.
- **Escalation:** Instance operator.
- **Closure:** No provider request from the expired or consumed record.

## 4. Provider unavailable

- **Trigger:** DNS, timeout, or retryable 5xx on the compiled GCS surface.
- **Containment:** Stop. Record retry disposition. Do not retry during the
  canary.
- **Evidence:** Bounded failure code, attempt ordinal 1, request count.
- **Forbidden:** Raising ceilings; disabling pinning; following redirects.
- **Recovery:** Human review; new authorization if later allowed.
- **Escalation:** Instance operator.
- **Closure:** Run failed or incomplete; no activation.

## 5. HTTP 429 or provider-rate concern

- **Trigger:** HTTP 429 or suspected rate limiting.
- **Containment:** Stop immediately. No Retry-After sleep. No automatic retry.
- **Evidence:** `provider_rate_limited` or mapped transport failure; request
  count.
- **Forbidden:** Parallel requests; inventing extra delays as a bypass to
  continue the same authorization.
- **Recovery:** New explicit authorization after review.
- **Escalation:** Instance operator.
- **Closure:** One-shot consumed; cooldown is operator-defined.

## 6. Listing token cycle

- **Trigger:** `listing_token_cycle`.
- **Containment:** Terminate the prefix. No body retrieval.
- **Evidence:** Page ordinal, digest-only cycle event. Never the raw token.
- **Forbidden:** Persisting or injecting a token.
- **Recovery:** New run from page one under a new authorization.
- **Escalation:** Instance operator.
- **Closure:** Cycle recorded; candidate not created from that run.

## 7. Inventory nonconvergence

- **Trigger:** Pass A and pass B disagree, or a pass is incomplete.
- **Containment:** No body retrieval. Do not force completeness.
- **Evidence:** Pass counts, convergence outcome.
- **Forbidden:** Treating canary completeness as production completeness.
- **Recovery:** New explicit attempt after review.
- **Escalation:** Instance operator.
- **Closure:** Evidence-only or failed; not listing-only success.

## 8. Listing ceiling reached

- **Trigger:** Page, observation, or byte ceiling.
- **Containment:** Stop incomplete. No silent truncation. No body retrieval.
- **Evidence:** Exact counts and ceiling dimension.
- **Forbidden:** Raising limits without a new policy identifier.
- **Recovery:** Record evidence-only outcome.
- **Escalation:** Instance operator.
- **Closure:** Incomplete inventory retained as evidence.

## 9. Deadline exceeded

- **Trigger:** 1800-second monotonic deadline.
- **Containment:** Cancel in-flight transport and parser work. Block successor
  stages.
- **Evidence:** Deadline outcome, stage at stop, lease observation.
- **Forbidden:** Retry; extending the same authorization.
- **Recovery:** Guarded release if current owner.
- **Escalation:** Instance operator.
- **Closure:** `deadline_exceeded`; evidence retained.

## 10. Lease heartbeat failure

- **Trigger:** Heartbeat CAS failure or missed keep-alive while work continues.
- **Containment:** Cancel protected work. Do not overlap heartbeat calls.
- **Evidence:** Heartbeat outcome without holder token.
- **Forbidden:** Continuing after ownership uncertainty.
- **Recovery:** Guarded release if still current; otherwise inspect fencing.
- **Escalation:** Instance operator.
- **Closure:** `heartbeat_failed`; no stale-owner continuation.

## 11. Ownership lost

- **Trigger:** Fencing mismatch, stale takeover, or expired owner.
- **Containment:** Discard late listing or retrieval success. Do not release
  another holder's lease. Do not fail another holder's run.
- **Evidence:** Ownership-lost code, fencing observation without digest.
- **Forbidden:** Heartbeat or release as the prior owner.
- **Recovery:** Inspect current lease; new authorization only after review.
- **Escalation:** Instance operator.
- **Closure:** Prior run not rewritten as the new owner's failure.

## 12. Object too large

- **Trigger:** Listing page or body exceeds 1,048,576 received bytes.
- **Containment:** Fail closed. Do not retry that unit as success.
- **Evidence:** Size bucket, not raw payload.
- **Forbidden:** Raising 1 MiB without a new policy.
- **Recovery:** Item or run incomplete; quarantine if required.
- **Escalation:** Instance operator.
- **Closure:** No truncated success.

## 13. Generation mismatch

- **Trigger:** Response generation ≠ requested `ifGenerationMatch`.
- **Containment:** Fail closed. No attach.
- **Evidence:** Bounded generation-mismatch code.
- **Forbidden:** Fetching by `mediaLink` or ignoring generation.
- **Recovery:** New authorization after review.
- **Escalation:** Instance operator.
- **Closure:** Snapshot not attached.

## 14. Integrity mismatch

- **Trigger:** SHA-256 or declared-size reconciliation failure.
- **Containment:** Fail closed. No attach.
- **Evidence:** Integrity failure code, expected vs received size bucket.
- **Forbidden:** Trusting ETag or md5Hash as PatchPilot identity.
- **Recovery:** New authorization after review.
- **Escalation:** Instance operator.
- **Closure:** Bytes not retained as attached evidence.

## 15. Storage failure

- **Trigger:** Object-storage timeout, conflict, or false attached state risk.
- **Containment:** Fail closed. Do not overwrite. Do not mint attached metadata
  without verified bytes.
- **Evidence:** Storage failure code without locator leakage.
- **Forbidden:** Broad bucket purge.
- **Recovery:** Known temp cleanup only when eligible.
- **Escalation:** Instance operator.
- **Closure:** Attached state remains truthful.

## 16. Parser timeout or crash

- **Trigger:** Parser timeout, worker crash, or malformed worker output.
- **Containment:** Occupancy remains 1. Pending remains 0. No retry during
  canary.
- **Evidence:** Parser attempt row, bounded failure kind.
- **Forbidden:** Raising pending capacity; feeding raw bytes to logs.
- **Recovery:** New authorization after review.
- **Escalation:** Instance operator.
- **Closure:** Attempt retained; no activation.

## 17. Source permission failure

- **Trigger:** Registry, legal gate, or per-advisory license failure.
- **Containment:** No retention. No external exposure. No matching.
- **Evidence:** Policy-violation or quarantine code; registry version.
- **Forbidden:** Inferring body permission from listing permission.
- **Recovery:** Legal revalidation.
- **Escalation:** Legal and provenance reviewer.
- **Closure:** `legal_gate_blocked` or quarantined item; canary not repeated
  until resolved.

## 18. Quarantine accumulation

- **Trigger:** Unexpected quarantine count during body canary.
- **Containment:** Stop if policy requires. Do not activate.
- **Evidence:** Quarantine counts and closed reasons.
- **Forbidden:** Deleting quarantine rows.
- **Recovery:** Review source and parser evidence.
- **Escalation:** Legal + operator.
- **Closure:** Candidate remains nonactive.

## 19. Reconciliation failure

- **Trigger:** Completeness equations fail.
- **Containment:** No activation. No matching.
- **Evidence:** Reconciliation counts.
- **Forbidden:** Waiving integer equations.
- **Recovery:** New authorization after review.
- **Escalation:** Instance operator.
- **Closure:** Candidate not ready for activation.

## 20. Lease release uncertainty

- **Trigger:** `release_uncertain` or release CAS miss.
- **Containment:** Do not retry release in a loop. Do not delete the lease row.
- **Evidence:** Release outcome, fencing observation.
- **Forbidden:** SQL that resets fencing.
- **Recovery:** Inspect current projection; escalate if another holder exists.
- **Escalation:** Instance operator.
- **Closure:** Uncertainty recorded; no fencing reset.

## 21. Unexpected activation attempt

- **Trigger:** Any call toward `activateReadyGeneration` or pointer mutation.
- **Containment:** Emergency halt. Do not continue the canary.
- **Evidence:** Call count, pointer snapshot before/after, activation history.
- **Forbidden:** Completing activation to "see what happens."
- **Recovery:** Prove pointer unchanged; security review.
- **Escalation:** Instance security reviewer.
- **Closure:** Canary must not be repeated until root cause is closed.

## 22. Unexpected tenant or Finding effect

- **Trigger:** Any organization, asset, component, Finding, Evidence,
  RiskCalculation, or `finding.recalculate` side effect.
- **Containment:** Emergency halt. Preserve forensics.
- **Evidence:** Zero-Finding proof failure details without tenant payload
  echo.
- **Forbidden:** Using a tenant user to "clean up."
- **Recovery:** Tenant-isolation incident process.
- **Escalation:** Instance security reviewer.
- **Closure:** Must not repeat until root cause is closed.

## 23. Postcanary review

- **Trigger:** Terminal canary of either phase.
- **Containment:** Do not start the next phase automatically.
- **Evidence:** ADR 0029 review package fields only.
- **Forbidden:** Bodies, tokens, URLs, headers, locators, tenant data.
- **Recovery:** Return one closed review verdict.
- **Escalation:** Independent reviewer, not the executing operator alone.
- **Closure:** Verdict recorded; authorization consumed.

## 24. Evidence retention and cleanup

- **Trigger:** Canary complete or failed.
- **Containment:** No broad deletion.
- **Evidence:** Classification of each artifact class.
- **Forbidden:** Deleting attached evidence because the canary ended;
  interpreting provider absence as deletion; inventing a retention duration.
- **Recovery:** Known temporary staged objects only, exact identity.
- **Escalation:** Legal reviewer if license questions arise.
- **Closure:** Retention disposition recorded; cleanup executor still not
  authorized.
