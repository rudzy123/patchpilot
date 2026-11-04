# Remediation lifecycle

**Status.** **RemediationTask** and **RiskAcceptance** remain unrouted. [ADR 0048](../adr/0048-controlled-remediation-queue.md) (Proposed) is a read-only Finding queue, not a **RemediationTask** list. [ADR 0049](../adr/0049-append-only-priority-review.md) (Proposed) is an append-only review of one immutable **RiskCalculation**. A review is not **RiskAcceptance**. A `manual_override` calculation and the override-expiry job below are not authorized. `risk_acceptance:*` stays unrouted. The member-request sentence in the risk-acceptance section conflicts with [ADR 0019](../adr/0019-local-password-sessions.md). The stricter ADR 0019 mapping applies: `risk_acceptance:request` is admin and owner only.

This document defines **RemediationTask** and **RiskAcceptance** states. Completing work records **remediation activity**. It does not prove the vulnerable component is gone. **Resolved (on rescan)** lives on the [finding](finding-lifecycle.md).

## RemediationTask

Assigned **remediation work** inside one organization, pointing at one **Finding**.

### States

`open`, `assigned`, `in_progress`, `blocked`, `completed`, `cancelled`.

```mermaid
stateDiagram-v2
  [*] --> open
  open --> assigned: assignee set
  open --> cancelled: cancelled
  assigned --> open: unassigned
  assigned --> in_progress: work started
  assigned --> cancelled: cancelled
  in_progress --> blocked: blocked
  in_progress --> completed: work recorded
  in_progress --> cancelled: cancelled
  blocked --> in_progress: unblocked
  blocked --> cancelled: cancelled
```

### Allowed transitions

| From | To | Actor | Guard |
| --- | --- | --- | --- |
| (create) | `open` | `member`+ | Finding in authorized org; finding not required to be `open` (may already be `risk_accepted`) |
| `open` | `assigned` | `member`+ | Assignee is a non-revoked member of the same organization |
| `open` | `cancelled` | `member`+ | Created in error; no assignee required |
| `assigned` | `open` | `member`+ | Unassign |
| `assigned` | `in_progress` | `member`+ | |
| `assigned` | `cancelled` | `member`+ | |
| `in_progress` | `blocked` | `member`+ | Reason required |
| `in_progress` | `completed` | `member`+ | Activity note required (what was done); not a new SBOM |
| `in_progress` | `cancelled` | `member`+ | |
| `blocked` | `in_progress` | `member`+ | |
| `blocked` | `cancelled` | `member`+ | |

`completed` and `cancelled` are terminal. Further work requires a **new** task.

### Disallowed

- Transition to `completed` implying finding `resolved`
- Assigning a user from another organization
- Updating a terminal task in place except for non-state metadata explicitly allowed later (v0.1: no edits; add activity via audit + optional notes only before terminal)

Each transition emits **AuditEvent** `remediation_task.transition` (or more specific names listed in [audit-model.md](audit-model.md)).

Finding coupling: assignment lives on the **RemediationTask**. Completing a task moves the finding to `verification_pending` **only if the finding is `open`**. If the finding is `risk_accepted`, `mitigated`, or `false_positive`, the task may still complete; finding state does **not** change to `verification_pending`. UI shows both records.

## RiskAcceptance

Explicit, auditable decision to accept residual risk on a **finding** (MVP scope is finding-level, not blanket asset-level). It never marks the **vulnerability** or finding as **resolved** / fixed.

### States

`active`, `expired`, `revoked`, `superseded`.

There is **no** permanent acceptance in v0.1.

### Allowed transitions

| From | To | Trigger |
| --- | --- | --- |
| (create as request) | `active` | `admin` or `owner` **approves**; `expiresAt` required |
| `active` | `expired` | Time passed `expiresAt` (system job, idempotent) |
| `active` | `revoked` | `admin` or `owner` |
| `active` | `superseded` | New acceptance created for the same finding |

A `member` may **request** (requester). Only `admin` or `owner` may **approve** (approver must be a different user when more than one eligible actor exists; solo-owner orgs may approve their own request — record that fact). That member-request sentence conflicts with [ADR 0019](../adr/0019-local-password-sessions.md). The stricter ADR 0019 mapping applies: `risk_acceptance:request` is admin and owner only, and the permission stays unrouted. Amendments do not edit reason in place. A new row is inserted; the previous becomes `superseded`.

### Required fields

| Field | Rule |
| --- | --- |
| Finding, organization | Authorized org; finding not used to "fix" intel |
| Requester user id | Membership in org |
| Approver user id | `admin` or `owner` |
| Reason | Required untrusted text |
| Compensating-control evidence ids | Optional claims |
| `validFrom` / `expiresAt` | Required UTC; `expiresAt` > `validFrom` |
| `reviewAt` | Required UTC; must be `< expiresAt`. Default proposal: 7 days before expiry when duration allows, else `validFrom` (configurable) |
| Supporting **Evidence** | Optional |
| Status | Lifecycle above |

Maximum duration is a **configurable initial recommendation**: 365 days. Operators may lower it. The product must reject missing `expiresAt` or missing `reviewAt`.

### Review and expiry jobs

- **Review job:** `reviewAt <= now` and `state = active` → emit audit `risk_acceptance.review_due` and surface the finding in a review queue. It does **not** auto-`resolved` or extend `expiresAt`.
- **Expiry job:** `expiresAt <= now` and `state = active` → `expired`, audit, finding state per [finding lifecycle](finding-lifecycle.md). Reopen to `open` only if the finding is still `risk_accepted` and the current observation is `present`. Do **not** reopen `resolved`. Idempotent on acceptance id. A scheduled **override-expiry** job (separate) was sketched to insert a non-override **RiskCalculation** when `manual_override` expires. That job is not authorized. [ADR 0049](../adr/0049-append-only-priority-review.md) does not insert a **RiskCalculation** when a review expires, and it does not delete history.

## Compensating controls

Stored as **Evidence** `compensating_control` plus audit. Finding may move to `mitigated` (still observed). Default policy does not auto-change **priority** unless a published factor catalog includes a named, schema-checked control. Reviewers see the claim and the still-observed component separately from `resolved`.

## Re-scan after remediation

Operators upload a newer SBOM. Compare rules in [finding lifecycle](finding-lifecycle.md) decide `present` / `absent` / `inconclusive` and whether coverage is adequate. Task `completed` plus observation `absent` (or out-of-range) is the evidence-preserving story. Absence from an incomplete SBOM is not proof.

## Exports

Exports include task history, acceptance records, policy version, and observation results, labeled as PatchPilot outputs.

## Related documents

- [Finding lifecycle](finding-lifecycle.md)
- [Audit model](audit-model.md)
- [Risk policy](risk-policy.md)
