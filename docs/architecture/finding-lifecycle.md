# Finding lifecycle

A **finding** is the tenant-owned link between an asset's observed component identity (from SBOMs) and a **vulnerability record**, plus later enrichment pointers and scores. Canonical fields: [domain model](domain-model.md#finding).

**Resolved** is a **calculated conclusion** that requires stored evidence. It is not implied by **RemediationTask** completion, a compensating control description, or archive of an asset by itself.

## Identity

Stable identity:

`organizationId` + `assetId` + component identity (PURL if parseable, else ecosystem + name) + vulnerability identity (OSV id, CVE when known).

Version is **not** part of finding identity. A newer SBOM that lists another version of the same package+vuln pair updates **FindingObservation** (`present` with a new occurrence) rather than always creating a second finding. If product later needs version-scoped findings, that requires an ADR.

## Evaluated states (recommended list)

Each candidate must have distinct operational meaning. Assignment workflow lives on **RemediationTask**, not on the finding.

| Candidate | v0.1 finding state? | Rationale |
| --- | --- | --- |
| OPEN | yes → `open` | Default while observed and not in an exclusive state |
| TRIAGED | no | No distinct data; notes can live on the task |
| ASSIGNED | no | **RemediationTask** `assigned` |
| IN_PROGRESS | no | **RemediationTask** `in_progress` |
| FIX_SUBMITTED | no | Recorded as task activity; verification is separate |
| VERIFICATION_PENDING | yes → `verification_pending` | Task completed (or verify requested); waiting for conclusive SBOM evidence |
| RESOLVED | yes → `resolved` | Evidence-backed absence / out-of-range / allowed decommission path |
| MITIGATED | yes → `mitigated` | Compensating control recorded; component still present; not accepted risk and not resolved |
| RISK_ACCEPTED | yes → `risk_accepted` | Time-boxed acceptance with approver |
| FALSE_POSITIVE | yes → `false_positive` | Authorized decision that the *match* is wrong |
| DEFERRED | no | Use **RiskAcceptance** with expiry |
| REOPENED | no | Transition into `open`, not a state |
| (prior `in_remediation`) | removed | Duplicated the task |

Additional v0.1 state: `inconclusive` — latest compare cannot decide; must not display as fixed.

## States

`open`, `verification_pending`, `risk_accepted`, `mitigated`, `false_positive`, `resolved`, `inconclusive`.

```mermaid
stateDiagram-v2
  [*] --> open
  open --> verification_pending: task completed or verify requested
  verification_pending --> open: still present on conclusive SBOM
  open --> risk_accepted: acceptance approved
  verification_pending --> risk_accepted: acceptance approved
  mitigated --> risk_accepted: acceptance approved
  risk_accepted --> open: expired or revoked and still present
  open --> mitigated: compensating control recorded
  open --> false_positive: authorized FP
  open --> resolved: evidence-backed
  verification_pending --> resolved: evidence-backed
  risk_accepted --> resolved: evidence-backed
  mitigated --> resolved: evidence-backed
  inconclusive --> resolved: later evidence-backed
  open --> inconclusive: rescan inconclusive
  verification_pending --> inconclusive: rescan inconclusive
  risk_accepted --> inconclusive: rescan inconclusive
  mitigated --> inconclusive: rescan inconclusive
  resolved --> open: later present
  resolved --> inconclusive: later inconclusive
  inconclusive --> open: later present
  false_positive --> open: FP revoked
```

If the diagram is not rendered, the transition table is authoritative.

## Who may transition

| Transition | Actor | Required fields |
| --- | --- | --- |
| Create `open` | system (correlation) | Observation `present`, vulnerability id, match method |
| → `verification_pending` | system when task → `completed`, or `member`+ request verify | Task id or reason |
| → `risk_accepted` | system when **RiskAcceptance** becomes `active` | See [remediation-lifecycle.md](remediation-lifecycle.md) (requester, approver, expiry) |
| → `mitigated` | `admin` or `owner` | Compensating-control **Evidence** id, reason |
| → `false_positive` | `admin` or `owner` | Reason; optional evidence; does **not** delete intel |
| → `resolved` | system only | Stored observation or verification record meeting evidence rules below |
| → `inconclusive` | system | Observation `inconclusive` with method |
| → `open` (reopen) | system on `present` after `resolved`/`inconclusive`; or `admin`/`owner` revoking FP/mitigated/acceptance | |

Due dates are **calculated recommendations** on **RiskCalculation**, not a finding state. Overdue does not auto-transition.

## Allowed transitions (summary)

| From | To | Trigger | Kind |
| --- | --- | --- | --- |
| (create) | `open` | Correlation created the finding from a `present` observation | Calculated from intel + SBOM |
| `open` | `verification_pending` | Remediation task `completed` or verify requested | Workflow |
| `verification_pending` | `open` | Latest conclusive observation is `present` | Calculated |
| `open` / `verification_pending` / `mitigated` | `risk_accepted` | Acceptance `active` | Workflow |
| `risk_accepted` | `open` | Acceptance `expired`/`revoked`/`superseded` without replacement, and still `present` | Workflow |
| `open` | `mitigated` | Compensating control recorded | Workflow |
| `open` | `false_positive` | Authorized FP | Workflow |
| `false_positive` | `open` | FP revoked | Workflow |
| `mitigated` | `open` | Control withdrawn | Workflow |
| `open`, `verification_pending`, `risk_accepted`, `mitigated`, `inconclusive` | `resolved` | Evidence-backed resolution (below) | Calculated / evidenced |
| `open`, `verification_pending`, `risk_accepted`, `mitigated` | `inconclusive` | Latest completed ingestion yields `inconclusive` | Calculated |
| `resolved` | `open` | Later completed ingestion yields `present` | Calculated |
| `resolved` | `inconclusive` | Later completed ingestion yields `inconclusive` | Calculated |
| `inconclusive` | `open` | Later completed ingestion yields `present` | Calculated |

`false_positive` stays until revoked even if later SBOMs still list the component; new **FindingObservation** rows are still written. UI shows still-observed + FP.

When `risk_accepted` and evidence supports `resolved`, the finding becomes `resolved`. The acceptance row remains historical.

### Disallowed

- Task `completed` → `resolved`
- Manual `resolved` without stored evidence
- Transitions from quarantined/failed ingestions
- Cross-organization merge
- Permanent risk acceptance (no `expiresAt`)

## FindingObservation

Each completed SBOM ingestion for the asset produces an observation per existing finding (and creates findings for new present matches).

| `result` | Meaning |
| --- | --- |
| `present` | Component identity observed with a recorded method |
| `absent` | Identity not observed; method confirms the compare was possible **and** coverage was adequate |
| `inconclusive` | Missing ecosystem/PURL, parse gaps, matcher cannot decide, or **coverage inadequate** |

`method` examples: `exact_purl`, `ecosystem_name_version`, `version_out_of_affected_range`, `missing_component_identity`, `incomplete_sbom_coverage`.

Inconclusive must not be displayed as "fixed."

## Remediation verification (evidence to `resolved`)

| Situation | May set `resolved`? | Evidence | Confidence |
| --- | --- | --- | --- |
| Component no longer present | yes | Observation `absent` + method showing compare was possible | `high` if PURL/ecosystem+name stable across SBOMs |
| Component upgraded outside affected range | yes | Observation `present` at a version the **VulnerabilitySourceRecord** marks unaffected/fixed, method `version_out_of_affected_range` | `high` when range parse succeeded; else `inconclusive` |
| Advisory withdrawn | no by itself | New calculation with `advisory_withdrawn`; finding may remain `open` | Withdrawal is intel, not asset evidence |
| VEX not-affected | **future** | Not MVP ([non-goals](../product/non-goals.md) extra formats) | — |
| Compensating mitigation | no | State `mitigated` + **Evidence**; component still present | Claim only |
| False-positive determination | no | State `false_positive`; intel remains | Match challenged, not remediated |
| Asset decommissioning | only with explicit verify | Asset `archived` **plus** `admin`/`owner` verification reason `asset_decommissioned` stored as **Evidence**; not implied by archive alone | `medium` |
| Newer SBOM omits component, coverage poor | no | Observation `inconclusive` / `incomplete_sbom_coverage` | Absence is **not** proof |

**Incomplete inventory:** if the new SBOM has dramatically fewer components than the previous completed graph (threshold is a **configurable proposal**, initial recommendation: drop of ≥50% component count), treat missing former components as `inconclusive`, not `absent`.

Withdrawn vulnerabilities: do not auto-`resolved`. Changed severity or KEV: new **RiskCalculation** only. Unsupported/archived assets: no new uploads; existing findings remain until verification rules apply.

## Intelligence changes vs state

| Change | Finding state | Calculation |
| --- | --- | --- |
| New/removed KEV | unchanged except via policy factors | new **RiskCalculation** `intel_refresh` |
| Severity change on source record | unchanged | new calculation |
| Withdrawn advisory | unchanged | new calculation with factor |

## Priority history

`currentRiskCalculationId` points at the latest calculation. Previous **RiskCalculation** rows remain. Changing finding state does not rewrite scores.

## Authorization and jobs

Finding reads and mutations require organization scope. Recalculation jobs reload the finding and confirm `organizationId` before insert.

## Related documents

- [Remediation lifecycle](remediation-lifecycle.md)
- [Risk policy](risk-policy.md)
- [SBOM ingestion](sbom-ingestion.md)
