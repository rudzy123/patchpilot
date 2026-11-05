# ADR 0051: Remediation queue export

- Status: Accepted
- Date: 2026-11-05
- Deciders: PatchPilot maintainers. Acceptance confirms the export operation below and that [ADR 0048](0048-controlled-remediation-queue.md) remains Accepted for every queue semantic except the export prohibition.
- Supersedes: none
- Superseded by: none

Accepted on 2026-11-05. This ADR authorizes one deliberate audited export of the
remediation queue. It does not implement that export. No route, serializer, web
control, or audit writer is added here.

This decision partially supersedes only the no-export sentences in the Decision
opening and in section 7 of ADR 0048. ADR 0048 stays Accepted. Its Superseded
by line stays none. Permission, pagination, section partition, comparator,
unaudited reads, and the rule that a review does not change order remain in
force.

[ADR 0038](0038-controlled-finding-web-workflow.md) section 24 records that the
ADR 0048 list lift does not authorize export, and section 25 still defers
exports for that workflow. This ADR is the later authority for the one
remediation-queue export below. It does not lift the rest of ADR 0038. Task,
acceptance, and observation exports stay unauthorized.

## Context

[ADR 0014](0014-append-only-audit.md) requires an append-only audit event for
exports. The catalog action is `export.created`. Tenant replay uniqueness is
the existing unique index `audit_event_tenant_replay_idx` on
`(organization_id, action, subject_id, correlation_id)` where `organization_id`
is not null. `correlation_id` is already required. `subject_type` is a string.
`AuditRetentionCategory` has one value, `security`, and that value is the
column default.

[ADR 0019](0019-local-password-sessions.md) treats an authenticated request that
changes state as requiring the session cookie, an exact Origin, the
synchronizer CSRF header, and `application/json`. Authentication and session
responses use `Cache-Control: no-store`.

[ADR 0045](0045-deterministic-p1-p4-priority-policy.md) defines
`compareForRemediationQueue`. A missing calculation is not a completed P4.
[ADR 0047](0047-controlled-priority-activation.md) resolves the published
admitted builtin. V-0001 admission does not publish a row. A repository merge
does not publish a row. API startup does not publish the builtin.
[ADR 0048](0048-controlled-remediation-queue.md) is the only Finding list:
`GET /remediation-queue` and `/remediation-queue`. The read is unaudited and
paginated. `REMEDIATION_QUEUE_MAX_LIMIT` is 50. The classified SQL order lives
in `packages/database/src/remediation-queue-persistence.ts`. The request path
does not call `compareForRemediationQueue`.
[ADR 0049](0049-append-only-priority-review.md) puts `humanReview` on a row.
The queue marker has `status`, and when present `reviewId`, `correctedBand`,
`expiresAt`, and `priorReviewExists`. It has no reason text. The marker does
not change order.

The Evidence check `evidence_one_target_chk` allows `export_snapshot` only when
`asset_id` is set and `finding_id` and `sbom_id` are null. That row cannot
represent an organization queue.

## Decision

PatchPilot adopts one organization-scoped remediation-queue export. Session 8B
implements it. This ADR adds no files beyond this decision and the
documentation it names.

### 1. Route

`POST /remediation-queue/export` is a deliberate audited operation.
`GET /remediation-queue` stays an unaudited paginated read. There is no second
Finding list and no second comparator.

Session 8B reuses the existing classified SQL order in
`packages/database/src/remediation-queue-persistence.ts`. The request path does
not call `compareForRemediationQueue`. A later contract test must show that the
SQL order matches that comparator on the same fixtures.

### 2. Permission and tenant

The permission pair remains `remediation_queue:read` and `priority:inspect`.
Owner and admin only. Member and viewer are denied. `finding:read` does not
grant the export. `finding:inspect` does not grant it by itself.

The organization id comes only from the trusted actor. A client-supplied
organization id is rejected, whether it arrives in a query string, a JSON
field, or an authority header. Authorization denial happens before the
transaction and writes no audit row.

### 3. Request shape

Because the request writes an audit row, it is a state-changing request under
ADR 0019. It requires the session cookie, an exact Origin, the synchronizer
CSRF header `x-csrf-token`, `Content-Type: application/json`, and
`Cache-Control: no-store` on the response. There is no query string. The body
is exactly `{ "format": "json" }` or `{ "format": "csv" }`. Anything else is
rejected and writes no audit row.

### 4. Transaction

One PostgreSQL `REPEATABLE READ` transaction resolves the published admitted
builtin, using the same reference as ADR 0048 and ADR 0047, classifies every
Finding in the organization with the existing section rules, serializes the
snapshot in memory, and inserts one `export.created` row. There is no HTTP,
object storage, Outbox, queue, or worker I/O inside the transaction. Response
bytes are sent only after commit.

`asOf` is the database read time the queue already uses: `clock_timestamp()`
truncated to milliseconds in UTC, rendered with millisecond precision.

### 5. Unpublished builtin

If no admitted published builtin exists, the route returns 503
`priority_policy_unavailable` with no rows and no audit row. V-0001 admission
does not publish a row. A repository merge does not publish a row. API startup
does not publish the builtin.

### 6. Row cap

The row cap is exactly 150. `REMEDIATION_QUEUE_MAX_LIMIT` is 50, and the
snapshot must include all three sections, so the cap is 3 × 50 = 150. If the
organization's Finding count is greater than 150, the operation fails closed.
There is no truncation, no partial file, and no audit row. The SBOM component
default of 10,000 and the intelligence staging default of 500 rows per
transaction are not this bound. Raising the cap requires a later ADR.

A count at or below 150 that fails the malformed-row rule in section 8 also
fails closed. The export does not drop malformed rows to get under the cap.

### 7. Sections and rows

The snapshot includes `ranked`, `incomparable`, and `not_calculated`, in the
existing ADR 0048 orders. A Finding with no calculation is only in
`not_calculated` and is never labeled P4. `incomparable` is not merged into
`ranked`. `humanReview` stays a separate field from calculated priority and
`priorityBand` and never reorders the row. `not_calculated` rows omit band,
priority, policy, and due fields.

The fixed incomparable comparison message remains `recalculation required for
comparison`.

### 8. Malformed stored rows

Malformed stored rows fail closed the same way the queue read does. A malformed
count greater than 0, or counts that do not partition the organization, returns
the same unavailable outcome as the queue read, with no rows and no audit row.

### 9. JSON envelope

The JSON `schemaVersion` is `remediation_queue_export_v1`. It is not
`remediation_queue_v1`. The envelope carries `format` (`json`), `asOf`, the
reference policy identity (`policyKey`, `policyVersion`,
`policyDefinitionSha256`, `engineVersion`), counts for the three sections,
`rowCount`, `cap` 150, and `sections.ranked`, `sections.incomparable`, and
`sections.not_calculated`.

Object keys are emitted in that order. Reference keys are `policyKey`,
`policyVersion`, `policyDefinitionSha256`, `engineVersion`. Count keys are
`ranked`, `incomparable`, `not_calculated`. Section keys follow that same
order. The body is UTF-8, has no byte-order mark, and has no insignificant
whitespace. `rowCount` equals the three counts added together and equals the
organization Finding count.

Row objects match the existing queue row contracts, including key order.
Every row has `findingId`, `assetId`, `assetName`, `componentName`,
`componentVersion`, `vulnerabilityPublicId`, and `humanReview`. Calculated
rows then have `priorityBand`, `priority`, `policy`, `calculatedAt`, and
`inputsChanged`. Incomparable rows then have the fixed comparison message.
A `not_calculated` row stops at the identity fields. Its `humanReview` marker
is `status` `none` and `priorReviewExists` false. Any other marker on that
row is malformed and fails closed with the queue read. `priority` is the
numeric priority the queue already returns. The JSON row does not gain an
`engineVersion` field. The envelope reference carries the published engine
version. The export does not add assignment, due date, Finding state, or
RemediationTask fields.

`humanReview` uses the queue marker. On a calculated row, `status` is `none`,
`none_for_current_calculation`, `accepted`, `withdrawn`, `corrected`, or
`expired`. `reviewId` is present for `accepted`, `withdrawn`, `corrected`, and
`expired`. `correctedBand` and `expiresAt` are present for `corrected` and
`expired`. `priorReviewExists` is present on every marker. The marker has no
reason text.

`inputsChanged` is `{ "status": "none_detected" | "detected", "signals": [...] }`.
Signals use the existing order: `policy_superseded`, `engine_version_changed`,
`kev_generation_changed`, `observed_after_calculation`,
`asset_updated_after_calculation`.

### 10. CSV

CSV uses one header, in this order:

| Column | Contents |
| --- | --- |
| `section` | `ranked`, `incomparable`, or `not_calculated` |
| `findingId` | Finding id |
| `assetId` | Asset id |
| `assetName` | Asset display name |
| `componentName` | Component name |
| `componentVersion` | Component version |
| `vulnerabilityPublicId` | Vulnerability public identifier |
| `humanReviewStatus` | Marker `status` |
| `humanReviewPriorReviewExists` | `true` or `false` |
| `humanReviewId` | `reviewId`, or an empty cell |
| `humanReviewCorrectedBand` | `correctedBand`, or an empty cell |
| `humanReviewExpiresAt` | `expiresAt`, or an empty cell |
| `priorityBand` | Calculated band, or an empty cell |
| `priority` | Numeric priority the queue already returns, or an empty cell |
| `riskPolicyId` | Row risk policy id, or an empty cell |
| `policyKey` | Row policy key, or an empty cell |
| `policyVersion` | Row policy version, or an empty cell |
| `policyDefinitionSha256` | Row definition SHA-256, or an empty cell |
| `calculatedAt` | Calculation time, or an empty cell |
| `inputsChangedStatus` | `none_detected` or `detected`, or an empty cell |
| `inputsChangedSignals` | Signals joined in the existing order, or an empty cell |
| `comparisonMessage` | The fixed incomparable message, or an empty cell |

Rows are all `ranked` rows in ranked order, then all `incomparable` rows in
incomparable order, then all `not_calculated` rows in not-calculated order.
Omitted calculated fields are empty cells, never P4. `inputsChangedSignals` is
a comma-joined list with no spaces, in the existing signal order, and is empty
when none. `humanReview` columns follow the marker field order: `status`,
`priorReviewExists`, then `reviewId`, `correctedBand`, and `expiresAt` when
the marker has them. Policy columns follow the queue policy object:
`riskPolicyId`, `policyKey`, `policyVersion`, `policyDefinitionSha256`.
The CSV does not add `engineVersion`. That value is not a queue row field.
For a ranked or incomparable row, the policy columns are that row's stored
policy. They may differ from the envelope reference when the section is
`incomparable`. A `not_calculated` row has `humanReviewStatus` `none` and
`humanReviewPriorReviewExists` `false`, and its calculated cells are empty.

The body is UTF-8 with no byte-order mark and with LF line endings. A cell that
contains a comma, a double quote, LF, or CR is quoted, and an internal double
quote is doubled. Empty cells are empty.

Every text cell whose first character is `=`, `+`, `-`, `@`, tab, or carriage
return is prefixed with a single apostrophe before quoting. That apostrophe is
export neutralization. It is not part of the stored value.

### 11. Audit

The transaction inserts one append-only audit event:

- action `export.created`
- actor type `user`
- actor user id and actor membership id from the trusted session
- organization id from the trusted actor
- `subject_type` `organization`
- `subject_id` equal to that organization id
- `correlation_id` required, using the request correlation id the API already assigns
- retention category `security`, the existing default and the only enum value
- row `schema_version` 1

The payload `schemaVersion` is 1. It contains `purpose`
`remediation_queue_export`, `format`, `rowCount`, the three counts, the
reference policy identity, `asOf`, `cap` 150, `byteLength`, and `sha256`.
`byteLength` and `sha256` describe the exact response body bytes, not the HTTP
headers. The payload omits names, versions, vulnerability ids, row text,
cursors, tokens, and the canonical redaction list. The canonical redaction list
includes authorization headers, cookies, API tokens, GitHub tokens, raw SBOMs,
private source code, plaintext credentials, and complete vulnerability-feed
payloads.

No more specific retention category exists. This decision does not add an enum
value.

### 12. Failure model

Any failure before commit rolls back and leaves no `export.created` row and no
export body. That includes validation failure, authorization denial (denied
before the transaction), 503, cap overflow, malformed rows, serialization
failure, and audit insert failure. A failure response contains no Finding rows
and no export bytes.

A unique conflict on `(organization_id, action, subject_id, correlation_id)`
rolls back the second attempt, writes no second audit row, and does not resend
bytes. Bytes are not stored. The conflict is not a replay of a saved file.

A client disconnect after a successful commit can leave an audit row without a
received file. That residual is explicit. The audit row does not prove client
receipt. A later request with a new correlation id is a new export. It is not a
retransmission of the earlier bytes.

### 13. What is not stored

The export does not write Evidence kind `export_snapshot`. That check requires
an asset id and cannot represent an organization queue. The export does not
write an IdempotencyRecord response body. It does not use object storage.
Idempotency for this operation is the existing tenant audit unique index, not a
stored file.

### 14. What the export does not do

The export does not calculate priority, call the policy engine, publish policy,
correlate, create Findings, or mutate Findings, reviews, evidence, advisories,
or queue inputs. There is no scheduled, anonymous, public, worker-generated, or
startup-generated export. There is no new permission. There is no migration.
The frozen migration count stays 28.

The file is not a claim of affectedness, exploitability, compliance,
certification, or remediation.

### 15. Session 8B

Session 8B implements the route, the serializer, the one owner and admin
control on `/remediation-queue` that posts this API, and the tests. Playwright
is out of this ADR's implementation. This ADR does not add those files. The web
application remains an API client under ADR 0038. The API remains the
authorization authority. The page does not gain a Next.js route handler that
builds the export.

### 16. Rate limit

The route uses the existing queue process-local ceilings: 30 requests per 60
seconds per direct socket peer and 20 requests per 60 seconds per organization.
It fails closed. Several API processes multiply the ceiling. There is no
rate-limit table. That multiplication is the same accepted residual as ADR
0048.

## Alternatives considered

- **Truncate at 150 rows.** A partial file would look complete. Rejected.
- **Use the SBOM component default of 10,000 or the intelligence staging default of 500 rows per transaction.** Those bounds belong to other workloads. Rejected.
- **Call `compareForRemediationQueue` on the request path.** ADR 0048 already requires the SQL order to match that comparator. A second ordering is rejected.
- **Merge `not_calculated` into P4, or let `humanReview` reorder the file.** Both contradict ADR 0045, ADR 0048, and ADR 0049. Rejected.
- **Write Evidence `export_snapshot` or an IdempotencyRecord body.** The evidence check is asset-scoped, and this decision does not store the file. Rejected.
- **Store the bytes in object storage.** The audit hash records the body without retaining it. Rejected.
- **Audit `GET /remediation-queue`.** Reads stay unaudited. Rejected.
- **Add a permission or a migration.** The existing permission pair and the existing audit index are sufficient. Rejected.
- **Mark ADR 0048 Superseded.** Only the export prohibition changes. Rejected.

## Consequences

- Positive: an owner or admin can take one coherent snapshot of the three queue sections after the audit row commits.
- Negative: an organization with more than 150 Findings cannot export until a later ADR raises the cap. A committed audit row can exist when the client never receives the file, and the server cannot resend those bytes.
- No migration. The frozen migration count stays 28.
- Process-local rate limits still multiply across API processes.
- The page is not a remediation workflow. Task, acceptance, and observation exports stay unauthorized.

## Security and tenancy

Every read and the audit insert use the actor's organization id. A foreign
organization's Findings are absent from the sections, the counts, and the file.
A client-supplied organization id is rejected. Member and viewer are denied
before the transaction.

Untrusted asset names, component names, and component versions stay untrusted
text. CSV formula neutralization applies to text cells. The JSON and CSV bodies
are the export, not a log line. Logs carry the route template and a closed
outcome. They omit row text, names, versions, vulnerability ids, response
bytes, cursors, tokens, and the canonical redaction list.

The audit payload may contain the response SHA-256, the byte length, the
counts, and the reference policy identity. It must not contain the redaction
list above. Audit rows are insert-only. This decision does not update or delete
them and does not cascade-delete evidence.

No outbound fetch is added. The transaction performs no network or
object-storage I/O.

## Operational failure plan

- **No admitted published builtin.** 503 `priority_policy_unavailable`. No rows. No audit row. The operator follows the ADR 0047 publication failure plan. Admission and a repository merge do not publish a row.
- **Validation or CSRF failure.** The existing rejection. No transaction audit row and no export body.
- **Authorization denial.** Deny before the transaction. No audit row and no export body. Member and viewer stay denied.
- **Cap overflow.** Fail closed. No truncation, no partial file, and no audit row. Raising 150 requires a later ADR.
- **Malformed rows or a broken partition.** The same unavailable outcome as the queue read. No audit row and no export body.
- **Serialization or audit insert failure.** Roll back. No audit row and no export body.
- **Duplicate correlation id.** The tenant audit unique index rolls back the second attempt. No second audit row and no resend. Bytes are not stored, so this is not a replay of the file.
- **Client disconnect after commit.** The audit row remains. It does not prove receipt. Recovery is a new request with a new correlation id, which takes a new snapshot.
- **Ordering drift.** The contract test fails. The SQL is corrected to the comparator. Stored rows are not rewritten.

## Follow-up

- Session 8B adds the route, the serializer, the one owner and admin control on `/remediation-queue`, and the tests. Playwright is out of this ADR's implementation. This ADR does not add those files.
- Tests cover tenant isolation, member and viewer denial, a client-supplied organization id, CSRF and Origin, the exact body, 503 before publication, the cap of 150 with no partial file, malformed rows, section partition, comparator equivalence on the same fixtures, CSV neutralization, no audit row on failure, unique-correlation rollback, and the disconnect residual.
- A runbook for the composed route belongs to that implementation.
- [Current state](../project/current-state.md) records that this architecture is accepted and not implemented. The frozen migration count stays 28.
