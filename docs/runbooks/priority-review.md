# Priority review

Owner `POST /findings/:findingId/priority-reviews` appends one review of one immutable RiskCalculation and one audit row in the same transaction. Admins can read the review on `GET /findings/:findingId/priority` and on the remediation queue. They cannot post.

A review does not change the calculated priority, the Finding row, the queue order, or `Finding.dueAt`.

## Failure handling

- A stale calculation or a stale review head returns 409 with `calculation_not_current` or `review_not_current`. Reload the priority read and submit again. The server does not substitute a newer calculation or head.
- A chain fork aborts on the unique index. No partial review row remains.
- UPDATE and DELETE are rejected by `patchpilot_forbid_mutation`.
- An audit unique collision aborts the transaction. Retry with a new correlation id. An exact content replay writes nothing.
- A wrong review stays. Append `withdrawn`, or append a later review that supersedes the head.
- An expired correction is reported at read time. No job writes, and the calculated rank stays unchanged.

The reason is stored on the review row and shown as text on the Finding page. It is not written to the audit payload and it is not logged.
