# Remediation-queue export

Owners and admins export the current remediation queue as one JSON or CSV file. Members and viewers cannot. The export reads the same ranked, incomparable, and not-calculated classification as `GET /remediation-queue`. It does not calculate priority, publish policy, or change a Finding, review, or product-match row.

## Call

`POST /remediation-queue/export`

Headers:

- session cookie
- `Origin` matching the configured web origin
- `x-csrf-token` matching the session
- `Content-Type: application/json`

Body, exactly one of:

```json
{ "format": "json" }
```

```json
{ "format": "csv" }
```

Do not send `organizationId`, a query string, or an organization header. The organization comes from the signed-in membership. An extra field, an unsupported format, or a client organization id returns HTTP 400 `Invalid request`.

The web page `/remediation-queue` posts this route from Export JSON and Export CSV. The browser does not build the file.

## Limits

The snapshot includes every open Finding in the organization, up to 150. A population above 150 returns HTTP 409 with the message `Remediation queue export exceeds 150 findings.` No file is sent and no `export.created` row is written.

The route shares the remediation-queue rate limits: 30 requests per 60 seconds for the direct peer and 20 per 60 seconds for the organization. The body limit is 1024 bytes.

Until an operator publishes the admitted builtin in that deployment, the route returns HTTP 503 with the message `Priority policy is unavailable.` A malformed queue row returns HTTP 503 with the message `Remediation queue is temporarily unavailable.`

## Files

Successful responses use `Cache-Control: private, no-store`.

| Format | Content-Type | Filename |
| --- | --- | --- |
| JSON | `application/json; charset=utf-8` | `remediation-queue.json` |
| CSV | `text/csv; charset=utf-8` | `remediation-queue.csv` |

The JSON envelope uses schema version `remediation_queue_export_v1`. The CSV has 22 columns from [ADR 0051](../adr/0051-remediation-queue-export.md). Text cells whose first character is `=`, `+`, `-`, `@`, tab, or carriage return are prefixed with one apostrophe before quoting. Numeric priority and policy version are not prefixed. Missing calculations are empty cells. They are not labeled P4.

## Audit

One PostgreSQL `REPEATABLE READ` transaction classifies the organization, serializes the response, and inserts one `export.created` audit row. The response is sent only after that transaction commits. The audit payload records the format, section counts, policy reference, `asOf`, the cap 150, the byte length, and the SHA-256 of the exact response bytes. It does not record names, versions, vulnerability ids, or row text. The bytes themselves are not stored.

A repeated correlation id rolls the transaction back and returns HTTP 409 with the message `The export was not recorded.` No second audit row is written and the first file is not sent again.

A client disconnect after commit can leave an audit row for a file the client did not receive. That row does not prove receipt. A new request uses a new correlation id and creates a new snapshot.

## What this is not

The file is a PatchPilot output. It is not a certification, an exploitability claim, or proof that a component was remediated. Task, acceptance, and observation exports are not available.
