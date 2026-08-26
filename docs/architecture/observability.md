# Observability

PatchPilot v0.1 uses **OpenTelemetry** for traces and metrics ([ADR 0016](../adr/0016-opentelemetry.md)) and structured **Pino** logs with correlation identifiers. Observability must not weaken [canonical redaction](../../.cursor/rules/security.mdc).

## Goals

- Reconstruct a request or job with `correlationId` / `traceId` / `jobId`.
- Measure success, failure, and saturation (queue lag, parse duration, feed errors).
- Avoid logging secrets, tokens, raw SBOMs, private source, or complete feed payloads.

## Correlation identifiers

| ID | Set where | Propagated to |
| --- | --- | --- |
| `requestId` | API on each HTTP request | Logs, traces, outbox payload, jobs |
| `correlationId` | Same as requestId or worker-generated for scheduled jobs | Same |
| `jobId` | Background job | Logs, traces, audit `correlationId` when the actor is system |
| `organizationId` | From authorized context only | Logs as UUID, never with SBOM bodies |
| `traceId` / `spanId` | OpenTelemetry | Exporters the operator configures |

Do not put raw authorization headers in trace attributes.

## Logs

- JSON logs via `packages/logger`.
- Redact: authorization headers, cookies, API tokens, GitHub tokens, raw SBOMs, private source code, plaintext credentials, complete vulnerability-feed payloads.
- Component names may appear as **truncated** untrusted strings in debug logs only when needed; prefer ids and hashes (`sha256` prefix).
- Log finding **priority** as a number plus policy version, not as "exploitable."

## Metrics (minimum)

| Signal | Purpose |
| --- | --- |
| HTTP request count by route class and status | API health |
| Upload bytes, reject counts by reason | Ingestion DoS and validation |
| Ingestion state transitions | Pipeline health |
| Job success / retry / dead-letter / lag | Worker saturation |
| OSV/KEV fetch success, latency, 429 | Feed health |
| Policy calculation count and duration | Scoring |
| Quarantine count | Poison |

Cardinality: label by `eventType` and `state`, not by tenant name or package name.

## Traces

Span the HTTP handler, use case name, DB transaction (without SQL text containing user data), storage put/get (key **template**, not full key if it includes tenant ids in high-cardinality exporters—prefer hashed org id or omit), and outbound HTTP (host allowlist name, not full URL query).

Sampling is operator-configured. Default local: always on. Production default: parent-based with a conservative ratio.

## Health endpoints

- API liveness: process up.
- API readiness: PostgreSQL ping.
- Worker readiness: PostgreSQL + Redis ping.
- Do not expose config secrets or dump queues on public health routes.

## What not to export

- Client bundles must not contain OTLP auth headers.
- Browser analytics must not receive raw SBOM JSON.
- Development pretty-print loggers that disable redaction are development adapters.

## Related documents

- [Reliability model](reliability-model.md)
- [Data classification](data-classification.md)
- [Secure development plan](../security/secure-development-plan.md)
