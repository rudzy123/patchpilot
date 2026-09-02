# Observability

PatchPilot v0.1 uses **OpenTelemetry** for traces ([ADR 0016](../adr/0016-opentelemetry.md)) and structured **Pino** logs with correlation identifiers. Metrics remain future work. Observability must not weaken [canonical redaction](../../.cursor/rules/security.mdc).

## Current implementation (traces lifecycle only)

`packages/observability` owns process-level trace SDK startup and shutdown. It is **disabled by default** (`OTEL_ENABLED=false`). When enabled, it provides lifecycle infrastructure only: there is no automatic HTTP or Fastify instrumentation and no broad product spans yet.

| Capability | This iteration |
| --- | --- |
| Traces | Explicit `NodeTracerProvider` + optional OTLP **HTTP JSON** exporter |
| Metrics export | Not implemented |
| Log export | Not implemented (logs stay in Pino) |
| Automatic instrumentation | Not implemented |
| Prometheus / Jaeger / Zipkin / gRPC / proto exporters | Not used; `@opentelemetry/sdk-node` was removed |

Configuration is read only in `@patchpilot/config` (`OTEL_ENABLED`, optional `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) and passed as `TelemetryOptions`. `packages/observability` does not read `process.env`. PatchPilot does not honor `OTEL_SDK_DISABLED`, `OTEL_TRACES_EXPORTER`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER`, `OTEL_PROPAGATORS`, `OTEL_METRICS_EXPORTER`, or `OTEL_LOGS_EXPORTER`.

When telemetry is enabled without an endpoint, the process registers a trace provider with a no-op span processor and does not contact `localhost:4318` or construct an OTLP exporter. When an endpoint is supplied, PatchPilot constructs `OTLPTraceExporter` with that URL only.

The upstream OTLP HTTP exporter may still merge unspecified transport fields from the process environment. PatchPilot minimizes that by constructing the exporter only when the typed traces endpoint is present and by supplying the URL and export timeouts explicitly. Do not set extra `OTEL_*` variables expecting PatchPilot to consume them.

Exporter or collector failure must not fail product request processing (fail-open on export). Shutdown flushes with a bounded timeout and is idempotent. API and worker processes own SIGTERM/SIGINT; this package does not install signal handlers.

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
| `ingestionId` | SBOM ingestion | Logs, traces |
| `providerSyncId` | Intel refresh job | Logs, traces |
| `organizationId` | From authorized context only | Logs as UUID, never with SBOM bodies |
| `traceId` / `spanId` | OpenTelemetry | Exporters the operator configures |

Do not put raw authorization headers in trace attributes.

## Logs

- JSON logs via `packages/logger`.
- Redact: authorization headers, cookies, API tokens, GitHub tokens and installation tokens, raw SBOMs, private source code, private repository content, plaintext credentials, complete vulnerability-feed payloads, object-storage **signed URLs**, provider URLs, DNS answers, remote addresses, raw ETag / Last-Modified, intelligence snapshot object keys, and response headers.
- Component names may appear as **truncated** untrusted strings in debug logs only when needed; prefer ids and hashes (`sha256` prefix).
- Log finding **priority** as a number plus policy version, not as "exploitable."

## Metrics (minimum, future)

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

This iteration registers a trace provider only. Product spans (HTTP handler, use case, DB transaction, storage, outbound HTTP) are future work and must not include SQL text containing user data, full object-storage keys, or URL query strings.

Sampling is currently `AlwaysOnSampler` in `packages/observability`. Operator-configured parent-based sampling is future work.

## Health endpoints

- API liveness: process up.
- API readiness: PostgreSQL ping.
- Worker readiness: PostgreSQL + Redis ping.
- Do not expose config secrets or dump queues on public health routes.

## Alert categories (proposals)

`ingestion_quarantine`, `job_dead_letter`, `queue_lag`, `intel_stale`, `authz_deny_spike`, `upload_reject_spike`. Alerts must not include Restricted bodies.

## SLO proposals (not contractual)

Initial recommendations pending production measurement:

| SLO | Proposal |
| --- | --- |
| API availability (non-upload) | 99% monthly, operator-hosted |
| Upload accept (authz + store + outbox) p95 | 5 seconds excluding worker parse |
| Ingestion complete p95 for SBOMs under 5 MiB / <1k components | 15 minutes excluding feed outage |
| Intel snapshot freshness | See staleness thresholds (configurable) |

## What not to export

- Client bundles must not contain OTLP auth headers.
- Browser analytics must not receive raw SBOM JSON.
- Development pretty-print loggers that disable redaction are development adapters.

## Related documents

- [Reliability model](reliability-model.md)
- [Data classification](data-classification.md)
- [Secure development plan](../security/secure-development-plan.md)
