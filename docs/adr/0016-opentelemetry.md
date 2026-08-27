# ADR 0016: OpenTelemetry observability

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Significant features need metrics, structured logs, and correlation. Operators bring their own backends in a self-hosted model.

## Decision

Instrument with **OpenTelemetry** traces and metrics via `packages/observability`. Logs use Pino with canonical **redaction**. Propagate `requestId` / `correlationId` / `jobId` into jobs and audit. Health endpoints do not dump secrets or queues. High-cardinality labels must not include package names or raw org display names. Details: [observability.md](../architecture/observability.md).

## Alternatives considered

- **Vendor-specific APM SDK in domain**: rejected.
- **Logs only**: insufficient for queue lag and parse saturation.

## Consequences

Operators enable traces explicitly and, when exporting, supply an OTLP HTTP JSON traces endpoint through `@patchpilot/config`. Telemetry remains disabled by default. This iteration does **not** use console exporters, `@opentelemetry/sdk-node`, Prometheus, Jaeger, Zipkin, gRPC, proto exporters, metrics SDKs, log exporters, or automatic instrumentation. Sampling is explicit in code (`AlwaysOnSampler`) until a versioned sampling setting exists in config.

## Security and tenancy

No authorization headers, cookies, tokens, raw SBOMs, or full feed payloads in logs or span attributes.

## Operational failure plan

Exporter down must not block requests (fail-open on export, fail-closed on redaction). Missing metrics is an ops issue, not a reason to skip instrumentation in new features.

## Follow-up

Logger redaction unit tests exist. Product HTTP, job, feed, and policy **metrics** remain future work in `packages/observability` after this trace-lifecycle security cut. Automatic instrumentation, parent-based production sampling, and operator-facing trace runbooks remain follow-up. Do not reintroduce `@opentelemetry/sdk-node` to restore those later; add only the specific trace, metric, or log packages required.
