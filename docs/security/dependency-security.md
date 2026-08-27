# Dependency security

This document covers how PatchPilot reviews **its own** dependencies. It is not PatchPilot product vulnerability-intelligence, OSV correlation, or customer-SBOM ingestion.

## Controls in this session

- A committed `pnpm-lock.yaml` and `pnpm install --frozen-lockfile` in CI
- Dependabot version updates and (when enabled in GitHub settings) Dependabot alerts and security updates
- Dependency Review on every pull request, failing on high or critical advisory severity
- License change reporting without an encoded legal allow/deny list

## What this does not prove

A green Dependency Review or Dependabot alert state does not mean the repository is free of vulnerable or malicious packages. Advisories lag. Transitive packages can be compromised without a CVE. Reviewers still read the diff.

## Unused observability SDKs

PatchPilot traces use an explicit OpenTelemetry trace provider and optional OTLP HTTP JSON exporter. Do not add `@opentelemetry/sdk-node`, Prometheus, Jaeger, Zipkin, gRPC, or proto exporters to restore convenience. Those packages pulled unused attack surface (including `protobufjs@8.0.0` via `@opentelemetry/otlp-transformer@0.211.0`). Prefer removing unused exporters over `pnpm.overrides` for `protobufjs`.

## Review process for dependency pull requests

1. Confirm the update is from Dependabot or a known maintainer, not an unexpected lockfile rewrite.
2. Require the normal CI, Integration, CodeQL, and Dependency review checks. Do not auto-merge. Do not wait on an E2E or container-build check; those workflows are deferred.
3. For high/critical advisories, prefer upgrading or replacing the package over ignoring.
4. Do not add `continue-on-error` to hide a review failure.
5. Licensing questions that are not obvious from SPDX identifiers need qualified review.

## Grouping

Development tools are grouped so ESLint or TypeScript-eslint upgrades arrive together. Runtime libraries stay ungrouped so a Next.js or Prisma bump is reviewed on its own.

## Related

- [Dependency management](../development/dependency-management.md)
- [Dependency alert runbook](../runbooks/dependency-alert.md)
- [CI security](ci-security.md)
