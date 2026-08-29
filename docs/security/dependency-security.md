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

## Session 8 Batch 2 approved dependencies

Installed as exact versions (no caret or tilde ranges). No `pnpm.overrides` entry was added. `allowBuilds` was not changed.

| Package | Version | License | Where | Purpose in this batch |
| --- | --- | --- | --- | --- |
| `ajv` | 8.20.0 | MIT | `@patchpilot/sbom` | Compile vendored CycloneDX JSON schemas offline |
| `ajv-formats` | 3.0.1 | MIT | `@patchpilot/sbom` | `date-time` and `uri` formats only; no URL fetch |
| `packageurl-js` | 2.0.1 | MIT | `@patchpilot/sbom` | Parse Package URLs |
| `secure-json-parse` | 4.1.0 | BSD-3-Clause | `@patchpilot/sbom` | Reject `__proto__` / `constructor.prototype` keys |
| `@aws-sdk/client-s3` | 3.1120.0 | Apache-2.0 | `@patchpilot/integrations` | Installed only; no S3 client construction, no default credential-provider chain, no public ACL |

`3.1120.0` is the newest exact version that satisfied Node 24, had no known advisory at install time, and met pnpm 11's default 1440-minute `minimumReleaseAge`. `3.1121.0` was newer than that gate; no `minimumReleaseAgeExclude` entry was kept.

Not installed: `@aws-sdk/lib-storage`, `minio`, `@cyclonedx/cyclonedx-library`, `ajv-formats-draft2019`, `@fastify/multipart`, XML libraries, `libxmljs2`, SPDX parser libraries, archive libraries, malware scanners, live schema clients, or another PURL parser.

## Vendored CycloneDX JSON schemas

Official JSON schemas for CycloneDX **1.4**, **1.5**, and **1.6** are stored under `packages/sbom/vendor/cyclonedx-json-schema/`.

- Source repository: `https://github.com/CycloneDX/specification`
- Source tag: `1.6.1` (lightweight tag; peeled commit equals the tag object)
- Source commit: `8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7`
- License: Apache-2.0 (`LICENSE` plus `NOTICE` in that directory)
- Provenance: `PROVENANCE.json` and `SHA256SUMS`

`$ref` discovery from the three BOM schemas required only `schema/jsf-0.82.schema.json` and `schema/spdx.schema.json` in addition to the BOM files. CycloneDX 1.7, older BOM schemas, XML, protobuf, and strict snapshots are not vendored.

Normal **install, test, build, runtime, and CI do not download schemas**. Re-vendoring is a maintainer-only script (`scripts/vendor-cyclonedx-json-schema.mjs --execute`) that is not a lifecycle or CI script.

## Remaining `pnpm audit` findings

Re-run on 2026-08-29 against `feat/sbom-ingestion` after Session 8 Batch 2 local verification, both before and after the new dependencies (`pnpm audit` exit 1; `pnpm audit --prod` exit 1). No `pnpm.overrides` entry hides an advisory. Session 8 Batch 2 did not add a second advisory. The remaining finding is the same Prisma-transitive `deepmerge-ts` advisory recorded after the observability cut and Session 6.

| Advisory | Package | Severity | How it is reached | Residual status |
| --- | --- | --- | --- | --- |
| [GHSA-ggr8-5vv4-36mx](https://github.com/advisories/GHSA-ggr8-5vv4-36mx) | `deepmerge-ts@7.1.5` (vulnerable `<8.0.0`, patched `>=8.0.0`) | high | Two paths, both through Prisma 6.19.x in `packages/database`: `@prisma/client` → `prisma` → `@prisma/config` → `deepmerge-ts`, and `prisma` → `@prisma/config` → `deepmerge-ts` | Unrelated to OpenTelemetry, SBOM schema compilation, `packageurl-js`, `secure-json-parse`, and `@aws-sdk/client-s3`. The advisory is stack exhaustion when merging recursive object graphs (CWE-674). PatchPilot does not depend on `deepmerge-ts` directly. Do not add a `pnpm.overrides` entry to silence it. Prefer a Prisma release that depends on `deepmerge-ts>=8.0.0` when one exists. |

Re-run `pnpm audit` after dependency changes. This table is a snapshot, not a claim that the tree is free of other unreported advisories. The post-install audit results in this batch must be compared with the pre-install run; do not treat this prose as a substitute for the recorded command output.

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
