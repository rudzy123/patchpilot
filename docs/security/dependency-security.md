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
| `@aws-sdk/client-s3` | 3.1120.0 | Apache-2.0 | `@patchpilot/integrations` | Streaming S3-compatible SBOM object storage. Static credentials only; no default credential-provider chain; no public ACL |
| `@smithy/node-http-handler` | 4.11.3 | Apache-2.0 | `@patchpilot/integrations` | Direct pin of the version already resolved by the S3 client, for bounded connection and request timeouts |

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

## Session 9 Batch 3B approved dependencies

Installed as exact versions (no caret or tilde ranges) on `@patchpilot/vulnerability-intelligence`. These versions were already resolved in the workspace lockfile by Session 8. No `pnpm.overrides` entry was added. `allowBuilds` was not changed. No `minimumReleaseAge` exclusion was added. No ZIP, archive, HTTP-client, CISA/OSV SDK, or second JSON Schema validator was installed.

| Package | Version | License | Where | Purpose in this batch |
| --- | --- | --- | --- | --- |
| `ajv` | 8.20.0 | MIT | `@patchpilot/vulnerability-intelligence` | Compile the vendored CISA KEV JSON Schema offline (draft-07, strict) |
| `ajv-formats` | 3.0.1 | MIT | `@patchpilot/vulnerability-intelligence` | `date` and `date-time` formats only; no URL fetch |
| `secure-json-parse` | 4.1.0 | BSD-3-Clause | `@patchpilot/vulnerability-intelligence` | Reject `__proto__` / `constructor.prototype` keys in untrusted JSON tests |

Not installed: ZIP or archive packages (`yauzl`, `unzipper`, `node-stream-zip`, `fflate`, `adm-zip`, `jszip`), provider or CISA/OSV SDKs, HTTP clients (`node-fetch`, `axios`, `got`, `undici` as a direct dependency), `ajv-formats-draft2019`, `ajv-keywords`, a second JSON Schema validator, `packageurl-js`, database packages, BullMQ, Redis, native addons, or schema-download packages.

## Vendored CISA KEV JSON Schema

The official CISA KEV JSON Schema is stored under `packages/vulnerability-intelligence/vendor/cisa-kev-schema/`.

- Source URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json`
- First-vendor SHA-256: `577f4ccc06b7b7c6a109e1a0d6457a26db7fc5219398ff2e287b9a7e14e2d9ef`
- Byte length: 3407
- Draft: JSON Schema draft-07
- Internal `$ref`: exactly `#/$defs/vulnerability` (no remote references)
- Formats: exactly `date` and `date-time`
- License: CC0-1.0 (`LICENSE` plus `NOTICE` in that directory)
- Provenance: `PROVENANCE.json` and `SHA256SUMS`
- Role: official JSON Schema for the CISA KEV JSON catalog, **not** the catalog body

The production KEV catalog JSON is **not** stored in the repository. Install, test, build, runtime, and CI do **not** download this schema. Re-vendoring is a maintainer-only script (`scripts/vendor-cisa-kev-schema.mjs --execute`) that is not a lifecycle, Turbo, or CI script. A changed upstream schema hash requires a new explicit review; the expected hash is not updated silently.

Batch 3B does not add provider HTTP runtime, a worker thread, a database migration, or Finding integration.

## Dependency advisory remediation (2026-10-06)

Commands: `pnpm audit` and `pnpm audit --prod`, on Node.js 24.20.0 and pnpm 11.24.0. No `pnpm.overrides` entry was added. `audit --fix` was not used. Both commands exit 1 after remediation because the two residual highs below remain. That exit is not a clean audit.

The 2026-10-05 implementation snapshot reported a post-upgrade full audit of 0 critical, 2 high, 0 moderate, and 0 low, and a production audit of 0 critical, 1 high, 0 moderate, and 0 low. The 2026-10-06 adversarial re-audit of that same resolved graph, before the review resolutions below, was different because two advisories had entered the audit database against versions this change had not moved: full 0 critical, 3 high, 1 moderate, 0 low; production 0 critical, 2 high, 1 moderate, 0 low. The extra high was `source-map-js@1.2.1` ([GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q)). The extra moderate was `fast-copy@4.0.4` ([GHSA-jggr-w7fw-pc2j](https://github.com/advisories/GHSA-jggr-w7fw-pc2j)). Both parent ranges already allowed a patched release, so the review resolved them in the lockfile. It did not add an override.

`pnpm audit --prod` counts dependencies of `@patchpilot/eslint-config` because that package declares ESLint tooling in `dependencies`. Those paths are development tooling. They are not the API, worker, or web runtime.

### Counts

| Audit | Critical | High | Moderate | Low |
| --- | --- | --- | --- | --- |
| Full, before | 1 | 19 | 15 | 3 |
| Production, before | 1 | 15 | 10 | 0 |
| Full, after the 2026-10-06 review resolutions | 0 | 2 | 0 | 0 |
| Production, after the 2026-10-06 review resolutions | 0 | 1 | 0 | 0 |

The production high that remains is `deepmerge-ts`. The second full-audit high is `braces`, and it is absent from the production audit. The 2026-10-06 review audit that still included `source-map-js` and `fast-copy` is recorded above; those two are not in the final counts.

### Direct dependency changes

| Package | Where | Previous | New | Class | Reason |
| --- | --- | --- | --- | --- | --- |
| `next` | `apps/web` dependencies | `16.3.3` exact | `16.3.8` exact | production | [GHSA-vcvr-r3jv-pc5j](https://github.com/advisories/GHSA-vcvr-r3jv-pc5j) is patched in `>=16.3.6`. `16.3.6` is the first patched 16.3 release. `16.3.7` is a non-security bugfix. `16.3.8` is the smallest 16.3 release that also contains the vendor's later same-line security fixes, including high [GHSA-cjq9-62q9-8jv4](https://github.com/advisories/GHSA-cjq9-62q9-8jv4) (image-optimization SSRF, affected `<16.3.8`). The npm audit snapshot used here did not list GHSA-cjq9; the version choice follows the vendor security release. Peer `react` `^19` remains satisfied by `react@19.2.4` and `react-dom@19.2.4`. |
| `eslint-config-next` | `apps/web` devDependencies | `16.3.3` exact | `16.3.8` exact | development | Kept on the same release as `next`. Peers `eslint >=9` and `typescript >=3.3.1` remain satisfied. |
| `fastify` | `apps/api` dependencies | `^5.6.2`, resolved `5.12.1` | `5.12.5` exact | production | High Fastify advisories are patched in `>=5.12.2`. Moderate [GHSA-4mh8-r7rc-xpvc](https://github.com/advisories/GHSA-4mh8-r7rc-xpvc) is patched in `>=5.12.5`. `5.12.5` is the newest and smallest 5.12 release that covers both. Existing `@fastify/cookie@11.1.2`, `@fastify/cors`, `@fastify/helmet`, and `@fastify/rate-limit@11.2.0` stayed in place. The install reported no peer failure. |
| `jsdom` | `apps/web` devDependencies | `^30.0.1`, resolved `30.0.1` | `^30.1.2`, resolved `30.1.2` | development | Parent of test-environment `undici`. `jsdom@30.1.2` depends on `undici ^8.11.2`, which is past the patched floor `>=8.10.2`. Vitest peers `jsdom` with `*`. Engines are `^22.22.2 \|\| ^24.15.0 \|\| >=26.0.0`; this review used Node.js 24.20.0. |

### Lockfile resolutions inside existing parent ranges

These moved inside existing parent ranges. No parent manifest range was rewritten except the direct changes above. No override was added. `source-map-js` and `fast-copy` were resolved during the 2026-10-06 review. The others moved with the original install.

| Package | Previous | New | Parent range | Class |
| --- | --- | --- | --- | --- |
| `fast-uri` | `3.1.6` | `3.1.8` | `ajv@8.20.0` depends on `^3.0.1` | production (Ajv URI format used by SBOM and vulnerability-intelligence schema compilation, and by Fastify's nested Ajv) |
| `fast-uri` | `4.1.3` | `4.2.1` | `@fastify/ajv-compiler@4.0.6` and `fast-json-stringify@7.0.1` depend on `^4.0.0` | production (Fastify validation and serialization) |
| `@eslint/eslintrc` | `3.3.6` | `3.3.7` | `eslint@9.39.5` depends on `^3.3.6` | development |
| `js-yaml` | `4.3.1` | `4.3.2` | `@eslint/eslintrc@3.3.7` depends on `^4.3.2` | development |
| `brace-expansion` | `1.1.18` | `1.1.21` | `minimatch@3.1.5` depends on `^1.1.7` | development |
| `brace-expansion` | `5.0.9` | `5.0.12` | `minimatch@10.2.6` depends on `^5.0.8` | development |
| `undici` | `8.10.0` | `8.11.2` | `jsdom@30.1.2` depends on `^8.11.2` | development |
| `ip-address` | `10.5.0` | `10.7.3` | `@fastify/rate-limit@11.2.0` depends on `^10.2.0` | production (rate-limit address parsing) |
| `sharp` | `0.35.3` | `0.35.5` | `next@16.3.8` optional dependency `^0.35.4` | production optional (Next image tooling; the web app does not configure `images.remotePatterns` and does not import `next/image`) |
| `source-map-js` | `1.2.1` | `1.2.2` | `postcss@8.5.23`, `postcss@8.5.26`, and `css-tree@3.2.1` depend on `^1.2.1` | production through `next` → `postcss`, and development through Vite and jsdom's `css-tree`. Resolved during the 2026-10-06 review. `1.2.2` is the patched release. |
| `fast-copy` | `4.0.4` | `4.1.1` | `pino-pretty@13.1.3` depends on `^4.0.0` | production (`@patchpilot/logger`). Resolved during the 2026-10-06 review. `4.1.0` is the patched floor. `4.1.2` is newer, but it was published 2026-10-05T19:12:04Z, inside pnpm 11's default 1440-minute release-age window at review time 2026-10-06T09:38:37Z. `4.1.1` is the newest release outside that window. |

`ajv` stays at exact `8.20.0`. `8.20.0` is the newest 8.x release, and its `fast-uri` range already allowed `3.1.8`. `ajv-formats` stays at `3.0.1`. `@fastify/ajv-compiler@4.0.6` and `fast-json-stringify@7.0.1` are already the newest releases in those lines.

`jsdom@30.1.2` requires these major closures. They are jsdom-owned, not an unrelated upgrade:

| Package | Previous | Resolved | Why it moved |
| --- | --- | --- | --- |
| `@asamuzakjp/css-color` | `6.0.7` | `7.1.3` | jsdom depends on `^7.1.3`. That release depends on newer `@csstools/css-calc@^3.4.2` and `@csstools/css-color-parser@^4.2.5`, which pull the other `@csstools/*` patch moves. |
| `@asamuzakjp/dom-selector` | `8.3.2` | `9.2.4` | jsdom depends on `^9.2.4`. That release depends on `bidi-js@^1.1.0` and `lru-cache@^11.5.3`. |
| `data-urls` | `7.0.0` | `8.0.0` | jsdom depends on `^8.0.0`. `data-urls@8` depends on `whatwg-url@^17.1.2`, so `whatwg-url@16.0.1` leaves the graph. |
| `html-encoding-sniffer` | `6.0.0` | `7.0.0` | jsdom depends on `^7.0.0`. |
| `tr46` | `6.0.0` | `7.0.0` | `whatwg-url@17.2.0` depends on `^7.0.0`. |
| `w3c-xmlserializer` | `5.0.0` | `6.0.0` | jsdom depends on `^6.0.0`. |
| `whatwg-url` | `17.1.0`, plus `16.0.1` | `17.2.0` only | jsdom depends on `^17.2.0`. |
| `symbol-tree` | `3.2.4` | removed | `jsdom@30.1.2` no longer depends on it. |
| `lru-cache` | `11.5.2` | `11.5.3` | jsdom and the CSS/DOM packages depend on `^11.5.3`. |
| `bidi-js` | `1.0.3` | `1.1.0` | `@asamuzakjp/dom-selector@9.2.4` depends on `^1.1.0`. |
| `@exodus/bytes` | `1.15.1` | `1.16.0` only | jsdom and `whatwg-url@17.2.0` depend on `^1.16.0`. `html-encoding-sniffer@7` depends on `^1.15.1`, which `1.16.0` satisfies, so the review resolution keeps one copy. |

`fast-uri@4.1.5` is the smallest 4.x release that clears the current high and moderate `fast-uri` advisories. `4.2.1` is the newest release allowed by `^4.0.0`. Its additional changes are IPv6 zone-identifier stability and idempotent `mailto` normalization. `fast-uri@3.1.8` is both the newest 3.x release and the smallest 3.x release that clears the moderate host-normalization advisory.

### Remediated by this change

The critical advisory [GHSA-vcvr-r3jv-pc5j](https://github.com/advisories/GHSA-vcvr-r3jv-pc5j) (`next@16.3.3`) is gone from the resolved graph. `next@16.3.8` is outside that vulnerable range.

Audited high Fastify advisories on `5.12.1` ([GHSA-667r-xxjv-c9mm](https://github.com/advisories/GHSA-667r-xxjv-c9mm), [GHSA-9q9j-q6p8-xq58](https://github.com/advisories/GHSA-9q9j-q6p8-xq58), [GHSA-hwr6-493r-vm6h](https://github.com/advisories/GHSA-hwr6-493r-vm6h), [GHSA-p68q-wchp-6fh7](https://github.com/advisories/GHSA-p68q-wchp-6fh7)) and moderate [GHSA-4mh8-r7rc-xpvc](https://github.com/advisories/GHSA-4mh8-r7rc-xpvc) are gone. The resolved version is `5.12.5`.

Audited high and moderate `fast-uri` advisories on `3.1.6` and `4.1.3` are gone. Resolved versions are `3.1.8` and `4.2.1`.

Audited high [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c) on `sharp@0.35.3` is gone. The optional resolution is `sharp@0.35.5`.

Audited high and moderate `undici` advisories on `8.10.0` are gone. The test-environment resolution is `undici@8.11.2`.

Audited high `js-yaml` and `brace-expansion` advisories are gone through the parent resolutions above. Audited moderate `ip-address` advisories on `10.5.0` are gone. The resolution is `10.7.3`.

The final 2026-10-06 audit contains no critical advisory and no high advisory beyond the two residuals below.

The web app does not import `next/og` or `ImageResponse`, does not define an Open Graph image route, and does not set `images.remotePatterns`. `next.config.ts` still sets `poweredByHeader: false`, `reactStrictMode: true`, the existing `transpilePackages` list, and `agentRules: false`.

`apps/api/src/app.ts` still passes top-level `disableRequestLogging: true` with `logger: false`. Fastify 5.12.5 still honors that option and still emits process warning `FSTDEP023`. The warning is not disabled. The option is removed in Fastify 6. Moving to `logController` is future maintenance. This change does not redesign logging.

Audited high [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q) on `source-map-js@1.2.1` is gone. The resolution is `1.2.2`. Audited moderate [GHSA-jggr-w7fw-pc2j](https://github.com/advisories/GHSA-jggr-w7fw-pc2j) on `fast-copy@4.0.4` is gone. The resolution is `4.1.1`. Those versions were already in the pre-remediation lockfile; the review moved only the resolutions, not their parents.

### Residual highs

| Advisory | Package | Severity | Path | Class | Blocker |
| --- | --- | --- | --- | --- | --- |
| [GHSA-ggr8-5vv4-36mx](https://github.com/advisories/GHSA-ggr8-5vv4-36mx) | `deepmerge-ts@7.1.5` (vulnerable `<8.0.0`, patched `>=8.0.0`) | high | Full audit: `packages/database` → `@prisma/client@6.19.3` optional peer `prisma@6.19.3` → `@prisma/config@6.19.3` → `deepmerge-ts`, and devDependency `prisma@6.19.3` → `@prisma/config` → `deepmerge-ts`. Production audit reports only the `@prisma/client` peer path. | Production dependency graph via the optional Prisma peer. Affected functionality is stack exhaustion while merging recursive object graphs (CWE-674) inside Prisma config merging. `@prisma/client` runtime does not import `deepmerge-ts`. That path is not on API or worker request handling. | Transitive residual. `prisma@6.19.3` is the newest Prisma 6 release and depends on `@prisma/config@6.19.3`, which depends on exact `deepmerge-ts@7.1.5`. Inspected on 2026-10-06, `@prisma/config@7.10.0` still depends on `deepmerge-ts@7.1.5`. The `prisma` `latest` dist-tag was prerelease `8.0.0-rc.20`, not a stable parent that removes the advisory. A Prisma major upgrade remains a separate compatibility decision. No override. |
| [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) | `braces@3.0.3` (patched versions: none; `3.0.3` is the newest release) | high | `apps/web` devDependency `eslint-config-next@16.3.8` → `@next/eslint-plugin-next@16.3.8` → `fast-glob@3.3.1` → `micromatch@4.0.8` → `braces@3.0.3` | Development tooling only. Absent from `pnpm audit --prod`. | No patched release. The plugin depends on exact `fast-glob@3.3.1`. The newest `fast-glob` is `3.3.3` and still depends on `micromatch@^4.0.8`, which depends on `braces@^3.0.3`. Replacing the lint stack would not be justified by a patched parent. No override. |

Residual owner for the PatchPilot review is dependency maintenance. Parent owners are Prisma (`@prisma/config`) and the `braces` / `micromatch` / `fast-glob` maintainers. There is no temporary mitigation and no package-manager override.

Next review trigger: a new critical or high result from `pnpm audit`; a Prisma release whose `@prisma/config` depends on `deepmerge-ts>=8.0.0`; or a `braces`, `micromatch`, or `fast-glob` release that no longer resolves `braces@<=3.0.3`. Review again before the next production dependency upgrade.

This table is a snapshot of the 2026-10-06 commands after the review resolutions. It is not a claim that the tree is free of advisories the audit database did not return. Do not treat this prose as a substitute for a fresh `pnpm audit`.

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
