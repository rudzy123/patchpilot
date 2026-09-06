# ADR 0010: OSV as the initial vulnerability correlation source

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Correlation needs ecosystem-aware version ranges and an open dataset. Extra providers are future work.

## Decision

Use **OSV** as the initial **correlation** source. Worker adapters query allowlisted HTTPS APIs. Persist **Vulnerability** and **VulnerabilitySourceRecord** with provenance (`retrievedAt`, payload hash, source identity). Matching uses a **versioned** occurrence (versioned PURL or ecosystem+name+version) against OSV ranges. No fuzzy name match. Do not upload original SBOMs to OSV. Updates are additive. Withdrawn advisories do not delete findings. Targeted package queries are org-scoped jobs and must not persist tenant names on the shared catalog.

This ADR remains the future correlation ADR and is **not** superseded. Later ADRs refine transport and identity without replacing that role: [ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md) rejects tenant package query APIs for the approved foundation; [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) sets Finding natural key to `organizationId` + `assetId` + `componentId` + `vulnerabilityId` (advisory UUID, not an OSV id string column).

## Alternatives considered

- **NVD only**: weaker package-version matching for ecosystems OSV already models.
- **Multiple providers at once**: conflict policy would land before MVP.
- **Vendor commercial feed**: not required for self-hosted MVP.

## Consequences

Findings depend on OSV freshness. Outages leave last snapshots in place. Rate limits apply.

## Security and tenancy

Feed payloads untrusted. Shared catalog is global; findings remain tenant-owned. SSRF controls on adapter HTTP.

## Operational failure plan

429/5xx: backoff; integration `degraded`. Local fixtures for tests; no live network on default test path.

## Follow-up

Matching tests for ecosystem confusion and withdrawn records.
