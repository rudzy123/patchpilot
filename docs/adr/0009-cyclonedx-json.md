# ADR 0009: CycloneDX JSON as the initial SBOM format

- Status: Proposed
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

MVP accepts a single upload format so validation, limits, and tests stay closed. SPDX and XML are non-goals for the first usable release.

## Decision

Accept **CycloneDX JSON** only. Allowlisted `specVersion` values: **1.4, 1.5, 1.6**. Reject other media types, archives, XML, and SPDX until a later ADR. Validate spec version before full parse. Do not execute content or fetch document URLs. Limits: [sbom-ingestion.md](../architecture/sbom-ingestion.md).

## Alternatives considered

- **SPDX alongside CycloneDX**: doubles parser attack surface.
- **Any JSON**: insufficient structure for components and deps.
- **CycloneDX XML**: extra parser; not MVP.

## Consequences

Operators must produce CycloneDX JSON. Parser versions are retained for reprocessing.

## Security and tenancy

Untrusted input; org-scoped storage; no SSRF via `externalReferences`.

## Operational failure plan

Unknown spec version: reject. Poison parse: quarantine. Reprocess with new parser as a new **SBOMIngestion**.

## Follow-up

Schema fixtures per allowlisted version. New spec versions need an ADR ([OD-14](../architecture/open-decisions.md)).
