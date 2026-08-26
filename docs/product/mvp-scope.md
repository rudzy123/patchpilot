# MVP scope

This is the first **usable** release: a complete, evidence-preserving journey without an AI provider.

Future ideas belong in [non-goals](non-goals.md) or in an explicitly labeled future-work section. Do not implement them as if they were MVP.

## Supported journey

1. Create an organization.
2. Register an asset.
3. Upload a CycloneDX JSON SBOM.
4. Validate and securely store the original SBOM.
5. Parse components and dependency relationships.
6. Correlate affected components with vulnerability records.
7. Enrich applicable findings using CISA KEV data.
8. Calculate an explainable priority.
9. Assign remediation work.
10. Record remediation activity.
11. Upload a newer SBOM.
12. Verify whether previous findings were resolved.
13. Export findings and remediation evidence.

## In scope for that journey

- Organization-scoped inventory of software assets.
- CycloneDX JSON upload, validation, hashing (SHA-256), and private object storage of the original document.
- Component and dependency persistence derived from the SBOM.
- Correlation of components to vulnerability intelligence with recorded provenance.
- CISA KEV enrichment when a finding matches; store why it matched.
- Versioned risk-scoring policy; persist policy version and contributing factors with each score.
- Assignment of remediation work to users within the organization.
- Recording of remediation activity, risk acceptance, and compensating controls as explicit records plus append-only audit events.
- Re-processing a newer SBOM for the same asset and comparing prior findings (still present, absent, or inconclusive).
- Exports suitable for operators and executives, labeled as PatchPilot outputs rather than compliance certificates.
- Local development topology: Docker Compose, PostgreSQL, Redis/BullMQ, MinIO, and the modular monolith apps (`web`, `api`, `worker`) once they are scaffolded.

## Explicitly not in this MVP

Anything in [non-goals](non-goals.md). Optional AI explanation or drafting is **future work** and must remain disabled-by-default.

## Future work (not MVP)

Label these as future work if mentioned in code or docs:

- User-supplied AI API keys or local compatible endpoints for non-authoritative drafting.
- Additional SBOM formats beyond CycloneDX JSON.
- Go CLI after the web MVP functions.
- Extra intelligence providers beyond the MVP correlation source plus CISA KEV.
- GitHub and other source-control integrations (including GitHub webhooks).
- Microservices split of the modular monolith.
- Hosted multi-tenant SaaS offering.

## Definition of a usable slice

A slice is not done when the UI renders. It is done when it meets [definition of done](../development/definition-of-done.md): tests, error handling, logs, metrics, documentation, and an operational failure plan appropriate to the change.
