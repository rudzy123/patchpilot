# Privacy model

PatchPilot is designed for **self-hosted** operation. The project does not operate a hosted multi-tenant SaaS that would make the project a data processor for all customers. This document describes how the **software** handles data. It is **not** a privacy policy, DPA, or GDPR/CCPA/HIPAA compliance claim.

Operators who deploy PatchPilot determine their own legal obligations.

## Data PatchPilot stores

See [data classification](../architecture/data-classification.md) and the [domain model](../architecture/domain-model.md).

Typical personal data an operator might put in the system:

- User email and authentication secrets (hashes, sessions)
- Names in membership and **AssetOwner**
- Remediation notes and risk-acceptance reasons (free text)
- Audit actor ids

SBOMs may accidentally contain personal data inside component metadata. PatchPilot treats SBOM contents as untrusted **Restricted** evidence, not as a structured PII inventory.

## Data PatchPilot sends outbound (v0.1)

| Destination | Data | Personal data? |
| --- | --- | --- |
| OSV | Ecosystem, package name, version, or PURL derived from parsed components | Unlikely but package names could be internal |
| CISA KEV | Catalog fetch; no tenant SBOM | No tenant PII |
| Object storage | Original SBOM bytes | Possible if present in the file |
| Operator log/metrics backends | Redacted operational data | Should not include Restricted raw |

PatchPilot must **not** upload original SBOM documents to OSV. Optional AI is off; no model provider receives data in v0.1 ([ADR 0017](../adr/0017-optional-ai-user-credentials.md)).

## Roles

| Role | Privacy-relevant power |
| --- | --- |
| Organization member | Sees Confidential data in their org |
| Organization owner/admin | Exports, membership, credentials |
| Instance operator | Infrastructure and backups; database superuser equivalent if they have disk access |
| PatchPilot project maintainers | Do not receive operator data unless an operator files a support artifact—operators must redact |

## Minimization

- Job payloads carry ids and hashes, not SBOM bodies.
- Logs omit Restricted fields.
- Shared catalogs do not include tenant component names.
- Exports are explicit user actions and are audited.

## Access and correction

v0.1 has no end-user "download all my personal data" API beyond what membership, findings, and exports already show. Session deletion happens on logout/expiry. Organization wipe is not a product feature ([retention](../architecture/retention-and-deletion.md)).

## Retention

Defaults retain evidence indefinitely. Operators who need shorter retention must use future purge jobs without deleting audit history in v0.1.

## International transfers

If an operator points OSV/KEV or object storage at a third country, that is the operator's transfer. The software uses allowlisted HTTPS endpoints from config.

## Related documents

- [Retention and deletion](../architecture/retention-and-deletion.md)
- [Threat model](threat-model.md) (insider, backup exposure, AI leakage)
