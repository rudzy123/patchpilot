# Data classification

This document labels data so logging, storage, exports, and backups use the same language. It is **not** a legal opinion and does not claim GDPR, HIPAA, or other regulatory compliance. Operators remain responsible for how they host PatchPilot.

Terms align with the [glossary](../product/glossary.md) and [privacy model](../security/privacy-model.md).

## Classes

| Class | Meaning | Examples |
| --- | --- | --- |
| **Public** | Safe to show without authentication | Product docs, CycloneDX spec URLs, PatchPilot license |
| **Internal** | Shared catalog; not tenant-secret but not dumped to logs | Normalized **Vulnerability** summaries, KEV listed boolean, builtin policy definition |
| **Confidential** | Tenant inventory and workflow | Asset names, finding lists, priorities, task notes, membership emails inside the org |
| **Restricted** | Evidence and secrets | Original SBOM bytes, object keys with org ids, **ExternalCredential** plaintext (memory only), password hashes, session ids, full feed snapshots, backups |

Untrusted SBOM fields (component names, versions) are **Confidential** once stored, and still **dangerous to render** (XSS). Classification does not make them trusted.

## Mapping to entities

| Entity | Class | Notes |
| --- | --- | --- |
| Organization name | Confidential | |
| User email | Confidential | |
| Password hash | Restricted | |
| Membership | Confidential | |
| Asset, Environment, Team | Confidential | |
| SBOM original bytes | Restricted | |
| SHA-256 of SBOM | Confidential | Hash is not the file but identifies it |
| Parsed components | Confidential | Tenant-owned |
| Vulnerability catalog | Internal | |
| VulnerabilitySourceRecord raw | Restricted | Full payload |
| Finding, observations | Confidential | |
| RiskCalculation factors | Confidential | May include environment |
| Remediation notes | Confidential | |
| RiskAcceptance reason | Confidential | |
| Evidence objects | Restricted if bytes; Confidential if structured claim |
| AuditEvent payload | Confidential | Already redacted |
| ExternalCredential ciphertext | Restricted | |
| Outbox/job payloads | Confidential | Ids only by design |
| Session cookie | Restricted | |
| OTLP exports | Must not upgrade Restricted into Public |

## Handling rules

| Class | Logs | Metrics labels | Browser | Object storage | Backups |
| --- | --- | --- | --- | --- | --- |
| Public | OK | OK | OK | n/a | OK |
| Internal | Summaries; no full feeds | Low cardinality | Authenticated OK | Optional snapshots private | OK |
| Confidential | Ids, hashes, counts | No package names | Authorized org only | n/a | Encrypted if possible |
| Restricted | **Never** raw | **Never** | Never raw SBOM by default | Private, org-prefixed keys | Restricted |

Canonical redaction list always applies, even to Internal feed payloads.

## Derived data

Parsed graphs and **priority** values are Confidential **derived** data. They do not replace Restricted originals. Exports are Confidential PatchPilot outputs, not certificates.

## Related documents

- [Privacy model](../security/privacy-model.md)
- [Retention and deletion](retention-and-deletion.md)
- [Observability](observability.md)
