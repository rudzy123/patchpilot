# Data classification

This document labels data so logging, storage, exports, and backups use the same language. It is **not** a legal opinion and does not claim GDPR, HIPAA, or other regulatory compliance. Operators remain responsible for how they host PatchPilot.

Terms align with the [glossary](../product/glossary.md) and [privacy model](../security/privacy-model.md).

## Classes

| Class | Meaning | Examples |
| --- | --- | --- |
| **Public** | Safe to show without authentication | Product docs, CycloneDX spec URLs, PatchPilot license |
| **Internal** | Shared catalog; not tenant-secret but not dumped to logs | Normalized **Vulnerability** summaries, KEV listed boolean, builtin policy definition |
| **Confidential** | Tenant inventory and workflow | Asset names, finding lists, priorities, task notes, membership emails inside the org |
| **Restricted** | Evidence and secrets | Original SBOM bytes, object keys with org ids, **ExternalCredential** plaintext (memory only), password hashes, session ids, full feed snapshots, backups, protected OSV listing object keys, listing-evidence ciphertext, nonce, authentication tag, and complete key identifiers |

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
| Protected OSV listing object key | Restricted | Exact provider object identity for later generation-bound retrieval; WeakMap-backed in Session 13 Batch 3D-P-R; never public JSON, logs, events, metrics, traces, or errors; bare SHA-256 of the raw key is also omitted from public surfaces; plaintext is prohibited at rest, including in Session 13 Batch 3D-S columns |
| Protected OSV listing-evidence ciphertext, nonce, and authentication tag | Restricted | Session 13 Batch 3D persisted 1000 AES-256-GCM envelopes as restricted `nonce_12 \|\| ciphertext \|\| tag_16` BYTEA; public selects omit envelope columns and opaque key aliases; not public JSON, logs, events, metrics, traces, errors, or APIs; database access is not decryption authority; ciphertext is not harmless public data; Session 13 Batch 3D-R independently reviewed that public inspection omits restricted envelope fields |
| Protected OSV listing-evidence encryption keys and opaque key references | Restricted | Operator-provided instance keys, derived material, and complete key identifiers; never hardcoded; never in database rows as raw key material; complete identifiers are omitted from public contracts and metric labels |
| Protected OSV listing-evidence envelope metadata | Internal | Envelope schema version, algorithm identifier, key-state classification, rotation and erasure state, and bounded length classification; not a decryption capability |
| Protected OSV listing evidence digest and bounded counts | Internal | Domain-separated evidence-set digest and counts only; not a bare object-key digest; not sufficient for retrieval |
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

Protected OSV listing object keys follow Restricted handling even though they are instance-owned catalog metadata, not tenant inventory. Session 13 Batch 3D-P-R public evidence-set results expose domain-separated set digests and counts only. They do not expose a bare SHA-256 of the raw provider object key. Session 13 Batch 3D-E additionally classifies ciphertext, nonce, authentication tag, and complete key identifiers as Restricted. Envelope schema version, algorithm identifier, and key-state classification are Internal. Public encryption contracts omit plaintext, ciphertext, nonce, tag, and raw key identifiers. Session 13 Batch 3D-E-R independently reviewed that classification: AEAD associated data is reconstructed from immutable row context and is Restricted in encoded form; opaque key aliases are not metric labels. Ciphertext may appear in operator-controlled database backups and remains Restricted. Raw encryption keys must not appear in those backups. Session 13 Batch 3D-R independently reviewed the persisted Batch 3D envelopes: public inspection omits BYTEA and opaque key alias; no plaintext provider identity entered PostgreSQL.

Canonical redaction list always applies, even to Internal feed payloads.

## Derived data

Parsed graphs and **priority** values are Confidential **derived** data. They do not replace Restricted originals. Exports are Confidential PatchPilot outputs, not certificates.

## Related documents

- [Privacy model](../security/privacy-model.md)
- [Retention and deletion](retention-and-deletion.md)
- [Observability](observability.md)
