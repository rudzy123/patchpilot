# Glossary

Terms below are used in product and engineering docs. Prefer these words in UI copy unless a user-facing label is decided separately.

| Term | Meaning |
| --- | --- |
| **Organization** | The tenant boundary. All customer-owned assets, SBOMs, findings, and audit events belong to one organization. |
| **Asset** | A software system the organization tracks (application, service, or other inventoried target) that can receive SBOM uploads. |
| **SBOM** | Software bill of materials. MVP accepts CycloneDX JSON. The original file is evidence and is stored, hashed, and not treated as trusted input. |
| **CycloneDX** | The SBOM specification used for MVP JSON uploads. Validate before parse. |
| **Component** | A package or library listed in an SBOM, including identifying coordinates used for correlation. |
| **Dependency relationship** | An edge between components as recorded in the SBOM. Observed fact, not a risk score. |
| **Vulnerability record** | Intelligence about a vulnerability (for example a CVE) from a named source, with provenance. |
| **Finding** | The link between an asset’s observed component (from a specific SBOM) and a vulnerability record, plus later enrichment and scores. |
| **Correlation** | Matching components to vulnerability records using defined identifiers and recorded method. |
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalog. Used to **enrich** applicable findings. KEV listing is not by itself proof of exploitation in the user’s environment. |
| **Enrichment** | Additional observed or catalog data attached to a finding, with source and time. Distinct from the priority calculation. |
| **Environmental risk / priority** | A calculated, explainable ranking for a finding under a versioned policy. Not an exploit proof. |
| **Policy version** | Identifier of the scoring rules used. Stored with each calculated priority. |
| **Contributing factors** | The inputs that produced a given priority, stored so the score can be explained later. |
| **Remediation work** | Assigned work to reduce or resolve a finding. |
| **Remediation activity** | A recorded action (fix, mitigate, verify) with actor and time. |
| **Risk acceptance** | An explicit, auditable decision to accept a finding for a defined reason and period. |
| **Compensating control** | A recorded control that reduces risk without removing the vulnerable component. It is evidence of a claim, not automatic score override unless policy says so. |
| **Re-scan** | Processing a newer SBOM for an asset and comparing prior findings. |
| **Resolved (on rescan)** | A calculated conclusion that a previous finding’s affected component is no longer observed. Requires evidence from the new SBOM; not implied by ticket status. |
| **Audit event** | Append-only record of a security-sensitive or remediation-sensitive operation. |
| **Provenance** | Source, time, and identity of how intelligence or evidence was obtained. |
| **Outbox** | Transactional outbox row used to schedule background work without I/O inside the same database transaction as the state change. |
| **Idempotency** | Reprocessing the same job or retried mutation does not create duplicate side effects. |
| **Evidence** | Stored artifacts and records needed to reproduce a finding (SBOM hash, parsed identifiers, intel source, policy version). |

When in doubt, label data as **observed fact** or **calculated conclusion**.
