# Security design

This directory is the v0.1 security design for PatchPilot. It complements [docs/architecture/](../architecture/README.md) and does not replace repository-wide rules in [`.cursor/rules/security.mdc`](../../.cursor/rules/security.mdc).

PatchPilot can support an organization's vulnerability-management process. These documents do **not** claim SOC 2, ISO 27001, FedRAMP, PCI DSS, HIPAA, CMMC, or any other certification or regulatory compliance.

| Document | Purpose |
| --- | --- |
| [Threat model](threat-model.md) | Actors, assets, attack surfaces, and mitigations for v0.1 |
| [Security controls](security-controls.md) | Control catalog mapped to architecture |
| [Privacy model](privacy-model.md) | Data handling for a self-hosted deployment |
| [Secure development plan](secure-development-plan.md) | How we design, review, and test security-sensitive change |
| [Risk register](risk-register.md) | Prioritized architecture and security risks |
| [CI security](ci-security.md) | GitHub Actions threat model and controls |
| [Dependency security](dependency-security.md) | Lockfile, Dependabot, and Dependency Review |
| [Data access](data-access.md) | Organization scoping at the persistence boundary |
| [Database security](database-security.md) | PostgreSQL controls, secrets, and migration safety |

Operational failure plans: [docs/runbooks/](../runbooks/README.md).

Report product vulnerabilities privately per [SECURITY.md](../../SECURITY.md). Do not document exploit payloads in public issues or READMEs.
