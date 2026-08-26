# Unresolved architecture decisions

These items are intentionally not closed by the v0.1 ADR set. Until an ADR accepts a choice, implementers must follow the **interim default** and must not treat the default as an irreversible product promise.

None of these defaults weaken [tenant isolation](tenant-isolation.md) or [security controls](../security/security-controls.md).

| ID | Topic | Why it is open | Interim default for design and first implementation |
| --- | --- | --- | --- |
| OD-1 | Authentication mechanism | Local passwords, OIDC, magic links, and passkeys were not chosen in an ADR. | Local email-and-password accounts, Argon2id hashes, opaque server-side sessions in PostgreSQL, `HttpOnly` + `Secure` + `SameSite=Lax` cookies, synchronizer CSRF tokens on cookie-authenticated mutations. OIDC is future work. |
| OD-2 | Session store | PostgreSQL vs Redis for session rows. | PostgreSQL. Redis is reserved for BullMQ and ephemeral cache, not session authority. |
| OD-3 | RBAC permission catalog | Product docs require assignment and least privilege but do not enumerate every permission. | Roles in [tenant-isolation.md](tenant-isolation.md): `owner`, `admin`, `member`, `viewer`. Refine with an ADR before expanding. |
| OD-4 | Credential encryption key management | Envelope encryption needs an operator key, KMS, or Vault. | AES-256-GCM data keys wrapped by an operator-supplied key encryption key (KEK) loaded only through `packages/config`. No cloud KMS required for MVP. |
| OD-5 | Production object-storage vendor | The port is S3-compatible; AWS, MinIO, or GCS interop is an operations choice. | Provider-neutral port ([ADR 0008](../adr/0008-private-object-storage.md)). Local Compose uses MinIO. Production uses any S3-compatible private bucket the operator provides. |
| OD-6 | Application-layer package split | Use cases could live in `packages/domain` or a dedicated package. | Use cases live in `packages/domain` as application services. Revisit only if the package becomes unwieldy. |
| OD-7 | Priority vs risk score split | Glossary treats them as the same until an ADR splits them. | Keep **priority** as the stored calculated ranking. **Risk score** is a synonym. Do not introduce a second authoritative number. |
| OD-8 | Exact outbound rate-limit numbers | OSV and KEV provider limits change. | Configured limits with conservative defaults in [vulnerability-intelligence.md](vulnerability-intelligence.md); operators may tighten. |
| OD-9 | Notification channels | Email, chat, or in-app-only is unspecified. | In-app state and exports only for MVP. No outbound notification provider. |
| OD-10 | Instance operator identity | How a self-hosted admin authenticates separately from organization membership. | A config-gated bootstrap user that can manage **system** integrations and shared catalogs only. No cross-organization read of tenant evidence. A bypass ADR is required before any cross-org operator console. |
| OD-11 | Team semantics | Teams are in the domain model; MVP journey does not require them. | Persist Team and optional AssetOwner.teamId. Do not block the MVP journey on teams. |
| OD-12 | RepositoryConnection provider | GitHub is not MVP. | Persist the entity with status `not_configured`. No webhooks, no tokens, no repo API calls. |
| OD-13 | Backup encryption and off-site copies | Operator responsibility for a self-hosted system. | Document duties in [deployment-model.md](deployment-model.md) and [retention-and-deletion.md](retention-and-deletion.md). Do not ship a hosted backup service. |
| OD-14 | CycloneDX minor versions beyond 1.6 | Spec will evolve. | Allowlist 1.4, 1.5, and 1.6. New versions need an ADR and parser tests. |
| OD-15 | Matching algorithm details beyond OSV ranges | PURL aliases, CPE, and fuzzy name match are high-risk. | Exact ecosystem + package + version using OSV ranges and PURL when present. No fuzzy name match in MVP. |

Related: [ADR index](../adr/README.md), [architecture risk register](../security/risk-register.md).
