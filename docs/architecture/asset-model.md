# Asset model

An **asset** is a software system the organization tracks (application, service, or other inventoried target) that can receive SBOM uploads. Canonical entity fields: [domain model](domain-model.md#asset).

## Purpose in v0.1

The MVP journey registers an asset, uploads SBOMs against it, and compares findings across SBOMs for **that** asset. Assets are tenant-owned. They are not inferred from Git remotes.

## What an asset is not

- Not a cloud account, Kubernetes cluster, or runtime inventory.
- Not a GitHub repository (see **RepositoryConnection**, always `not_configured` in v0.1).
- Not a finding, SBOM, or team.
- Not automatically created from an SBOM `metadata.component` name. Operators register the asset first so organization scope and ownership are explicit.

## Core attributes

| Attribute | Role |
| --- | --- |
| Name | Operator-facing label (untrusted text in logs/UI) |
| Organization | Tenant scope |
| Environment | Optional FK to org **Environment**; input to environmental **priority** |
| Internet-facing flag | Optional **observed** operator assertion; never inferred from SBOM URLs |
| Owners | **AssetOwner** rows (user and/or team) |
| Lifecycle | `active` or `archived` |

Missing environment or missing internet-facing flag is an observed gap. The policy engine records the gap as a factor; it does not invent a production default.

## Environment

**Environment** is an organization-scoped catalog (production, staging, development, or custom). `sensitivityClass` is stored as data (`production` vs `non_production`) so renaming "prod" does not silently change scoring.

An asset references at most one environment in v0.1. Moving an asset to another environment is an audited update. It does **not** rewrite historical **RiskCalculation** rows. New calculations after the move use the new observed environment.

## Ownership

**AssetOwner** is operational assignment (who gets the work, who is listed on exports). It is not an authorization substitute. A user must still have **Membership** in the organization.

Teams may own assets ([OD-11](open-decisions.md)) without blocking the MVP journey.

## Lifecycle states

States: `active`, `archived`.

| From | To | Actor | Guard |
| --- | --- | --- | --- |
| (create) | `active` | `admin` or `owner` | Valid name; organization from membership |
| `active` | `archived` | `admin` or `owner` | No requirement to delete evidence |
| `archived` | `active` | `admin` or `owner` | Restore |

### Rules

- Only `active` assets accept new SBOM uploads. Uploads to `archived` assets are rejected with a stable error.
- Archived assets remain readable to authorized roles so history and exports still work.
- There is no `deleted` state in v0.1. Retention-driven purge is a later, explicit process ([retention](retention-and-deletion.md)) and must not cascade-delete evidence as a foreign-key convenience.
- Archive and restore emit **AuditEvent** `asset.archived` / `asset.restored`.

## SBOM relationship

An asset has many **SBOM** documents, ordered by `uploadedAt`. The latest **completed** ingestion is the current observation source for rescan conclusions. Failed or quarantined ingestions do not change finding presence.

## RepositoryConnection

At most one **RepositoryConnection** per asset in the v0.1 model. Status is `not_configured`. No provider calls. Future GitHub mapping must be one installation to one PatchPilot organization and is out of MVP.

## Authorization

All asset operations use `organizationId` from **authorized organization**. Asset UUID lookup without that predicate is forbidden.

## Related documents

- [SBOM ingestion](sbom-ingestion.md)
- [Finding lifecycle](finding-lifecycle.md)
- [Risk policy](risk-policy.md)
