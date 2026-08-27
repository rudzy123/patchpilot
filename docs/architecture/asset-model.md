# Asset model

An **asset** is a software system the organization tracks (application, service, or other inventoried target) that can receive SBOM uploads. Canonical entity: [domain model](domain-model.md#asset).

## Purpose in v0.1

The MVP journey registers an asset, uploads SBOMs against it, and compares findings across SBOMs for **that** asset. Assets are tenant-owned. They are not inferred from Git remotes.

## What an asset is not

- Not a cloud account, Kubernetes cluster, or runtime inventory.
- Not a GitHub repository (see **RepositoryConnection**, always `not_configured` in v0.1).
- Not a finding, SBOM, or team.
- Not automatically created from an SBOM `metadata.component` name. Operators register the asset first so organization scope and ownership are explicit.

## Attributes

| Attribute | Required | Role |
| --- | --- | --- |
| Name | yes | Operator-facing label (untrusted text) |
| Description | no | Untrusted text |
| Type | yes | Controlled `assetType` |
| Environment | no | FK to org **Environment**; scoring input |
| Owning team | no | **AssetOwner** with `teamId` |
| Individual owner | no | **AssetOwner** with `userId` |
| Business criticality | no | Controlled vocabulary; scoring input |
| Internet exposure | no | Controlled vocabulary; scoring input |
| Data classification | no | Classification of data the *asset* handles |
| Lifecycle status | yes | `active` or `archived` |
| Repository URL | no | Stored, not fetched (SSRF) |
| Repository connection | no | Entity `not_configured` in v0.1 |
| Deployment context | no | Free text (untrusted) |
| Last observed | system | Set when an ingestion **completes** |
| Last successful SBOM ingestion | system | FK to completed **SBOMIngestion** |
| Tags | no | Short labels; count/length capped in config |
| External identifiers | no | Namespaced keys (for example internal CMDB id) |

Missing optional scoring inputs are **unavailable** factors, not favorable defaults.

## Controlled vocabularies

These are initial v0.1 catalogs. Adding a value is a documented change; do not accept arbitrary strings for these fields.

**assetType:** `application`, `service`, `library`, `container_image`, `other`.

**businessCriticality:** `critical`, `high`, `medium`, `low`, `unspecified`.

**internetExposure:** `internet_facing`, `internal`, `unknown`. (`unknown` is stored when the operator has not asserted a value; it is not treated as `internal`.)

**dataClassification** (asset-handled data): `restricted`, `confidential`, `internal`, `public`, `unspecified`. This is an operator assertion about the asset, distinct from [PatchPilot data classification](data-classification.md) of stored rows.

**Environment.sensitivityClass:** `production`, `non_production`.

## Environment

**Environment** is an organization-scoped catalog (production, staging, development, or custom name). `sensitivityClass` is stored so renaming "prod" does not silently change scoring.

An asset references at most one environment in v0.1. Moving an asset to another environment is an audited update. It does **not** rewrite historical **RiskCalculation** rows. New calculations after the move use the new observed environment (`calculationReason: asset_change`).

## Ownership

**AssetOwner** is operational assignment (who gets the work, who is listed on exports). It is not an authorization substitute. A user must still have **Membership**.

`role` on AssetOwner: `technical`, `business`, `security`.

Teams may own assets ([OD-11](open-decisions.md)) without blocking the MVP journey.

## Lifecycle states

States: `active`, `archived`.

| From | To | Actor | Guard |
| --- | --- | --- | --- |
| (create) | `active` | `admin` or `owner` | Valid name and `assetType`; organization from membership |
| `active` | `archived` | `admin` or `owner` | No requirement to delete evidence |
| `archived` | `active` | `admin` or `owner` | Restore |

### Rules

- Only `active` assets accept new SBOM uploads.
- Archived assets remain readable so history and exports still work. Existing findings stay; new observations are not created until restore + new SBOM.
- Decommissioning is **archive**, not a silent `resolved` on all findings. Operators may then mark findings per [finding lifecycle](finding-lifecycle.md) using `asset_decommissioned` verification with required reason — that is a calculated/workflow path with evidence, not implied by archive alone.
- There is no `deleted` state in v0.1 ([retention](retention-and-deletion.md)).
- Archive and restore emit **AuditEvent** `asset.archived` / `asset.restored`.
- Updates to scoring-relevant fields emit `asset.updated` and outbox `finding.recalculate` for open findings on that asset.

## Recalculation on context change

When `environmentId`, `businessCriticality`, `internetExposure`, or asset `dataClassification` changes:

1. Persist the asset in a transaction with audit + outbox (no feed I/O).
2. Worker reloads each affected finding with organization predicate.
3. Insert new **RiskCalculation** rows. Previous rows remain.

## SBOM relationship

An asset has many **SBOM** documents, ordered by `receivedAt`. The **current** observation source for rescan conclusions is the `completed` **SBOMIngestion** whose SBOM `receivedAt` is greatest (tie-break ingestion `createdAt`, then id) — not the last worker to finish. Failed, quarantined, or still-`processing` ingestions do not change finding presence or `lastObservedAt`. Completing an older upload still stores that ingestion's graph; it must not overwrite `lastSuccessfulSbomIngestionId` if a newer upload already completed.

## RepositoryConnection

At most one **RepositoryConnection** per asset in v0.1. Status is `not_configured`. Optional `repositoryUrl` on the asset is display metadata only. No provider calls. Future GitHub mapping must be one installation to one PatchPilot organization and is out of MVP.

## Authorization

All asset operations use `organizationId` from **authorized organization**. Asset UUID lookup without that predicate is forbidden.

## Related documents

- [SBOM ingestion](sbom-ingestion.md)
- [Finding lifecycle](finding-lifecycle.md)
- [Risk policy](risk-policy.md)
