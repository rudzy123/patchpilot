# ADR 0033: Product Match Evidence cardinality

- Status: Accepted
- Date: 2026-10-05
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the product-match evidence grain. Merge to `main` remains subject to normal pull-request review. This ADR does not authorize automatic matching, production evaluator composition, provider contact, Finding creation, or a change to Finding identity.

## Context

`product_match_evaluation_evidence` was unique per organization and component occurrence, and unique per organization and advisory revision. Replay fingerprints were unique globally. Those restrictions made one occurrence unable to retain evidence for more than one advisory revision, and one revision unable to retain evidence for more than one occurrence. They were not the intended evidence grain.

[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) keeps future Finding identity as organization, asset, versionless component, and vulnerability. That identity does not include a Product Match Evidence id, occurrence id, advisory revision id, evaluator version, or ingestion id.

## Decision

Product Match Evidence is append-only evidence of one exact evaluation of one component occurrence against one advisory revision under one reviewed approval, evaluator identity and version, matching-policy identity and version, and product-evidence policy identity and version.

The organization-scoped unique key is that evaluation identity. Outcome, explanation codes, and other derived facts do not mint a second row for the same identity. Exact replay and reevaluation are different operations. Exact replay returns the existing row and changes no timestamp. Reevaluation under a changed authoritative identity may append a new immutable row. If the same identity agrees and any immutable bound fact differs, the result is `immutable_conflict` and nothing is modified.

Bound facts that remain part of semantic comparison are the component-evidence fingerprint, package identity, observed version, advisory content fingerprint, affected-range fingerprint, `Vulnerability.id`, license decision through the approved authority, origin, outcome, and explanation codes. Fingerprint equality does not replace that comparison. A uniqueness race reloads the stored row and compares it. A uniqueness violation that is not that identity is not automatically `immutable_conflict`.

Replay uniqueness is `(organization_id, replay_fingerprint)`. Occurrence and revision lookup indexes are not unique.

A new evaluation is admitted only for the current reviewed tip: not withdrawn, not quarantined, valid under the committed reviewed-approval policy, and not itself superseded. A successor may be evaluated after it becomes that tip. Historical evidence for the previous revision stays unchanged. Current applicability is derived at query time from organization, occurrence, advisory family, revision, vulnerability, evaluator, and policy. It is not stored on the evidence row.

Multiple versions of one component on one SBOM remain separate occurrences. [ADR 0034](0034-multi-version-component-occurrence-normalization.md) preserves that grain during CycloneDX normalization.

## Alternatives considered

Keeping one row per occurrence would preserve history only by overwriting it. Keeping one row per revision would hide the same advisory on another asset. A materialized current-evidence pointer would make applicability mutable. Global replay uniqueness would let one tenant's fingerprint block another tenant.

## Consequences

Forward-only migration `20261005120000_product_match_evidence_cardinality` replaces the accidental unique indexes. Existing evidence, if any, already satisfies the narrower identity because the old keys were stricter. No evidence is rewritten or seeded. Automatic matching and Finding creation stay unavailable.

## Security and tenancy

Evidence remains tenant-owned. Uniqueness includes `organization_id`. A foreign row and an absent row stay publicly indistinguishable. Advisory and reviewer authority are not broadened. Affected evidence is not Finding authority. Suppression authority stays false.

## Operational failure plan

An exact replay inserts nothing and does not change timestamps. An immutable conflict modifies nothing. A concurrent duplicate converges on the stored row. A failed migration is recovered by restoring the database and reapplying the forward-only chain. Operators do not edit the predecessor migration.

## Follow-up

Multiple-version SBOM normalization is accepted by [ADR 0034](0034-multi-version-component-occurrence-normalization.md). Automatic matching remains unavailable. Finding creation remains unavailable. Suppression authority remains false.
