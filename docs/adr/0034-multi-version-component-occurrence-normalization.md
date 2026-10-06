# ADR 0034: Multi-version component occurrence normalization

- Status: Accepted
- Date: 2026-10-05
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the CycloneDX occurrence grain. Merge to `main` remains subject to normal pull-request review. This ADR does not authorize automatic matching, production evaluator composition, provider contact, Finding creation, a schema migration, or automatic reprocessing of historical graphs.

## Context

`Component` is the stable, organization-scoped, versionless package identity. `ComponentOccurrence` is one observed version of one Component in one immutable SBOM ingestion. Product Match Evidence is occurrence-specific ([ADR 0033](0033-product-match-evidence-cardinality.md)). Future Finding identity remains `organization_id` + `asset_id` + `component_id` + `vulnerability_id` ([ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)).

The previous normalizer collapsed every representation that shared a versionless identity key into one occurrence. Distinct observed versions of one package were dropped before any later Product Match Evidence evaluation. Occurrence uniqueness in PostgreSQL was already `(organization_id, sbom_ingestion_id, component_id, version)`. That constraint can store more than one version. The loss happened in normalization, not in the schema.

`bom-ref` is document-local graph addressing. It is not stable product identity.

## Decision

One ingestion may contain multiple `ComponentOccurrence` rows for one `Component` when their observed versions differ. Repeated dependency paths to the same resolved version produce dependency edges, not extra occurrences.

The occurrence grain is organization + SBOM ingestion + versionless Component + observed version. For a resolved PURL:

- version does not become part of Component identity;
- qualifiers and subpath stay out of the versionless identity, as they do today;
- `bom-ref` does not become Component identity;
- different observed versions do not alias;
- the same normalized observed version may alias only after the security facts below agree.

Before aliasing two representations of the same Component and observed version, compare:

- version-known classification;
- observed version value;
- normalized versioned PURL, when both representations have one;
- CycloneDX version and PURL version, when both are present on one representation;
- SHA-256 sets, when both representations provide SHA-256 evidence.

A missing fact does not contradict a present fact. Disagreeing present facts fail closed. The normalizer does not keep the first representation when those facts disagree.

A CycloneDX version and a PURL version that disagree reject the ingestion with `component_version_conflict`. Different SHA-256 digests for the same Component and observed version reject it with `component_hash_conflict`. Neither rejection persists a graph. A missing SHA-256 and a present SHA-256 do not conflict by themselves. Unknown version stays an explicit unknown occurrence. It is not `unaffected`, and it does not replace a known version of the same Component.

Direct and transitive versions of the same package remain separate occurrences. An edge that names one version is not redirected to another version. Alias rewriting does not manufacture a self-edge by collapsing distinct versions. A self-edge that appears only because two bom-refs alias to the same occurrence is still skipped and counted as `self_dependency_skipped`. Cycles between distinct versions remain.

Occurrence versions are not updated in place. A completed ingestion is not rewritten. Exact byte replay reuses the existing SBOM and ingestion. A new byte sequence creates a new SBOM and ingestion under the existing upload rules.

Newly normalized graphs use normalization version `2` (`CURRENT_SBOM_NORMALIZATION_VERSION`, and the `SBOM_NORMALIZATION_VERSION` default). The current normalizer rejects any other label with `unsupported_normalization_version` and writes no graph. Existing completed rows may remain labeled `1`. Nothing reprocesses them, and nothing rewrites their graphs, timestamps, or occurrence rows.

Component natural identity and `ComponentOccurrence` database uniqueness stay as they are. No component-instance table and no bom-ref alias table are persisted. Alias resolution is in-memory for the document being normalized. One canonical `bom-ref` is stored on the occurrence. That canonical `bom-ref` is the lexicographically earliest `bom-ref` among the agreeing representations, compared by UTF-16 code unit. The stored display name is the lexicographically earliest CycloneDX name under the same comparison. Other bom-refs for that same version are rewritten onto edges and then discarded. Document order does not choose the observed version, the versioned PURL, the SHA-256 decision, the display name, or the canonical `bom-ref`.

## Alternatives considered

Keeping the versionless collapse would continue to drop inventory versions before evidence evaluation. Putting version into Component identity would change the versionless package key and the future Finding key. A component-instance table or a persisted bom-ref alias table would require a migration that the existing occurrence uniqueness does not need. Reprocessing historical graphs would rewrite immutable ingestion evidence.

## Consequences

New graphs can retain every distinct observed version. Same-version aliases still produce one occurrence and one Product Match Evidence subject for that version. Contradictory version or SHA-256 evidence rejects the whole ingestion. Historical normalization-version-1 graphs stay attributed to version 1. There is no schema migration and no automatic reprocessing. An in-flight ingestion whose stored label is not `2` is rejected when the current normalizer runs, and it receives no graph.

## Security and tenancy

Components, occurrences, and edges remain organization-scoped. The same package and versions may exist independently in different organizations. A foreign occurrence and an absent occurrence stay indistinguishable under an organization predicate. Inventory persistence does not invoke an evaluator, write Product Match Evidence, write a Finding, or write a FindingObservation. Suppression authority stays false. Unknown version is not affectedness.

## Operational failure plan

`component_version_conflict`, `component_hash_conflict`, and `unsupported_normalization_version` are rejected outcomes. The user must upload a consistent document, or the deployment must use normalization label `2`. Do not requeue those codes. Do not edit completed version-1 graphs to make them look like version 2. A completed ingestion replay does not parse again and does not change occurrence rows or timestamps.

## Follow-up

Automatic matching remains unavailable. Finding creation remains unavailable. Suppression authority remains false. Historical graphs are not reprocessed by this decision.
