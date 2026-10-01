# Product-evidence provenance

Session 15 Batch 1 architecture. Policy `osv_product_evidence_provenance_architecture_v1`.
Contract `osv_product_evidence_provenance_contract_v1`. Persistence is
`not_implemented`. Production registration is `absent`. Finding creation remains
unavailable.

Session 14 is merged. Its npm evaluator and immutable match-evaluation evidence
stay authoritative. This document does not change those semantics and does not
relabel synthetic evidence.

## Provenance dimensions

| Dimension | Values | Who sets it |
| --- | --- | --- |
| Origin | `synthetic_fixture`, `provider_derived`, `unrecognized` | Request. A Session 14 synthetic marker forces `synthetic_fixture`. `unrecognized` stays `unrecognized` and is `ineligible_unreviewed` |
| Trust | `not_applicable_synthetic`, `unreviewed`, `reviewed` | Derived. A caller `trust` or `eligible` field is rejected |
| Withdrawal | `not_withdrawn`, `withdrawn` | Explicit revision fact |
| Quarantine | `not_quarantined`, `quarantined` | Explicit revision fact |
| Eligibility | Closed classification below | Derived |

`eligible` would mean the immutable fact bundle satisfies the contract. Batch
1-R does not return it. The active ecosystem and evaluator registries are
empty, and `reviewedRegistriesAuthorizeProductEligibility()` is false, so a
complete provider-shaped bundle is `ineligible_registry` with trust
`unreviewed`. `eligible` does not authorize execution, persistence, catalog
activation, provider contact, or Finding creation.
`supportsProductEvaluationNow` stays false.

## Advisory identity

Family identity is source-bound: source plus advisory identifier. Grammar is
the committed parser pattern `^[A-Z0-9][A-Z0-9._+-]{0,511}$`, maximum 512 UTF-8
bytes, case-sensitive. A family digest is SHA-256 of the length-prefixed
canonical form. It is not a database row id, title, severity, KEV status, or
active pointer.

Revision identity changes when authoritative content changes. The revision
digest binds family digest, provider generation, content fingerprint, Session
14 range fingerprint, product range fingerprint, parser id, parser resource
policy, schema version, schema commit, source-license registry, SPDX license
identifier, withdrawal, quarantine, supersession digest, and retrieval-evidence
id. Retrieval time, catalog generation ids, and `Vulnerability.id` are outside
the revision digest. Replay compares the full immutable tuple: canonical
revision material, classification, origin, trust, SPDX id, Vulnerability
binding, catalog generation claims, and the replay fingerprint. Equal revision
digests do not skip that comparison. Equal digests with different canonical
material, bindings, or catalog claims are `immutable_conflict`.

## Fingerprints

Content fingerprint domain `osv_product_advisory_content_fingerprint_v1` covers
source, advisory id, schema version, schema commit, withdrawal, SPDX license
identifier, sorted aliases, the Session 14 range fingerprint, ecosystem, and
package identity. It excludes retrieval time, headers, paths, row ids, the
active pointer, tenant state, KEV, risk, and Finding state.

Range fingerprint domain `osv_product_affected_range_fingerprint_v1` binds
ecosystem, package identity, the Session 14 range fingerprint, parser, matching
policy, evaluator version, and schema version. The Session 14 fingerprint is
the evaluator's length-prefixed range canonical form. A mismatch is
`ineligible_range_fingerprint`.

Both digests are 64 lowercase hex SHA-256 characters.

## Source and license

The accepted npm product source is `github_advisory_database` only, registry
`osv_source_license_registry_v1`, SPDX `CC-BY-4.0`, internal matching
`permitted`. A recognized source or a permitted license is necessary and
insufficient. `cisa_kev` and `manual_curated` are `ineligible_source`. KEV does
not establish affectedness or a Vulnerability binding. License evidence URLs
are not copied into the public contract.

## Retrieval, parser, and schema

Reviewed provider provenance requires retrieval evidence, provider-contact
authorization, synchronization request, and run as UUID v4 values, response
classification `within_generation_bound_ceiling`, and a UTC timestamp that is
recorded and excluded from revision identity. Provider generation matches
`^[1-9][0-9]{0,19}$`. Parser pins are `osv_advisory_parser_protocol_v1` and
`osv_advisory_parser_resource_policy_v1`. Schema pins are OSV schema `v1.9.0`
commit `f3f826310aeca8e324baabd195632f2229952abe`. A parser or schema change
creates a new revision. It does not overwrite an earlier one. Public contracts
omit provider object identity, raw body, URL, and continuation token.

## Withdrawal and supersession

Withdrawal is part of the revision. A withdrawn revision is
`ineligible_withdrawn`. It does not delete prior evidence, close a Finding, or
suppress review. Listing absence is
`presence_not_observed_not_withdrawal`.

Supersession stores `none` or the prior revision digest. `linkSuccessor` returns
the same prior object with `priorMutated` false. An active-revision digest that
does not equal this revision is `ineligible_catalog` with `catalog_mismatch`.
It is not `ineligible_superseded`. Listing absence does not mark a revision
superseded. The active pointer does not mutate prior ranges, bindings, or
eligibility. `ineligible_superseded` stays in the closed taxonomy and is not
inferred from a caller digest.

## Catalog and registries

Catalog membership binds catalog generation id and active catalog generation id.
They must be equal UUID v4 values. Membership is necessary and insufficient.
The active pointer version is not an input. `activePointerIsEvidenceIdentity`
is false. Catalog activation policy is
`osv_catalog_activation_not_authorized_v1`. This batch does not activate a
catalog. ADR 0027 remains Proposed.

The defined npm ecosystem and evaluator entries bind the Session 14 evaluator
`osv_first_ecosystem_affected_version_evaluator_v1` version
`session_14_batch_2_in_memory`, policy
`osv_first_ecosystem_matching_architecture_v1`, range type `SEMVER`, events
`introduced`, `fixed`, `last_affected`, and `limit`, and explanation catalog
`session_14_first_ecosystem_explanation_codes`. Activation classification is
`not_activated`. `registryImplemented` is false. The entries do not authorize
provider contact, body retrieval, catalog activation, Finding creation, risk,
tenant access, or callbacks. `activeEcosystemRegistry()` and
`activeEvaluatorRegistry()` return empty arrays. Callers cannot supply an entry.
`productionRegistryReadiness()` is `ineligible_registry`.
`reviewedRegistriesAuthorizeProductEligibility()` reads those empty registries
and returns false. A request that satisfies every other pin is still
`ineligible_registry`. Batch 1-R does not activate the defined entry.

## Vulnerability binding

Mapping policy `one_vulnerability_id_per_product_evidence_record_v1`. Method
`exact_uuid_and_exact_alias_set`. One `Vulnerability.id` per product-evidence
record. A single canonical CVE alias is evidence for that binding. It is not
the Vulnerability id and it does not prove package affectedness. Two or more
CVE aliases, duplicate aliases, or an additional Vulnerability id are
`ineligible_vulnerability_binding`. Zero CVE aliases may be
`provider_native_without_cve` when the advisory family id and Vulnerability UUID
are exact. No CVE is invented from package names or ranges.

Prohibited methods, including string similarity, title, package name, CVE
substring, first alias, KEV membership, operator boolean, and active pointer,
are `vulnerability_binding_ambiguous`. Conflicting mappings are append-only
conflict evidence. They do not overwrite a prior mapping and they grant no
Finding authority. `Vulnerability.osvId` remains `VARCHAR(128)` and is not
revision identity. `vulnerabilityOsvIdColumnSufficient` records whether the
advisory id fits that column. It does not change schema and does not block
eligibility by itself.

## Product evaluation and synthetic evidence

A future product-eligible evaluation still requires a tenant component
occurrence, npm, the reviewed evaluator pins, a valid raw version, a
non-withdrawn revision, matching fingerprints, and one accepted Vulnerability
binding. Only product-eligible `affected` evidence may later be one Finding
prerequisite. Product-eligible `unaffected` evidence stays nonsuppressive.
Product-eligible `unknown` evidence stays uncertainty evidence.

Session 14 synthetic rows stay synthetic. `relabelSession14SyntheticEvidence`
returns `rejected_synthetic_immutable` and does not mutate them. A request that
carries `synthetic_record` is stored as origin and source `synthetic_fixture`
with classification `ineligible_synthetic`.

## Finding and authority chain

Product-eligible affected evidence is necessary and insufficient for Finding
creation. Finding creation remains unavailable. This batch does not design the
Finding write gate and does not modify Finding tables.

```text
protected listing observation
-> reviewed candidate selection
-> body-specific authorization
-> immutable body retrieval evidence
-> strict parsing
-> immutable advisory revision
-> reviewed Vulnerability binding
-> reviewed catalog membership
-> reviewed active-catalog policy
-> accepted ecosystem and evaluator registry
-> product-eligible evaluation
-> future Finding gate
```

A protected listing observation is not advisory evidence. Candidate selection
is not body authority. A retrieved body is not parsed authority. A parsed
advisory is not catalog authority. Catalog membership is not active-catalog
authority. Active-catalog status is not matching authority. Matching readiness
is not Finding authority.

Session 15 Batch 1 stops at
`product_evidence_provenance_architecture_defined`, then
`persistence_not_implemented`, `composition_unavailable`, and
`finding_unavailable`.

There is no edge from `received` to `active_eligible`, from `synthetic` to
`product_evidence_eligible`, from `withdrawn` to `product_evidence_eligible`,
or from `product_evidence_eligible` to `finding`.

## Failure and capacity

Closed failures include invalid request, unsupported source, unrecognized
advisory, malformed identity or revision, fingerprint mismatch, parser or
schema mismatch, source-registry mismatch, license rejection, synthetic
evidence, unreviewed evidence, withdrawn or quarantined revision, catalog
unavailable or mismatch, registry unavailable, missing, ambiguous, or
conflicted Vulnerability binding, replay mismatch, immutable conflict, policy
mismatch, and internal failure. Results omit provider bodies, object keys,
URLs, database URLs, stack traces, tenant fields, and Finding fields.

| Limit | Value |
| --- | --- |
| Advisory family id | 512 UTF-8 bytes |
| Family canonical form | 1024 UTF-8 bytes |
| Provider generation | 20 UTF-8 bytes |
| Aliases | 256 |
| Canonical CVE | 28 UTF-8 bytes |
| Vulnerability mappings | 1 |
| Additional ids inspected | 8 |
| Fingerprints | 64 lowercase hex |
| Provenance contract | 32768 UTF-8 bytes |
| Registry entries | 1 |
| Eligibility explanations | 8 |

No caller override. No metadata JSON.

## Confidentiality

Advisory identity, revision identity, ranges, Vulnerability binding, catalog
identity, registry entries, and eligibility results are internal. Provider
object identity, raw advisory body, and license URLs are restricted and absent
from the contract. Do not use advisory id, Vulnerability id, tenant id, or
component id as metric labels.
