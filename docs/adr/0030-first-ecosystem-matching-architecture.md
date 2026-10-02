# ADR 0030: First ecosystem matching architecture

- Status: Proposed
- Date: 2026-10-01
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Implementation status

Status remains **Proposed**. This note does not accept the ADR. Current checkpoint: [current-state.md](../project/current-state.md).

- npm evaluator: implemented, production uncomposed
- Synthetic match-evaluation evidence persistence: implemented, immutable, production uncomposed
- Real product-eligible match evidence: unavailable
- Finding creation: unavailable

Sentences below that say evaluation evidence is not persisted, or that match persistence remains a later gate, record the Batch 1 and Batch 2 decision text. The follow-up section records Session 14 Batch 3 persistence. Affected and unaffected rows in that schema require synthetic origin.

Session 14 Batch 1 selects the first ecosystem and defines the matching architecture. It does
**not** implement a comparator or evaluator, persist match evaluations, create Findings, contact a
provider, or change Prisma, migrations, or dependencies. [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md)
remains the closed-registry and fail-closed policy. This ADR does not mark npm as a supported
runtime ecosystem.

## Context

[ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md) left the implemented
registry empty and named npm as the preferred candidate to evaluate after catalog measurements.
Those measurements are still absent. Session 13 listing evidence for `crates.io/` is not package
identity authority and does not select an ecosystem.

Committed repository evidence that does exist:

- Session 8 component rows store ecosystem, namespace, name, and a separate occurrence version.
- Parser, persistence, and contract fixtures use `pkg:npm/...`, including scoped `%40` namespaces.
- Synthetic OSV advisory parser fixtures use ecosystem `npm`.
- The vendored OSV schema accepts range types `SEMVER`, `ECOSYSTEM`, and `GIT`.
- `packageurl-js` is an inventory parser. It is not the matching identity API.

## Decision

### Selected ecosystem

The first ecosystem is **npm**.

- Internal identifier, OSV ecosystem string, and PURL type are exactly `npm`.
- The identifier is case-sensitive. `NPM` is not accepted.
- Ecosystem is part of package identity. The same package name in another ecosystem does not match.
- Version syntax does not select an ecosystem. Advisory identifiers do not select an ecosystem.
- Provider listing prefixes do not select an ecosystem.

The implemented registry remains **empty**. `ecosystemIsImplemented('npm')` is false. Selection
means later Session 14 batches may implement this one ecosystem. It does not make npm supported
today.

Deferred, with no fallback comparator:

| Ecosystem | Why deferred |
| --- | --- |
| PyPI | PEP 440 and name folding are a separate comparator and a separate false-positive review |
| Maven | Group plus artifact identity and Maven comparable versions are not SemVer |
| Go | Module paths, pseudo-versions, and `+incompatible` are not npm SemVer |
| NuGet | Case-insensitive identifiers and four-part versions differ from npm |
| crates.io | No committed SBOM fixture uses `pkg:cargo`. The Session 13 `crates.io/` listing prefix is not selection authority |

Linux, GIT ranges, and the other ecosystems deferred by ADR 0025 stay deferred.

Catalog range-type measurements remain absent. Because of that absence, only `SEMVER` ranges are
eligible for a future npm comparator. `ECOSYSTEM` and `GIT` are unsupported and produce `unknown`.
They do not produce `unaffected`.

### Package identity

Natural identity is `npm` + namespace + name.

- Unscoped name grammar: `^[a-z0-9][a-z0-9._-]*$`, excluding `node_modules` and `favicon.ico`.
- Namespace, when present, is `@` plus that same grammar. Scope participates in identity.
- Names are not lowercased, Unicode-normalized, or separator-folded. `-`, `_`, and `.` are distinct.
- Unicode, whitespace, and uppercase are invalid identity, which evaluates to `unknown`.
- The full canonical name, including `@scope/`, is at most 214 UTF-8 bytes.
- Version is not part of package identity.
- PURL qualifiers and subpath are non-identity for npm under `npm_purl_qualifiers_are_non_identity_v1`. Their values are not retained. Malformed qualifiers are invalid identity.
- Percent-encoding is decoded once at the PURL boundary. A second decode is not performed.
- The observed identity string is preserved. A display form that is not already canonical is invalid.

### Version evidence

Three distinct values:

1. Observed raw version, preserved exactly.
2. Parsed classification: `valid_strict_semver`, `malformed`, `unsupported`, `absent`, or `capacity_exceeded`.
3. Future comparison representation: SemVer 2.0.0 precedence. Prerelease identifiers participate. Build metadata is ignored for precedence and retained on the raw version. The representation token is `semver_2_0_0_precedence_prerelease_included_build_metadata_ignored`.

Parsing does not trim, pad segments, strip a leading `v`, drop prerelease or build data, or coerce
numbers. Invalid and unsupported versions produce `unknown`.

Comparator authority is `npm_semver_2_0_0_precedence_v1` (SemVer 2.0.0 precedence). It is **not**
implemented. A strict implementation or library is a later dependency review. Loose mode, coerce
mode, lexical order, and a generic semver library for other ecosystems are prohibited. No
dependency is added in this batch.

Prerelease policy `npm_prerelease_boundary_containment_v1` follows SemVer 2.0.0 item 11 and is not
executed in this batch:

- A prerelease is less than the same core without a prerelease.
- Numeric prerelease identifiers compare as integers. Alphanumeric identifiers compare as ASCII.
- Numeric identifiers have lower precedence than non-numeric identifiers.
- A longer prerelease list has higher precedence when the shared prefix is equal.
- An observed prerelease equal to an inclusive `introduced` boundary is inside that interval.
- An observed prerelease equal to an exclusive `fixed` boundary is outside that interval.
- An observed prerelease below a stable `fixed` boundary is inside the interval. node-semver's
  default `includePrerelease: false` behavior is not authority.
- Leading `v` is unsupported and is not rewritten. Omitted or extra core segments are unsupported
  and are not padded or truncated. Leading-zero numeric identifiers are malformed. More than 20
  digits in a numeric identifier is unsupported and is not coerced with `Number`.

Until the comparator exists, a structurally valid prerelease observation or prerelease boundary
includes `unknown_prerelease_membership_not_proven`. Build metadata stays on the raw version and
does not by itself decide affectedness. Two versions that differ only in build metadata have equal
precedence and distinct raw evidence.

### Ranges

Accepted type: `SEMVER`. Accepted events: `introduced`, `fixed`, `last_affected`, `limit`.

- `introduced` is inclusive. The exact string `0` is the OSV sentinel meaning before every strict SemVer version. It is not version `0.0.0`. It is legal only on `introduced`. Missing `introduced` is not inferred.
- `fixed` is exclusive.
- `last_affected` is inclusive and is not equivalent to `fixed`. Both in one range are contradictory.
- `limit` is an exclusive applicability bound, not a fix. A version equal to `limit` is outside that range. `limit` does not by itself prove `unaffected`. `limit` must be the last event. The sentinel `0` is rejected on `limit`.
- `introduced` must be the first event. Another `introduced` is allowed only after `fixed`. `last_affected` does not open another interval. Events are not reordered.
- Multiple ranges are a union. `affected` may later be returned when one valid range proves inclusion only if every range is valid. `unaffected` requires every accepted range to exclude the version. One malformed, unsupported, or contradictory range makes the advisory `unknown`.
- Exact duplicate events and exact duplicate explicit versions are contradictory.
- Numeric order of boundary values is not decided here. A structurally valid range still cannot become `affected` or `unaffected`.
- Empty range evidence is `unknown`, not `unaffected`.

### Outcomes

Principal outcomes are `affected`, `unaffected`, and `unknown`.

`affected` and `unaffected` require a comparator proof. This batch admits neither.
`unaffected` is the ADR 0025 `not_affected` status and is returned only for proven exclusion.
`unknown` covers ADR 0025 `indeterminate`, `unsupported`, and `withdrawn`, plus malformed,
contradictory, incomplete, untrusted, and comparator-absent cases. Explanation codes keep those
distinctions. No explanation code creates a Finding. KEV membership does not establish
affectedness.

### Evidence and determinism

The request and the evidence record are closed, immutable, and versioned. Replay identity is a
SHA-256 over the canonical field encoding, policy version, and evaluator version. It does not use
wall-clock time, locale, property order, randomness, KEV state, or the active catalog pointer.
Evaluation evidence is not persisted. Synthetic advisory evidence is labeled synthetic only when
the request's source, origin, and provenance fields are the closed synthetic tokens. Any other
request is recorded as `untrusted_not_recorded` and is not relabeled synthetic. The raw observed
version is retained when it is within 256 UTF-8 bytes; a longer version is represented by its
SHA-256 only. Explanation codes are emitted in closed-catalog order.

Package identity and raw versions are tenant-sensitive when bound to an observation. They are not
metric labels.

Finding creation remains unavailable.

## Alternatives considered

Selecting crates.io because Session 13 listed that prefix was rejected. Selecting every candidate
behind one semver comparator was rejected. Waiting again for a catalog measurement was rejected for
this batch because non-SEMVER ranges already fail closed to `unknown`, and the committed SBOM and
PURL evidence is npm.

## Consequences

Session 14 Batch 2 implements the npm comparator in memory. Dependency review closed without a
library (`closed_no_library_strict_semver_2_0_0_comparator`). Match persistence and Findings remain
later gates. Production OSV acquisition stays disabled.

## Security and tenancy

Evaluation requests reject tenant, organization, asset, Finding, risk, and provider-identity
fields. No outbound network is introduced. Inventory PURL normalization remains a separate path
and is not reused as silent qualifier dropping beyond the explicit npm non-identity qualifier
policy.

## Operational failure plan

There is no production operation. The in-memory evaluator returns `unknown` when it cannot prove
inclusion or exclusion, and it creates no Finding.

## Follow-up

Session 14 Batch 1-R adversarially reviewed this architecture and corrected timeline validation,
limit semantics, the multiple-range poison rule, SemVer precedence rules, provenance labeling, and
over-limit version classification. Batch 1 and Batch 1-R are committed.

Session 14 Batch 2 implements `evaluateSelectedEcosystemAffectedVersion` for npm. Accepted range
type remains `SEMVER`. Accepted events remain `introduced`, `fixed`, `last_affected`, and `limit`.
`introduced` and `last_affected` are inclusive. `fixed` is exclusive. `limit` is an exclusive
applicability bound and does not by itself prove `unaffected`. Prerelease identifiers use SemVer
2.0.0 precedence. Build metadata is ignored for precedence and retained on the raw version.
Evaluation evidence stays in memory. Finding creation remains unavailable. The evaluator is
production-uncomposed. Match-evaluation persistence and Finding writes remain later gates.

Session 14 Batch 2-R reviewed that evaluator. A `limit` that removes an otherwise included
version is not an exclusion proof, so `unaffected` still requires every accepted range to exclude
the version. Range fingerprints are length-prefixed. Oversized and hostile requests return
`unknown` or a strict request rejection. Comparator failure returns `unknown` and does not create
a Finding. Batch 2 and Batch 2-R are committed.

Session 14 Batch 3 persists that reviewed evidence. The durable model is
`match_evaluation_evidence` plus ordered `match_evaluation_explanation` rows in
`20261001120000_match_evaluation_evidence_persistence` (frozen SHA-256
`9df1146eee813cd3359e1d043475b49df8a083e397aa750373feef039ee8b63e`). Each row binds one tenant
component occurrence and copies advisory identity, source, origin, and fingerprints. There is no
advisory-body foreign key. The adapter does not recalculate affectedness. Affected rows grant no
Finding authority. Unaffected rows grant no suppression authority. Unknown rows are retained.
Production composition does not construct the adapter.

Session 14 Batch 3-R reviewed that persistence. The evaluator replay fingerprint does not include
tenant or occurrence identity, so uniqueness is `(organization_id, component_occurrence_id,
replay_fingerprint)`. Another occurrence may store the same fingerprint only when package identity,
raw version, advisory identity, fingerprints, outcome, and explanation codes agree. Disagreement is
`immutable_conflict` and does not overwrite the prior row. `cisa_kev` evidence can be stored only
as `unknown` with `unknown_kev_not_affectedness_authority`. Affected and unaffected evidence require
synthetic fixture origin. Parent version, name, and namespace comparisons use UTF-8 bytes.
Explanation inserts require the parent row to belong to the current transaction. Session 14 branch-closure review passed and the session is merged. Current checkpoint: [current-state.md](../project/current-state.md).
