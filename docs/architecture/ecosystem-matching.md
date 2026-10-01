# First ecosystem matching architecture

Session 14 Batch 1 selects **npm**. Session 14 Batch 1-R reviewed that architecture and is
committed. Session 14 Batch 2 implements one in-memory affected-version evaluator for npm.
Session 14 Batch 2-R reviewed that evaluator and is committed. Session 14 Batch 3 persists the
reviewed evidence in tenant-owned append-only rows. Finding creation remains unavailable. The
evaluator and persistence adapter are not composed into API, worker, or scheduler startup.
Production OSV acquisition remains disabled. Acquisition halt remains engaged.

Authority: [ADR 0030](../adr/0030-first-ecosystem-matching-architecture.md), which remains Proposed.
[ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md) still keeps the
implemented registry empty. `ecosystemIsImplemented('npm')` remains false. npm is not a supported
production matching ecosystem. Session 14 Batch 3 stores immutable evidence for one component
occurrence. Session 14 Batch 3-R reviewed that persistence. Next checkpoint is Session 14
branch-closure review.

## Selection

| Question | Answer |
| --- | --- |
| Selected ecosystem | `npm` |
| OSV ecosystem string | `npm` |
| PURL type | `npm` |
| Deferred | PyPI, Maven, Go, NuGet, crates.io |
| Why npm | Committed SBOM fixtures, scoped PURL tests, and synthetic OSV parser fixtures use npm. Component rows already store ecosystem, namespace, and name separately from version |
| Why not crates.io | The Session 13 listing prefix is not selection authority, and committed SBOM fixtures do not use `pkg:cargo` |
| Catalog measurements | Absent. `ECOSYSTEM` and `GIT` ranges therefore stay `unknown` |

## Identity

Identity is ecosystem + namespace + name. Version, qualifiers, and subpath are not identity.
Names are not case-folded or Unicode-normalized. `-`, `_`, and `.` stay distinct. The canonical
npm name is at most 214 UTF-8 bytes. Invalid identity evaluates to `unknown`.

Observed identity is preserved. A PURL is decoded once. `packageurl-js` remains the inventory
parser and is not the matching API.

## Versions and ranges

Raw versions are preserved. Parsing and comparison are separate. Comparison authority is SemVer
2.0.0 precedence (`npm_semver_2_0_0_precedence_v1`), implemented in memory with no added
dependency. Prerelease identifiers participate in that precedence. A prerelease below the same
core release is lower precedence, so a prerelease below a stable `fixed` boundary stays inside
the interval. Build metadata stays on the raw version and is ignored only for precedence.
Versions that differ only in build metadata have equal precedence and distinct raw evidence.
Leading `v`, partial versions, and extra segments are unsupported and are not rewritten. Leading
zeros and whitespace are malformed and are not repaired. A numeric identifier longer than 20
digits is unsupported and is not coerced through a JavaScript number. node-semver
`includePrerelease: false` is not the authority. Numeric identifiers compare as exact decimal
strings.

`introduced` is inclusive and must be the first event. The event value `0` means before every
strict SemVer version. It is not version `0.0.0`. `fixed` is exclusive. `last_affected` is
inclusive and mutually exclusive with `fixed`. `limit` is an exclusive applicability bound, not a
fix. A version at or after `limit` is outside that range and is not `unaffected` unless every
accepted range excludes it. Events are a timeline and are not reordered. A later `introduced` is
allowed only after `fixed`. `limit` must be the last event. Exact duplicate events are
contradictory.

`affected` is returned when one valid range proves inclusion, or an explicit version matches,
and no range is malformed, unsupported, or contradictory. `unaffected` requires every accepted
range to exclude the version. A `limit` that removes an otherwise included version does not prove
`unaffected` and does not drop that range out of the union. One bad range makes the whole advisory
`unknown`, including when an explicit version would otherwise match. Empty evidence is not
`unaffected`. Missing `introduced` is not inferred. Event order inside a range is not repaired.
Range-array order does not change the outcome or the replay fingerprint. Range canonicalization is
length-prefixed so event text cannot collide with a neighboring event.

## Outcomes

`affected`, `unaffected`, and `unknown`. `affected` requires positive proof. `unaffected` requires
complete exclusion by every accepted range. Malformed, unsupported, contradictory, and incomplete
evidence return `unknown`. KEV does not establish affectedness. Explanation codes are closed,
catalog-ordered, and do not create Findings. An affected outcome does not create a Finding.

Replay of the same validated inputs, evaluator version, and policy version produces the same
outcome, catalog-ordered explanation codes, and replay fingerprint. A non-synthetic request is
not recorded as synthetic. The raw observed version is retained on the evidence record when it is
within 256 UTF-8 bytes.

Session 14 Batch 3 stores that evidence on `match_evaluation_evidence` and ordered
`match_evaluation_explanation` rows. Session 14 Batch 3-R keeps the evaluator fingerprint unique
per component occurrence. Affected evidence grants no Finding authority. Unaffected evidence grants
no suppression authority. Unknown evidence is retained. The persistence adapter does not call the
evaluator. Neither factory is production-composed.

Session 15 Batch 1 defines the provenance required before any of that evidence can be product eligible. Session 15 Batch 1-R reviewed it. See [product-evidence provenance](product-evidence-provenance.md). Synthetic Session 14 rows stay synthetic. The active registries stay empty, and admission does not return `eligible`. Finding creation remains unavailable.

## What this batch does not do

- No production composition of the evaluator or the persistence adapter
- No Finding, FindingObservation, tenant Evidence, or RiskCalculation
- No `finding.recalculate`
- No provider contact
- No second ecosystem and no universal comparator export
