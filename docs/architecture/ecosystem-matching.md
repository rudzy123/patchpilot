# First ecosystem matching architecture

Session 14 Batch 1 selects **npm** and defines the affected-version architecture. The comparator
is not implemented. Match evaluations are not persisted. Finding creation remains unavailable.
Production OSV acquisition remains disabled. Acquisition halt remains engaged.

Authority: [ADR 0030](../adr/0030-first-ecosystem-matching-architecture.md), which remains Proposed
after Session 14 Batch 1-R. [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md)
still keeps the implemented registry empty. npm is not a supported runtime ecosystem. Batch 2
follows only after this review is committed.

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
2.0.0 precedence (`npm_semver_2_0_0_precedence_v1`) and is not implemented. Prerelease identifiers
participate in that precedence. Build metadata stays on the raw version and is ignored only for
precedence. Versions that differ only in build metadata are not the same raw evidence. Leading
`v`, partial versions, and extra segments are unsupported and are not rewritten. Leading zeros and
whitespace are malformed and are not repaired. A numeric identifier longer than 20 digits is
unsupported and is not coerced through a JavaScript number. node-semver `includePrerelease: false`
is not the authority.

`introduced` is inclusive and must be the first event. The event value `0` means before every
strict SemVer version. It is not version `0.0.0`. `fixed` is exclusive. `last_affected` is
inclusive and mutually exclusive with `fixed`. `limit` is an exclusive applicability bound, not a
fix. A version at or after `limit` is outside that range and is not `unaffected` unless every
accepted range excludes it. Events are a timeline and are not reordered. A later `introduced` is
allowed only after `fixed`. `limit` must be the last event. Exact duplicate events are
contradictory.

`affected` is allowed later only when one valid range proves inclusion and no range is malformed,
unsupported, or contradictory. `unaffected` requires every accepted range to be valid and to
exclude the version. One bad range makes the whole advisory `unknown`. Empty evidence is not
`unaffected`. Missing `introduced` is not inferred.

## Outcomes

`affected`, `unaffected`, and `unknown`. This batch can construct only `unknown`, because
`affected` and `unaffected` require the missing comparator. KEV does not establish affectedness.
Explanation codes are closed and do not create Findings.

Replay of the same validated inputs, evaluator version, and policy version produces the same
outcome, catalog-ordered explanation codes, and replay fingerprint. A non-synthetic request is
not recorded as synthetic. The raw observed version is retained on the evidence record when it is
within 256 UTF-8 bytes.

## What this batch does not do

- No production evaluator
- No persisted match evidence
- No Finding, FindingObservation, tenant Evidence, or RiskCalculation
- No `finding.recalculate`
- No provider contact
- No Prisma or migration change
- No dependency or lockfile change
