# ADR 0025: Ecosystem-aware package identity and version evaluation

- Status: Accepted
- Date: 2026-09-03
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as architectural direction on this feature branch. Merge to `main` remains subject to normal
pull-request review. This ADR does **not** implement package normalization, PURL parsing, version
parsing, version comparison, affected-range evaluation, a comparator registry, a comparator library,
a semver dependency, ecosystem-specific dependencies, OSV transport, OSV runtime, ZIP or archive
processing, configuration, domain contracts, Prisma, migrations, affected-data persistence, provider
schemas, a parser, matching, Finding writes, Outbox events, BackgroundJob types, workers,
schedulers, APIs, permissions, or web UI.

This ADR does **not** supersede [ADR 0010](0010-osv-correlation.md) as the future correlation ADR,
[ADR 0011](0011-cisa-kev-enrichment.md) as the future Finding-enrichment ADR,
[ADR 0021](0021-vulnerability-intelligence-import-foundation.md) as the Session 9 import-only catalog
and zero-Finding foundation, [ADR 0022](0022-intelligence-provider-status-authorization.md) as
sanitized provider-status authorization, [ADR 0023](0023-provider-neutral-cve-identity.md) as
canonical CVE identity and the four-condition Finding-write gate, or
[ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md) as the OSV
affected-version authority and instance-owned acquisition direction.

It **closes** the package-identity and fail-closed evaluation portion of
[OD-15](../architecture/open-decisions.md). Exact OSV event-edge behavior, comparator selection,
numeric complexity limits, and the first implemented ecosystem remain future implementation work.
Finding evidence and lifecycle are accepted by [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md). That ADR does not implement writes.

## What this ADR is and is not

| Kind | Meaning in this ADR |
| --- | --- |
| Accepted architecture | Binding for later Session 11 and Session 12 design and implementation batches |
| Initial supported scope | The closed registry policy, fail-closed results, and empty implemented set |
| Deferred ecosystem support | Named ecosystems that must not be evaluated until separately reviewed |
| Future implementation | Required later; **not** present in Batch 1C |
| Rejected | Must not be the approved matching foundation |

Batch 1C records decisions only. No evaluator, comparator, or matching runtime exists after this ADR.

## Context

Session 11 Batch 1A established, and [ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md)
preserved:

1. PatchPilot cannot authoritatively determine whether a tenant component version is affected by an
   advisory today.
2. OSV is the future authoritative provider for affected-package and affected-version data.
3. CISA KEV remains an independent exploitation signal.
4. Tenant SBOMs provide tenant software inventory, not vulnerability advisory authority.
5. Tenant package inventory must not be sent to OSV.
6. OSV acquisition is instance-owned and precedes matching.
7. Current `VulnerabilitySourceRecord` normalized JSON is insufficient for matching. The v1
   `VulnerabilityNormalizedJson.affectedPackages` shape stores a free-form `versionRange` string and
   is **not** an approved matching authority.
8. Future OSV persistence must preserve structured packages, ranges, events, explicit versions,
   revisions, and withdrawals.
9. Session 11 remains zero-Finding.
10. Finding writes remain deferred beyond Session 11.
11. This ADR governs package identity and affected-version evaluation.
12. Match evidence and Finding lifecycle are governed by [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md).

This ADR must not reverse or weaken those decisions.

Additional repository facts:

- Session 8 persists tenant-owned `Component` and `ComponentOccurrence` rows, including known and
  unknown versions (`versionKnown`). Inventory PURL normalization strips version, qualifiers, and
  subpath for **Component** identity. That inventory persistence is **not** matching-identity policy.
- `packageurl-js` is an approved Session 8 SBOM parser dependency. It is **not** an approved matching
  identity parser, comparator, or transitive runtime API for evaluation.
- No OSV catalog body, range-type inventory, or affected-package measurement exists in the
  repository. Exact OSV ecosystem strings, range-type mix, and identity quality are therefore
  **unquantified**.
- No comparator, version parser, or affected-version evaluator exists.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. No OSV runtime exists.

Without a closed, ecosystem-aware identity and fail-closed evaluation policy, later matching would
invent a generic name matcher, treat lexical or one-semver comparison as universal, or return
`not_affected` for unknown, unsupported, or malformed data.

## Decision

### 1. Core evaluation decision

Package identity and version comparison are **ecosystem-specific**.

- There is **no** generic package-name matcher.
- There is **no** generic lexical version comparator.
- There is **no** assumption that one semver implementation is correct for every ecosystem.
- A **closed registry** controls supported ecosystems.
- Unsupported ecosystems **fail closed**.
- Unknown or unparsable component versions do **not** create Findings.
- Unsupported range types do **not** become `not_affected`.
- Malformed provider data does **not** become `not_affected`.
- Only a deterministic **affected** result may eventually contribute to Finding creation.
- Evaluation itself remains read-only and zero-Finding in Session 11 and Session 12.
- Finding creation remains governed by [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)
  and a later explicit implementation authorization.

This ADR does **not** claim that an evaluator exists.

### 2. Definitions

#### Package identity

A provider-neutral but ecosystem-aware identity used to determine whether a tenant component and one
OSV affected-package record refer to the same package.

It is **not**:

- a component display name
- a CISA `product` string
- a CISA `vendorProject` string
- a repository URL
- a CPE string by default
- a CVE
- an OSV advisory ID
- an arbitrary alias
- an unparsed PURL string
- a package version

#### Component observation

A tenant-owned observation of a package and version within an SBOM ingestion and
`ComponentOccurrence`. It includes a known or unknown version state. It must **not** redefine the
global package identity.

#### Affected-package rule

A provider-attributed OSV affected-package entry containing a supported ecosystem/package identity
and one or more affected-version rules.

#### Affected-version rule

A structured rule composed of:

- range type
- ordered events where the type supports them
- explicit affected versions where present
- provider revision
- deterministic source order or normalized order
- **no** free-form `versionRange` interpretation

#### Comparator

An ecosystem-specific, deterministic implementation that validates and orders or compares versions
under one explicitly supported version scheme.

#### Evaluator

A pure, framework-independent operation that compares:

- one validated tenant component observation
- one validated provider affected-package rule
- one pinned provider revision
- one evaluator version

and returns a strict result without performing persistence or external I/O.

### 3. Package identity model

The future **logical** package identity is:

- one closed ecosystem identifier
- one normalized package name
- one normalized namespace where the ecosystem requires it
- optional versionless normalized PURL as a **derived** identifier
- explicit normalization version

The authoritative comparison key must **not** be a single free-form display name.

Requirements:

- ecosystem participates in identity
- namespace participates when relevant
- package name participates
- version is **not** part of the versionless package identity
- qualifiers are **not** automatically identity
- subpath is **not** automatically identity
- repository URL is **not** identity
- CPE is **not** identity in the initial design
- provider prose is **not** identity
- tenant aliases are **not** identity
- CVE and advisory IDs are **not** package identity
- normalization must be deterministic
- normalization must be versioned
- malformed values fail closed
- no Unicode normalization occurs unless explicitly required and documented for a supported
  ecosystem
- no cross-ecosystem package name match exists

A tenant `Component.identityKey` remains organization-scoped inventory identity. Matching must map a
resolved observation to a registry identity. Inventory identity and matching identity must not be
treated as interchangeable without that mapping.

This conversion does **not** exist.

### 4. Normalized PURL decision

A normalized versionless PURL is useful but **not sufficient** as the sole authoritative identity.

Reasons:

- PURL type names do not always equal OSV ecosystem names
- some ecosystems require normalization not encoded by a generic PURL parser
- version, qualifiers, and subpath have different semantics
- distribution package ecosystems may require distro context
- Go module, Maven, npm scope, and other namespace rules differ
- unsupported or malformed PURLs must not fall back to name matching

Future matching may use PURL as an **input** to the closed ecosystem registry. The registry must
convert an accepted PURL and provider package identity into one canonical internal identity.

This conversion does **not** exist. Session 8 `normalizePackageUrl` is inventory persistence, not
matching-identity policy. Matching must not treat `packageurl-js` as a transitive runtime API.

### 5. PURL field treatment

#### Version

Observation only. It is not part of versionless package identity.

#### Qualifiers

Excluded from the initial identity unless the ecosystem registry entry explicitly promotes a
specific qualifier as identity.

Unknown or unreviewed qualifiers that can change package identity return `unsupported`. Do **not**
map them to `indeterminate` (reserved for unknown or unparsable tenant versions) or `not_affected`.
Do **not** silently drop security-relevant qualifiers during matching. A qualifier may be ignored
only when that registry entry explicitly classifies it as non-identity.

Current SBOM inventory persistence strips qualifiers from the versionless Component PURL. That
inventory behavior must not be reused as silent matching authorization.

#### Subpath

Excluded from package identity. It identifies a portion of a package, not a distinct provider
package, unless a future ecosystem policy explicitly says otherwise.

#### Repository or download URL

Never an identity or fetch target. Do not fetch URLs contained in PURLs, provider records, package
metadata, or advisory references.

### 6. Initial ecosystem registry

The implemented registry set is **empty**. No ecosystem is currently supported.

Candidate initial ecosystems to **evaluate**, not to treat as implemented or authorized:

- npm
- PyPI
- Maven
- Go
- NuGet
- crates.io

Acceptance of an ecosystem into the eventual **runtime** registry requires all of:

1. Exact OSV ecosystem identifier.
2. Exact PURL type mapping.
3. Package-name normalization.
4. Namespace rules.
5. Case-sensitivity rules.
6. Version parser.
7. Version comparator.
8. Supported OSV range types.
9. Boundary and prerelease tests.
10. Malformed-input tests.
11. Dependency review where a library is needed.
12. Deterministic behavior.
13. Complexity limits.
14. Independent adversarial review.

This ADR therefore distinguishes:

| Set | Meaning now |
| --- | --- |
| Candidate initial ecosystems | Named above; not implemented; not authorized |
| Implemented ecosystems | **Empty** |
| Unsupported ecosystems | Everything else, including deferred Linux, GIT, CPE, and unreviewed OSV ecosystems |

Do **not** describe npm, PyPI, Maven, Go, NuGet, or crates.io as currently supported.

Session 12 should begin with **one** narrowly selected ecosystem, prove the complete identity and
comparison model, and add other ecosystems only through reviewed registry entries. There is **no**
generic fallback.

The first ecosystem is **not** selected in this ADR. Repository evidence does not quantify OSV range
types, identity quality, or alias behavior in the still-unreviewed OSV source. Selection waits for
catalog measurements and a separate dependency and evaluator design review. npm is the preferred
candidate **to evaluate first** after those measurements, not an implemented or authorized
ecosystem.

### 7. Ecosystem identifiers

Future registry entries must define:

- internal registry key
- exact OSV ecosystem strings accepted
- exact PURL types accepted
- normalization version
- package identity parser
- component version parser
- advisory version parser
- supported range types
- comparator identifier and version
- maximum input lengths
- maximum range and event counts
- timeout or complexity budget
- unsupported behavior

No provider or tenant may add registry entries at runtime. No environment variable may add an
arbitrary ecosystem or comparator. No plugin loading. No dynamic module path. No `eval`. No remote
comparator code.

Exact OSV ecosystem strings and PURL type mappings below are **commonly cited labels for later
verification**. They are not accepted runtime identifiers.

### 8. Candidate ecosystem analysis

None of the following candidates is implemented. Exact parser, comparator, and range behavior require
later proof against the authoritative OSV schema, OSV documentation, and synthetic tests. Do not
treat this analysis as authorization.

#### npm

- Commonly cited OSV ecosystem label: `npm`. Commonly cited PURL type: `npm`. Both require later
  verification.
- Scoped packages typically encode scope as namespace and the unscoped name as name
  (`@scope/name`). Scope participates in identity.
- Case-sensitivity, canonical registry lowercase rules, and non-canonical names require later
  review. Do not assume display-case equality.
- Semantic-version expectations are common but not universal. Historical or malformed registry
  values may not be strict semver.
- Prerelease ordering and build-metadata ignore/compare rules must be defined by a reviewed npm
  policy. Do not guess.
- Package aliases must not collapse distinct identities.
- A standard semver dependency is **not** approved. If later selected for npm `SEMVER` ranges, it
  needs an independent dependency and semantics review, including strict parsing, no coerce/loose
  mode, and non-semver rejection.

npm is **not** currently supported.

#### PyPI

- Commonly cited OSV ecosystem label: `PyPI`. Commonly cited PURL type: `pypi`. Both require later
  verification. PURL type and OSV ecosystem name are not assumed equal.
- PEP 503 name normalization (case-insensitive; hyphen, underscore, and period folding) is the
  expected identity direction, subject to later proof.
- PEP 440 version semantics include epochs, local versions, prereleases, post releases, and
  developmental releases. Generic semver must **not** evaluate PyPI.
- A Python-compatible comparator or a reviewed implementation is required before support. None is
  selected.

PyPI is **not** currently supported.

#### Maven

- Group and artifact together form package identity. PURL namespace and name mapping must be proven
  against OSV Maven records.
- Maven comparable-version semantics, including qualifiers, are not semver and are not lexical.
- Case behavior requires later review.
- A Maven-specific comparator is required. None is selected.

Maven is **not** currently supported.

#### Go

- Commonly cited OSV ecosystem label: `Go`. Commonly cited PURL type: `golang`. Both require later
  verification. Type and ecosystem names are not assumed equal.
- Module paths, case sensitivity, semantic import paths, pseudo-versions, and `+incompatible`
  participate in identity or version semantics and must not be reduced to generic semver without
  reviewed rules.
- GIT range interaction is **not** authorized by selecting Go as a candidate. GIT remains
  unsupported in the initial matcher.

Go is **not** currently supported.

#### NuGet

- Package ID case behavior and four-part version normalization require a NuGet-specific policy.
- Prerelease labels and SemVer differences from npm must not be assumed equivalent.
- Commonly cited OSV ecosystem label: `NuGet`. Commonly cited PURL type: `nuget`. Both require later
  verification.
- A NuGet-specific comparator is required. None is selected.

NuGet is **not** currently supported.

#### crates.io

- Commonly cited OSV ecosystem label: `crates.io`. Commonly cited PURL type: `cargo`. Both require
  later verification.
- Crate-name rules, semver expectations, prerelease and build metadata, and Cargo version
  requirements require later review.
- Do not assume npm semver equivalence.

crates.io is **not** currently supported.

### 9. Deferred ecosystems

Explicitly deferred until separately reviewed:

- Debian
- Alpine
- Ubuntu
- Red Hat
- other Linux distributions
- Packagist
- RubyGems
- Hex
- Pub
- SwiftURL
- OSS-Fuzz
- GitHub Actions
- Git ranges
- CPE-based ecosystems
- arbitrary repository-based packages
- unsupported and future OSV ecosystems

Reasons include epochs, distro revisions, architecture qualifiers, repository provenance, commit
graph requirements, ecosystem-specific normalization, absent comparators, and insufficient tenant
identity.

Unsupported ecosystems must **not** fall back to:

- lexical version comparison
- string equality against ranges
- package-name-only comparison
- PURL-type-only matching
- CVE matching
- CISA text matching

They return `unsupported`. They do not create Findings.

### 10. Version range types

Analyze OSV range types as design principles. Exact edge behavior requires later implementation
proof. Do not treat this section as a parser specification.

#### SEMVER

Future support may use an explicitly reviewed semver comparator **only** for registry entries that
authorize `SEMVER`.

Requirements:

- exact parser behavior defined
- invalid versions rejected
- prerelease semantics defined
- build metadata behavior defined
- no loose or coercive parsing
- no global fallback
- finite input
- finite event list
- deterministic ordering

Do **not** approve one generic semver dependency for all ecosystems. Do **not** install a semver
library in Batch 1C.

#### ECOSYSTEM

Support requires an ecosystem-specific comparator registered for that ecosystem. Do **not** route
all `ECOSYSTEM` ranges through semver. If no comparator exists, return `unsupported`. Do not return
`not_affected`.

#### GIT

Deferred from the initial matcher unless a complete, local, bounded commit identity and ancestry
model exists.

Do not:

- fetch repositories
- resolve remote commits
- call Git hosting APIs
- trust advisory repository URLs
- make network requests from an evaluator

GIT ranges must return `unsupported` in the initial implementation.

### 11. Range-event semantics

Future handling of `introduced`, `fixed`, `last_affected`, and `limit` follows these principles.
Exact algorithm proof belongs to Session 12 evaluator tests against the authoritative OSV schema,
authoritative OSV documentation, synthetic edge cases, and differential tests where a trusted
reference implementation exists. Do not invent sentinel behavior.

Requirements:

- events are ordered and validated under the selected range comparator
- malformed event sequences fail closed
- overlapping ranges are evaluated deterministically
- multiple ranges are logically combined according to reviewed OSV semantics
- multiple affected-package entries are handled independently
- explicit versions are preserved separately
- no free-form range expression parser
- no lexical ordering
- no event repair
- no silent event reordering unless deterministic normalization explicitly authorizes it and records
  the original order
- before evaluating, parser limits bound the number of ranges and events

#### Introduced

Begins an affected interval. OSV may document a special starting sentinel. Implementation must
verify that sentinel against provider semantics. This ADR does **not** invent one.

#### Fixed

Excludes the fixed version and later versions from that affected interval unless another range
reintroduces impact. Exact inclusive/exclusive behavior must be proven in evaluator tests.

#### last_affected

Includes the last affected version. It must **not** be treated as equivalent to `fixed`.

#### limit

Defines an upper limit according to OSV range semantics. It must not be guessed from lexical
ordering. If the selected comparator cannot represent the event safely, return `unsupported`.

### 12. Explicit affected versions

OSV may provide explicit versions separately from ranges.

Requirements:

- versions preserved exactly within bounded input limits
- ecosystem parser validates each version before evaluation
- membership uses comparator-defined equality or canonical ecosystem-specific equality
- malformed explicit versions make the affected entry invalid provider data: they must not be
  activated as valid evaluator input, must not return `not_affected`, and must not be mapped to
  `indeterminate` (reserved for unknown or unparsable tenant versions)
- duplicate versions are normalized deterministically
- no string trimming or coercion unless the ecosystem policy explicitly requires and records it
- explicit versions do not override withdrawn status
- explicit versions and ranges are combined according to reviewed OSV semantics, not guessed

An **explicit-version-only** first evaluator slice is architecturally acceptable for one later
approved ecosystem if:

- it is clearly labeled as supporting explicit-version entries only
- affected entries that also contain unsupported ranges are **not** partially interpreted as
  complete `not_affected` evidence
- unsupported residual rules keep the final result `unsupported` or `indeterminate` unless a
  positive explicit-version match is independently sufficient under verified semantics

This evaluator is **not** implemented in Batch 1C.

### 13. Withdrawn advisory behavior

A withdrawn advisory must produce `withdrawn`.

It must **not** produce `affected` or `not_affected`.

A withdrawn advisory must not authorize Finding creation. Future provider records and prior match
evidence remain historically preserved.

Withdrawal does not:

- delete historical evaluations
- delete Findings
- automatically close Findings
- remove historical provider snapshots

Finding lifecycle is accepted by [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md). That ADR does not implement writes.

### 14. Unknown and malformed behavior

#### Unknown component version

Return `indeterminate`.

Conditions include:

- `versionKnown` false
- version absent
- blank version
- placeholder version
- versionless observation without a separate known version
- component version fails an otherwise supported parser

No Finding creation.

#### Unsupported ecosystem or range type

Return `unsupported`. No Finding creation.

#### Malformed provider affected data

Do **not** return `not_affected`.

Preferred:

- fail the advisory revision as invalid provider data
- quarantine or reject it during ingestion
- do not activate malformed normalized affected data
- if corruption is encountered at evaluation time, return a safe internal or invalid-source error
- do not create a Finding

#### Malformed tenant package identity

Return `invalid_input` as a `Result`/`AppError`, or `unsupported` when the input belongs to an
unsupported ecosystem. Do not guess. Existing domain error codes remain unchanged in this batch;
future implementation should map invalid input to the existing `validation` code unless a later
contract ADR adds a narrower code.

### 15. Strict result model

Normal evaluation statuses:

- `affected`
- `not_affected`
- `indeterminate`
- `unsupported`
- `withdrawn`

Errors, through `Result`/`AppError` rather than as normal evaluated statuses:

- invalid input
- invalid source record
- persistence unavailable
- evaluator internal failure
- complexity or timeout failure

The pure evaluator does not perform persistence. Persistence-unavailable errors belong to
orchestration.

#### affected

Meaning:

- component package identity exactly matches a supported affected package
- component version is known and valid
- the affected rule is supported
- deterministic evaluation proves inclusion
- advisory revision is not withdrawn

Future affected output must include bounded structured proof.

#### not_affected

Meaning:

- identity and version are supported and valid
- relevant authoritative rules have been fully evaluated
- deterministic evaluation proves exclusion

`not_affected` must **never** be returned merely because:

- ecosystem unsupported
- range type unsupported
- component version unknown
- provider data malformed
- one of several rules could not be evaluated
- package identity normalization failed
- provider catalog unavailable

#### indeterminate

Meaning:

- the package identity may be valid and supported
- evaluation cannot decide because tenant version evidence is absent, unknown, or unparsable
- no Finding creation

#### unsupported

Meaning:

- ecosystem, PURL mapping, range type, comparator, or rule combination is outside the closed
  implementation registry
- no Finding creation

#### withdrawn

Meaning:

- provider revision is withdrawn
- no positive affected decision
- no Finding creation
- later lifecycle decisions remain separate

### 16. Positive-proof contract

Minimum future structured proof for `affected` is assembled in two layers. This is a future
match-evaluation output, not a Batch 1C implementation.

Pure evaluator proof binds only:

- evaluator version
- input fingerprint
- observed component version
- normalized package identity
- provider revision/content identity
- affected-package record ID
- matched rule kind
- matched range type when applicable
- matched event or explicit-version identity
- normalization versions

Orchestration-wrapped persisted evidence, under [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md), may additionally bind trusted
tenant locators and catalog pointers that the pure evaluator must not accept or emit:

- evaluation timestamp
- tenant Organization ID
- Asset ID
- SBOM ingestion ID
- Component ID
- ComponentOccurrence ID
- Vulnerability ID
- VulnerabilitySourceRecord or future normalized provider revision ID
- OSV advisory ID

Do **not** include:

- unrestricted raw OSV JSON
- full provider object body
- unbounded version lists
- unbounded event arrays
- provider prose
- URLs
- tenant package inventory beyond the one evaluated occurrence
- KEV provider text
- risk score
- remediation instruction

Separation:

- the **pure evaluator** receives provider package/rule and tenant component identity/version and
  returns package/version proof without performing authorization
- **orchestration** wraps that proof with trusted tenant locators for future persistence
- the evaluator itself has no repository or tenant authorization
- persisted match evidence includes tenant IDs

Tenant IDs do **not** belong in the pure evaluator result. They belong in orchestration-wrapped
persisted evidence under [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md).

### 17. Purity and source boundaries

The future evaluator must be pure and framework-independent.

It must not import or invoke:

- Prisma
- database repositories
- provider HTTP
- object storage
- parser worker
- Redis
- BullMQ
- Fastify
- Next.js
- `process.env`
- filesystem
- network
- timers except an injected evaluation budget abstraction if needed
- FindingRepository
- FindingObservationRepository
- EvidenceRepository
- RiskCalculationRepository
- ComponentRepository
- ComponentOccurrenceRepository
- CISA transport
- KEV membership as matching authority
- OSV transport
- dynamic module loading
- `eval`
- remote code
- plugins from configuration

Inputs are already validated records. Output is deterministic for the same package identity, same
component version, same provider revision, and same evaluator version. No current time may be read
implicitly. Evaluation timestamp belongs to orchestration, not pure comparison, unless explicitly
injected.

### 18. Complexity and denial-of-service limits

Future evaluation must be finite. At minimum:

- package-name bytes
- namespace bytes
- PURL bytes
- version bytes
- affected-package count per advisory
- range count per affected package
- event count per range
- explicit-version count
- alias count where relevant
- comparator operation count
- evaluation wall-clock budget
- total normalized output size
- recursion prohibited or bounded
- no catastrophic regular expressions
- no unbounded sorting
- no network access
- no repository checkout
- no Git ancestry traversal in the initial implementation
- no archive processing in the evaluator

Limits must be typed and fail closed. Exact values remain for a later configuration and
implementation design. Batch 1C adds no configuration.

### 19. Comparator ownership and versioning

Every supported registry entry must identify:

- ecosystem key
- identity normalization version
- component-version parser version
- advisory-version parser version
- comparator implementation identifier
- comparator version
- supported range types
- evaluator version

Changes to normalization or comparison semantics must:

- create a new version
- preserve prior match evidence
- trigger later controlled reevaluation
- never silently reinterpret historical evidence
- never mutate historical evaluations

No comparator version may be inferred solely from a package dependency version without recording an
application-owned semantic version.

### 20. Dependency decision

Do **not** select or add a dependency in Batch 1C.

An independent dependency review is required before each ecosystem implementation.

Review criteria:

- exact pinned version
- supported syntax and semantics
- strict parsing mode
- no coercive or loose mode
- native code
- install or postinstall scripts
- regex complexity
- malformed-input behavior
- license
- maintenance status
- supply-chain history
- browser/server assumptions
- deterministic behavior
- maximum input behavior
- compatibility with Node.js 24
- pnpm release-age policy
- whether an existing approved runtime dependency can be reused

Do not use a transitive dependency as a runtime API. Do not approve one generic semver dependency
for all ecosystems. Do not reuse Session 8 `packageurl-js` as an undeclared matching API.

### 21. Potential first ecosystem

**No first ecosystem is selected** until OSV catalog measurements and affected-range inventory are
complete.

npm remains the preferred candidate to evaluate first after those measurements because:

- CycloneDX commonly supplies npm PURLs in current parser tests and fixtures
- scoped package identity is representable
- OSV is expected to support npm affected data, subject to source verification
- SEMVER behavior may later be implemented with a rigorously reviewed dependency
- the end-to-end identity path is relatively testable

Identified npm risks:

- npm aliases
- non-canonical package names
- scoped package parsing
- semver loose/coerce modes
- prerelease rules
- build metadata
- non-semver historical versions
- OSV entries with `ECOSYSTEM` or `GIT` ranges
- multiple range types

Those risks, plus the absence of an OSV range-type inventory in this repository, prevent selecting
npm as the first implementation ecosystem now.

npm is **not** implemented.

### 22. Provider-data activation boundary

Future OSV ingestion must not activate provider records that violate the strict affected-data schema
selected for the catalog scope. Unsupported but structurally valid ecosystems may be stored.

Distinguish:

| Kind | Catalog fate | Evaluation |
| --- | --- | --- |
| Malformed provider data | Parser or semantic validation failure; cannot be activated as valid normalized data | Error / invalid source; never `not_affected` |
| Structurally valid but unsupported matching data | May be retained as provider-attributed catalog data | `unsupported`; does not enter affected-version evaluation; does not create a Finding |

The OSV catalog need not support every ecosystem before activation. Catalog scope must record:

- what was acquired
- what was parsed
- what is structurally valid
- what evaluator ecosystems are supported

This ADR does not implement that catalog.

### 23. OSV range interpretation

This ADR avoids claiming exact OSV event semantics without source verification.

A later implementation batch must verify semantics against:

- authoritative OSV schema
- authoritative OSV documentation
- synthetic edge cases
- differential tests where a trusted reference implementation exists

Design principles are recorded now. Exact edge behavior requires implementation proof. Do not copy
provider documentation verbatim. Do not include real advisories as fixtures.

### 24. KEV relationship

KEV remains outside the affected-version evaluator.

The evaluator must not:

- query KEV
- require KEV membership
- increase match confidence based on KEV
- return `affected` because a CVE is in KEV
- match through CISA vendor or product text
- use KEV due dates
- use known-ransomware status

After a future deterministic `affected` result and Finding creation, active KEV membership may be
attached or derived independently. No KEV risk weight is authorized.

### 25. Zero-Finding boundary

Session 11 remains zero-Finding. This ADR prohibits:

- Finding creation
- Finding update
- FindingObservation creation
- Evidence creation
- match-evaluation persistence
- RiskCalculation creation
- `finding.recalculate`
- tenant matching runtime
- matching jobs
- package reconciliation
- advisory fan-out
- automatic Finding close or reopen

This ADR describes evaluator architecture only. The first actual evaluator implementation belongs to
Session 12 and must also remain zero-Finding.

Finding writes remain blocked until:

1. OSV acquisition and affected data are implemented.
2. At least one ecosystem registry entry is implemented and reviewed.
3. Deterministic affected-version evaluation exists.
4. Match evidence is designed under ADR 0026.
5. Finding lifecycle and idempotency are accepted.
6. A later session explicitly authorizes Finding writes.
7. Tenant isolation and replay are proven.

Do not weaken [ADR 0023](0023-provider-neutral-cve-identity.md) or
[ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md). Matching remains
Session 12 or later. Finding writes remain Session 13 or later, subject to all gates including the
ADR 0023 four-condition gate.

### 26. Risk boundary

- evaluator results are not risk scores
- no hard-coded weights
- no KEV weight
- no OSV severity weight
- no `finding.recalculate` event
- no RiskCalculation creation
- `unsupported` and `indeterminate` are not low risk
- `not_affected` does not imply global safety beyond the evaluated package, version, and advisory
  revision
- risk integration is a later versioned policy decision

No risk code is added. The production policy engine remains without approved scoring.

### 27. Tenant-isolation boundary

The pure evaluator is tenant-agnostic. It does not authorize access, query tenant tables, or accept
a client-supplied `organizationId` as proof of scope.

Orchestration, when it exists later, must:

- reload the tenant-owned `Component` / `ComponentOccurrence` with the authorized organization
  predicate from trusted session or job context
- pass only the already authorized identity and version into the evaluator
- wrap evaluator proof with trusted tenant locators before any future persistence
- process one organization's observation per evaluation unit
- never scan all tenants from a global advisory
- never send tenant package inventory to a provider

`Component` and `ComponentOccurrence` remain tenant-owned. Logical package identity is not
tenant-owned and is not a global component catalog of tenant names. Provider affected-package rules
remain instance-owned. Future persisted match evidence is tenant-owned and must include the
authorized organization.

Looking up a package name is not authorization. Evaluator output is not a Finding.

### 28. Runtime enablement

This ADR does **not** enable OSV, matching, or evaluation. `INTELLIGENCE_OSV_ENABLED=true` remains
rejected. No environment-variable behavior changes. No comparator may be enabled by configuration.

## Alternatives considered

| Alternative | Disposition | Rationale |
| --- | --- | --- |
| Generic package-name matcher | **Rejected** | Cross-ecosystem homonyms; ignores namespace and ecosystem |
| Generic lexical version comparator | **Rejected** | Wrong ordering for semver, PEP 440, Maven, NuGet, and distro revisions |
| One semver library for every ecosystem | **Rejected** | Semver is not PEP 440, Maven, NuGet, or Go module policy |
| Versionless PURL as sole authoritative identity | **Rejected** as sole key | PURL type ≠ OSV ecosystem; qualifier/subpath/version semantics differ; distro context missing |
| Unparsed PURL string equality | **Rejected** | Encoding variants and unreviewed qualifiers |
| CPE as initial identity | **Rejected** | Not ecosystem package identity; deferred |
| CISA `vendorProject` / `product` matching | **Rejected** | KEV is an exploitation signal, not package identity |
| CVE or OSV ID as package identity | **Rejected** | Advisory identifiers, not packages |
| Tenant aliases as identity | **Rejected** | Untrusted and organization-local |
| Fallback to name-only or PURL-type-only matching | **Rejected** | False `affected` / `not_affected` |
| Treat unknown version as `not_affected` | **Rejected** | Absence of evidence is `indeterminate` |
| Treat unsupported range as `not_affected` | **Rejected** | Fail closed with `unsupported` |
| Repair malformed events or versions | **Rejected** | Silent repair hides provider-data failure |
| Evaluate GIT ranges by fetching repositories | **Rejected** | SSRF, unbounded work, untrusted URLs |
| Runtime plugin / env-var ecosystem registry | **Rejected** | Unreviewed comparators and remote code |
| Select npm now as the first implemented ecosystem | **Rejected for Batch 1C** | No OSV range-type inventory or identity-quality measurement exists |
| One-ecosystem-first Session 12 approach | **Accepted as approach** | Prove the model before expanding the registry |
| Explicit-version-only first evaluator slice | **Accepted as a later labeled slice** | Must not interpret residual unsupported ranges as complete exclusion |
| Current `VulnerabilityNormalizedJson.affectedPackages` | **Rejected** as matching authority | Free-form `versionRange` cannot evaluate structured events |
| KEV membership as matching authority | **Rejected** | Independent exploitation signal |

## Consequences

Positive:

- later matching has a named fail-closed result model and a closed ecosystem registry
- unknown, unsupported, malformed, and withdrawn cases cannot be laundered into `not_affected`
- PURL is usable as input without becoming a false universal key
- Session 9 KEV runtime, Session 10 identity, and ADR 0024 acquisition direction are unchanged
- zero-Finding and `INTELLIGENCE_OSV_ENABLED=true` fail-closed behavior are preserved

Negative / deferred cost:

- PatchPilot still cannot match versions after Batch 1C
- no ecosystem is implemented
- no first ecosystem is selected
- Session 12 still needs OSV catalog measurements, a dependency review, and evaluator proof
- current SBOM inventory PURL stripping is not matching-identity policy and must not be reused
  silently

This ADR does **not** claim that package normalization, comparators, matching, or Finding creation
exists.

## Security and tenancy

The future evaluator is tenant-agnostic and performs no I/O. Orchestration must apply the authorized
organization predicate before reading tenant observations. Provider affected data remains
instance-owned. Tenant package inventory must not leave the instance.

False `not_affected`, generic semver, name-only matching, silently dropped qualifiers, Unicode
confusables, catastrophic regex, unbounded event lists, GIT fetches, repository URL fetches,
plugin-loaded comparators, KEV-as-affected, cross-tenant scans, and Finding writes from evaluation
are in-scope threats for later implementation review.

Batch 1C adds no evaluator, no network client, and no persistence.

Canonical log redaction in `security.mdc` still forbids logging raw SBOMs, complete vulnerability-feed
payloads, credentials, and authorization headers. Future evaluator logs may include ecosystem key,
normalization version, result status, and hashes — not package inventory lists, provider bodies, or
URLs.

## Operational failure plan

No evaluator exists, so there is no evaluation operational failure path to recover. CISA KEV
synchronization, Session 8 SBOM ingestion, and authentication are unchanged.

When an evaluator is later implemented, failures must fail closed:

| Future failure | Detection | Recovery |
| --- | --- | --- |
| Unsupported ecosystem or range | `unsupported` | No Finding; retain catalog data if structurally valid |
| Unknown tenant version | `indeterminate` | No Finding |
| Malformed provider affected data | Ingestion quarantine or invalid-source error | Do not activate; never `not_affected` |
| Withdrawn revision | `withdrawn` | No Finding; preserve history |
| Complexity or timeout | `AppError` | Fail the evaluation unit; do not guess exclusion |
| Missing local OSV catalog | Orchestration error | Do not evaluate; last accepted catalog remains if one exists |

Do not invent a success path that creates Findings, Evidence, or `finding.recalculate`.

## Follow-up

Open after Batch 1C:

- OSV transport, licensing, completeness, and persistence review ([ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md))
- OSV catalog measurements and affected-range inventory before selecting the first ecosystem
- independent dependency and evaluator design review for that ecosystem
- Session 12 zero-Finding evaluator implementation for one reviewed registry entry
- exact OSV event-edge proof
- typed evaluation limits
- ADR 0026: Finding evidence and lifecycle
- [OD-19](../architecture/open-decisions.md) full provider-neutral `Vulnerability` advisory identity
- ZIP/archive support, remaining deferred and unauthorized
- OSV runtime enablement, remaining fail-closed

Required tests for this batch: documentation and architecture-invariant coverage that ADR 0025
exists as Accepted direction, keeps the implemented ecosystem set empty, selects no first ecosystem
until measurements exist, preserves fail-closed results, and does not enable OSV, ZIP, matching, or
Finding writes.

Docs updated with this ADR: [ADR index](README.md),
[open-decisions.md](../architecture/open-decisions.md),
[vulnerability-intelligence.md](../architecture/vulnerability-intelligence.md),
[architecture README](../architecture/README.md), [AGENTS.md](../../AGENTS.md),
[tenant-isolation.md](../architecture/tenant-isolation.md),
[data-flow.md](../architecture/data-flow.md),
[domain-model.md](../architecture/domain-model.md),
[finding-lifecycle.md](../architecture/finding-lifecycle.md),
[threat-model.md](../security/threat-model.md), and
[risk-register.md](../security/risk-register.md).
