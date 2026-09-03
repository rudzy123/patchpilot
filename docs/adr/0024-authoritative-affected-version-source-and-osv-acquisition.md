# ADR 0024: Authoritative affected-version source and OSV acquisition

- Status: Accepted
- Date: 2026-09-03
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as architectural direction on this feature branch. Merge to `main` remains subject to normal
pull-request review. This ADR does **not** implement OSV transport, a parser, persistence, a
migration, workers, schedulers, APIs, permissions, web UI, ZIP support, package matching, version
comparison, affected-range evaluation, Finding writes, or OSV runtime enablement.

This ADR does **not** supersede [ADR 0010](0010-osv-correlation.md) as the future correlation ADR,
[ADR 0011](0011-cisa-kev-enrichment.md) as the future Finding-enrichment ADR,
[ADR 0021](0021-vulnerability-intelligence-import-foundation.md) as the Session 9 import-only catalog
and zero-Finding foundation, [ADR 0022](0022-intelligence-provider-status-authorization.md) as
sanitized provider-status authorization, or
[ADR 0023](0023-provider-neutral-cve-identity.md) as canonical CVE identity and the four-condition
Finding-write gate.

It **refines** the Session 9 OSV acquisition sketch: [ADR 0021](0021-vulnerability-intelligence-import-foundation.md)
recorded official GCS bulk export and `all.zip` as a research completeness baseline whose
implementation was blocked on a measured archive assessment. This ADR decides that `all.zip` is
**not** approved for the first implementation, that ZIP remains unauthorized, and that tenant
package-query APIs are rejected for the approved foundation. [ADR 0010](0010-osv-correlation.md)
language about targeted package queries is a **rejected alternative** for that foundation; matching
itself remains later work.

## What this ADR is and is not

| Kind | Meaning in this ADR |
| --- | --- |
| Accepted architectural direction | Binding for later Session 11 design and implementation batches |
| Future implementation | Required later; **not** present in Batch 1B |
| Deferred | Needs a later ADR, design batch, or measured review before selection |
| Rejected | Must not be the approved foundation |

Batch 1B records decisions only. No OSV runtime exists after this ADR.

## Context

Session 11 Batch 1A established, and this ADR preserves:

1. PatchPilot cannot authoritatively determine whether a tenant component version is affected by an
   advisory today.
2. Current `VulnerabilitySourceRecord` normalized JSON is insufficient for affected-version
   evaluation. The v1 `VulnerabilityNormalizedJson.affectedPackages` shape stores a free-form
   `versionRange` string and is **not** an approved matching authority.
3. OSV is the recommended authoritative source for affected-package and affected-version data.
4. CISA KEV remains an independent exploitation signal.
5. Tenant SBOMs remain inventory and are not an advisory authority.
6. Tenant package inventory must not be sent to an external provider without an explicit ADR.
7. Current OSV query APIs must not be used with tenant package identities.
8. OSV catalog ingestion must exist before authoritative matching.
9. Session 11 remains zero-Finding.
10. Finding writes are deferred beyond Session 11.
11. Package identity and comparator decisions belong to ADR 0025.
12. Finding evidence and lifecycle decisions belong to a future ADR 0026.

Session 9 imports a global CISA KEV catalog. Session 10 persists canonical CVE identity and
read-only active-catalog KEV membership. Generic Finding tables exist and remain unused by
production workflows. The policy engine has no approved production scoring implementation.
`INTELLIGENCE_OSV_ENABLED=true` remains rejected. No OSV runtime, ZIP dependency, OSV schema, or
OSV parser exists.

Without a selected affected-version authority and a privacy-preserving acquisition boundary,
later matching would either invent ranges, query tenant packages through a provider API, or treat
KEV listing as proof of impact.

## Decision

### 1. Authoritative provider source

**OSV** is the authoritative provider source for package-specific affected-version data.

Future OSV intelligence is:

- global and instance-owned
- authoritative provider data for affected-package and affected-version rules
- provider-attributed
- immutable or append-only after ingestion
- revision-aware
- reproducible
- suitable for **offline** tenant matching after ingestion
- separate from tenant inventory
- separate from CISA KEV exploitation status

Explicit non-proofs:

- OSV data does **not** prove that a tenant has an affected component until an exact package
  identity and a supported version evaluation succeed.
- OSV advisory existence alone does **not** create a Finding.
- An OSV alias or CVE alone does **not** create a Finding.
- CISA KEV does **not** provide affected-version authority.
- SBOM-embedded vulnerability claims are **not** authoritative provider data.
- Existing synthetic or v1 `VulnerabilitySourceRecord` data is **not** an authoritative matching
  source.

`Vulnerability.osvId` remains required and unique. This ADR does **not** make `osvId` nullable.
Full provider-neutral advisory identity remains deferred through
[OD-19](../architecture/open-decisions.md).

### 2. Distinct roles of existing data sources

| Source | Role | Must not |
| --- | --- | --- |
| **OSV** | Future affected-package and affected-version authority | Prove tenant exposure by advisory existence; create Findings; replace KEV as an exploitation signal |
| **CISA KEV** | Independent known-exploitation membership signal | Create a Finding; prove an affected version; match `vendorProject` or `product` to a tenant component; replace OSV affected-package data; supply package identity; supply version ranges |
| **Tenant SBOM** | Tenant-owned software inventory and observed component versions | Be treated as authoritative vulnerability advisory data |
| **Canonical CVE identity** | Provider-neutral identifier linkage (`CveIdentity`, `VulnerabilityCveIdentityLink`) | Prove package impact; prove affected versions; create Findings; merge advisories solely because they share a CVE |
| **Vulnerability** | Existing advisory identity, still OSV-oriented for the approved foundation | Drop required unique `osvId` in this ADR |

Tenant SBOMs remain inventory. An SBOM `vulnerabilities` array, VEX claim, or similar embedded
statement is an observation about what a document asserted, not PatchPilot's provider catalog.

### 3. Acquisition privacy

The approved foundation **prohibits** sending tenant package inventory to OSV or another external
provider.

Rejected:

- OSV batch queries containing tenant packages
- OSV query API calls using tenant PURLs
- OSV query API calls using tenant package names or versions
- per-request disclosure of tenant inventory
- on-demand tenant matching through a provider API
- embedding tenant data in provider URLs, query parameters, bodies, headers, logs, metrics, or
  queue payloads

Reasons:

- package inventory may reveal proprietary technologies, versions, and attack surface
- tenant disclosure requires a separate explicit architecture and privacy decision
- instance-owned provider ingestion supports offline matching without disclosing tenant inventory

No tenant information may be included in future OSV acquisition requests. Acquisition is
independent of tenant matching.

### 4. Acquisition model

Approved **architectural direction**:

- instance-owned OSV catalog acquisition
- provider endpoints are compiled or closed by code
- no tenant package query
- acquisition is independent of tenant matching
- provider data is stored privately
- provider bodies are bounded
- provider data is validated before activation
- advisory revisions and withdrawals are preserved
- active provider state is selected atomically
- tenant matching reads the accepted **local** catalog

The first implementation is **not** fully selected. A subsequent design batch must verify the exact
OSV-controlled host, path, listing mechanism, licensing, removal semantics, limits, and transport
behavior. Implementation is **not** authorized until that review is complete.

This ADR does **not** select a concrete downloadable artifact. It does **not** present a provider
endpoint as stable. It does **not** claim that arbitrary public bucket listing is automatically
safe.

### 5. Acquisition alternatives

#### Alternative 1: Tenant package query API — **rejected**

Includes `POST /v1/query`, batch query, PURL query, and any on-demand matching that sends tenant
package identities to a provider.

Reasons: tenant inventory disclosure; provider outage couples directly to matching; difficult
deterministic replay; request amplification; availability and rate-limit sensitivity; weaker
private offline operation.

#### Alternative 2: Per-advisory OSV API — **deferred**

A possible later operator or reconciliation mechanism for **known instance-owned advisory IDs
only**. It is not a complete catalog acquisition model. It must not accept tenant package
identifiers.

#### Alternative 3: `all.zip` bulk ingestion — **not approved for initial implementation**

`all.zip` is a documented OSV full-database export and remains a Session 9 research completeness
baseline in [ADR 0021](0021-vulnerability-intelligence-import-foundation.md). It is **not**
approved for the first Session 11 implementation.

- ZIP support remains absent
- no ZIP dependency is authorized
- large compressed and expanded sizes create resource and archive risks
- archive parsing requires a separate measured decision
- compressed-size, expanded-size, entry-count, per-entry, path, ratio, timeout, storage, and
  worker-memory limits would be required
- archive extraction must prevent traversal, links, duplicate names, and ambiguous encodings
- current Session 11 work must not add ZIP merely because OSV publishes archives

Dated Session 9 size observations recorded in
[vulnerability-intelligence.md](../architecture/vulnerability-intelligence.md) are
**non-contractual** maintainer measurements. They are not architecture facts, not provider
guarantees, and not download authorization. This ADR does not repeat them as selected limits.

#### Alternative 4: Ecosystem archives — **deferred**

Reasons: still require ZIP handling; ecosystem subsets may not establish global deletion or
withdrawal authority; completeness and removal semantics must be proven; closed ecosystem support
belongs to [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md).

#### Alternative 5: Provider object export over allowlisted HTTPS — **preferred direction to investigate**

Subject to a dedicated transport and inventory design review. Potential model, **not implemented**:

- closed OSV-controlled host
- exact allowlisted object paths or listings
- instance-owned requests only
- no tenant identifiers
- no provider-supplied redirect destinations
- no URLs taken from advisory content
- bounded listing pagination
- bounded object count
- bounded per-object size
- bounded total synchronization work
- content hashing
- private snapshots
- strict parser isolation
- revision and withdrawal handling
- deterministic activation

This model is **not** implemented. Arbitrary public bucket listing is **not** automatically safe.

#### Alternative 6: Hybrid — **permitted later refinement**

Later work may combine:

- allowlisted provider object acquisition as the initial catalog foundation
- optional per-ID reconciliation for known instance-owned advisory IDs
- optional archive ingestion only after a separate measured approval

The hybrid must **not** include tenant package queries.

### 6. Concrete implementation checkpoint

| Item | Decision |
| --- | --- |
| Instance-owned provider object acquisition | Approved **direction**; first implementation still requires a transport-design checkpoint |
| Implementation authorization | **Not** granted by this ADR |
| `all.zip` | **Not** authorized |
| Tenant package APIs | **Not** authorized |
| Arbitrary ecosystem archives | **Not** authorized |
| Exact host, path, listing, licensing, removal semantics, and limits | **Deferred** to the transport and provenance review |

Avoid falsely presenting a provider endpoint as stable without verification.

### 7. Endpoint and SSRF requirements

Any future OSV transport must:

- use HTTPS only
- use a closed provider identifier
- use a closed source identifier
- accept no caller-provided URL
- accept no tenant-provided URL
- use an exact approved host
- use an exact approved path grammar
- put no credentials in the URL
- use no non-default port
- reject redirects by default
- reject all redirect targets unless separately compiled and reviewed
- use no ambient proxy
- use no provider prose as a URL
- fetch no advisory `references`
- resolve DNS on each attempt
- validate the destination as public
- pin the resolved address
- verify the connected remote address
- validate the TLS certificate
- preserve hostname and SNI
- provide no TLS bypass
- use no custom untrusted CA
- apply a finite timeout
- apply a finite response limit
- consume the body by streaming
- perform no automatic decompression unless an archive-specific ADR approves it
- not log provider error bodies
- bound retries and limit them to idempotent reads
- support cancellation
- never write raw response bodies to logs

Reuse the Session 9 CISA transport **security posture** where applicable. Do **not** claim the CISA
adapter itself supports OSV.

### 8. Snapshot and provenance requirements

Future OSV source provenance must include:

- private object storage
- no public ACL
- no signed public URL
- content-addressed immutable final objects
- bounded temporary objects
- content SHA-256
- exact byte count
- provider and source identifiers
- retrieval timestamp (UTC)
- source object identity or revision
- media type
- normalization version
- parser version
- schema version
- licensing and provenance metadata
- object consistency verification
- no final-object overwrite
- no final-object deletion during normal failure recovery
- no provider body in PostgreSQL
- no tenant information in object keys
- no provider-controlled path fragment in local object keys

Preferred snapshot arrangement, schema deferred:

- one immutable snapshot represents **one provider object**
- a synchronization **manifest or generation** defines one accepted provider catalog
- exact tables, columns, and SQL are **not** defined in this ADR

### 9. Revision and withdrawal semantics

Future ingestion must preserve:

- OSV advisory ID
- modified timestamp
- published timestamp when present
- withdrawn timestamp when present
- aliases
- affected package data
- affected ranges
- explicit versions
- provider object identity
- provider revision or content identity
- ingestion generation
- parser and normalization versions

Withdrawn advisories:

- remain historically stored
- are excluded from future positive affected matching
- do not delete historical provider records
- do not delete Findings or evidence
- do not automatically close Findings
- require later Finding-lifecycle policy (future ADR 0026)

Modified advisories:

- create a new immutable provider revision or generation-visible record
- do not mutate historical normalized affected data
- future matching pins the exact provider record revision
- provider updates trigger later reconciliation only after a separate execution design

Deleted or missing provider objects:

- must not be inferred from a partial failed synchronization
- become authoritative only after a complete accepted catalog generation
- must be modeled separately from transport failure
- must preserve historical data

No provider update may rewrite past match evidence.

### 10. Affected-data requirements

The future OSV parser and persistence model must preserve enough structured data for later ADR 0025
evaluation. At minimum:

- OSV advisory ID
- advisory modified timestamp
- advisory published timestamp when available
- advisory withdrawn timestamp when available
- affected package ecosystem
- affected package name
- affected package PURL when provided
- affected range type
- introduced events
- fixed events
- last_affected events
- limit events
- explicit affected versions
- database-specific fields only when explicitly selected and bounded
- aliases
- schema and parser versions
- source revision or content identity

Do **not** collapse ranges into one free-form `versionRange` string. Do **not** authorize matching
directly against the current `VulnerabilityNormalizedJson.affectedPackages` shape. Do **not** rely
on free-form JSON without strict versioned validation. Package identity and comparators are
specified by [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md). This ADR
does not implement that schema.

### 11. Parser requirements

Future parser requirements, **not implemented** in Batch 1B:

- isolated worker
- fixed entrypoint
- strict versioned protocol
- fatal UTF-8 decoding
- secure JSON parsing
- prototype-key rejection
- bounded input
- bounded output
- iterative structural walk
- object-count limit
- array-count limit
- depth limit
- string-byte limit
- key-byte accounting
- affected-package limit
- range limit
- event limit
- explicit-version limit
- alias limit
- no remote schema references
- no runtime schema download
- strict provider schema or reviewed subset schema
- no silent advisory repair
- no version normalization beyond provider-defined canonical parsing
- deterministic normalization
- deterministic ordering
- duplicate detection
- timeout
- cancellation
- worker termination
- no network, storage, database, Redis, or BullMQ inside the parser
- no provider text in errors or logs

### 12. Licensing and provenance

Existing repository documentation already records that OSV **schema** licensing (Apache-2.0 on the
schema repository) does **not** establish one universal license for aggregated advisory content,
and that further review is required before distribution or republishing. CISA KEV remains CC0 1.0
with a non-endorsement limitation.

This ADR requires a later verification of:

- OSV data license
- schema license
- provider terms
- redistribution rights
- attribution obligations
- source URLs
- retrieval dates
- checksum
- non-endorsement requirements if applicable
- license compatibility with private snapshot retention
- whether copied provider objects may be stored and redistributed
- whether APIs and bucket exports have distinct terms

Do **not** make a universal licensing claim without verified evidence. Do **not** claim that all OSV
ecosystem records necessarily share one content license unless authoritative provider documentation
proves it. Initial implementation must not proceed until the exact selected source and its
provenance are documented. This ADR is **not** legal advice.

### 13. Runtime enablement

`INTELLIGENCE_OSV_ENABLED=true` currently fails closed. This ADR **preserves** that behavior.

Batch 1B does **not** enable OSV. No environment-variable behavior changes. No scheduler, worker,
parser, persistence schema, or transport exists. No provider endpoint is contacted. OSV `true`
remains rejected in development, test, and production.

A future implementation may enable OSV only after **all** of:

1. Transport design accepted.
2. Licensing and provenance verified.
3. Limits defined.
4. Parser design accepted.
5. Persistence design accepted.
6. Migration implemented and frozen.
7. Tests prove zero-Finding behavior.
8. Operational runbooks exist.
9. Adversarial review passes.

This ADR alone does **not** approve runtime enablement.

### 14. Zero-Finding boundary

Session 11 remains zero-Finding. This ADR prohibits:

- Finding creation
- Finding updates
- FindingObservation creation
- Evidence creation for matches
- RiskCalculation creation
- `finding.recalculate`
- tenant component matching
- package/version evaluation
- advisory fan-out to tenants
- KEV-based Finding creation

Future OSV ingestion is instance-owned only. It may create future **global** OSV intelligence
records, but it must not write tenant data.

Finding writes remain blocked until:

- OSV affected data is ingested and validated
- ADR 0025 evaluation is implemented
- a deterministic affected result exists
- match evidence is designed
- ADR 0026 Finding lifecycle is accepted
- tenant isolation and replay behavior are proven
- a later session explicitly authorizes the first Finding write

Do **not** weaken the [ADR 0023](0023-provider-neutral-cve-identity.md) four-condition gate.
Matching is Session 12 or later. Finding writes are Session 13 or later, subject to all gates.

### 15. Risk boundary

- no risk calculation
- no hard-coded OSV weight
- no hard-coded KEV weight
- no `finding.recalculate` event
- no risk policy change
- OSV ingestion does not imply risk
- affected-version evaluation does not yet exist
- risk remains a separate later foundation

No risk documentation should imply that scoring implementation exists. The production policy engine
remains without approved scoring.

### 16. Tenant-isolation boundary

Future OSV acquisition is global and instance-owned.

Requirements:

- no `organizationId` in provider requests
- no `organizationId` in provider snapshot keys
- no tenant package data in requests
- no tenant foreign key on future provider snapshots or catalog generations
- no tenant object-store namespace
- no matching during provider synchronization
- no cross-tenant scan
- no tenant fan-out
- no Finding writes
- API access, if ever added, requires a separate authorization review

OSV ingestion jobs should use `organizationId` null under the existing global intelligence
convention. This ADR does **not** implement jobs.

### 17. Reliability direction

Future reliability requirements, **not implemented** for OSV:

- transactional synchronization request
- Outbox delivery
- BackgroundJob as execution lease
- bounded retry
- PostgreSQL as durable retry authority
- provider HTTP outside database transactions
- private snapshot before normalized persistence
- parser outside database transactions
- permanent persisted stages
- crash-safe resume
- no provider refetch after authoritative snapshot attachment
- immutable generations
- complete-before-active transition
- atomic active-generation pointer
- prior accepted catalog remains readable on failure
- partial generation invisible
- disabled provider creates no new synchronization request
- graceful shutdown
- no exactly-once claim
- at-least-once delivery with idempotent persistence

Reuse Session 9 architecture **principles** where appropriate. These OSV mechanisms do **not**
already exist.

### 18. Catalog completeness and deletion authority

An OSV catalog generation can become active only if its acquisition mode proves completeness for
the **selected scope**.

A complete generation must establish:

- source scope
- object or advisory inventory
- successful retrieval of required objects
- parser success
- expected and actual counts
- deterministic normalized records
- no missing page or listing segment
- no ambiguous provider deletion
- bounded failures handled before activation

Partial acquisition must never become deletion authority. An ecosystem-only source may be complete
for that ecosystem but not for all of OSV. A future implementation must record the selected scope
explicitly. Do not treat one failed or missing object as advisory withdrawal.

### 19. Archive decision

- ZIP remains **deferred and not authorized**
- no ZIP or archive dependency is authorized
- `all.zip` is not the initial implementation assumption
- ecosystem ZIPs are not the initial implementation assumption
- archive support requires a later ADR amendment or new ADR based on measurements
- no archive extraction design is implemented now

The existing ZIP open decision is **not** closed as implemented. It is recorded as deferred and
unauthorized.

### 20. Proposed future implementation sequence

Not Batch 1B work:

1. Verify official OSV source endpoints and licensing.
2. Measure listing and object sizes using a maintainer-only research procedure.
3. Define closed provider/source identifiers.
4. Define typed fail-closed OSV configuration.
5. Define response, object-count, parser, and worker limits.
6. Define vendored schema or reviewed strict subset schema.
7. Define private snapshot and catalog-generation persistence.
8. Design forward-only migration.
9. Implement restricted transport.
10. Implement isolated parser.
11. Implement immutable generation staging and atomic activation.
12. Add scheduler, Outbox, BackgroundJob, retry, and shutdown behavior.
13. Prove zero-Finding behavior.
14. Perform adversarial review.
15. Enable OSV runtime only after all gates pass.
16. Build ecosystem comparators later in Session 12 under the accepted [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md) architecture. ADR 0025 does not itself implement a comparator.
17. Build authoritative matching later.
18. Build Finding writes still later under ADR 0026.

## Alternatives considered

| Alternative | Disposition | Rationale |
| --- | --- | --- |
| Existing `VulnerabilitySourceRecord` / `VulnerabilityNormalizedJson.affectedPackages` JSON | **Rejected** as matching authority | Free-form `versionRange` cannot authoritatively evaluate introduced/fixed/last_affected/limit events; synthetic seed data is not provider evidence |
| Tenant OSV query API (`POST /v1/query`, PURL or package/version queries) | **Rejected** | Tenant inventory disclosure; weak replay; outage and rate-limit coupling; not a catalog |
| Per-advisory fetch (`GET /v1/vulns/{id}` or equivalent) | **Deferred** | Useful later for known instance-owned IDs; incomplete as a catalog; must not accept tenant packages |
| Provider object export over allowlisted HTTPS | **Accepted direction to investigate**; not implemented | Instance-owned, no tenant query, offline matching after ingestion; exact host/path/listing still require review |
| `all.zip` bulk ingestion | **Not approved** for initial implementation | Archive threat model, ZIP dependency, and measured limits are absent; Session 11 must not add ZIP |
| Ecosystem archives | **Deferred** | Still ZIP; incomplete global deletion/withdrawal authority; ecosystem closure belongs to ADR 0025 |
| Hybrid object export plus optional per-ID reconciliation, with archive only after measured approval | **Permitted later**; no tenant queries | Refinement path after the object-export foundation; not Batch 1B |
| GitHub Security Advisories | **Rejected** for this foundation | GitHub is not MVP; not an approved Session 9/11 provider |
| NVD CPE | **Rejected** as affected-version authority | Weaker ecosystem package-version matching; NVD is not an approved Session 9/11 provider |
| SBOM-embedded vulnerability claims | **Rejected** as authoritative provider data | Tenant inventory and document assertions, not the instance-owned catalog |
| CISA KEV as affected-version authority | **Rejected** | KEV is an exploitation-membership signal; it does not supply package identity or version ranges |
| CISA KEV as exploitation signal | **Accepted** (already) | Independent of OSV affected data; listing does not create Findings |

Acquisition direction is **not** ambiguous: instance-owned provider object acquisition is the
approved architectural direction; tenant package APIs and `all.zip` are not the first
implementation.

## Consequences

Positive:

- later matching has a named authority (OSV affected data) distinct from KEV and from SBOMs
- tenant inventory stays off the wire during approved acquisition
- withdrawn and revised advisories can be preserved without rewriting evidence
- Session 9 KEV runtime is unchanged
- zero-Finding and `INTELLIGENCE_OSV_ENABLED=true` fail-closed behavior are preserved

Negative / deferred cost:

- PatchPilot still cannot match versions after Batch 1B
- operators still have no OSV catalog
- a transport, licensing, and completeness review must precede implementation
- `all.zip` remains unavailable as a shortcut
- ADR 0010 package-query language must not be treated as the approved matching transport

This ADR does **not** claim that OSV ingestion, matching, or Finding creation exists.

## Security and tenancy

Future OSV acquisition is instance-owned global intelligence, not tenant-owned data. Jobs, if
later added, use null `organizationId`. Snapshot keys must not include organization, package, or
provider-controlled path fragments.

SSRF, DNS rebinding, redirects, proxies, TLS bypass, oversized listings and objects, object-count
flooding, provider-data amplification, later compressed-data amplification, malformed JSON,
prototype pollution, deeply nested data, huge affected arrays and version lists, malicious aliases,
Unicode confusables, provider text in logs, provider URLs in advisory records, schema-reference
fetching, rate limiting, retry storms, object-storage exposure, stale or incomplete catalog
activation, false withdrawal inference, tenant inventory disclosure, cross-tenant fan-out, worker
exhaustion, and provider licensing uncertainty are in-scope threats for later design review.

Batch 1B adds no network client, no parser, and no storage layout.

## Operational failure plan

No OSV runtime exists, so there is no OSV operational failure path to recover. CISA KEV
synchronization, Session 8 SBOM ingestion, and authentication are unchanged.

When OSV runtime is later implemented, failure handling must follow the reliability direction
above: keep the last accepted catalog readable, never activate a partial generation, never infer
deletion from transport failure, and never write Findings from import.

## Follow-up

Open after Batch 1B:

- exact OSV-controlled host, path grammar, listing mechanism, and object inventory
- licensing and provenance verification for the selected source
- numeric listing, object, parser, and worker limits
- vendored or reviewed subset schema
- snapshot and catalog-generation persistence (no SQL in this ADR)
- [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md): package identity, ecosystems, and fail-closed evaluation (accepted in Session 11 Batch 1C; no evaluator exists)
- ADR 0026: Finding evidence and lifecycle
- [OD-19](../architecture/open-decisions.md) full provider-neutral `Vulnerability` advisory identity
- ZIP/archive support, remaining deferred and unauthorized
- OSV runtime enablement, remaining fail-closed

Required tests for this batch: documentation and architecture-invariant coverage that ADR 0024
exists as Accepted direction without enabling OSV or adding ZIP, Findings, or migrations.

Docs updated with this ADR: [ADR index](README.md),
[open-decisions.md](../architecture/open-decisions.md),
[vulnerability-intelligence.md](../architecture/vulnerability-intelligence.md),
[architecture README](../architecture/README.md), [AGENTS.md](../../AGENTS.md),
[tenant-isolation.md](../architecture/tenant-isolation.md),
[data-flow.md](../architecture/data-flow.md),
[threat-model.md](../security/threat-model.md), and
[risk-register.md](../security/risk-register.md).
