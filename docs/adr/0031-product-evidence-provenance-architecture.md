# ADR 0031: Product-evidence provenance architecture

- Status: Proposed
- Date: 2026-10-01
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Session 15 Batch 1 defines how a future reviewed advisory revision can become
product-eligible match-evaluation evidence. It does **not** persist that
evidence, accept [ADR 0027](0027-osv-acquisition-persistence-and-catalog-activation.md),
activate a catalog, contact a provider, run product matching, or create a
Finding. [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)
and [ADR 0030](0030-first-ecosystem-matching-architecture.md) remain in force.
This ADR does not make npm a supported runtime ecosystem.

## Context

Session 14 stores immutable tenant match-evaluation evidence for the uncomposed
npm evaluator. Durable `affected` and `unaffected` results are admitted only
for synthetic provenance. KEV and unrecognized evidence stay `unknown`. The
rows have no foreign key to `Vulnerability.id`. The implemented ecosystem
registry is empty. No active production OSV catalog exists. ADR 0027 remains
Proposed. Those gaps are the subject of this architecture.

## Decision

Product provenance keeps four independent dimensions:

| Dimension | Closed values |
| --- | --- |
| Origin | `synthetic_fixture`, `provider_derived`, `unrecognized` |
| Trust | `not_applicable_synthetic`, `unreviewed`, `reviewed` (derived) |
| Revision state | `not_withdrawn` or `withdrawn`, and `not_quarantined` or `quarantined` |
| Product eligibility | Closed classification, never a caller boolean |

Eligibility is derived from immutable facts. `eligible` is a contract
classification. It is not execution authority, catalog activation, or Finding
authority. The active ecosystem and evaluator registries stay empty.
`reviewedRegistriesAuthorizeProductEligibility()` is false, so admission does
not return `eligible`. Production evaluation remains unavailable.

Advisory family identity is the source plus the exact advisory identifier.
Advisory revision identity is a separate digest over family identity, provider
generation, content fingerprint, Session 14 range fingerprint, product range
fingerprint, parser and schema pins, source-license registry, SPDX license
identifier, withdrawal, quarantine, supersession, and retrieval-evidence
identity. A mutable active catalog pointer is not evidence identity. Hash
equality does not replace canonical-field comparison. Replay also compares
Vulnerability binding and catalog-generation claims, which stay outside the
revision digest.

The only accepted product source for npm is `github_advisory_database` under
`osv_source_license_registry_v1` and SPDX `CC-BY-4.0` with internal matching
permitted. CISA KEV is not affectedness or Vulnerability-binding authority.
One product-evidence record binds one exact `Vulnerability.id`. Multiple CVE
aliases, string similarity, and an unmapped advisory stay product ineligible.
An advisory without a CVE may bind a provider-native `Vulnerability.id` when
the advisory family identifier and UUID are exact. No CVE is invented.

Withdrawal is an explicit revision classification. Absence from a later listing
is `presence_not_observed_not_withdrawal`. A later revision is a new immutable
record. Supersession records the prior revision digest on the successor and
does not mutate the prior record. Existing Session 14 synthetic evidence stays
synthetic. Relabeling it is rejected.

## Alternatives considered

- One Boolean `productEligible` on the Session 14 evidence row. Rejected: it
  collapses origin, trust, withdrawal, and eligibility, and it would rewrite
  synthetic rows.
- Using `Vulnerability.osvId` or the active catalog pointer as revision
  identity. Rejected: `osvId` is `VARCHAR(128)` and mutable catalog state is
  not content identity.
- Treating the first CVE alias as the Vulnerability. Rejected: multi-CVE
  advisories would collapse silently.
- Accepting ADR 0027 in this batch. Rejected: catalog activation is still
  unauthorized.

## Consequences

Later Session 15 batches may persist this contract. They must not edit frozen
migrations. Finding creation still requires a later Finding policy and write
gate. The defined npm registry entry stays `not_activated`.

## Security and tenancy

Product-evidence contracts omit provider object keys, raw bodies, URLs, and
continuation tokens. Advisory identifiers, Vulnerability ids, tenant ids, and
component ids are not metric labels. Tenant match evidence remains organization
scoped. This batch performs no network I/O and writes no tenant data.

## Operational failure plan

Admission failures are closed codes. They do not echo oversized identifiers,
provider bodies, or stack traces. There is no job, retry, or catalog mutation
to recover. A conflicting revision is `immutable_conflict` and leaves the prior
revision unchanged.

## Follow-up

Session 15 Batch 1-R reviewed this architecture and corrected it. An empty
registry blocks `eligible`. Unrecognized origin is not relabeled
provider-derived. Replay requires the full immutable tuple, so a shared
revision digest does not hide a different Vulnerability binding, SPDX id, or
catalog claim. The SPDX identifier is part of revision identity. An active
digest mismatch is `ineligible_catalog`, not supersession. Persistence, catalog
activation, and Finding writes remain later gates. Batch 2 has not started.
