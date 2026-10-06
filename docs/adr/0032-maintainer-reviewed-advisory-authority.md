# ADR 0032: Maintainer-reviewed advisory authority architecture

- Status: Accepted
- Date: 2026-10-02
- Accepted on: 2026-10-06
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted for the maintainer-reviewed advisory authority architecture and its production-uncomposed implementation. Acceptance does not create a user-facing approval workflow, return registry eligibility, authorize production composition, or create a Finding.

## Implementation status

Status is **Accepted** on 2026-10-06. The proposal date remains 2026-10-02. Acceptance records that the decisions below are implemented and production uncomposed. It does not add a writer, a route, or a worker. Current checkpoint: [current-state.md](../project/current-state.md).

- Architecture contracts exist and remain production uncomposed (`maintainer_reviewed_advisory_architecture_v1`).
- Immutable approval persistence exists (`20261002120000_maintainer_reviewed_advisory_approval`, SHA-256 `9f4ae2a6402952ff0ecca27a88cb15859a2164d89591fe2afe64e7e9ddbfb380`). The adapter is production uncomposed. No approval is seeded. Update and delete are rejected. Parent deletion is restricted.
- Author and reviewer separation exists. Exact distinct identities are required. Self-approval fails closed.
- An approval binds the exact revision, content and range fingerprints, npm package identity, one `Vulnerability.id`, the approval purpose `approve_maintainer_reviewed_advisory_for_product_evaluation`, the approval policy, and the accepted `CC-BY-4.0` license evidence.
- Decision 3 is implemented. Reviewer authority is an issued capability under `reviewer_approval_capability_policy_v1`. The public package entry does not export an issuer. `reviewer_capability_issuance` stores one immutable issuance row. `reviewer_capability_lifecycle_observation` stores one append-only terminal observation (`consumed`, `revoked`, or `cancelled`) in `20261003120000_reviewer_capability_issuance` (SHA-256 `08f18ce42ba19165f6d0a1bf872e5973bf74e26888e7f052c70c53779656dfbd`). The natural identity is the approval-claim fingerprint. Correlation does not mint a second capability.
- Database time is authoritative. Insert guards set `issued_at` and `expires_at` from PostgreSQL `clock_timestamp()`. Validity is half-open for 900000 milliseconds: valid while database time is before `expires_at`, expired when database time is greater than or equal to `expires_at`. The process-local presentation handle is not a column.
- Approval insertion and capability consumption commit in one transaction (`persistMaintainerReviewedAdvisoryApprovalWithCapability`). The consumed observation must match the stored approval target. `recordMaintainerReviewedAdvisoryApproval` returns `capability_authority_required` and does not write. A consumed or revoked capability cannot mint another approval.
- Exact issuance and approval replay return `already_applied`, insert nothing, and do not renew authority. An immutable conflict overwrites nothing. Concurrent issuance converges on one row. Concurrent consumption has one recorded winner and one `already_applied` result.
- Product Match Evidence evaluation is one explicit command, implemented and production uncomposed. It does not return the eligibility-registry result `eligible`. The active registries that admit `eligible` remain empty. Persistent product-eligible evaluation count: 0. The command does not create a Finding.
- Decision 11 still holds for production. Production startup does not submit, approve, evaluate, or persist these advisories. The explicit command is not production composition.
- Decision 10 remains in force. Corrections are the next revision in the same family, with the prior revision digest and the same npm package identity and `Vulnerability.id`. Withdrawal is an explicit revision fact. Absence is not withdrawal. Withdrawal does not close a Finding.
- The capability grants no evaluator, product-match, or Finding authority. User-facing reviewer approval is not operational. Batches 1, 1-R, 2, and 2-R are committed. Branch-closure review is complete.
- Real product-eligible evaluation count: 0
- Production OSV acquisition: disabled
- Finding creation: unavailable

This ADR defines how a local advisory document can become a legitimate, non-synthetic, maintainer-reviewed product evidence source. Approval is necessary and insufficient for product evidence. Product Match Evidence is necessary and insufficient for Finding creation. [ADR 0035](0035-controlled-finding-creation.md) is the creation-only Finding architecture and does not make this approval a Finding writer.

## Context

Session 14 and Session 15 established immutable npm match-evaluation evidence and trusted advisory provenance. However, in the current checkpoint, real product-eligible evaluation count remains 0 because the active registries are empty, production OSV acquisition is disabled, and existing match evidence requires synthetic origin.

To reach the product milestone of exactly one legitimate non-synthetic affected evaluation without enabling risky external provider acquisition or compromising tenant isolation, PatchPilot needs an authorized mechanism for maintainer-reviewed local advisories.

Crucially:
- A local file is not automatically trusted.
- A Git-tracked file is not automatically trusted.
- Maintainer role alone is not approval authority.
- Synthetic fixtures must never be converted or relabeled into product authority.
- Product-eligible affected evidence is necessary and insufficient for Finding creation.

## Decision

PatchPilot establishes a **Maintainer-Reviewed Advisory Authority Architecture** under policy `maintainer_reviewed_advisory_architecture_v1`:

1. **Source Classification:**
   The conceptual source is `maintainer_reviewed_advisory`. It is permanently distinct from `synthetic_fixture`, `provider_derived`, and `unrecognized`. The parser stamps that source only after structural synthetic and provider markers fail closed. A caller-supplied origin is rejected. No conversion from `synthetic_fixture` exists. Git tracking, directory placement, and repository write access grant no authority.

2. **Submission versus Approval:**
   Document submission is untrusted input that grants zero product authority. Valid submission parses into `ineligible_unapproved`. Schema validation, canonicalization, and fingerprint calculation do not approve. Approval is a separate issued decision.

3. **Reviewer Authority:**
   Reviewer authority is an issued capability, not a caller-assembled record. It binds one reviewer identity, one advisory revision, the content fingerprint, the range fingerprint, the exact `Vulnerability.id`, the npm package identity key, and the source-license decision. The public package entry does not export an issuer or a generic approval constructor. Administrative status, Git authorship, file ownership, environment variables, and status inspection grant no authority. A consumed or revoked capability cannot mint another approval.

4. **Separation of Duties:**
   Author and reviewer identities are exact ASCII identities. Case-folded equality, surrounding whitespace, and non-ASCII confusable text fail closed as `ineligible_self_approved`. There is no break-glass self-approval path.

5. **Approval Purpose:**
   The approval decision has exactly one closed purpose: `approve_maintainer_reviewed_advisory_for_product_evaluation`. Approval does not authorize provider contact, catalog activation, matching, Finding creation, risk calculation, suppression, or remediation.

6. **Advisory Document Contract and Canonicalization:**
   Documents conform to `maintainer_reviewed_advisory_document_v1` with a closed property set. Canonicalization reuses the committed length-prefixed encoding and Session 14 range canonical form under `canonicalization_policy_v1`. Canonical bytes are not a public export. npm package identity reuses the committed classifier and is not lowercased or trimmed into validity. Ranges stay inside Session 14 SEMVER events.

7. **Vulnerability.id Binding:**
   The advisory binds exactly one `Vulnerability.id` (lowercase UUID v4). Similarity, title text, KEV membership, and first-CVE-wins are not binding authority. More than one CVE alias fails closed. Zero CVE aliases do not invent a CVE. The UUID is not proof that a Vulnerability row exists.

8. **Source-License Policy:**
   Local advisories require an explicit source-license decision under `maintainer_reviewed_source_license_policy_v1`. Product-use acceptance follows the committed product-evidence SPDX, `CC-BY-4.0`, with a required notice and maintainer-original content provenance. Apache-2.0 and MIT are not product-matching authority. An author SPDX string is not a review. Approval cannot override a rejected decision. Copied provider material labeled as local content is rejected.

9. **Replay and Conflict Semantics:**
   Exact submission replay produces `already_applied` and does not create a second revision. Conflicting content for an existing revision produces `immutable_conflict` and does not overwrite it. Exact approval replay produces `already_applied` and returns the existing decision. A different reviewer for the same revision is an immutable conflict. Process-local single-use marks are not a durable store.

10. **Correction, Supersession, and Withdrawal:**
    Corrections require the next revision number, the prior revision digest, the same family, and the same npm package identity and `Vulnerability.id`. Cross-family supersession and cycles are rejected. Withdrawal is an explicit revision fact. Absence is not withdrawal. Prior revisions remain. Withdrawal does not close a Finding.

11. **Finding Boundary and Production Exclusion:**
    This batch does not return `eligible`. Approval is necessary and insufficient, the active registries are empty, and product evaluation is not authorized. Finding creation remains unavailable. Production startup does not submit, approve, evaluate, or persist these advisories.

12. **Future persistence:**
    After this architecture is committed, Batch 2 should add one forward-only migration that reuses advisory family and revision records and adds immutable approval evidence. Approval timestamps use database time. Update and delete are prohibited. Parent deletion is restricted. There is no mutable latest-approval pointer and no approval-status Boolean. Supersession and withdrawal stay on the revision. This ADR does not freeze that SQL.

## Alternatives considered

- **Option B: Single Provider-Body Retrieval.** Rejected for Batch 1: contacts external network, requires provider transport authorization, and risks unverified provider schema changes.
- **Relabeling Synthetic Fixtures.** Rejected: violates evidentiary integrity and security invariants against synthetic-evidence laundering.
- **Ambient Maintainer Approval.** Rejected: ambient Git or admin privileges lack cryptographic binding to document fingerprints and violate auditability.
- **Self-Approval.** Rejected: violates separation of duties.

## Consequences

### Positive
- Defines non-synthetic advisory authority without external network access or OSV acquisition enablement.
- Prevents synthetic-evidence laundering through strict origin separation and anti-tampering invariants.
- Maintains strict tenant isolation and enforces Finding-write authority containment.

### Negative
- Requires a two-step maintainer submission and independent review process for local advisories.
- Persistence and matching remain deferred to later batches.

## Security and tenancy

- No external network requests, DNS queries, or provider API calls.
- Pure domain architecture with zero tenant cross-contamination.
- Complete separation of duties prevents single-maintainer compromise.
- Canonical bytes and intermediate hashes remain internal.

## Operational failure plan

- Invalid documents fail closed during submission validation with explicit rejection codes (`ineligible_schema`, `ineligible_package`, `ineligible_range`, etc.).
- Conflicting updates produce `immutable_conflict` and leave existing records unchanged.
- Operational runbooks will be established when persistence and CLI/API ingestion are implemented in subsequent batches.

## Follow-up

- Batch 1 and Batch 1-R are committed. Batch 1-R corrected caller-origin, caller-built authority, license allowlist, fingerprint, and eligibility defects.
- Batch 2 records immutable approval evidence. Exact replay does not change the row. A conflicting replay does not overwrite it. Author and reviewer identities stay distinct. Synthetic origin cannot be approved. The Session 14 match-evaluation shape was not extended.
- Batch 2-R reviewed the uncommitted persistence. A provider-derived revision cannot carry source `maintainer_reviewed_advisory`. Batch 3 is next only after commit. An approval does not authorize evaluation. There is no user-facing approval workflow.
- Later batches are committed and remain production uncomposed: the explicit evaluation command, Product Match Evidence, and reviewer-capability issuance and consumption. An approval still does not by itself evaluate or create a Finding. User-facing approval and ingestion remain absent. [ADR 0035](0035-controlled-finding-creation.md) does not turn this ADR into a Finding writer.
