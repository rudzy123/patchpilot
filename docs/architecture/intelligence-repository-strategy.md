# Intelligence repository strategy

Status: repository boundary recorded for principal architect review. It is not an accepted ADR. The governing proposal is [ADR 0052](../adr/0052-patchpilot-intelligence-boundary.md). This document does not change a license file or move an artifact. Cursor did not create, inspect, or modify `patchpilot-intelligence-evals`.

[ADR 0017](../adr/0017-optional-ai-user-credentials.md) remains Accepted. v0.1 ships with AI disabled. [docs/releases/v0.1.0-licensing.md](../releases/v0.1.0-licensing.md) stays the dated 2026-11-06 licensing snapshot and is not rewritten here.

## Three repositories

Use three separate responsibilities. Do not merge the trees.

| Responsibility | Owner | Intelligence Track 1 |
| --- | --- | --- |
| Production application, deterministic authority, authorization, audit, and tenant boundaries | `patchpilot` | Unchanged |
| Educational laboratory for tokenization, transformers, tuning, and model exercises | `neural-from-scratch` | Untouched and uninspected |
| Original PatchPilot synthetic corpora, evaluation harnesses, schemas, benchmarks, model cards, experiment manifests, and promotion evidence | `patchpilot-intelligence-evals` | Created by the maintainer. Not inspected or modified by Cursor |

The maintainer created `patchpilot-intelligence-evals` during Intelligence Track 1. It exists on GitHub and as an independent local clone. Creation is an existing fact. It is not acceptance of ADR 0052, and it does not authorize experiment implementation.

PatchPilot has no build-time or runtime dependency on that repository. It is outside PatchPilot CI, container images, package manifests, and deployment. No tenant or production data may enter it. Its work must be original PatchPilot evaluation work. Files from `neural-from-scratch` may not be copied into it without a recorded provenance and licensing review.

This session did not establish the evaluation repository's current files, license, security rules, branch protection, CI, artifact conventions, or operating contract. Those facts stay unresolved. Intelligence Track 2 is the bootstrap session for that contract. Track 2 is not authorized by this document.

`patchpilot` is the right home for a future product adapter only after a later accepted composition ADR. It is the wrong home for notebooks, weights, red-team corpora, and experiment logs. Those artifacts would enter PatchPilot CI, container images, and release review before a composition decision exists.

The educational repository is the wrong home for tenant data, Product Match Evidence, Findings, and promotion records. Its license and file inventory are unrecorded in PatchPilot. Putting original PatchPilot evaluation data there would mix an unreviewed upstream tree with product evidence rules.

A separate evaluation repository keeps original PatchPilot work distinguishable from educational and upstream-derived work, and keeps both outside production CI.

## Accepted licensing facts

These facts are already committed. This strategy does not add to them.

- `LICENSE` is the Apache License, Version 2.0. `NOTICE` states that the product is Apache-2.0 and records copyright 2026 PatchPilot contributors.
- `NOTICE` and the v0.1.0 licensing record attribute `caniuse-lite` as CC-BY-4.0, vendored CycloneDX and OSV schemas as Apache-2.0 with their upstream notices, the vendored CISA KEV schema as CC0-1.0, and optional `@img/sharp-libvips-linux-x64` as LGPL-3.0-or-later through optional `sharp` of `next`. The web application does not import `next/image`.
- The v0.1.0 licensing record lists the SPDX counts observed on 2026-11-06 and says it does not claim legal certainty.
- [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) section 13 is Accepted: the Apache-2.0 license of the OSV schema repository does not establish one universal license for aggregated advisory content. CISA KEV is recorded as CC0 1.0. License and source provenance require further review before distribution or republishing.
- [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) section 12 repeats that limit and forbids a universal licensing claim.
- [ADR 0046](../adr/0046-offline-npm-osv-import.md) is Proposed. It records one GHSA registry entry as SPDX `CC-BY-4.0`. It does not claim that every OSV ecosystem shares that license. Imported rows stay ineligible for product evaluation.

## Required external review

Committed PatchPilot files do not record the license, copyright holder, upstream model licenses, upstream dataset licenses, or file inventory of `neural-from-scratch`. Session specs and this architecture set name it as an educational laboratory that this repository must not inspect, copy, or modify, and neither records its license.

That gap is a required external review. Until the review is recorded, no code, notebook, dataset, weight, or derivative artifact moves from that repository into `patchpilot` or into `patchpilot-intelligence-evals`. Apache-2.0 compatibility is not assumed. This session did not read that repository.

## Permitted and prohibited movement

Permitted, as a recommendation for later review:

- Restating a concept in original PatchPilot prose, with no copied implementation.
- Moving an original PatchPilot specification or implementation from `patchpilot-intelligence-evals` into `patchpilot` when a later accepted ADR authorizes that product artifact and the manifest records source, license, version, digest, and evaluation evidence.

Prohibited until that review and ADR exist:

- Copying an educational notebook into `patchpilot`.
- Copying upstream-derived implementation into `patchpilot` or into the evaluation repository.
- Adding `neural-from-scratch` or the evaluation repository to a PatchPilot package manifest, lockfile, Dockerfile, Compose file, CI workflow, or runtime import.
- Treating model output as source evidence or as an upstream license grant.
- Placing tenant secrets, credentials, raw SBOM bytes, raw advisory payloads, or another organization's Findings in the evaluation repository.

Public vulnerability data used in a future corpus remains under the source-license controls in ADR 0021 and ADR 0024. A fixture records source, license, version, retrieval date, and permitted evaluation use before inclusion. Raw advisory bodies stay out of model prompts unless a later ADR authorizes a bounded representation.

## Experiment manifests and promotion records

Every artifact proposed for promotion carries:

- source repository and path;
- license and attribution obligations;
- version or git revision;
- content digest;
- evaluation record identity;
- generation method and contamination notes when the artifact is synthetic;
- model identity and model digest when a model was used, or an explicit digest gap.

A missing license or a missing digest blocks promotion. The evaluation architecture defines the metric record. `patchpilot` retains a promoted artifact only after the later composition ADR. The evaluation repository keeps the manifest and the promotion evidence.

## CI, security ownership, and retention

PatchPilot CI does not build, test, or publish `neural-from-scratch` or `patchpilot-intelligence-evals`. Evaluation runs stay outside production workflows until a later ADR adds a specific job. Development adapters remain disabled when production disallows them, which is the existing ADR 0015 rule.

Security ownership of production tenant data stays with `patchpilot`. The evaluation repository receives no production credentials and no tenant exports. The instance operator's infrastructure access, already accepted as R19, is not a reason to copy tenant evidence into an evaluation tree.

Archive the evaluation manifests, digests, and promotion decisions with the evaluation repository. Do not delete PatchPilot audit rows or evidentiary product data to make room for model artifacts. Audit retention stays the rule in [retention-and-deletion.md](retention-and-deletion.md): audit events are insert-only and are not deleted in v0.1.

## What this document does not do

It does not change `LICENSE`, `NOTICE`, or the v0.1.0 licensing record. It does not choose a license for `patchpilot-intelligence-evals`. It does not authorize Intelligence Track 2 to bootstrap that repository. Track 2 remains a later session in [intelligence-architecture.md](intelligence-architecture.md).
