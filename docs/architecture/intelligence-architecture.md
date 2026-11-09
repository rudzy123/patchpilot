# PatchPilot intelligence architecture

This document is the map for Intelligence Track 1. It is not a checkpoint and it is not an accepted ADR. The proposal is [ADR 0052](../adr/0052-patchpilot-intelligence-boundary.md). [ADR 0017](../adr/0017-optional-ai-user-credentials.md) remains Accepted. v0.1 ships with AI disabled, and the product remains useful without a model.

No model, adapter, prompt, dataset, weight, route, or page is added here. The frozen migration count stays 28.

## Questions this architecture answers

1. Lessons from `neural-from-scratch` may be restated as original PatchPilot concepts. Educational notebooks, upstream-derived code, weights, and datasets stay out until a recorded provenance and license review. That review is still required. See [intelligence-repository-strategy.md](intelligence-repository-strategy.md).
2. Original PatchPilot evaluation artifacts belong in `patchpilot-intelligence-evals`. The maintainer created that independent repository during Intelligence Track 1. Cursor did not inspect or modify it. Formal adoption, license, and bootstrap remain subject to ADR 0052 review and Intelligence Track 2. `patchpilot` keeps production authority and does not depend on the evaluation repository.
3. A future model may receive the minimum projection an owner or admin with `finding:inspect` can already read for one Finding: inspection fields, linked Product Match Evidence summaries, stored priority factors and closed reason codes, and stored KEV display facts.
4. Raw SBOM documents, raw advisory payloads, secrets, credentials, session tokens, keys, connection strings, private configuration, and every other tenant's data stay out. Training on tenant data is prohibited unless a later accepted architecture and explicit tenant consent both exist.
5. The first capability may produce labeled, ephemeral, non-authoritative explanation text. The contract is [finding-explanation-assistant.md](finding-explanation-assistant.md).
6. Asset identity, Product Match Evidence, affectedness, Finding creation, KEV interpretation, policy, P1–P4, queue rank, due-date recommendations, priority review, export contents, authorization, and audit remain deterministic.
7. Grounding, hallucination, privacy, citation, refusal, and security are measured by the metrics and gates in [intelligence-evaluation.md](intelligence-evaluation.md).
8. Movement from experiment toward shadow mode requires zero invariant failures and passage of the initial proposed rate gates, followed by a later ADR. Percentage gates require empirical calibration before anyone treats them as measured science.
9. The smallest useful first capability is an Evidence-grounded Finding Explanation Assistant beside existing inspection of one Finding.
10. ADR 0052 must be reviewed by the principal architect before implementation. Acceptance of that ADR still does not compose a model. Shadow mode, persistence, Restricted prompts, provider selection, and production composition each need a further accepted ADR.

## Authority map

Accepted authority, unchanged by this track:

| Topic | Authority |
| --- | --- |
| Asset and component identity | Finding natural key is organization, asset, versionless component, and vulnerability. [ADR 0035](../adr/0035-controlled-finding-creation.md). |
| Product Match Evidence | Owner `POST /assets/:assetId/product-match-evaluations` writes immutable evidence and does not write a Finding. [ADR 0044](../adr/0044-deliberate-product-match-evidence-evaluation.md). Real product-eligible evaluation count remains 0. |
| Affectedness | `unknown` is not `unaffected`. An `affected` row is not Finding authority. The checkpoint states both. |
| Finding creation | Owner `POST /findings` only. Automatic creation remains unavailable. [ADR 0036](../adr/0036-controlled-finding-operator-api.md). |
| Inspection attachment point | Owners and admins with `finding:inspect` read one Finding. Members and viewers are denied. [ADR 0038](../adr/0038-controlled-finding-web-workflow.md), [ADR 0041](../adr/0041-controlled-finding-latest-observation-transport.md). |
| KEV | Catalog enrichment. Not affectedness and not proof of exploitation in the tenant environment. [ADR 0045](../adr/0045-deterministic-p1-p4-priority-policy.md). |
| P1–P4 | Pure deterministic engine. AI never sets priority. ADR 0045 and ADR 0017. Calculation returns 503 until the operator publishes the admitted builtin. [ADR 0047](../adr/0047-controlled-priority-activation.md). |
| Queue rank | Stored order on `GET /remediation-queue`. A review does not change it. [ADR 0048](../adr/0048-controlled-remediation-queue.md). |
| Human review | Append-only. The calculated band remains the calculated band. [ADR 0049](../adr/0049-append-only-priority-review.md). |
| Export | Owner and admin export of stored queue rows. The file is not a model product. [ADR 0051](../adr/0051-remediation-queue-export.md). |
| Tenant scope | Trusted actor from the session. A client organization id is not authority. [ADR 0019](../adr/0019-local-password-sessions.md), [tenant-isolation.md](tenant-isolation.md). |
| Audit | Insert-only. Generated prose is not an audit record. [ADR 0014](../adr/0014-append-only-audit.md). |
| AI today | Disabled. [ADR 0017](../adr/0017-optional-ai-user-credentials.md). |
| Public vulnerability licenses | Per-source review. No universal OSV content license. [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md), [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md). |
| Evidence provenance | [ADR 0031](../adr/0031-product-evidence-provenance-architecture.md) remains Proposed. Synthetic evidence is not product evidence. |

Existing prohibitions this track keeps: no authoritative model scores ([non-goals](../product/non-goals.md)); no production OSV acquisition; no automatic Finding creation; development adapters disabled when production disallows them ([ADR 0015](../adr/0015-provider-neutral-integrations.md)).

Documents amended with this track: the ADR index, the architecture index, the security index, the risk register from R26's cross-link and rows R71–R90, and the current-state checkpoint. The v0.1 threat model, the v0.1.0 licensing snapshot, the README, and the checkpoint ledger are unchanged.

## Provider-neutral adapter boundary

This section documents a future port. It does not add the port to a package. Domain code would depend on the port and would not import Fastify, Next.js, Prisma, or a vendor SDK. `packages/config` remains the only reader of `process.env`. This section names no environment variable.

A later ADR must choose the provider, the model, and key management before any adapter is implemented. Until that ADR, production composition is disabled.

The same port must be able to front local inference, self-hosted inference, explicitly approved hosted inference, a deterministic test double, or no runtime. A test double is a development adapter. ADR 0015 already forbids constructing development adapters when the deployment disallows them. Local inference has the same tenant-isolation duty as a hosted call.

| State | Result |
| --- | --- |
| Disabled | Production default. No network, no model selection, and no generated text. Scoring continues. |
| Unavailable | A later composition exists, but this call has no credential, no reachable runtime, or no model identity. No generated text. Deterministic records stay unchanged. |
| Complete | The call finished inside the timeout and byte limits and matched the output sections. The result carries advisory text, the caller-supplied organization scope, the model identity, and the digest or an explicit digest gap. It does not set priority or write a Finding. |
| Failed | Timeout, provider error, or schema-invalid output. Partial text is discarded. Deterministic records stay unchanged. |

The caller passes organization scope from the trusted actor, a bounded input, a model identity, a timeout, and a maximum output size. The port does not choose a vendor. It does not write Findings, evidence, or priority. It does not perform network or object-storage I/O inside a database transaction. It does not fetch a user-controlled URL. It does not call tools, retrieve with embeddings, or use a vector database. It does not retry by sending tenant data to a different provider or a different model. Prompts and outputs are not logged by default. A hosted provider is not authorized to retain or train on tenant data.

The initial fail-closed budgets in the assistant contract are 15 seconds, 16 KiB of authorized input, 32 KiB of output, and 1,200 words of explanation. They are uncalibrated proposals. Crossing one discards partial text. They are not quality gates. Quality gates live in the evaluation document.

## Promotion stages

Each stage is a gate for a later decision. This document does not authorize entry to stages 2 through 7. Stage 1 is the continuing educational boundary and adds no PatchPilot artifact.

The responsible reviewer for every stage is the principal architect. A security review joins at adversarial evaluation and stays through production composition. The deployment operator becomes the runtime owner only after an accepted composition ADR.

### 1. Educational learning

- Entry: study outside PatchPilot.
- Permitted data: no PatchPilot tenant data.
- Infrastructure: the educational repository, outside PatchPilot CI, images, and package manifests.
- Required evidence: none inside PatchPilot.
- Exit: a concept restated in original prose, with no copied implementation.
- Failure and rollback: any copied notebook or upstream-derived file is excluded from promotion.
- ADR: none for learning. Artifact transfer waits for the external license review and a later ADR.

### 2. Original PatchPilot experiment

- Entry: a later session authorizes original experimental work in the existing evaluation repository.
- Permitted data: synthetic data, or public data with a recorded license and permitted use.
- Infrastructure: `patchpilot-intelligence-evals` only. Repository creation is already done and is not this authorization.
- Required evidence: an experiment manifest with source, license, version, digest, and contamination notes.
- Exit: a reproducible offline plan that names the corpus and the model identity.
- Failure and rollback: the artifact stays out of `patchpilot`.
- ADR: ADR 0052 reviewed. This stage still does not modify the production tree.

### 3. Offline evaluation

- Entry: a frozen corpus and a complete manifest.
- Permitted data: the approved corpus only.
- Infrastructure: outside production CI and outside the production database.
- Required evidence: the reproducibility record and every metric in the evaluation document.
- Exit: every invariant count is zero, and every initial proposed rate gate passes, or the gate set is explicitly revised and re-run.
- Failure and rollback: a non-zero invariant count blocks promotion. The deterministic product is unchanged because this stage does not touch it.
- ADR: a later session ADR before any harness is added to PatchPilot CI.

### 4. Adversarial evaluation

- Entry: an offline evaluation report that met the exit rule above.
- Permitted data: the approved adversarial corpus. No tenant secrets.
- Infrastructure: isolated from production.
- Required evidence: prompt-injection results and a tenant-isolation count of zero.
- Exit: the proposed resistance gate passes and the invariant counts stay zero, or the gate set is explicitly revised and re-run.
- Failure and rollback: return to experiment. Do not open shadow mode.
- ADR: security review recorded with the report. Shadow mode is still a separate ADR.

### 5. Shadow mode

- Entry: adversarial evaluation met its exit rule, and a later ADR accepts shadow mode for this capability.
- Permitted data: the minimum authorized projection for the calling organization. Raw SBOM documents and Restricted evidence stay out unless that later ADR, or a further one, allows a bounded form.
- Infrastructure: a read path beside production. Output is withheld from users and from default logs. A purpose-built shadow record, defined by that ADR, may retain outcome class and digests inside the organization. It is not an application log and it is not an audit body.
- Required evidence: shadow comparisons against stored priority and stored evidence, with invariant counts still zero.
- Exit: a written review that the drafts did not change deterministic state.
- Failure and rollback: disable the shadow path. Scoring, Findings, and evidence stay as they were.
- ADR: required before entry. This document does not supply it.

### 6. Human-reviewed advisory mode

- Entry: reviewed shadow evidence and a later ADR that allows labeled drafts to be shown.
- Permitted data: the same minimum projection.
- Infrastructure: the product UI or API, still read-only with respect to Findings, evidence, priority, queue order, and audit bodies.
- Required evidence: the assistant contract's acceptance criteria, plus the evaluation gates.
- Exit: reviewers accept the labeling, refusal, and citation behavior on the approved corpus and on the shadow sample.
- Failure and rollback: hide the drafts and return the capability to disabled. Human acceptance of a draft still does not change calculated priority.
- ADR: required before entry. Persistence of drafts is a further ADR if it is wanted at all.

### 7. Explicit production composition

- Entry: an accepted ADR that names the provider, the model, credential handling, the route or page, and the operator enablement switch.
- Permitted data: only the classes that ADR lists.
- Infrastructure: `patchpilot` production processes. The default remains disabled until the operator enables it in that deployment. Development defaults must not enable it.
- Required evidence: the composition ADR, the evaluation record, and the threat-model rows R71–R90 still matched to controls.
- Exit: the capability can be turned off without disabling scoring.
- Failure and rollback: configuration returns to disabled. ADR 0017 already requires that an AI failure leave the core journey up.
- ADR: this stage is that ADR. Intelligence Track 1 is not it.

## Recommended later sessions

These sessions are an order of work. None of them is authorized by ADR 0052 or by this document.

| Session | Subject | Prerequisite |
| --- | --- | --- |
| Intelligence Track 2 | Bootstrap the existing `patchpilot-intelligence-evals` repository and a synthetic corpus contract | Principal architect disposition of ADR 0052. License, security rules, provenance, branch protection, CI isolation, and a synthetic-only data policy. External license review recorded before any educational artifact is reused. No tenant data. |
| Intelligence Track 3 | Provider-neutral offline adapter and a deterministic test double, outside production composition | Track 2 corpus plan. A later ADR for the port. Test double disabled when production disallows development adapters. |
| Intelligence Track 4 | Baseline offline evaluation | Tracks 2 and 3. The reproducibility record. No production CI job unless a separate ADR adds one. |
| Intelligence Track 5 | Shadow-mode assistant | Track 4 gates passed. A shadow-mode ADR. Output withheld from users and from default logs. |
| Intelligence Track 6 | Human-reviewed production-composition decision | Track 5 evidence. An explicit composition ADR. Default remains disabled. |

## Data, privacy, and tenant controls

Organization scope comes from the trusted actor. Cross-tenant prompting, caching, evaluation, and logging are prohibited. The threat model is [ai-ml-threat-model.md](../security/ai-ml-threat-model.md). R26 stays the accepted statement that leakage is controlled by leaving AI disabled. R89 is the cross-tenant model risk and is P0 in design only.

Prompts and outputs are not default logs. Generated text is ephemeral. Tenant data is not training data. Evaluation fixtures do not contain production exports.

## Failure

Disabled, unavailable, and failed model calls return no generated text. Findings, Product Match Evidence, RiskCalculations, queue order, and audit rows stay unchanged. Priority routes keep their current 503 behavior until the operator publishes the builtin. An AI misconfiguration must not turn that 503 into a model-invented priority, and it must not disable the engine.

## What this document does not authorize

It does not accept ADR 0052. It does not implement the assistant. It does not modify `patchpilot-intelligence-evals`. It does not grant a model authority over affectedness, Findings, priority, or remediation. It does not change the frozen migration count.
