# ADR 0052: PatchPilot intelligence boundary

- Status: Proposed
- Date: 2026-11-09
- Deciders: Principal architect review pending. Drafted during Intelligence Track 1.
- Supersedes: none
- Superseded by: none

This ADR is a proposal. It does not supersede [ADR 0017](0017-optional-ai-user-credentials.md). Acceptance by a maintainer would adopt the boundary below. Acceptance would still not implement a model, authorize an experiment, open shadow mode, or compose a model in production.

## Context

PatchPilot v0.1.0 is published. The annotated tag `v0.1.0` resolves to `73a9e9026de240d6e2702f2ac4dfe583978fafcb`. The GitHub Release is published, is not a draft, and is not a prerelease. The frozen migration count is 28. The released product is a deterministic system for inventory, CycloneDX ingestion, vulnerability intelligence, Product Match Evidence, controlled Finding creation, KEV enrichment, P1–P4 priority, the remediation queue, append-only human review, and audit.

[ADR 0017](0017-optional-ai-user-credentials.md) is Accepted. v0.1 ships with AI disabled. The product remains useful without an AI provider. Optional AI, if a later decision adds it, may draft explanations or tickets only. It must never set authoritative priority. Users supply a key or a local endpoint at runtime. Keys are never hardcoded, never placed in client bundles, and never enabled by development defaults in production. Sending SBOM originals or Restricted evidence to a model requires a future ADR. [ADR 0012](0012-explainable-policy-engine.md) and [ADR 0045](0045-deterministic-p1-p4-priority-policy.md) keep priority explainable and deterministic. ADR 0045 records that AI never sets priority.

[ADR 0014](0014-append-only-audit.md) makes audit events insert-only. [ADR 0019](0019-local-password-sessions.md) derives the trusted actor from the session. [ADR 0044](0044-deliberate-product-match-evidence-evaluation.md) writes immutable Product Match Evidence and does not write a Finding. [ADR 0035](0035-controlled-finding-creation.md) and [ADR 0036](0036-controlled-finding-operator-api.md) limit Finding creation to owner `POST /findings`. [ADR 0038](0038-controlled-finding-web-workflow.md) and [ADR 0041](0041-controlled-finding-latest-observation-transport.md) limit inspection to owners and admins with `finding:inspect`. [ADR 0047](0047-controlled-priority-activation.md), [ADR 0048](0048-controlled-remediation-queue.md), [ADR 0049](0049-append-only-priority-review.md), and [ADR 0051](0051-remediation-queue-export.md) keep calculation, queue order, human review, and export on stored deterministic records. [ADR 0046](0046-offline-npm-osv-import.md) remains Proposed and does not make imported rows product-evaluation eligible.

The session spec `docs/specs/intelligence-track-1.md` is an execution contract for one documentation session. It is not an ADR and it is not a checkpoint.

Lessons from the independent educational repository `neural-from-scratch` may inform original PatchPilot work. Committed PatchPilot records do not contain that repository's license, copyright holder, file inventory, or upstream model and dataset licenses. This ADR does not inspect that repository and does not assume Apache-2.0 compatibility.

## Decision

### Four layers

This proposal separates four layers. Only the first is in scope, and only as a proposal.

| Layer | Meaning under this ADR |
| --- | --- |
| Architecture authorization | The boundary in this document, after a maintainer sets this ADR to Accepted. Acceptance adopts the boundary. It does not add code. |
| Experimental implementation | Original offline experiments and a synthetic corpus. Not authorized by this ADR. |
| Shadow mode | A model runs beside production reads while its output stays out of the product. Not authorized by this ADR. |
| Production composition | A deployed adapter, route, or page that can show generated assistance. Not authorized by this ADR. |

No provider, model, weight, dataset, prompt, adapter, API route, or user interface is selected or added here.

### Deterministic authorities

These PatchPilot decisions remain exclusively deterministic. A model must not create, delete, or alter them:

- asset and component identity;
- Product Match Evidence eligibility and evidence rows;
- affectedness, including any treatment of `unknown` as `unaffected`;
- Finding creation and Finding lifecycle;
- KEV membership interpretation, including any claim that a listing proves affectedness or exploitation in the tenant environment;
- policy facts, policy weights, and policy publication;
- P1–P4 calculation, band, numeric priority, and escalation;
- queue rank and due-date recommendations;
- priority review;
- export contents;
- tenant authorization;
- audit records.

An `affected` Product Match Evidence row remains evidence. It is not Finding authority. KEV remains catalog enrichment. A human priority review remains a statement about one immutable RiskCalculation. It does not replace the calculated priority.

### Advisory role and human control

Model output is advisory generated assistance. It is labeled as generated. A human may accept, reject, or edit a draft. Acceptance does not make the draft authoritative, and it does not write a Finding, a RiskCalculation, a priority review, or an audit record.

The smallest useful first capability, if a later session implements it, is the Evidence-grounded Finding Explanation Assistant described in [finding-explanation-assistant.md](../architecture/finding-explanation-assistant.md). It may summarize one existing controlled Finding, explain stored Product Match Evidence and stored priority factors, state KEV membership accurately, distinguish available, unavailable, unknown, stale, and incomparable evidence, name missing evidence, translate stored reason codes, organize remediation references the product already authorizes, draft non-authoritative guidance, and ask questions for a human analyst. It may not invent facts or change deterministic state.

### Tenant data

Tenant scope comes from the trusted server actor. A client-supplied organization id is not authority. Cross-tenant retrieval, prompting, caching, evaluation, and logging are prohibited.

A future prompt uses the minimum authorized projection already available to that actor for one Finding. Secrets, credentials, session tokens, encryption keys, raw environment variables, database connection strings, and private operational configuration are prohibited model inputs. Raw SBOM documents and raw advisory payloads stay excluded until a later accepted ADR authorizes a bounded representation. That exclusion preserves ADR 0017.

Training or fine-tuning on tenant data is prohibited unless a later accepted architecture and explicit tenant consent both exist. Tenant data must not be used to improve a third-party model. Evaluation fixtures are synthetic, public, or explicitly licensed.

### Provider neutrality

PatchPilot must not depend on one model vendor. A future port, described in [intelligence-architecture.md](../architecture/intelligence-architecture.md), must be able to represent local inference, self-hosted inference, explicitly approved hosted inference, a deterministic test double, and a disabled or unavailable state. Production remains disabled until a later composition ADR. Credentials stay user-supplied or operator-supplied, are read only through `packages/config`, and are decrypted only inside a future adapter. ADR 0015 still requires allowlists, blocked link-local and metadata ranges, timeouts, and size limits for any outbound fetch.

### Model-output status and citations

Generated prose is not Product Match Evidence, a Finding, a RiskCalculation, a policy publication, or an audit record. It is not source evidence. A factual claim cites a field in the authorized projection. The citation names that stored value. Model prose is not a citation target.

### Persistence, logging, and failure

Generated output is ephemeral. Storing it requires a later accepted ADR. Prompts and outputs are not written to default application logs. A later shadow-mode ADR, if one is accepted, must define a purpose-built record. That record is not a default log sink, excludes secrets, and stays inside the calling organization.

Disabled, unavailable, timeout, provider error, and schema-invalid output all return no generated text. Findings, Product Match Evidence, priority, queue order, and audit rows stay unchanged. An AI failure must not disable deterministic scoring. That duty is already in ADR 0017.

### Repository relationship

`patchpilot` keeps production code, deterministic authority, authorization, audit, and tenant boundaries. A future product adapter enters this repository only after a later accepted composition ADR.

`neural-from-scratch` stays outside the PatchPilot dependency graph, CI, release artifacts, container images, runtime imports, and package manifests. Educational notebooks and upstream-derived implementation are not copied into PatchPilot. Concepts may be restated in original PatchPilot documents. Code, datasets, notebooks, weights, and derivative artifacts move only after a recorded provenance, license, security, and architecture review. That review is still required, because the upstream license is unrecorded here.

Original PatchPilot evaluation work belongs in `patchpilot-intelligence-evals`. The maintainer created that independent repository during Intelligence Track 1. It exists on GitHub and as an independent local clone. Cursor did not create, inspect, or modify it. Its current files, license, security rules, branch protection, CI, and operating contract are unestablished in committed PatchPilot evidence. Creation does not authorize experiments, and it does not accept this ADR.

Whether PatchPilot formally adopts that repository as the exclusive evaluation workspace, and under which license, security controls, provenance rules, CI boundary, and promotion process, remains a Proposed decision. Intelligence Track 2 is the bootstrap session for those controls. This ADR does not authorize that session. PatchPilot does not depend on the evaluation repository at build time or runtime. The responsibilities are recorded in [intelligence-repository-strategy.md](../architecture/intelligence-repository-strategy.md).

### Evaluation before promotion, and shadow mode

A model-assisted capability moves toward shadow mode only after offline evaluation and adversarial evaluation meet the gates in [intelligence-evaluation.md](../architecture/intelligence-evaluation.md). Invariant gates are zero cross-tenant disclosure, zero unauthorized state mutations, zero model-driven changes to affectedness or P1–P4 priority, and zero secrets in the prompt, the output, or logs. The percentage gates in that document are initial proposals and require empirical calibration before anyone treats them as measured science.

Shadow mode is a later stage. It is not authorized here. User-visible assistance requires a further accepted ADR after shadow evidence exists. Production composition requires an explicit later ADR that names the provider, the model, credential handling, and the route or page. The stage order is in [intelligence-architecture.md](../architecture/intelligence-architecture.md).

### Later ADRs required before implementation

A later accepted ADR is required before any of the following:

- experimental code in either repository that PatchPilot will rely on;
- creation of an evaluation harness in PatchPilot CI;
- shadow mode;
- showing generated text to a user;
- persisting generated text;
- sending raw SBOM bytes or other Restricted evidence to a model;
- training or fine-tuning on tenant data;
- selecting a provider, a model, or a key-management design;
- adding an audit event for an invocation.

An invocation audit, if later accepted, records identifiers and an outcome class. The generated text is not the audit body.

## Alternatives considered

- **Copy educational code into PatchPilot.** Rejected. It would mix an unrecorded upstream license with the production tree and would make educational notebooks a product dependency.
- **Keep experiments inside the production repository.** Rejected for corpora, weights, red-team cases, and adapter prototypes. Those artifacts would enter PatchPilot CI, images, and review scope before a composition decision.
- **Let a model set affectedness, Findings, or P1–P4.** Rejected by ADR 0012, ADR 0017, and ADR 0045.
- **Bind v0.1 to one hosted model vendor.** Rejected. ADR 0015 and ADR 0017 already keep providers behind ports and keep the product useful with AI disabled.
- **Treat creation of the evaluation repository as acceptance of this ADR.** Rejected. The repository exists because the maintainer created it. Existence is not a decision to adopt it, and it is not permission to run experiments.
- **Mark this ADR Accepted in the drafting session.** Rejected. Repository convention leaves Accepted to a maintainer after review.

## Consequences

The proposal gives reviewers one boundary for later intelligence work. It adds no migration, package, workflow, or runtime setting. The frozen migration count stays 28. Operators gain no new procedure, because no model is composed. A maintainer who accepts this ADR still needs later ADRs before code.

The percentage promotion gates can be misread as measured quality. The evaluation document labels them as initial proposals that require calibration. The zero-count gates are security invariants and do not depend on that calibration.

The unrecorded license of `neural-from-scratch` blocks artifact transfer. It does not block this architecture, because the architecture forbids that transfer until the review exists.

## Security and tenancy

Organization scope comes from the trusted actor. Foreign and absent Findings stay indistinguishable on reads that already have that property. A future model call uses one organization's credential on that organization's authorized projection only.

Restricted data stays out of prompts until a later ADR. Confidential Finding projections, if later sent, are minimum fields the same actor can already inspect. Prompts and outputs stay out of default logs. Generated text is not an audit row and is not evidence. Canonical redaction still applies. No outbound model call exists in this change, so no new SSRF path is opened.

The threat model is [ai-ml-threat-model.md](../security/ai-ml-threat-model.md). New register rows begin at R71. R26 remains the accepted statement that optional AI leakage is controlled by keeping AI disabled.

## Operational failure plan

There is no runtime to operate. If a later adapter exists, disabled and failed calls return no text and leave scoring, Findings, evidence, and the queue unchanged. Detection of a future failure is an outcome class without prompt or output bodies. Recovery is to leave the capability disabled. Misconfiguration must not disable priority calculation.

## Follow-up

- Principal architect review of this Proposed ADR.
- External review of the `neural-from-scratch` license, copyright, and any upstream model or dataset licenses before any artifact is reused.
- Intelligence Track 2 bootstrap of the existing `patchpilot-intelligence-evals` repository, including license, security rules, provenance, branch protection, CI isolation, synthetic-data policy, and artifact-promotion controls. This ADR does not authorize that bootstrap.
- Intelligence Tracks 3 through 6 in the architecture document are a recommended order. This ADR does not authorize them.
