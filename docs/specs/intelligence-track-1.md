Execution contract for this session only. It authorizes only the work it names. It is subordinate to repository security rules, accepted ADRs, frozen migrations, and docs/project/[current-state.md](http://current-state.md). If those disagree with this spec, stop and report the conflict. This file is not a checkpoint and is not an ADR.

# Intelligence Track 1: AI Boundary, Evaluation Architecture, and Repository Strategy

## Identity

- **Track:** PatchPilot Intelligence Track

- **Session ID:** Intelligence Track 1

- **Mission:** Define the architectural, security, licensing, evaluation, and repository boundaries through which ML knowledge developed in neural-from-scratch may inform original PatchPilot intelligence capabilities without making educational code a production dependency or granting a model authority over affectedness, Findings, deterministic P1-P4 priority, or remediation state.

- **First candidate capability:** Evidence-grounded Finding Explanation Assistant.

- **Base commit:** The parent of the spec-only commit that introduces this file. Before editing architecture documents, git rev-parse HEAD^ must equal git rev-parse origin/main.

- **Expected PatchPilot release state:** v0.1.0 published.

- **Expected frozen migration count:** 28.

- **Branch prefix:** docs/intelligence-track-1-architecture

- **Change type:** Architecture, security, evaluation, and repository-strategy documentation only.

- **Commit policy:** One Conventional Commit after Principal Architect review.

- **Automatic Git actions:** Cursor must not commit, push, create a pull request, create a tag, publish a release, deploy, or modify Git history.

## Architectural Outcome

Intelligence Track 1 must establish one coherent architecture answering:

1. How may lessons from neural-from-scratch support PatchPilot without copying educational or upstream-derived implementation into the product?

2. Which repository owns original PatchPilot-specific ML experiments and evaluations?

3. Which PatchPilot data may be supplied to a model?

4. Which data must always remain excluded?

5. What may an intelligence capability produce?

6. Which PatchPilot decisions remain exclusively deterministic?

7. How will grounding, hallucination, privacy, citation, refusal, and security be measured?

8. What evidence is required before a model-assisted capability may progress from experiment to shadow mode or production?

9. What is the smallest useful first capability?

10. What architectural decisions must be accepted before implementation begins?

The Session must result in an architecture that permits research while keeping the released PatchPilot deterministic system authoritative.

## Strategic Vision

PatchPilot provides the production security platform:

- trusted inventory ingestion;

- licensed vulnerability intelligence;

- Product Match Evidence;

- controlled Finding creation;

- CISA KEV enrichment;

- deterministic P1-P4 policy evaluation;

- immutable RiskCalculations;

- remediation queue;

- append-only human review;

- tenant isolation;

- auditability;

- self-hosted deployment.

neural-from-scratch provides an independent educational laboratory for learning and experimenting with:

- tokenization;

- embeddings;

- attention;

- decoder-only transformers;

- pretraining;

- classification;

- instruction tuning;

- parameter-efficient tuning;

- preference optimization;

- model evaluation.

The repositories must not be physically merged.

Educational notebooks and upstream-derived implementation must not be copied into PatchPilot.

Knowledge may transfer. Code, datasets, notebooks, generated weights, and derivative artifacts require explicit provenance, licensing, security, and architectural review before reuse.

## Invariants

### Deterministic authority

The following remain exclusively authoritative within PatchPilot:

- asset and component identity;

- Product Match Evidence eligibility;

- affectedness decisions;

- Finding creation;

- KEV membership interpretation;

- policy facts;

- policy weights;

- P1-P4 calculation;

- escalation;

- queue rank;

- due-date recommendations;

- Finding lifecycle;

- priority review;

- export contents;

- tenant authorization;

- audit records.

A model must not:

- create or delete a Finding;

- infer affectedness as authoritative state;

- assign or change P1-P4 priority;

- modify queue rank;

- alter Product Match Evidence;

- claim KEV proves affectedness;

- mutate a RiskCalculation;

- publish policy;

- write remediation state;

- execute a patch;

- contact an external provider without explicit approved composition.

### First-capability boundary

The Evidence-grounded Finding Explanation Assistant may eventually:

- summarize an existing controlled Finding;

- explain Product Match Evidence;

- explain deterministic priority factors;

- explain KEV membership accurately;

- distinguish available, unavailable, unknown, stale, and incomparable evidence;

- identify missing evidence;

- translate reason codes into analyst-oriented language;

- organize remediation references already authorized by PatchPilot;

- draft non-authoritative remediation guidance;

- generate questions for a human analyst.

The assistant must not:

- invent package, asset, advisory, KEV, or Finding facts;

- assert affectedness beyond stored PatchPilot evidence;

- change calculated priority;

- present human assessment as calculated priority;

- claim remediation has succeeded;

- execute remediation;

- conceal uncertainty;

- omit material contradictory evidence;

- use information from another tenant;

- treat generated prose as an audit record;

- silently contact a hosted model or external API.

### Human control

- Model output is advisory.

- Model output must be visibly labeled as generated assistance.

- A human remains responsible for accepting, rejecting, or editing generated guidance.

- Generated output does not become authoritative merely because a user accepts it.

- Any future persistence of generated output requires a separate accepted ADR.

- No model-generated result may bypass existing PatchPilot authorization.

### Tenant and data isolation

- Tenant scope must come from trusted PatchPilot server context.

- Client-provided organization identity is never authority.

- Cross-tenant retrieval, prompting, caching, evaluation, or logging is prohibited.

- Prompts must use the minimum necessary authorized evidence.

- Secrets, credentials, session tokens, encryption keys, raw environment variables, database connection strings, and private operational configuration are prohibited model inputs.

- Raw SBOM documents and raw advisory payloads are excluded unless a future accepted ADR authorizes a bounded representation.

- Model prompts and outputs must not be logged by default.

- Training or fine-tuning on tenant data is prohibited without a separate accepted architecture and explicit tenant consent.

- Tenant data must not be used to improve a third-party model.

- Evaluation fixtures must use synthetic, public, or explicitly licensed data.

### Repository isolation

The existing repositories retain distinct responsibilities.

#### patchpilot

Owns:

- production application code;

- authoritative security records;

- deterministic policy;

- authorization;

- audit;

- tenant boundaries;

- human workflows;

- approved model-adapter interfaces after future authorization;

- product-facing intelligence composition after future authorization.

#### neural-from-scratch

Remains:

- an independent educational laboratory;

- outside the PatchPilot production dependency graph;

- outside PatchPilot CI;

- outside PatchPilot release artifacts;

- outside PatchPilot Docker images;

- outside PatchPilot runtime imports;

- outside PatchPilot package manifests.

Intelligence Track 1 must not modify neural-from-scratch.

Cursor must not inspect or copy local files from the sibling neural-from-scratch repository.

Architecture may rely only on user-provided facts and committed PatchPilot documentation concerning the intended relationship. If exact upstream provenance or licensing details are required and are not already recorded in PatchPilot, identify them as a required external review rather than accessing the sibling repository.

#### Original PatchPilot intelligence evaluation workspace

The architecture must decide whether to create a separate repository, provisionally named:

patchpilot-intelligence-evals

That repository would own original PatchPilot-specific:

- synthetic evaluation datasets;

- prompt and output schemas;

- grounding tests;

- hallucination tests;

- privacy tests;

- tenant-isolation tests;

- model benchmarks;

- model cards;

- experiment manifests;

- promotion evidence;

- red-team cases;

- adapter prototypes that do not belong in production.

The final name is not automatically authorized by this spec. Cursor must recommend the repository strategy and justify it.

### Licensing and provenance

- Apache-2.0 compatibility must not be assumed without evidence.

- Upstream-derived educational code must retain required attribution.

- No educational notebook may be copied into PatchPilot.

- No model weights may enter PatchPilot without a documented license and usage disposition.

- No dataset may be used without documented provenance and permitted use.

- Synthetic datasets must record generation method and contamination risks.

- Public vulnerability data must remain subject to PatchPilot source-license controls.

- Model output must not be represented as source evidence.

- Original PatchPilot-specific work must be distinguishable from upstream-derived work.

- Every promoted artifact must have a traceable source, license, version, digest, and evaluation record.

### Model-provider neutrality

The architecture must not make PatchPilot dependent on one model vendor.

Future model composition should use a narrow adapter boundary capable of supporting:

- local inference;

- self-hosted inference;

- explicitly approved hosted inference;

- deterministic test doubles;

- disabled or unavailable model state.

No provider is authorized during Intelligence Track 1.

No API key, hosted endpoint, model download, model weight, or inference runtime may be added in this Session.

### No production composition

Intelligence Track 1 must not add:

- a model adapter;

- a model API route;

- prompt construction code;

- inference code;

- retrieval code;

- embeddings;

- a vector database;

- fine-tuning code;

- model weights;

- an explanation UI;

- model-generated product output;

- model-selection configuration;

- runtime model credentials.

This Session defines architecture only.

## Governing Authority

Before editing, Cursor must reread:

- all applicable [AGENTS.md](http://AGENTS.md) files;

- repository security rules;

- docs/project/[current-state.md](http://current-state.md);

- the latest project checkpoint;

- the ADR index;

- the v0.1.0 publication and release-verification records;

- ADR 0012;

- ADR 0014;

- ADR 0019;

- ADR 0038;

- ADR 0044;

- ADR 0045;

- ADR 0046;

- ADR 0047;

- ADR 0048;

- ADR 0049;

- ADR 0050;

- ADR 0051;

- the evidence and provenance architecture;

- the tenant and authorization architecture;

- the risk policy;

- the remediation lifecycle;

- the reliability model;

- the audit model;

- licensing and attribution records;

- dependency and supply-chain records;

- the current risk register;

- existing AI, ML, automation, privacy, data-retention, or external-provider statements in the repository.

## Assumed Repository State

Before editing, Cursor must prove:

- PatchPilot v0.1.0 is published.

- The annotated tag resolves to the recorded release commit.

- The GitHub Release is published.

- Local main equals origin/main.

- The working tree is clean after the spec-only commit.

- The parent of the spec-only commit equals origin/main.

- Frozen migration count remains 28.

- No migration 29 exists.

- No existing PatchPilot package depends on neural-from-scratch.

- No notebooks or source files from neural-from-scratch exist in PatchPilot.

- No production LLM or model runtime exists in PatchPilot.

- No embeddings or vector database exist in PatchPilot.

- No model has authority over affectedness, Findings, priority, or remediation.

- Existing deterministic product boundaries remain intact.

- No uncommitted post-v0.1.0 implementation exists.

- neural-from-scratch remains outside the PatchPilot repository.

If a material assumption is false, stop and report the conflict.

## Allowed Change Surface

Permitted:

- docs/specs/[intelligence-track-1.md](http://intelligence-track-1.md);

- one new ADR defining the PatchPilot intelligence boundary;

- one intelligence architecture document;

- one AI or ML threat model;

- one evaluation architecture document;

- one repository-strategy document;

- one first-capability product contract for the Finding Explanation Assistant;

- one model-promotion-gates document or section;

- ADR index;

- architecture index;

- current risk register;

- docs/project/[current-state.md](http://current-state.md);

- latest project checkpoint;

- licensing or provenance documentation where required;

- README only if a factual statement about the post-v0.1.0 roadmap is necessary.

Not permitted:

- product implementation;

- model integration;

- API routes;

- web UI;

- database changes;

- Prisma schema;

- migrations;

- tests for unimplemented product behavior;

- workflows;

- dependencies;

- lockfile;

- Dockerfiles;

- Compose;

- provider configuration;

- credentials;

- datasets;

- model weights;

- notebooks;

- changes to neural-from-scratch;

- creation of another repository;

- GitHub repository settings;

- deployment.

## Multi-Agent Execution Model

Cursor Plan is the lead architecture orchestrator.

Use **Grok 4.7 Extra High** for:

- parent-agent synthesis;

- authority conflicts;

- privacy and security decisions;

- repository-strategy decisions;

- evaluation-threshold decisions;

- independent final verification.

Delegate parallel read-only investigation to specialist agents.

### Agent 1: PatchPilot authority and product-boundary specialist

Determine:

- existing deterministic authorities;

- Finding, evidence, priority, queue, review, and audit boundaries;

- where generated assistance could safely attach in a future release;

- which existing ADRs constrain intelligence composition.

### Agent 2: Security, privacy, and tenant-isolation specialist

Develop the AI threat model covering:

- cross-tenant leakage;

- prompt injection;

- evidence poisoning;

- sensitive-data disclosure;

- insecure model providers;

- training-data retention;

- prompt and output logging;

- model inversion;

- membership inference;

- data exfiltration;

- malicious advisory text;

- malicious package names or versions;

- tool-use escalation;

- unsafe remediation guidance;

- denial of service;

- unbounded inference cost;

- model supply-chain compromise.

### Agent 3: Evaluation and ML-systems specialist

Define evaluation dimensions, datasets, metrics, thresholds, and reproducibility for:

- evidence faithfulness;

- factual support;

- citation correctness;

- unsupported-claim rate;

- omission of decisive evidence;

- contradiction detection;

- uncertainty handling;

- refusal behavior;

- prompt-injection resistance;

- tenant-isolation behavior;

- output-schema validity;

- deterministic replay under fixed conditions;

- latency;

- resource use;

- model-version reproducibility.

### Agent 4: Repository, licensing, and provenance specialist

Define:

- responsibilities of patchpilot;

- boundaries of neural-from-scratch;

- whether patchpilot-intelligence-evals should exist;

- permitted artifact movement;

- prohibited code copying;

- license and attribution requirements;

- model and dataset provenance;

- experiment manifests;

- digest and version requirements;

- promotion evidence.

This agent must not inspect the local sibling repository.

### Agent 5: First-capability product specialist

Define the Evidence-grounded Finding Explanation Assistant:

- user;

- user problem;

- authorized inputs;

- prohibited inputs;

- structured output;

- citations;

- uncertainty behavior;

- human-review boundary;

- failure states;

- observability;

- security controls;

- non-goals;

- acceptance criteria.

### Agent 6: Model-adapter and deployment-boundary specialist

Define a future provider-neutral boundary covering:

- local and hosted inference;

- runtime API-key ownership;

- model identity;

- model digest;

- disabled state;

- timeout and resource limits;

- data-retention controls;

- retry behavior;

- deterministic test doubles;

- no-provider and unavailable-provider behavior.

This Session must document only. It must not implement the adapter.

### Agent 7: Independent architecture-verification specialist

After the primary documents are written, independently verify:

- deterministic PatchPilot authority is preserved;

- no production composition is authorized accidentally;

- repository boundaries are coherent;

- evaluation gates are measurable;

- security threats have mitigations;

- thresholds are internally consistent;

- licensing statements do not overclaim;

- the first capability is useful but bounded;

- no document implies that model output is evidence or authoritative state.

### Coordination rules

The parent agent must:

- run read-only investigations in parallel;

- require evidence from committed PatchPilot files;

- distinguish accepted authority from new recommendation;

- reconcile findings into one coherent architecture;

- assign exclusive ownership of each document;

- prevent concurrent edits to the same file;

- avoid placeholder decisions;

- stop on unresolved material policy;

- commission independent verification after primary drafting.

No agent may modify product code or neural-from-scratch.

## Ordered Execution Plan

### Task 1: Establish the Post-v0.1.0 Baseline

#### Allowed files or subsystem

Read-only Git state, published-release records, current-state documentation, ADRs, architecture documents, risk register, licensing records, and repository structure.

#### Required behavior

Confirm every assumed repository-state item.

Produce an authority map identifying:

- deterministic authorities;

- security boundaries;

- tenant boundaries;

- evidence authorities;

- audit authorities;

- licensing authorities;

- existing prohibitions on AI, automation, or external providers;

- documentation that must be amended or superseded.

#### Tests

Run safe read-only Git, repository, migration-integrity, and documentation inspection commands.

#### Done condition

The parent agent has a proven baseline and assigns exclusive document ownership.

### Task 2: Define the Repository and Provenance Strategy

#### Allowed files or subsystem

New repository-strategy document and relevant licensing or provenance documentation.

#### Required behavior

Recommend one coherent repository model.

The recommendation must address:

- whether to create patchpilot-intelligence-evals;

- why original PatchPilot evaluation artifacts should or should not live separately;

- the continuing role of neural-from-scratch;

- the prohibition on copying educational notebooks into PatchPilot;

- permitted transfer of concepts, specifications, and original implementations;

- license and attribution review;

- model-weight provenance;

- dataset provenance;

- experiment manifests;

- artifact digests;

- release and promotion records;

- CI isolation;

- security ownership;

- archival and retention.

Do not create another repository in this Session.

#### Tests

Run documentation, link, and consistency checks.

#### Done condition

Repository responsibilities and artifact-promotion boundaries are explicit, unambiguous, and compatible with PatchPilot’s released architecture.

### Task 3: Create the Intelligence Boundary ADR

#### Allowed files or subsystem

Create the next available ADR and update the ADR index.

#### Required behavior

The ADR must decide:

- deterministic authorities that models may never override;

- advisory-only model role;

- human-control boundary;

- tenant-data boundary;

- provider-neutral design;

- no training on tenant data by default;

- model-output status;

- citation requirements;

- persistence restrictions;

- logging restrictions;

- failure and unavailable-model behavior;

- repository relationship;

- evaluation-before-promotion requirement;

- shadow-mode requirement;

- conditions requiring a future ADR.

The ADR must distinguish:

- architecture authorization;

- experimental implementation;

- shadow mode;

- production composition.

Use Accepted or Proposed status according to repository conventions and actual authority. Do not imply that production model composition is implemented.

#### Tests

Run ADR format, documentation alignment, and link checks.

#### Done condition

One governing ADR defines the intelligence boundary without authorizing production model behavior.

### Task 4: Create the AI and ML Threat Model

#### Allowed files or subsystem

New threat-model document and current risk register.

#### Required behavior

Define assets, trust boundaries, threat actors, threat scenarios, mitigations, detection, residual risk, and release gates.

At minimum cover:

- tenant-data leakage;

- prompt injection from advisory or package data;

- poisoned Product Match Evidence;

- unsupported claims;

- false certainty;

- omitted decisive evidence;

- embedded malicious instructions;

- provider retention;

- logging leakage;

- credential exposure;

- model and weight tampering;

- unsafe model downloads;

- evaluation contamination;

- supply-chain risk;

- denial of service;

- excessive context;

- excessive cost;

- untrusted model output rendering;

- unsafe remediation guidance;

- model-generated links or commands;

- cross-tenant cache keys;

- replay and nondeterminism.

Add identified material risks to the existing risk register using repository conventions.

#### Tests

Run risk-register, documentation, and architecture-alignment checks.

#### Done condition

Every material AI-specific threat has an owner, mitigation, evidence requirement, and residual-risk classification.

### Task 5: Define the Evaluation Architecture

#### Allowed files or subsystem

New evaluation-architecture document.

#### Required behavior

Define an evaluation system for the Finding Explanation Assistant.

The architecture must include:

- synthetic evaluation corpus;

- public or explicitly licensed source material;

- scenario taxonomy;

- gold evidence;

- decisive-evidence annotations;

- unsupported-claim annotations;

- refusal cases;

- cross-tenant negative cases;

- prompt-injection cases;

- contradiction cases;

- unavailable-evidence cases;

- stale-evidence cases;

- model and prompt identity;

- model digest where available;

- inference settings;

- software version;

- hardware or runtime profile;

- repeat count;

- result schema;

- experiment manifest;

- reproducibility record.

Define measurable metrics.

At minimum:

- evidence-attribution accuracy;

- factual-support precision;

- unsupported-claim rate;

- decisive-evidence omission rate;

- citation validity;

- output-schema validity;

- correct uncertainty rate;

- correct refusal rate;

- prompt-injection resistance;

- tenant-isolation failure count;

- deterministic-replay consistency;

- latency percentiles;

- peak memory or resource use.

Define initial promotion gates.

The minimum initial gates must include:

- zero cross-tenant disclosure events;

- zero unauthorized state mutations;

- zero model-driven changes to affectedness or P1-P4 priority;

- zero secrets in prompt, output, or logs;

- 100% structurally valid output on the approved corpus;

- at least 95% citation validity;

- at least 95% evidence-attribution accuracy;

- no more than 2% unsupported factual claims;

- at least 95% correct refusal on insufficient-evidence cases;

- at least 95% prompt-injection resistance on the approved adversarial corpus.

If a threshold cannot be justified, label it as an initial proposed gate requiring empirical calibration rather than silently treating it as scientific truth.

#### Tests

Run documentation, schema-description, and internal consistency checks.

#### Done condition

The evaluation framework is reproducible, measurable, security-aware, and capable of preventing unsupported promotion.

### Task 6: Define the Finding Explanation Assistant Contract

#### Allowed files or subsystem

New first-capability product-contract document.

#### Required behavior

Define:

- authorized users;

- exact user problem;

- invocation boundary;

- authorized inputs;

- prohibited inputs;

- structured output;

- required citations;

- explanation sections;

- uncertainty and refusal behavior;

- human-review behavior;

- generated-content labeling;

- timeout and unavailable-model behavior;

- safe rendering;

- safe remediation guidance;

- audit expectations;

- persistence restrictions;

- latency and size budgets;

- model-provider failure behavior;

- accessibility expectations;

- non-goals.

The proposed structured output must separate:

- source facts;

- deterministic PatchPilot conclusions;

- generated explanation;

- missing evidence;

- uncertainty;

- remediation suggestions;

- citations;

- safety warnings.

The output must never represent generated prose as Product Match Evidence, a Finding, a RiskCalculation, or an audit record.

#### Tests

Run contract consistency and architecture-alignment checks.

#### Done condition

The first capability is useful to an analyst, non-authoritative, explainable, and safe to evaluate offline.

### Task 7: Define Promotion Stages and Implementation Roadmap

#### Allowed files or subsystem

Intelligence architecture, roadmap, current-state, and latest checkpoint.

#### Required behavior

Define these promotion stages:

1. Educational learning.

2. Original PatchPilot experiment.

3. Offline evaluation.

4. Adversarial evaluation.

5. Shadow mode.

6. Human-reviewed advisory mode.

7. Explicit production composition.

For every stage define:

- entry criteria;

- permitted data;

- permitted infrastructure;

- required evidence;

- exit criteria;

- failure and rollback behavior;

- responsible reviewer;

- required ADR or security approval.

Define the next bounded Sessions without implementing them.

Recommended sequence:

- Intelligence Track 2: evaluation repository bootstrap and synthetic corpus;

- Intelligence Track 3: provider-neutral offline model adapter and deterministic test double;

- Intelligence Track 4: baseline model evaluation;

- Intelligence Track 5: shadow-mode Finding Explanation Assistant;

- Intelligence Track 6: human-reviewed production-composition decision.

Do not authorize those Sessions automatically.

#### Tests

Run roadmap, documentation, and current-state consistency checks.

#### Done condition

The post-v0.1.0 intelligence roadmap is staged, measurable, reversible, and subordinate to explicit review gates.

### Task 8: Independent Final Verification

#### Allowed files or subsystem

Complete Intelligence Track 1 documentation diff.

Only narrow factual corrections inside the allowed documentation surface are permitted.

#### Required behavior

A fresh agent must verify:

- no product code changed;

- no dependency or lockfile changed;

- no schema or migration changed;

- no model integration was implemented;

- no production composition was authorized accidentally;

- deterministic authority remains intact;

- tenant-data controls are explicit;

- repository boundaries are explicit;

- educational and original work remain distinguishable;

- evaluation metrics are measurable;

- promotion gates are enforceable;

- first-capability scope is bounded;

- threat model is complete enough for the next Session;

- neural-from-scratch was not accessed or modified.

#### Tests

Run every command in the Verification section.

#### Done condition

The independent reviewer reports no unresolved architectural blocker and the parent agent produces the required handoff.

## Out of Scope

Intelligence Track 1 must not:

- implement model inference;

- add a model provider;

- add API keys;

- implement prompts;

- add a model adapter;

- add an API route;

- add a web page;

- add a database table;

- create migration 29;

- change the Prisma schema;

- add dependencies;

- modify the lockfile;

- add model weights;

- download a model;

- add a dataset;

- add notebooks;

- add embeddings;

- add a vector database;

- add RAG;

- add fine-tuning;

- add LoRA;

- add preference optimization;

- add autonomous agents;

- add tool use;

- add remediation execution;

- change affectedness;

- change Findings;

- change P1-P4 priority;

- change queue ranking;

- create another repository;

- modify GitHub organization settings;

- modify neural-from-scratch;

- inspect local files inside neural-from-scratch;

- deploy anything.

## Stop Conditions

Stop and report if:

1. The parent of the spec-only commit does not equal origin/main.

2. The working tree contains unrelated changes.

3. PatchPilot v0.1.0 is not published.

4. Migration count is not 28.

5. Migration 29 exists.

6. Existing product code already imports or depends on neural-from-scratch.

7. Educational notebooks or upstream-derived source already exist inside PatchPilot.

8. A production model dependency already exists.

9. An existing accepted ADR grants a model authority over affectedness, Findings, priority, or remediation.

10. A proposed architecture requires copying upstream-derived educational code into PatchPilot.

11. A proposed architecture requires tenant data for training without explicit consent and accepted authority.

12. A material licensing question cannot be resolved from committed PatchPilot evidence.

13. A material privacy or tenant-isolation decision remains unresolved.

14. Evaluation gates cannot be made measurable.

15. The first capability cannot remain read-only and non-authoritative.

16. A schema, migration, dependency, workflow, product-code, or runtime change appears necessary.

17. The work cannot fit inside one architecture pull request.

18. neural-from-scratch is accessed or appears in the change set.

On a stop condition:

- make no speculative workaround;

- do not weaken deterministic authority;

- do not broaden scope;

- cite the conflicting repository authority;

- identify the smallest required decision;

- return the conflict for Principal Architect review.

## Verification

Run the repository-authorized equivalents of:

- pnpm format:check;

- pnpm lint;

- pnpm typecheck;

- pnpm test:unit;

- pnpm db:validate;

- pnpm build;

- pnpm workflows:lint;

- documentation and relative-link checks;

- architecture-alignment checks;

- risk-register consistency checks;

- ADR format and index checks;

- migration-integrity validation;

- frozen-migration-count validation;

- license and attribution documentation checks;

- git diff --check;

- git status --short --branch.

Integration and Playwright need not be rerun for a documentation-only architecture Session unless repository CI rules require them. Protected CI remains authoritative after the pull request is opened.

Before handoff, confirm:

- no product code changed;

- no tests or workflows changed;

- no schema or migration changed;

- migration count remains 28;

- no dependency or lockfile changed;

- no model, dataset, notebook, or weight was added;

- no repository was created;

- no deployment occurred;

- neural-from-scratch was not accessed or modified.

Recommended Conventional Commit:

docs(architecture): define PatchPilot intelligence boundary

Do not create the commit automatically.

## Handoff Requirements

Return one consolidated handoff containing:

1. Outcome

2. Base commit, branch, and working-tree state

3. Multi-agent execution summary

4. Authority reviewed

5. Repository strategy

6. Relationship to neural-from-scratch

7. Intelligence boundary ADR

8. AI and ML threat model

9. Evaluation architecture

10. Metrics and promotion thresholds

11. Finding Explanation Assistant contract

12. Model-provider boundary

13. Data, privacy, and tenant controls

14. Licensing and provenance controls

15. Promotion stages

16. Proposed Intelligence Track roadmap

17. Files changed

18. Every verification command and actual result

19. Independent verification findings

20. Scope compliance

21. Unresolved decisions

22. Residual risks

23. Proposed Conventional Commit

24. Proposed pull-request title and summary

25. Recommended Intelligence Track 2 prerequisites

Final verdict:

- ARCHITECTURE READY FOR PRINCIPAL REVIEW

- ARCHITECTURE READY WITH DOCUMENTED RESIDUALS

- ARCHITECTURE NOT READY

- BLOCKED BY UNRESOLVED AUTHORITY

Explicitly confirm:

- no product code changed;

- no model integration was implemented;

- no dependency installed or updated;

- no automatic commit or push;

- no pull request created automatically;

- no repository created;

- no deployment occurred;

- migration count remains 28;

- neural-from-scratch was not accessed or modified.

End with exactly one:

INTELLIGENCE TRACK 1 READY FOR PRINCIPAL ARCHITECT REVIEW BEFORE COMMIT

or:

INTELLIGENCE TRACK 1 BLOCKED PENDING PRINCIPAL ARCHITECT REVIEW