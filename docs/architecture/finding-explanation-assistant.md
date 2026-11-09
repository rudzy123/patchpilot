# Evidence-grounded Finding Explanation Assistant

This is a product contract for a future read-only assistant. It adds no route, page, prompt, permission, migration, audit type, or stored text. [ADR 0052](../adr/0052-patchpilot-intelligence-boundary.md) is Proposed and is the boundary. [ADR 0017](../adr/0017-optional-ai-user-credentials.md) remains Accepted: the product stays useful with AI disabled, and a model never sets authoritative priority.

Sentences that restate an accepted ADR are accepted product behavior today. Sentences about the assistant are recommendations for a later session. They are not implemented.

The glossary defines a Finding as the tenant-owned link between an asset, a versionless Component, and one Vulnerability advisory. Priority is the stored explainable ranking under a versioned policy. Risk score means the same thing until an ADR splits the terms. A priority band is a calculated grouping such as P1–P4, and it is not vulnerability severity. Match-evaluation evidence is an immutable tenant record of an affected-version evaluation. An affected row is not Finding authority. Product Match Evidence, as used by [ADR 0044](../adr/0044-deliberate-product-match-evidence-evaluation.md), is one deliberate evaluation and remains evidence only.

## Authorized users

Accepted: inspection requires `finding:inspect`. Owners and admins hold it. Members and viewers do not. [ADR 0036](../adr/0036-controlled-finding-operator-api.md) makes `finding:read` a different permission and not this inspection authority. [ADR 0038](../adr/0038-controlled-finding-web-workflow.md) keeps admin review read-only and reserves Finding creation confirmation for owners. [ADR 0041](../adr/0041-controlled-finding-latest-observation-transport.md) reuses `finding:inspect` and denies members and viewers. The server takes the role from the active membership.

Recommendation: the assistant uses that same set and adds no permission. It does not require `priority:review_controlled`, and it does not grant it.

## User problem

An owner or admin who can already open one Finding needs a shorter analyst-oriented account of stored inspection fields, the Product Match Evidence summary already returned, deterministic priority factors and closed reason codes, and KEV membership as stored. ADR 0045 already persists closed explanation codes. The assistant, later, would assemble those stored facts, the gaps, and questions for a human. The product remains complete when the assistant is absent.

## Invocation boundary

Recommendation: one read-only request names one Finding. Organization scope comes from the trusted server actor. A client-supplied organization id is not authority. Foreign and absent Findings stay indistinguishable, which is the existing ADR 0041 read behavior. The request writes no Finding, observation, evidence row, RiskCalculation, queue order, due date, or review.

Output is ephemeral. Persistence requires a later ADR. This contract adds no audit event. A later ADR may decide to audit an invocation. The generated text must not be the audit body. There is no silent contact with a hosted model. A later model uses a user-supplied key or a local endpoint. Keys stay out of client bundles and out of production defaults, which is ADR 0017.

## Authorized inputs

Recommendation: send only projections that actor can already receive for that Finding.

- Finding inspection fields returned by the existing inspection read.
- Product Match Evidence summaries already included in that inspection explanation: linked identities, outcomes, and policy versions. ADR 0035 bounds that explanation and keeps raw SBOM bytes out of it.
- When a priority row exists and `GET /findings/:findingId/priority` returns it, the stored factor rows, rule rows, closed explanation codes, contributions, band, numeric priority, escalation recommendation, due-date recommendation days, policy identity, and engine version. ADR 0047 returns stored rows and does not recompute them. Until an operator publishes the builtin, that route returns 503 and there are no factor rows to narrate.
- KEV membership display facts already available with that priority or inspection projection.
- Availability labels already stored: available, unavailable, unknown, stale, and incomparable.

These inputs are Confidential or Internal under [data-classification.md](data-classification.md). Unknown and unavailable both contribute 0 to priority and stay distinct. A KEV listing may raise the stored floor and may support an escalation recommendation. It does not prove affectedness or exploitation in the tenant environment. Escalation does not change the stored score, band, or due date.

## Prohibited inputs

Excluded from any future prompt:

- raw SBOM documents and raw advisory payloads;
- secrets, credentials, session tokens, encryption keys, raw environment variables, database connection strings, and private operational configuration;
- another organization's data, prompts, or outputs;
- provider object identities, retrieval proofs, and license URLs;
- audit payloads, priority-review reason text, and remediation notes.

Restricted evidence waits for a later ADR. One organization's credential is never applied to another organization's data.

## Structured output

The output keeps these parts separate:

| Part | Contents |
| --- | --- |
| Label | The text is generated assistance. |
| Source facts | Values copied from the authorized inputs, each named by projection and field. |
| Deterministic conclusions | Stored priority, band, policy identity, engine version, explanation codes, rule results, and due-date recommendation days. Quoted, not recomputed. |
| Generated explanation | Analyst-oriented restatement of those codes, plus optional questions for a human. |
| Missing evidence | Unavailable, unknown, stale, and incomparable inputs that the task needed. |
| Uncertainty | What those gaps leave open. Contradictory stored facts are repeated here and under source facts. |
| Remediation suggestions | References the product already authorizes, organized as non-authoritative guidance. |
| Citations | Structured pointers to authorized fields. |
| Safety warnings | Generated text is not authority. KEV is not exposure proof. Affectedness stops at stored evidence. Priority is unchanged. |

An empty part is an explicit empty list. Generated prose in the explanation and suggestion parts is never Product Match Evidence, a Finding, a RiskCalculation, or an audit record. Human acceptance of the draft does not change that.

## Citations

A claim about a package, asset, advisory, KEV record, Finding, priority, or evidence row cites an authorized field from this request. The citation carries the stored value or closed code. It does not cite another tenant, a raw document, a model-invented URL, or the model's own sentence. Static product text for a closed reason code may be cited as deterministic copy. A factual claim without a citation fails a later offline evaluation.

## Uncertainty and refusal

The draft adds no package, asset, advisory, KEV, or Finding fact. It does not assert affectedness beyond stored evidence. It does not present a human assessment as the calculated priority. It does not claim that remediation succeeded, and it does not execute remediation. It does not hide uncertainty or drop material contradictory evidence.

The assistant refuses when the answer would require an invented fact or a prohibited input, when the caller lacks `finding:inspect`, or when the Finding is foreign or absent. A refusal still returns the generated-assistance label, the authorized stored calculations the caller is allowed to see, the missing-evidence part, and the safety warning. A foreign or absent Finding returns the same non-disclosing result the inspection API already returns, with no generated facts. `unknown` stays `unknown`. An affected evidence row is not described as a Finding.

## Human review

Accepted: [ADR 0049](../adr/0049-append-only-priority-review.md) appends a human judgment of one immutable RiskCalculation. The review does not change calculated priority, queue rank, the due-date recommendation, the Finding, or occupancy. A corrected band is the human's working band. The stored band remains the calculated band. Posting a review is owner-only.

Recommendation: the assistant may mention a closed review status only when that status is already visible to this actor. It labels that status as human assessment. Accepting the draft does not post a review.

## Failure, budgets, and unavailable models

Accepted: if an AI endpoint is down, the core journey continues, and misconfiguration must not disable scoring.

Recommendation: timeout, rejected configuration, provider error, and a draft that fails the output sections all return no generated prose. Partial text is discarded. Findings and stored priority stay unchanged.

No latency or size budget is implemented. These ceilings are an initial proposal for later calibration, not a measured service objective:

- finish or fail within 15 seconds;
- authorized input at or under 16 KiB;
- model output at or under 32 KiB;
- explanation at or under 1,200 words.

Crossing a ceiling discards partial text. The evaluation architecture measures latency percentiles and does not use them as promotion gates.

## Observability and audit

Prompts and outputs stay out of default logs. Restricted values are never logged. A future operational record may hold a correlation id, an outcome class, and a duration. Metric labels omit Finding identifiers, package names, and generated text. A later ADR may audit the correlation id and the outcome class. The generated text must not be the audit body.

## Security controls

The server derives the actor, the organization, and `finding:inspect` before any prompt is built. Model text is rendered as untrusted text so it cannot carry markup into the page. Links and commands in that text are not executed and are not fetched. Remediation text only organizes references PatchPilot already authorizes. Cache keys for any future tenant prompt include the organization. Cross-tenant cache entries are prohibited.

Accessibility recommendation: the generated label and the band are text. Priority is not conveyed by color alone. The words "calculated priority" accompany a stored band.

## Non-goals

This capability does not add a permission, a Finding list, a lifecycle transition, automatic matching, ticket creation, patch execution, or policy publication. ADR 0017 allows a later decision to draft tickets. This first capability does not include tickets. It does not claim compliance, certification, exploitability, or completed remediation. It does not change an evidence row, a Finding, a RiskCalculation, queue rank, or an audit row.

## Acceptance criteria for later offline evaluation

A later offline run, on synthetic, public, or explicitly licensed fixtures, is eligible for discussion only when all of the following hold:

- members and viewers are denied, and inspecting owners and admins are allowed;
- foreign and absent identifiers share one non-disclosing result;
- every factual claim cites the fixture;
- prohibited inputs are absent from the request;
- KEV stays catalog enrichment;
- `unknown` stays distinct from `unaffected`;
- a human corrected band stays distinct from calculated priority;
- contradictory stored evidence remains visible;
- remediation text claims no success and includes no command;
- an unavailable model leaves stored priority and the Finding unchanged;
- the output parts stay separate, and the assistance label is text;
- the invariant gates in [intelligence-evaluation.md](intelligence-evaluation.md) are zero.

Those criteria do not authorize the run. The promotion stages in [intelligence-architecture.md](intelligence-architecture.md) still apply.
