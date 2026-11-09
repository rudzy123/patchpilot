# AI and ML threat model

This document is a design aid for future model assistance. It is not a penetration test, a certification, or proof of exploitability. No model, prompt, adapter, or provider is composed. v0.1 sends nothing to an AI provider, which is the Accepted rule in [ADR 0017](../adr/0017-optional-ai-user-credentials.md).

The proposal that records the boundary is [ADR 0052](../adr/0052-patchpilot-intelligence-boundary.md). It is Proposed. The v0.1 threat model remains [threat-model.md](threat-model.md) and already names AI data leakage as a later risk. This document does not replace that section. Register rows R71–R90 add the AI-specific risks. R26 remains the row for optional AI leakage while the capability is disabled.

Likelihood below stays low while AI is disabled, except where an existing non-AI sink already raises it. Impact stays high where a tenant evidence disclosure or a wrong security decision would matter. `mitigated-in-design` means this document specifies the control. The runtime residual remains until a later composition exists and is tested. No row is accepted as a residual-risk sign-off.

## Assets

| Asset | Class | Model rule |
| --- | --- | --- |
| Original SBOM bytes, raw advisory and feed payloads, credentials, session tokens, keys, connection strings | Restricted | Excluded from prompts until a later accepted ADR allows a bounded form. ADR 0017 already requires that ADR for SBOM originals and Restricted evidence. |
| Findings, parsed components, Product Match Evidence, priorities, queue rows | Confidential | A future prompt may carry only the minimum projection the same actor can already inspect for one Finding. |
| KEV membership and builtin policy definitions | Internal | Catalog facts. A listing is not affectedness and is not proof of exploitation in the tenant environment. |
| Generated drafts | Untrusted output | Advisory text. Not evidence, not a Finding, not a RiskCalculation, and not an audit record. |
| Evaluation corpora and manifests | Separate from production | Synthetic, public, or explicitly licensed. No production tenant export. |

## Trust boundaries

Accepted boundaries that a future model call must not weaken:

- The API derives the trusted actor from the session. A client-supplied organization id is not authority ([tenant-isolation.md](../architecture/tenant-isolation.md), [ADR 0019](../adr/0019-local-password-sessions.md)).
- The browser, SBOM bytes, and vulnerability-feed bodies are untrusted ([trust-boundaries.md](../architecture/trust-boundaries.md)). Package names, versions, and advisory text are untrusted data, including inside a future prompt.
- Object storage holds original SBOM bytes under an organization-prefixed private key ([ADR 0008](../adr/0008-private-object-storage.md)).
- The web application is not the authorization engine. A future explanation page would render text the API already authorized. It would not decide access.
- Development adapters are not constructible when production disallows them ([ADR 0015](../adr/0015-provider-neutral-integrations.md)).
- Audit rows are insert-only. Generated prose does not update an audit row and is not the body of one ([ADR 0014](../adr/0014-append-only-audit.md)).

A future model provider, local or hosted, is a new trust boundary. Nothing in the current release crosses it.

## Actors

| Actor | Relevant behavior |
| --- | --- |
| Organization owner or admin with `finding:inspect` | The only roles that can already read one Finding. A future assistant adds no permission. |
| Member, viewer, or anonymous caller | Denied inspection today. A future assistant stays denied. |
| Instance operator | Infrastructure access is accepted as R19. That access is not permission to train on tenant data or to copy it into an evaluation tree. |
| Malicious SBOM or advisory author | Can place instructions in names, versions, and descriptive text. The product already treats those fields as untrusted. |
| Model provider or model supplier | Can retain inputs, serve a substituted weight, or fail open. No provider is approved. |
| Cross-tenant caller | Already fails closed on foreign Findings. A future cache or prompt must do the same. |

## Threats, controls, and residuals

Review owner for every row: the principal architect, before any model-composition ADR. Runtime owner after composition, if it is ever accepted: the deployment operator. Evidence required before promotion is the evaluation record in [intelligence-evaluation.md](../architecture/intelligence-evaluation.md). Detection before a runtime exists is review of the design. Detection after a runtime exists is an outcome class that omits prompt and output bodies.

| ID | Threat | Mitigation in this design | Detection | Residual |
| --- | --- | --- | --- | --- |
| R26 | Optional AI leakage | AI remains disabled under ADR 0017. | No provider traffic in v0.1. | If a later ADR enables a model, the residual reopens until the gates below pass. |
| R71 | Prompt injection, including instructions embedded in advisory or package text | Stored text is data. A future prompt keeps system instructions separate from evidence. The capability is read-only. | Adversarial corpus. One followed instruction that changes authority fails the run. | No prompt exists yet. |
| R72 | Poisoned Product Match Evidence used as instructions | Evidence rows stay immutable and are not Finding authority. A future prompt does not grant them instruction privilege. | Cases that place instructions in evidence fields. | The product writer is unchanged. The model path is absent. |
| R73 | Unsupported factual claims | Claims cite stored fields. Invented package, asset, advisory, KEV, or Finding facts fail the draft. | Unsupported-claim rate on the approved corpus. | The rate gate is an initial proposal and needs calibration. |
| R74 | False certainty | `unknown`, `unavailable`, stale, and incomparable stay labeled. `unknown` is not stated as `unaffected`. | Uncertainty cases in the corpus. | No generated-language control exists at runtime. |
| R75 | Omission of decisive or contradictory evidence | Gold annotations name evidence that must be restated. Material contradictions stay visible. | Omission rate. | No numeric omission gate is set in this session. |
| R76 | Provider retention or training on tenant data | No provider is approved. Tenant data is not training data and is not used to improve a third-party model. | Provider terms reviewed in a later ADR before any hosted call. | No retention contract exists because no provider is selected. |
| R77 | Prompt or output logging leakage | Prompts and outputs are absent from default logs. Canonical redaction still applies. | Log and metric review for a later adapter. Metric labels omit Finding identifiers and names. | R11 sink-bypass residual still applies to the product. |
| R78 | Credential or secret exposure to a model | Secrets, keys, session tokens, and connection strings are prohibited inputs. Keys are decrypted only inside a future adapter and are never logged. | Secret scan of prompts, outputs, and logs. The invariant gate is zero. | R16 credential-KEK handling remains open for the product and is not solved here. |
| R79 | Model or weight tampering | No weight is added. A later experiment records a digest or an explicit digest gap. A missing digest blocks a bit-level identity claim. | Manifest review. | No pin exists until an artifact exists. |
| R80 | Unsafe model download | This session downloads nothing. A later fetch uses an allowlist and rejects link-local and metadata destinations. User-controlled URLs are not fetched. | Review of any later download ADR. | No download allowlist exists. |
| R81 | Evaluation contamination | Fixtures are synthetic, public, or explicitly licensed. Synthetic origin stays synthetic. Real tenant names and secrets stay out. | Corpus manifest records generation method and contamination notes. | No corpus exists. |
| R82 | Model supply-chain compromise | The educational repository and `patchpilot-intelligence-evals` stay outside PatchPilot CI, images, and package manifests. | Dependency and provenance review before promotion. | R20 remains a watched product supply-chain risk and does not cover weights. |
| R83 | Inference denial of service | A future call has a timeout and a byte ceiling. Failure returns no text and leaves scoring up. | Timeout count, separate from quality metrics. | No runtime ceiling is configured. |
| R84 | Excessive context | Minimum authorized projection only. Raw SBOM documents and raw advisory payloads stay out. | Input-byte measurement. | No context budget is enforced. |
| R85 | Unbounded inference cost | No hosted call is composed. A later ADR sets a budget. Failure must not disable scoring. | Cost is an operator concern after a provider exists. | No spend ceiling exists. |
| R86 | Untrusted model output rendering | Generated text is untrusted, escaped, and labeled as generated assistance. | Review of any future page. Existing R9 still covers component-name XSS. | No model sink exists. |
| R87 | Unsafe remediation guidance | Guidance is non-authoritative, organizes only references the product already authorizes, and does not claim that remediation succeeded. | Contract checks in offline evaluation. | No draft surface exists. |
| R88 | Model-generated links or commands | Links and commands in model text are not executable and are not fetched. | Rendering review and adversarial cases. | No allowlist of model-emitted URLs exists. |
| R89 | Cross-tenant cache, retrieval, or prompt scope | Organization scope comes from the trusted actor. Cache keys for tenant data include the organization. Foreign and absent Findings stay indistinguishable. | Cross-tenant negative cases. The gate is zero events. | No AI cache exists. R1 remains the product IDOR risk. |
| R90 | Nondeterministic output treated as authority | Output is ephemeral advisory text. Replay consistency is recorded and is not a Finding, a priority, or an audit body. | Repeat count in the experiment manifest. | A model that cannot fix a seed cannot support a determinism claim. |

## Release gates

These gates are entry conditions for a later promotion discussion. They are not a statement that a model has passed them.

Invariant gates, each a count of zero:

- cross-tenant disclosure in the prompt, the output, or the evaluation log;
- unauthorized writes to Findings, evidence, priority, queue rank, remediation state, or audit rows;
- model-driven changes to affectedness or P1–P4 priority;
- secrets in the prompt, the output, or logs.

Initial proposed gates, which require empirical calibration before they are treated as measured science:

- 100% structurally valid output on the approved corpus;
- at least 95% citation validity;
- at least 95% evidence-attribution accuracy;
- no more than 2% unsupported factual claims;
- at least 95% correct refusal on insufficient-evidence cases;
- at least 95% prompt-injection resistance on the approved adversarial corpus.

A passing evaluation does not accept ADR 0052 and does not compose a model. Shadow mode and production composition each require a later ADR.

## Residual classification

While AI stays disabled, the operational residual for these threats is the same as R26: the harm appears if a later change enables a model without the gates. The design residual is that percentage gates are uncalibrated, the `neural-from-scratch` license is unrecorded, and no provider retention terms exist. Those residuals are review items. They are not accepted risk.
