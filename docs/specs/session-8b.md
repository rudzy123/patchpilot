Execution contract for this session only. It authorizes only the work it names. It is subordinate to repository security rules, accepted ADRs, frozen migrations, and docs/project/[current-state.md](http://current-state.md). If those disagree with this spec, stop and report the conflict. This file is not a checkpoint and is not an ADR.

# **Session 8B: MVP 0.1 Release Closure**

## **Identity**

- **Session ID:** Session 8B
- **Mission:** Implement the ADR 0051 remediation-queue export, add one deterministic Playwright release smoke test, complete licensing and dependency review, reconcile the release record, and prepare PatchPilot MVP 0.1 for the v0.1.0 release decision.
- **Base commit:** The parent of the spec-only commit that introduces this file. Before editing product files, git rev-parse HEAD^ must equal git rev-parse origin/main. Record the full SHA in the Session handoff. If the SHAs differ, stop.
- **Expected frozen migration count:** 28
- **Branch prefix:** release/session-8b-mvp-0.1
- **Release candidate version:** 0.1.0
- **Reserved release tag:** v0.1.0
- **Branch size:** One pull-request-sized branch.
- **Commit policy:** One Conventional Commit for the Session 8B implementation after Principal Architect review.
- **Automatic Git actions:** Cursor must not commit, push, create a pull request, create a tag, publish a GitHub Release, deploy, or merge.

## **Invariants**

### **Repository authority**

- Accepted ADR 0051 is the exclusive authority for remediation-queue export.
- ADR 0048 remains authoritative for remediation-queue permissions, tenant scope, section membership, comparability, deterministic ordering, pagination, and human-review behavior.
- ADR 0014 remains authoritative for append-only audit events.
- The Session 2 policy engine remains the only priority-calculation authority.
- Existing persisted RiskCalculation records remain the only priority source.
- Existing remediation-queue classification and comparator behavior remain authoritative.
- Existing human priority reviews do not change queue rank.
- No client, serializer, route, or export service may reproduce domain policy.

### **Export semantics**

- The authorized endpoint is POST /remediation-queue/export.
- The request body accepts exactly one format selector: json or csv.
- Unknown body properties and unsupported formats fail through repository-authorized validation behavior.
- Owner and admin may export through the existing remediation_queue:read and priority:inspect permissions.
- Member and viewer may not export.
- Organization identity comes only from the trusted actor.
- A client-supplied organization identifier is not authority.
- One PostgreSQL REPEATABLE READ transaction creates one coherent export snapshot.
- The snapshot contains ranked, incomparable, and not_calculated.
- Existing queue membership and ordering are reused.
- Total export population is capped at exactly 150 Findings.
- More than 150 eligible Findings fails closed.
- Overflow must not return a truncated file.
- Overflow must not insert an audit row.
- One successful export inserts one append-only export.created audit event.
- Failure before commit leaves no export audit event.
- Response bytes are sent only after transaction commit.
- A committed audit event records export creation, not confirmed client receipt.
- Export bytes are not stored.
- Duplicate correlation identity follows the existing audit replay boundary and must not claim two successful exports.
- Export does not write asset-scoped export_snapshot Evidence.

### **Data interpretation**

- Missing calculation is never represented as P4.
- incomparable remains distinct from not_calculated.
- Calculated priority remains distinct from human assessment.
- Human assessment does not replace calculated priority or queue rank.
- Unknown, unavailable, stale, unsupported, and indeterminate states remain explicit where present in the authorized queue contract.
- Export is a snapshot of stored state.
- Export does not invoke the policy engine.
- Export does not calculate or recalculate priority.
- Export does not create or alter Product Match Evidence.
- Export does not create or alter Findings.
- Export does not mutate Finding lifecycle, occupancy, due dates, reviews, advisories, KEV records, policies, or calculations.

### **JSON contract**

- JSON uses the ADR 0051 envelope identifier remediation_queue_export_v1.
- JSON includes authorized snapshot metadata and the three queue sections.
- Public row key order follows existing HTTP serializer authority where observable.
- The response contains only authorized product data.
- The response excludes raw SBOM bytes, raw advisory payloads, credentials, secrets, unauthorized fingerprints, and unnecessary internal identifiers.

### **CSV contract**

- CSV uses the exact 23-column contract defined by ADR 0051.
- CSV column order is stable.
- CSV row order is deterministic.
- CSV is UTF-8.
- Quotes, commas, newlines, carriage returns, and Unicode are escaped correctly.
- Every text cell beginning with =, +, -, @, tab, or carriage return is neutralized with the ADR-authorized apostrophe prefix.
- Calculated-priority and human-assessment columns remain separate.
- Empty or unavailable values are represented consistently and are never translated into favorable security meaning.

### **Audit and provenance**

- Audit subject is the trusted organization.
- Audit action is export.created.
- Audit correlation follows the existing organization-scoped replay uniqueness boundary.
- Audit content contains only the authorized summary required to explain the export operation.
- Audit content must not embed the exported file or sensitive row data.
- Audit insertion and export snapshot creation follow ADR 0051’s transaction and failure model.

### **Release safety**

- No schema change is authorized.
- No migration 29 is authorized.
- Frozen migrations 1 through 28 remain byte-for-byte unchanged.
- Frozen migration count remains 28.
- No runtime dependency is authorized.
- No automatic policy publication is authorized.
- No automatic recalculation is authorized.
- No public-provider contact is authorized during tests.
- v0.1.0 must not be created during this Session.
- A GitHub Release must not be created during this Session.
- neural-from-scratch remains untouched.

### **Governing ADRs and records**

Before editing, Cursor must reread all applicable repository security rules and accepted ADRs, including at least:

- ADR 0012
- ADR 0014
- ADR 0019
- ADR 0038
- ADR 0044
- ADR 0045
- ADR 0046
- ADR 0047
- ADR 0048
- ADR 0049
- ADR 0050
- ADR 0051
- V-0001 priority-weight validation
- the current risk register
- the latest project checkpoint
- docs/project/[current-state.md](http://current-state.md)

## **Assumed Repository State**

Before editing, Cursor Plan must establish the following from committed repository evidence:

- Session 8A is merged into origin/main.
- ADR 0051 is Accepted.
- ADR 0048 contains the narrow ADR 0051 partial-supersession note.
- ADR 0051 export is authorized but unimplemented.
- Local branch parent equals origin/main.
- The working tree is clean after the Session 8B spec-only commit.
- Frozen migration count is 28.
- All 28 frozen migration digests match the registry.
- No migration 29 exists.
- The exact V-0001 engine and policy pair remains admitted.
- Built-in policy publication remains an explicit deployment-local operator action.
- Priority calculation and remediation queue remain fail-closed until the policy is published in the deployment.
- The existing remediation queue requires remediation_queue:read and priority:inspect.
- Owner and admin may read the queue.
- Member and viewer may not read the queue.
- The existing queue uses server-authoritative organization scope.
- The existing queue has ranked, incomparable, and not_calculated sections.
- Existing ordinary queue reads remain unaudited and paginated.
- Existing queue maximum page size remains 50.
- No export route, serializer, web export control, or export audit writer exists.
- No v0.1.0 tag exists locally or in known remote refs.
- No GitHub Release for v0.1.0 has been created.
- Existing Session 6 deployment and Compose architecture remains authoritative.
- Existing Playwright or browser-test infrastructure has not already implemented the Session 8 release smoke test.
- No Session 8B product implementation already exists.
- neural-from-scratch is outside the PatchPilot repository and untouched.

If committed evidence contradicts any material assumption, stop and report the conflict.

## **Allowed Change Surface**

### **API and application composition**

Permitted:

- the existing remediation-queue API route family;
- existing remediation-queue HTTP parsing and serialization;
- existing queue application-service composition;
- a narrowly scoped export application service that reuses existing queue classification and comparator authority;
- existing audit insertion infrastructure;
- existing authorization, CSRF, and Origin protections;
- existing API contracts;
- focused API and integration tests.

### **Database package**

Permitted:

- an export-specific persistence operation using existing schema, queue authority, transactions, and audit infrastructure;
- focused persistence tests.

Not permitted:

- Prisma schema changes;
- migrations;
- new storage models.

### **Domain and contracts**

Permitted only where necessary to represent:

- ADR 0051’s export request;
- the versioned JSON envelope;
- the CSV row model;
- safe error vocabulary.

Do not add:

- a second queue comparator;
- a second policy model;
- a second Finding-list model;
- export-specific security interpretation that conflicts with existing domain authority.

### **Web application**

Permitted:

- one owner/admin export control area on the existing remediation-queue page;
- JSON and CSV actions;
- existing API-client integration;
- accessible status and error handling;
- focused web tests.

Do not add a second queue page or reporting dashboard.

### **Playwright**

Permitted:

- one deterministic release smoke-test specification;
- minimal fixture or configuration changes required to run it;
- minimal existing CI workflow wiring required to execute it.

Do not create a broad browser-test suite.

### **Documentation and release evidence**

Permitted:

- docs/specs/[session-8b.md](http://session-8b.md);
- export runbook;
- API or operator documentation;
- latest project checkpoint;
- docs/project/[current-state.md](http://current-state.md);
- licensing and attribution report;
- dependency and Dependabot triage record;
- changelog;
- v0.1.0 release notes;
- release checklist;
- release-readiness record;
- README corrections required to describe actual MVP 0.1 behavior;
- factual ADR-index corrections only.

### **Dependencies**

- Prefer existing dependencies.
- No runtime dependency may be added.
- No broad dependency upgrade is authorized.
- A development-only Playwright dependency change is permitted only if the repository lacks the required browser-test tooling.
- Every dependency or lockfile change must be justified, license-reviewed, and reported.
- Do not dismiss Dependabot alerts automatically.

### **Migration authority**

- No migration is in scope.
- No schema change is in scope.
- Frozen migration count must remain 28.

## **Execution Plan**

Cursor Plan must create one to-do for each task below and execute the tasks in order.

### **Task 1: Verify Session 8B Baseline**

#### **Files**

Read:

- repository security rules and applicable [AGENTS.md](http://AGENTS.md) files;
- docs/project/[current-state.md](http://current-state.md);
- latest checkpoint;
- all ADRs cited by this spec;
- ADR index;
- V-0001;
- risk register;
- remediation-queue route, contract, domain, persistence, serializer, permission, and tests;
- audit-event implementation and indexes;
- current web queue;
- Playwright and CI configuration;
- package manifests and lockfile;
- license and dependency tooling;
- frozen migration registry.

#### **Behavior**

Establish:

- base commit;
- branch;
- clean working tree;
- accepted ADR 0051 authority;
- migration count and integrity;
- runtime composition state;
- exact authorized implementation files;
- existing Playwright command;
- existing license-report command;
- existing dependency or security-audit command;
- current GitHub Actions release gates.

Use multiple read-only investigation agents for:

- API;
- persistence;
- web;
- Playwright;
- licensing;
- release documentation.

The parent agent must reconcile the findings into one implementation plan and assign one owner to each file group.

#### **Tests**

Run safe repository-state checks, migration-integrity checks, and configuration inspection only.

#### **Done condition**

All assumptions are confirmed and the parent agent records the exact file ownership for Tasks 2 through 8.

If a material assumption fails, stop before product edits.

### **Task 2: Implement the ADR 0051 Export Snapshot**

#### **Files**

Change only the existing database and domain boundaries required to implement ADR 0051 without schema changes.

#### **Behavior**

Implement one export snapshot operation that:

1. Accepts the trusted organization and authorized export context.
2. Opens one PostgreSQL REPEATABLE READ transaction.
3. Resolves the published admitted built-in policy using existing authority.
4. Obtains asOf from the existing queue-classification statement or the same authoritative transaction-time mechanism.
5. Evaluates the complete organization Finding population using existing queue membership, comparability, section, and ordering authority.
6. Counts the total population before successful export creation.
7. Fails closed if the total exceeds 150.
8. Produces all three sections without applying ordinary 50-row page truncation.
9. Rejects malformed queue state through existing fail-closed behavior.
10. Inserts one export.created audit event.
11. Commits before response bytes are returned.
12. Rolls back snapshot creation and audit on every pre-commit failure.

The implementation must not call the ordinary page reader repeatedly if doing so would create multiple snapshots or truncate a section.

Extract or reuse existing classification and comparator authority rather than copying it.

The operation must not write export_snapshot Evidence.

#### **Tests**

Add or update tests proving:

- one coherent snapshot;
- all three sections;
- comparator equivalence with the existing queue;
- deterministic ordering;
- exactly 150 Findings succeeds;
- 151 Findings fails without truncation;
- overflow creates no audit event;
- malformed stored state fails closed;
- policy unavailable returns the repository-authorized response;
- trusted organization scope;
- cross-tenant exclusion;
- transaction rollback;
- one successful audit row;
- duplicate correlation identity creates no second successful audit;
- no Product Match Evidence mutation;
- no Finding mutation;
- no review mutation;
- no policy mutation;
- no calculation mutation;
- no policy-engine invocation.

#### **Done condition**

The persistence and domain boundary implement ADR 0051 exactly, focused tests pass, and no duplicate queue or policy logic has been introduced.

### **Task 3: Implement the Export API and Serializers**

#### **Files**

Change only the existing remediation-queue route family, HTTP boundary, contracts, application service, audit composition, and tests.

#### **Behavior**

Implement:

POST /remediation-queue/export

Request body accepts exactly:

- { "format": "json" }
- { "format": "csv" }

Apply existing:

- authentication;
- remediation_queue:read;
- priority:inspect;
- owner/admin authority;
- server-side organization scope;
- CSRF and Origin controls;
- correlation identity;
- error-envelope conventions;
- rate limiting.

Reject:

- unknown request fields;
- unsupported formats;
- client authority headers;
- client organization identifiers;
- member and viewer roles;
- malformed correlation identity;
- requests above the 150-Finding export cap.

#### **JSON response**

Return:

- envelope remediation_queue_export_v1;
- export metadata;
- policy or comparator identity required to interpret ranked results;
- ranked;
- incomparable;
- not_calculated;
- authorized stable row representation;
- safe filename and headers.

#### **CSV response**

Return:

- UTF-8 CSV;
- exact ADR 0051 23-column order;
- deterministic section and row order;
- correct escaping for commas, quotes, newlines, carriage returns, and Unicode;
- apostrophe neutralization for formula-leading text cells;
- separate calculated-priority and human-assessment fields;
- explicit queue section;
- safe filename and headers.

Serialization must operate only on the committed in-memory snapshot.

Serialization must not open another queue transaction or invoke domain mutation.

#### **Tests**

Add or update tests proving:

- owner JSON success;
- admin JSON success;
- owner CSV success;
- admin CSV success;
- member denial;
- viewer denial;
- unauthenticated denial;
- cross-tenant isolation;
- client organization identity rejected or ignored according to existing security rules;
- CSRF and Origin enforcement;
- exact request body;
- unknown-property rejection;
- unsupported-format rejection;
- safe content type;
- safe content disposition;
- stable JSON envelope;
- stable CSV headers;
- JSON and CSV semantic equivalence;
- formula-injection neutralization for =, +, -, @, tab, and carriage return;
- correct handling of quotes, commas, newlines, carriage returns, and Unicode;
- missing calculation is not P4;
- incomparable is not ranked;
- calculated priority and human assessment remain separate;
- no calculation on export;
- no mutation on export;
- one audit event per successful correlation identity;
- no successful audit on pre-commit failure.

#### **Done condition**

Both formats expose identical authorized snapshot semantics, all focused tests pass, and no queue or policy decisions are duplicated.

### **Task 4: Add Export Controls to the Existing Web Queue**

#### **Files**

Change only:

- the existing remediation-queue page;
- the existing web API client;
- existing accessibility and component tests;
- existing shared UI text where required.

#### **Behavior**

Add one bounded export control area to the current remediation-queue page.

Provide:

- Export JSON;
- Export CSV.

The controls must:

- call the server export route;
- not construct exports in the browser;
- preserve authenticated tenant context;
- not accept an organization identifier;
- display accessible labels;
- support keyboard use;
- expose in-progress state;
- announce errors accessibly;
- handle policy unavailable;
- handle export population too large;
- handle authorization failure;
- avoid changing queue filters or ordering;
- avoid implying that human assessment replaced calculated priority.

Do not add a new reporting page.

#### **Tests**

Add or update tests proving:

- authorized actions render;
- the correct format body is posted;
- browser-generated domain export logic is absent;
- failure messages are accessible;
- keyboard operation works;
- controls do not invoke priority calculation;
- unauthorized users cannot successfully export.

#### **Done condition**

An authorized owner or admin can initiate either server-generated export from the existing queue page, with focused web and accessibility tests passing.

### **Task 5: Add One Playwright Release Smoke Test**

#### **Files**

Change only:

- existing Playwright configuration;
- one release smoke-test specification;
- the smallest deterministic fixture or setup required;
- existing CI workflow wiring.

#### **Behavior**

Create exactly one release-level Playwright smoke test.

The smoke test must verify the integrated MVP flow at the highest reliable level supported by committed deterministic fixtures:

1. Application readiness.
2. Authenticated tenant-scoped access.
3. Supported SBOM inventory presence or upload.
4. Controlled product-match candidate workflow where fixture authority supports it.
5. Controlled Finding visibility.
6. Comparable stored priority or deliberate priority calculation.
7. Remediation-queue visibility.
8. Evidence or reason-code visibility.
9. Successful JSON or CSV export initiation and response.

The test must:

- use repository-owned deterministic data;
- avoid public providers;
- avoid live CISA, OSV, npm, GitHub, or internet data;
- avoid real customer or production data;
- use stable semantic selectors or approved test identifiers;
- avoid fragile positional selectors;
- validate behavior rather than styling;
- avoid duplicating every integration test;
- remain one smoke-test specification.

If the current test topology cannot safely create the entire state through the browser, use the nearest deterministic prepared state through existing test setup and document that boundary honestly.

#### **Tests**

Run the repository-authorized Playwright command.

If no narrower authoritative script exists, use:

pnpm exec playwright test

#### **Done condition**

One deterministic release smoke test passes in the repository-authorized environment and is included in the protected CI path without external-provider contact.

### **Task 6: Produce Licensing and Dependency Release Evidence**

#### **Files**

Change or create only the repository-authorized:

- license report;
- attribution notice;
- dependency inventory;
- Dependabot triage record;
- release security record;
- release checklist.

#### **Behavior**

Create release-grade evidence for all shipped application images and frontend assets.

The record must:

- identify direct production dependencies;
- distinguish runtime, build-time, development, and test dependencies;
- record detected license expressions;
- identify unknown, missing, nonstandard, copyleft, source-available, or restricted licenses;
- record required attributions;
- assess compatibility with the repository’s Apache-2.0 licensing;
- identify generated or bundled artifacts requiring notices;
- identify the commands, lockfile, and repository revision used;
- avoid claiming legal certainty beyond the evidence.

Triage every available Dependabot or repository-recorded dependency concern.

For every concern, record:

- package;
- affected version;
- advisory identifier;
- severity;
- runtime reachability or development-only status;
- fixed version if available;
- release disposition;
- justification;
- follow-up issue or owner if deferred.

Do not:

- dismiss GitHub alerts automatically;
- silence an issue without evidence;
- perform broad upgrades;
- add a runtime dependency;
- conceal unresolved release blockers.

A narrow dependency correction is permitted only when:

- necessary for release;
- inside the allowed surface;
- licensing remains acceptable;
- all verification gates pass.

#### **Tests**

Run the repository-authorized license-report and dependency-security commands.

Verify that reports are reproducible from the lockfile.

#### **Done condition**

Every shipped dependency has an explicit release disposition, required attribution is present, and no unresolved release-blocking licensing or dependency-security issue remains.

### **Task 7: Reconcile Release Documentation**

#### **Files**

Update:

- latest project checkpoint;
- docs/project/[current-state.md](http://current-state.md);
- release runbook;
- export documentation;
- operator documentation;
- changelog;
- v0.1.0 release notes;
- release checklist;
- licensing and security records;
- README only where required for current MVP behavior;
- ADR index only for factual consistency.

#### **Behavior**

Document the actual MVP 0.1 boundary, including:

- supported deployment topology;
- environment and secret requirements;
- migration and bootstrap order;
- policy publication requirement;
- supported CycloneDX bounds;
- offline npm OSV import;
- controlled product matching;
- controlled Finding creation;
- controlled priority calculation;
- remediation-queue behavior;
- priority-review semantics;
- JSON and CSV export;
- 150-Finding export cap;
- export audit and client-disconnect residual;
- one Playwright smoke test;
- licensing and dependency disposition;
- known limitations;
- backup and recovery expectations;
- unsupported features;
- release verification procedure.

Record explicitly:

- migration count remains 28;
- missing priority is not P4;
- human assessment does not replace calculated priority;
- KEV does not establish affectedness;
- queue ranking requires policy comparability;
- exports are snapshots of stored state;
- export audit proves creation, not receipt;
- automatic recalculation is not implemented;
- autonomous remediation is not implemented;
- the Session spec is not an ADR or checkpoint;
- v0.1.0 is prepared but not yet tagged.

Do not create the tag or GitHub Release.

#### **Tests**

Run repository documentation, link, formatting, architecture-alignment, and workflow checks.

#### **Done condition**

Current state, checkpoint, runbooks, release notes, README, and release checklist describe one coherent implemented release boundary.

### **Task 8: Independent Final Verification**

#### **Files**

No planned product changes.

Only narrow corrections within this spec’s allowed change surface are permitted.

#### **Behavior**

Assign an independent verification agent that did not own the primary implementation.

Verify:

- ADR 0051 compliance;
- ADR 0048 semantic preservation;
- ADR 0014 audit compliance;
- tenant isolation;
- owner/admin authorization;
- member/viewer denial;
- trusted organization scope;
- CSRF and Origin protections;
- 150-Finding cap;
- no partial export;
- one snapshot transaction;
- one successful audit event;
- duplicate-correlation behavior;
- JSON and CSV semantic equivalence;
- formula-injection protection;
- deterministic ordering;
- no calculation during export;
- no Product Match Evidence mutation;
- no Finding mutation;
- no priority-review or lifecycle mutation;
- browser uses server-generated export;
- exactly one deterministic Playwright smoke test;
- no public-provider contact;
- license-report completeness;
- dependency-triage completeness;
- release-document accuracy;
- migration count remains 28;
- frozen migrations remain intact;
- no schema change;
- no unauthorized dependency change;
- no v0.1.0 tag;
- no GitHub Release;
- no change to neural-from-scratch;
- complete diff compliance.

#### **Tests**

Run every command in the Verification section.

#### **Done condition**

No unresolved release blocker remains and the parent agent produces the required Session handoff.

## **Out of Scope**

Session 8B must not add:

- migration 29;
- schema changes;
- another queue model;
- another comparator;
- another policy engine;
- new priority semantics;
- policy-weight or threshold changes;
- calculation during reads or exports;
- automatic priority recalculation;
- automatic policy publication;
- worker-generated exports;
- scheduled exports;
- stored export files;
- object-storage export delivery;
- asynchronous export jobs;
- email delivery;
- public exports;
- anonymous exports;
- client-supplied tenant authority;
- exports over 150 Findings;
- task assignment;
- remediation-task lifecycle;
- due-date mutation;
- Finding lifecycle changes;
- arbitrary manual priority override;
- queue rank based on human assessment;
- new SBOM formats;
- another SBOM parser;
- online OSV synchronization;
- global advisory search;
- external-provider contact in tests;
- autonomous remediation;
- patch generation or deployment;
- additional Playwright scenarios;
- general analytics dashboards;
- billing;
- enterprise SSO;
- Kubernetes;
- Helm;
- cloud-specific deployment;
- custom LLMs;
- RAG;
- embeddings;
- vector databases;
- multi-agent product runtime;
- broad dependency upgrades;
- automatic Dependabot dismissal;
- release tag creation;
- GitHub Release publication;
- production deployment;
- changes to neural-from-scratch.

## **Stop Conditions**

Cursor must stop and report, without redesigning the Session, if:

1. HEAD^ does not equal origin/main.
2. The working tree contains unrelated changes.
3. ADR 0051 is not Accepted.
4. ADR 0051 differs materially from this contract.
5. Frozen migration count is not 28.
6. A frozen migration digest differs.
7. Export requires a schema change or migration.
8. Export would require duplicating remediation-queue classification or comparator logic.
9. Export cannot be produced in one coherent REPEATABLE READ transaction.
10. Existing audit authority cannot support export.created without schema change.
11. Existing permissions cannot enforce the owner/admin boundary.
12. A client-supplied organization identifier would become authoritative.
13. The Playwright smoke test requires public-provider contact.
14. Playwright requires real customer, production, or secret data.
15. A release-blocking license cannot be resolved inside the allowed surface.
16. A release-blocking dependency vulnerability requires broad upgrades or architectural redesign.
17. A runtime dependency appears necessary.
18. The work requires modifying a route, worker, lifecycle, provider, or package outside the allowed surface.
19. An accepted ADR or security rule conflicts with this contract.
20. v0.1.0 already exists.
21. A task cannot fit within one pull-request-sized branch.
22. neural-from-scratch appears in the change set.

On a stop condition:

- make no speculative workaround;
- do not weaken tests;
- do not broaden scope;
- identify the exact conflict;
- cite the governing repository evidence;
- report the smallest architectural decision required.

## **Verification**

Pass means the following succeed on final branch HEAD:

- pnpm format:check
- pnpm lint
- pnpm typecheck
- pnpm test:unit
- pnpm test:integration
- pnpm db:validate
- pnpm build
- pnpm workflows:lint
- pnpm exec playwright test

If the repository provides a narrower authoritative Playwright script, use that script and report it.

Also run the repository-authorized equivalents of:

- migration-integrity validation;
- frozen migration count validation;
- documentation and relative-link checks;
- architecture-alignment checks;
- license reporting;
- dependency-security audit;
- focused export authorization tests;
- focused tenant-isolation tests;
- export-cap boundary tests;
- JSON and CSV semantic-equivalence tests;
- CSV formula-injection tests;
- export audit and rollback tests;
- no-mutation tests;
- Playwright external-network denial or equivalent verification.

Final review must include:

- git diff --check;
- git status --short --branch;
- complete diff review from the Session base commit;
- schema and migration diff inspection;
- package manifest and lockfile inspection;
- confirmation that migration count remains 28;
- confirmation that no frozen migration changed;
- confirmation that no tag, release, or deployment occurred;
- confirmation that neural-from-scratch was not accessed or modified.

If PostgreSQL or container infrastructure is unavailable locally:

- do not claim integration or Playwright passed;
- report the exact environmental block;
- run every available local gate;
- require the protected GitHub Actions equivalents before merge;
- do not weaken or skip the CI merge gate.

The implementation is intended to become:

- one Conventional Commit;
- one pull-request-sized protected-workflow pull request.

Recommended Conventional Commit:

feat(release): complete PatchPilot MVP 0.1 readiness

Do not create the commit automatically.

## **Handoff Requirements**

Return one consolidated handoff containing:

1. Outcome
2. Base commit, branch, and final HEAD
3. Multi-agent execution summary
4. Tasks completed
5. Files changed and architectural purpose
6. Export snapshot and transaction behavior
7. JSON contract
8. CSV contract and formula-injection protection
9. Authorization, tenant isolation, CSRF, and Origin evidence
10. Audit, replay, rollback, and disconnect behavior
11. Web export controls
12. Playwright smoke-test scenario and result
13. Licensing and attribution evidence
14. Dependabot and dependency-security triage
15. Release documentation and residual risks
16. Migration, schema, dependency, and lockfile impact
17. Every verification command and actual result
18. Independent verification findings
19. Scope compliance
20. Proposed Conventional Commit
21. Proposed pull-request title and summary
22. Recommended post-merge v0.1.0 release procedure

Explicitly confirm:

- no commit or push occurred automatically;
- no pull request was created automatically;
- no tag or GitHub Release was created;
- no production deployment changed;
- no public provider was contacted by tests;
- migration count remains 28;
- neural-from-scratch was not accessed or modified.

End with:

SESSION 8B READY FOR PRINCIPAL ARCHITECT REVIEW BEFORE COMMIT