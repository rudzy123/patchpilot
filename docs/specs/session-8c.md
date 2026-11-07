Execution contract for this session only. It authorizes only the work it names. It is subordinate to repository security rules, accepted ADRs, frozen migrations, and docs/project/[current-state.md](http://current-state.md). If those disagree with this spec, stop and report the conflict. This file is not a checkpoint and is not an ADR.

# Session 8C: Final Release Verification and Authorization

## Identity

- **Session ID:** Session 8C

- **Mission:** Verify the exact PatchPilot MVP 0.1 release candidate, preserve the evidence in a durable release-verification record, close factual release-document discrepancies, and determine whether the synchronized release commit may receive the annotated tag `v0.1.0`.

- **Base commit:** The parent of the spec-only commit that introduces this file. Before editing any release record, `git rev-parse HEAD^` must equal `git rev-parse origin/main`.

- **Expected frozen migration count:** 28

- **Branch prefix:** `release/session-8c-v0.1.0-verification`

- **Release candidate version:** `0.1.0`

- **Reserved release tag:** `v0.1.0`

- **Change type:** Release verification and documentation only.

- **Branch size:** One pull-request-sized branch.

- **Commit policy:** One Conventional Commit after Principal Architect review.

- **Automatic Git actions:** Cursor must not commit, push, create a pull request, create a tag, publish a GitHub Release, deploy, or modify Git history.

## Architectural Outcome

Session 8C must answer one question with evidence:

> Is the exact synchronized PatchPilot `main` commit a reproducible, secure, internally consistent, and adequately documented MVP 0.1 release candidate?

The Session produces a committed release-verification record. It does not add product behavior.

A successful Session establishes that, after the Session 8C verification pull request is merged, the resulting synchronized `main` commit may be considered for the `v0.1.0` tag through a separate operator-controlled release procedure.

## Invariants

### Product and architecture

- No product behavior changes.

- No API route changes.

- No web behavior changes.

- No database or domain-service changes.

- No queue, export, policy, Finding, evidence, review, KEV, or advisory semantics change.

- ADRs 0012, 0014, 0045, 0047, 0048, 0049, 0050, and 0051 remain authoritative.

- ADR 0051 remains the exclusive authority for remediation-queue export.

- The remediation-queue CSV contract contains exactly 22 columns as defined by ADR 0051 section 10.

- Missing priority remains distinct from P4.

- Incomparable calculations remain outside the ranked queue section.

- Human assessment remains distinct from calculated priority.

- Export remains capped at 150 Findings.

- Export remains a stored-state snapshot.

- Export audit records creation, not confirmed client receipt.

- KEV does not establish affectedness.

- Automatic recalculation remains withheld.

- Autonomous remediation remains withheld.

### Security and tenancy

- Trusted server-side tenant context remains authoritative.

- Client-provided organization identity is never authority.

- Existing owner and admin export authority remains unchanged.

- Member and viewer denial remains unchanged.

- No secrets, credentials, tenant data, raw SBOM content, raw advisory payloads, or private deployment configuration may enter the release-verification record.

- No public-provider contact is authorized during verification.

- No production or customer data may be used.

- No production deployment may be accessed or modified.

### Database and migrations

- Frozen migrations 1 through 28 remain byte-for-byte unchanged.

- All frozen migration digests must match the registry.

- No migration 29 is authorized.

- No Prisma schema change is authorized.

- Frozen migration count remains 28.

### Dependencies and licensing

- No dependency change is authorized.

- No `package.json` or lockfile modification is authorized.

- No dependency installation or upgrade is authorized.

- Existing Session 8B licensing, attribution, dependency-security, and Dependabot records remain authoritative unless verification discovers a factual inconsistency.

- A factual documentation correction is allowed.

- A dependency or licensing correction requiring code, manifest, or lockfile changes is a stop condition.

### Release control

- `v0.1.0` must not exist locally or remotely when verification begins.

- Session 8C must not create `v0.1.0`.

- Session 8C must not create a GitHub Release.

- Session 8C must not deploy PatchPilot.

- Session 8C must not publish the built-in policy into a shared or production database.

- The future tag must point to the post-Session-8C merged release commit, not the earlier Session 8B commit.

- Tagging and GitHub Release publication remain separate operator actions after Session 8C is merged and final post-merge identity is confirmed.

### Repository boundaries

- `patchpilot` is the only repository in scope.

- `neural-from-scratch` must not be inspected, accessed, copied from, or modified.

- No generated cache, coverage output, browser binary, secret, local environment file, or editor artifact may enter the change set.

## Governing Authority

Before verification begins, Cursor must reread:

- all applicable `AGENTS.md` files;

- repository security rules;

- `docs/project/current-state.md`;

- the latest project checkpoint;

- the ADR index;

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

- V-0001 priority-policy validation;

- the current risk register;

- the Session 8B release notes;

- the release checklist;

- the deployment and operator runbooks;

- the licensing and attribution report;

- the dependency and Dependabot triage record;

- the Session 8B Playwright smoke test;

- relevant GitHub Actions workflow definitions.

## Assumed Repository State

Before editing, Cursor must prove from committed repository evidence:

- Session 8B is merged into `origin/main`.

- The parent of the Session 8C spec-only commit equals `origin/main`.

- The working tree is clean after the spec-only commit.

- Frozen migration count is 28.

- All 28 frozen migration digests match the frozen registry.

- No migration 29 exists.

- ADR 0051 is Accepted and implemented.

- `POST /remediation-queue/export` exists.

- JSON export uses `remediation_queue_export_v1`.

- CSV follows the exact 22-column contract defined by ADR 0051 section 10.

- `REMEDIATION_QUEUE_EXPORT_CSV_HEADER` contains those same 22 columns in the ADR-authorized order.

- The Session 8B readiness record correctly identifies the earlier “23-column” statement as a counting error.

- Formula-leading CSV text is neutralized.

- Export uses one `REPEATABLE READ` snapshot.

- Export population is capped at 150 Findings.

- One successful export inserts one `export.created` audit event.

- Export performs no policy calculation or domain-state mutation.

- The existing remediation-queue web page contains server-backed JSON and CSV controls.

- Exactly one authorized Playwright release smoke specification exists.

- The Playwright test is isolated from public providers.

- Session 8B licensing and dependency evidence exists.

- Session 8B release notes and release checklist exist.

- Required protected GitHub Actions for the merged Session 8B pull request passed.

- No uncommitted Session 8B implementation remains.

- No local or known remote `v0.1.0` tag exists.

- No GitHub Release for `v0.1.0` is recorded in repository release evidence.

- `neural-from-scratch` remains outside this repository and untouched.

If any material assumption is false, stop and report the exact conflict.

## Allowed Change Surface

Permitted:

- `docs/specs/session-8c.md`;

- one durable `v0.1.0` release-verification record under the repository’s established release or project documentation location;

- the latest project checkpoint;

- `docs/project/current-state.md`;

- release checklist;

- `v0.1.0` release notes;

- release runbook;

- licensing, attribution, dependency, or security release records only for factual corrections discovered during verification;

- README only for a factual contradiction with the verified MVP 0.1 release boundary;

- ADR index only for a factual status inconsistency.

Not permitted:

- product code;

- API code;

- web code;

- domain or database code;

- tests;

- workflows;

- package manifests;

- lockfile;

- schema;

- migrations;

- Dockerfiles;

- Compose files;

- runtime configuration;

- release tag;

- GitHub Release;

- deployment.

## Multi-Agent Execution Model

Cursor Plan is the lead release orchestrator.

Cursor must use multiple specialist agents for independent, read-only verification workstreams.

Required specialist agents:

1. **Git and release-identity agent**

   - Verifies branch, commit, remote synchronization, tag absence, and Session 8B merge identity.

2. **Architecture and scope agent**

   - Verifies accepted ADR compliance, Session 8B implementation boundaries, export behavior, and absence of post-MVP scope.

3. **Security and tenant-isolation agent**

   - Verifies permissions, trusted tenant scope, CSRF, Origin, correlation, rate limits, cross-tenant protections, and sensitive-data boundaries.

4. **Test and protected-CI evidence agent**

   - Verifies local, committed, and GitHub Actions evidence tied to the exact candidate.

5. **Migration and deployment-readiness agent**

   - Verifies frozen migrations, schema integrity, application images, Compose, migration job, bootstrap, health checks, and operator runbooks.

6. **Licensing and dependency-security agent**

   - Verifies dependency inventories, attribution, licenses, Dependabot dispositions, and release-security records.

7. **Release-document consistency agent**

   - Verifies current state, checkpoint, README, release notes, runbooks, release checklist, risk records, readiness record, and ADR index.

8. **Independent final-verification agent**

   - Reviews the complete evidence and final documentation changes after the primary verification record is written.

   - Must not author the release-verification record.

   - Must not perform the parent agent’s primary architectural synthesis.

   - Must not own another Session 8C documentation change.

### Coordination rules

The parent agent must:

- run specialist investigations in parallel where safe;

- require every agent to cite committed repository evidence;

- distinguish local evidence from protected GitHub Actions evidence;

- reconcile findings into one release decision;

- assign exclusive ownership of the durable release-verification record to one agent;

- prevent concurrent edits to the same documents;

- allow only documentation edits inside the approved surface;

- commission independent final verification after the primary record is complete.

The parent agent remains accountable for the consolidated release verdict.

## Ordered Execution Plan

Cursor Plan must create one to-do for each task and execute the tasks in order.

### Task 1: Establish Exact Release Identity

#### Allowed files or subsystem

Read-only Git state, repository metadata, and existing release records.

#### Required behavior

Record:

- repository root;

- current branch;

- current `HEAD`;

- `origin/main`;

- the parent of the spec-only commit;

- working-tree state;

- active Git operation state;

- local `v0.1.0` tag status;

- remote `v0.1.0` tag status;

- Session 8B merge commit or squash commit where local history proves it;

- Session 8B pull-request identity where repository evidence proves it.

Confirm that the spec-only commit is exactly one commit above synchronized `origin/main`.

#### Tests

Run safe read-only Git commands sufficient to prove identity and cleanliness.

#### Done condition

The release-candidate base is unambiguous, clean, synchronized, and untagged.

If the base is ambiguous or the tag exists, stop.

### Task 2: Verify Architecture and Scope

#### Allowed files or subsystem

Read-only review of accepted ADRs, current-state documentation, Session 8B implementation, and the full Session 8B merged diff.

#### Required behavior

Verify:

- ADR 0051 compliance;

- ADR 0048 semantic preservation;

- ADR 0014 audit compliance;

- one `REPEATABLE READ` snapshot;

- exact 150-Finding cap;

- failure without truncation;

- ranked, incomparable, and not-calculated separation;

- missing priority not represented as P4;

- human assessment not used for rank;

- JSON and CSV semantic equivalence;

- the exact 22-column CSV contract from ADR 0051 section 10;

- `REMEDIATION_QUEUE_EXPORT_CSV_HEADER` matches those 22 columns exactly and in order;

- formula-injection protection;

- one successful `export.created` audit event;

- rollback on pre-commit failure;

- no policy-engine invocation;

- no Finding, Evidence, review, policy, advisory, KEV, or calculation mutation;

- server-generated exports;

- no migration 29;

- no unapproved post-MVP feature.

#### Tests

Use committed tests, protected CI evidence, and read-only code review.

Do not modify or add tests.

#### Done condition

The implemented Session 8B behavior matches accepted architecture without a release-blocking discrepancy.

### Task 3: Verify Security and Tenant Isolation

#### Allowed files or subsystem

Read-only review of authentication, authorization, tenant scope, CSRF, Origin, correlation, rate limiting, API contracts, web controls, and focused tests.

#### Required behavior

Verify:

- owner and admin export authority;

- member and viewer denial;

- unauthenticated denial;

- authoritative actor organization;

- rejection or non-authoritative treatment of client organization identity;

- cross-tenant exclusion;

- CSRF enforcement;

- Origin enforcement;

- correlation identity behavior;

- rate-limit behavior;

- no secret or raw-payload exposure;

- safe filenames and headers;

- no browser-side reconstruction of domain export semantics.

#### Tests

Use committed focused tests and protected CI evidence.

#### Done condition

No unresolved tenant-isolation, authorization, request-integrity, or sensitive-data release blocker remains.

### Task 4: Verify Test and CI Evidence

#### Allowed files or subsystem

Read-only review of test records, workflow definitions, merge checks, release checklist, and local command availability.

#### Required behavior

Tie evidence to the exact merged Session 8B candidate for:

- formatting;

- lint;

- typecheck;

- unit tests;

- integration tests;

- Prisma or database validation;

- build;

- workflow lint;

- migration integrity;

- frozen migration count;

- export authorization;

- tenant isolation;

- 150 and 151 boundary behavior;

- JSON and CSV equivalence;

- exact 22-column CSV header behavior;

- formula-injection protection;

- audit rollback and replay;

- no-mutation behavior;

- one Playwright smoke test;

- loopback or network-isolation behavior;

- dependency review;

- CodeQL or equivalent security analysis;

- applicable container builds.

Do not claim a result unless the evidence is tied to the candidate.

Do not rerun expensive suites merely to duplicate successful protected checks unless repository release rules explicitly require it.

#### Tests

Run only safe, non-mutating, low-cost release checks required by repository rules and not already adequately evidenced.

#### Done condition

Every mandatory release gate has attributable passing evidence, or the Session stops with a missing-evidence report.

### Task 5: Verify Migrations, Deployment, and Operational Readiness

#### Allowed files or subsystem

Read-only review of migration registry, schema, Dockerfiles, Compose configuration, migration job, bootstrap, health checks, operator runbooks, and recovery documentation.

#### Required behavior

Verify:

- migration count 28;

- all frozen migration hashes;

- no migration 29;

- no unapproved schema change;

- reproducible application image definitions;

- explicit migration job;

- production-safe bootstrap;

- runtime secret injection;

- durable volumes;

- health and readiness behavior;

- restart and shutdown guidance;

- backup and recovery expectations;

- explicit built-in policy publication;

- no automatic OSV import;

- no automatic Product Match Evidence creation;

- no automatic Finding creation;

- no automatic priority calculation;

- no automatic policy publication;

- no automatic export;

- no autonomous remediation.

#### Tests

Use committed deployment tests, workflow evidence, and read-only configuration validation.

#### Done condition

The release is operationally deployable according to the documented self-hosted MVP boundary, with all prerequisites explicit.

### Task 6: Verify Licensing, Attribution, and Dependency Security

#### Allowed files or subsystem

Read-only review of package manifests, lockfile, Session 8B licensing report, attribution notices, dependency inventory, security audit, and Dependabot triage.

#### Required behavior

Verify:

- direct production dependencies are inventoried;

- runtime, build, development, and test dependencies are distinguished;

- license expressions and unknowns are documented;

- required attribution is present;

- no unresolved release-blocking license issue remains;

- Dependabot findings have explicit dispositions;

- runtime reachability is documented where relevant;

- deferred issues have an owner or follow-up;

- no unauthorized runtime dependency entered Session 8B;

- manifest and lockfile changes match the release record;

- documentation does not claim legal certainty beyond the evidence.

#### Tests

Use existing reporting commands only when needed to validate reproducibility.

Do not install or update dependencies.

#### Done condition

Licensing and dependency-security evidence supports release, or the Session stops with the unresolved blocker.

### Task 7: Create the Durable Release-Verification Record

#### Allowed files or subsystem

Create one release-verification document in the repository’s established release or project documentation location.

Update only the permitted release documents necessary for consistency.

#### Required behavior

The release-verification record must include:

- version `0.1.0`;

- candidate base commit;

- Session 8B merge identity;

- verification date;

- verifier role;

- architecture verdict;

- security and tenancy verdict;

- migration and schema verdict;

- test and protected-CI evidence;

- Playwright verdict;

- licensing and dependency verdict;

- deployment-readiness verdict;

- documentation-consistency verdict;

- confirmation that ADR 0051 and the serializer define the same 22-column CSV contract;

- accepted residual risks;

- operational prerequisites;

- post-v0.1.0 follow-ups;

- explicit release blockers, if any;

- exact statement whether the eventual post-Session-8C merged commit may receive `v0.1.0`.

The document must distinguish:

- evidence tied to Session 8B’s merged implementation;

- documentation changes introduced by Session 8C;

- final tag identity, which remains unknown until Session 8C merges.

Do not write a placeholder tag SHA.

State that the release tag must target synchronized `main` after the Session 8C verification pull request merges and all protected checks pass.

If verification fails, record a non-approved outcome and do not imply release authorization.

#### Tests

Run documentation format, link, consistency, and architecture-alignment checks.

#### Done condition

The repository contains a truthful durable release-verification record with no unresolved placeholders and no claim that the tag already exists.

### Task 8: Independent Final Review

#### Allowed files or subsystem

Read-only review of the complete Session 8C change set and all gathered evidence.

Only narrow factual corrections inside the allowed documentation surface are permitted.

#### Required behavior

Assign an independent verification agent that did not own the primary release review.

Verify:

- spec compliance;

- no product-code change;

- no schema or migration change;

- no dependency or lockfile change;

- release-verification evidence is attributable;

- the CSV contract is correctly recorded as 22 columns;

- residual risks are classified honestly;

- no mandatory gate is silently omitted;

- `v0.1.0` remains absent;

- no GitHub Release exists through actions performed in this Session;

- no deployment occurred;

- no secret or tenant data entered documentation;

- the final release recommendation is internally consistent;

- `neural-from-scratch` was not accessed or modified.

#### Tests

Run every command in the Verification section.

#### Done condition

The independent reviewer reports no unresolved release blocker and the parent agent produces the required Session handoff.

## Out of Scope

Session 8C must not:

- modify product code;

- change API routes;

- change web behavior;

- change export behavior;

- add or remove a CSV column;

- change the ADR 0051 22-column CSV contract;

- add tests;

- change workflows;

- add dependencies;

- update dependencies;

- modify the lockfile;

- change policy semantics;

- change queue ordering;

- change human-review behavior;

- change Finding lifecycle;

- change tenant or role authority;

- create migration 29;

- change the Prisma schema;

- alter frozen migrations;

- add another Playwright test;

- contact public providers;

- use production data;

- access a production deployment;

- publish the built-in policy into a shared deployment;

- create `v0.1.0`;

- create a GitHub Release;

- deploy PatchPilot;

- create release assets;

- modify `neural-from-scratch`;

- begin post-v0.1.0 feature development.

## Stop Conditions

Stop and report without redesigning the Session if:

1. The parent of the spec-only commit does not equal `origin/main`.

2. The working tree contains unrelated changes.

3. Session 8B is not present on `origin/main`.

4. ADR 0051 is absent, not Accepted, or materially inconsistent with implementation.

5. ADR 0051 section 10 and `REMEDIATION_QUEUE_EXPORT_CSV_HEADER` do not contain the same 22 columns in the same order.

6. Frozen migration count is not 28.

7. A frozen migration digest differs.

8. Migration 29 exists.

9. An unapproved schema change exists.

10. `v0.1.0` already exists locally or remotely.

11. Required protected GitHub Actions evidence cannot be tied to the candidate.

12. A mandatory check failed, was cancelled, or was skipped without accepted authority.

13. Playwright contacted or required a public provider.

14. A cross-tenant, authorization, or CSRF discrepancy exists.

15. JSON and CSV do not represent equivalent authorized snapshots.

16. Formula-injection protection is incomplete.

17. Export invokes calculation or mutates domain state.

18. A release-blocking license issue remains.

19. A release-blocking dependency vulnerability has no accepted disposition.

20. Operational documentation cannot reproduce the intended self-hosted startup.

21. A factual correction requires product, schema, migration, dependency, lockfile, test, or workflow changes.

22. Repository evidence contradicts release notes materially.

23. The work cannot fit inside one documentation-only pull request.

24. `neural-from-scratch` appears in the change set or investigation.

On a stop condition:

- make no speculative workaround;

- do not weaken evidence requirements;

- do not broaden scope;

- cite the exact repository authority;

- identify the smallest required corrective Session;

- classify the issue as a release blocker.

## Verification

Pass requires:

- `pnpm format:check`

- `pnpm lint`

- `pnpm typecheck`

- `pnpm test:unit`

- `pnpm test:integration`

- `pnpm db:validate`

- `pnpm build`

- `pnpm workflows:lint`

- the repository-authorized Playwright command;

- migration-integrity validation;

- frozen-migration-count validation;

- documentation and relative-link checks;

- architecture-alignment checks;

- license-report verification;

- dependency-security verification;

- `git diff --check`;

- `git status --short --branch`.

The parent agent may rely on protected GitHub Actions evidence tied to the merged Session 8B commit for expensive or infrastructure-dependent gates.

When relying on CI evidence, record:

- workflow name;

- job name;

- result;

- commit SHA;

- source of the evidence.

Do not claim a local pass when the result came from CI.

Before the Session 8C handoff, confirm:

- no product file changed;

- no schema changed;

- no migration changed;

- migration count remains 28;

- no dependency or lockfile changed;

- no tag exists;

- no GitHub Release was created;

- no deployment occurred;

- `neural-from-scratch` was not accessed or modified.

Recommended Conventional Commit:

`docs(release): verify PatchPilot v0.1.0 readiness`

Do not create the commit automatically.

## Handoff Requirements

Return one consolidated handoff containing:

1. Outcome

2. Base commit, branch, and final working-tree state

3. Multi-agent execution summary

4. Session 8B merge identity

5. Architecture and scope verification

6. Security and tenant-isolation verification

7. Test and protected-GitHub-Actions evidence

8. Migration and database-integrity verification

9. Licensing, attribution, and dependency-security verification

10. Deployment-readiness verification

11. Documentation-consistency verification

12. Durable release-verification record

13. Files changed

14. Every command actually run and its result

15. Evidence taken from CI rather than local execution

16. Independent verification findings

17. Accepted residual risks

18. Operational prerequisites

19. Post-v0.1.0 follow-ups

20. Release blockers, if any

21. Exact release recommendation

22. Proposed Conventional Commit

23. Proposed pull-request title and summary

24. Required post-merge release procedure

The final verdict must be exactly one of:

- `RELEASE READY`

- `RELEASE READY WITH DOCUMENTED RESIDUALS`

- `NOT RELEASE READY`

- `BLOCKED BY MISSING EVIDENCE`

Explicitly confirm:

- no product code changed;

- no dependency was installed or updated;

- no commit or push occurred automatically;

- no pull request was created automatically;

- no tag or GitHub Release was created;

- no deployment occurred;

- migration count remains 28;

- `neural-from-scratch` was not accessed or modified.

End with exactly one:

`SESSION 8C READY FOR PRINCIPAL ARCHITECT REVIEW BEFORE COMMIT`

or:

`SESSION 8C RELEASE BLOCKER REQUIRES PRINCIPAL ARCHITECT REVIEW`