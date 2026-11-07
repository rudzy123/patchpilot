Execution contract for this session only. It authorizes only the work it names. It is subordinate to repository security rules, accepted ADRs, frozen migrations, and docs/project/[current-state.md](http://current-state.md). If those disagree with this spec, stop and report the conflict. This file is not a checkpoint and is not an ADR.

# Session 8D: Reproducible Prisma Generation and Release Integration Repair

## Identity

- **Session ID:** Session 8D

- **Mission:** Diagnose and correct the smallest repository or CI reproducibility defect that caused the required Integration workflow to fail on the exact PatchPilot MVP 0.1 release candidate after passing on the Session 8C pull-request head.

- **Base commit:** The parent of the spec-only commit that introduces this file. Before implementation, git rev-parse HEAD^ must equal git rev-parse origin/main.

- **Known failing candidate:** 2a1329039c93499db7859f902973eaf8a745f377

- **Failed GitHub Actions run:** 42375461643

- **Expected frozen migration count:** 28

- **Branch prefix:** fix/session-8d-release-integration

- **Change type:** Release-blocker correction only.

- **Branch size:** One pull-request-sized branch.

- **Automatic Git actions:** Cursor must not commit, push, create a pull request, create or push a tag, publish a GitHub Release, deploy, or modify Git history.

## Architectural Outcome

Session 8D must restore deterministic release verification so a clean GitHub Actions runner can build the database package, execute the Integration workflow, install the release-smoke browser, and run the single authorized Playwright smoke test against the exact post-merge commit.

The correction must address reproducibility or workflow ordering. It must not alter PatchPilot product semantics.

The desired invariant is:

> A clean checkout with only committed files and the locked dependency graph generates every required Prisma artifact before any package typecheck, build, integration test, or release-smoke step that consumes @prisma/client.

## Governing Evidence

The current release blocker is:

- synchronized main and origin/main at 2a1329039c93499db7859f902973eaf8a745f377;

- clean working tree;

- no v0.1.0 tag;

- no GitHub Release;

- pull request #110 checks passed;

- required Integration push run 42375461643 failed on the merge commit;

- failure occurred in @patchpilot/database#build;

- TypeScript reported missing Prisma and PrismaClient exports from @prisma/client;

- downstream repository types were reduced to { id: string };

- browser installation and the release smoke test were skipped.

Cursor must inspect the complete run logs and committed workflow before deciding the cause.

## Invariants

### Product behavior

- No change to vulnerability ingestion.

- No change to Product Match Evidence.

- No change to controlled Finding creation.

- No change to KEV behavior.

- No change to deterministic P1-P4 policy semantics.

- No change to RiskCalculation behavior.

- No change to remediation-queue membership or ordering.

- No change to priority-review behavior.

- No change to export semantics or the ADR 0051 22-column CSV contract.

- No change to authorization, tenant isolation, lifecycle, audit meaning, or provenance.

### Database and migrations

- No Prisma schema change is authorized.

- No migration 29 is authorized.

- Frozen migrations 1 through 28 remain byte-for-byte unchanged.

- All frozen migration digests must continue to match.

- Migration count remains 28.

- Generated Prisma artifacts must not be mistaken for schema authority.

- Generated artifacts must follow existing repository tracking and ignore conventions.

### Dependencies

- Prefer no dependency change.

- No runtime dependency may be added.

- No broad dependency upgrade is authorized.

- A manifest or lockfile change is permitted only if committed repository evidence proves that the pinned Prisma toolchain is internally inconsistent and the smallest compatible correction is necessary.

- Any dependency correction requires license, security, and lockfile review.

- Do not upgrade unrelated packages.

### CI reproducibility

- CI must not depend on generated files left in a developer working tree.

- CI must not depend on an untracked local Prisma client.

- Required generation must occur explicitly before the first consumer.

- Workflow correctness must not rely on an accidental cache hit.

- A cache miss must produce the same result as a cache hit.

- PR and push events must execute equivalent preparation for equivalent jobs unless an explicit documented distinction is required.

- The release smoke test remains exactly one Playwright specification.

- Tests must not contact public providers.

- The workflow must fail rather than silently omit Prisma generation or the release smoke test.

### Release control

- v0.1.0 must remain absent locally and remotely.

- No GitHub Release may be created.

- No deployment may occur.

- The release-readiness record must not be changed to claim release approval before the corrected post-merge workflow succeeds.

- neural-from-scratch must not be accessed or modified.

## Assumed Repository State

Before editing, Cursor must verify:

- current branch is the Session 8D branch;

- the parent of the spec-only commit equals origin/main;

- origin/main is based on release candidate 2a1329039c93499db7859f902973eaf8a745f377;

- working tree is clean after the spec-only commit;

- no local or remote v0.1.0 tag exists;

- GitHub Actions run 42375461643 is the failed Integration run for the release candidate;

- the failure occurs before browser installation and Playwright execution;

- frozen migration count is 28;

- all migration digests match;

- no migration 29 exists;

- Prisma schema and generation configuration are committed;

- package manifests and workflow files identify the expected Prisma generation lifecycle;

- the PR-head Integration run passed;

- the merge-commit push Integration run failed.

If any material assumption is false, stop and report the discrepancy.

## Allowed Change Surface

Permitted only where evidence requires:

- docs/specs/[session-8d.md](http://session-8d.md);

- existing GitHub Actions Integration workflow;

- existing root or workspace scripts governing install, generate, typecheck, build, integration tests, and release smoke;

- database-package build scripts;

- Prisma generation scripts and configuration;

- focused workflow or script tests;

- relevant release-readiness, current-state, checkpoint, or runbook records needed to describe the blocker and correction;

- package manifests and lockfile only under the dependency exception defined above.

Not permitted:

- product routes;

- application behavior;

- domain semantics;

- Prisma schema;

- migrations;

- API contracts;

- web UI;

- export serializers;

- additional Playwright specifications;

- deployment;

- tag or GitHub Release.

## Multi-Agent Execution Model

Cursor Plan is the lead orchestrator.

Use Grok 4.7 Extra High for parent-agent synthesis, authority conflicts, independent verification, and the release recommendation.

Delegate parallel read-only investigation to:

1. **GitHub Actions failure agent**

   - Inspects run 42375461643, the passing PR run, job steps, event differences, caches, generated artifacts, and exact failure order.

2. **Prisma lifecycle agent**

   - Inspects Prisma versions, schema locations, generators, package scripts, generated-client expectations, workspace dependencies, and import boundaries.

3. **Monorepo build-order agent**

   - Inspects pnpm lifecycle behavior, workspace task dependencies, build orchestration, Turbo configuration, clean-checkout assumptions, and package output boundaries.

4. **Cache and clean-runner agent**

   - Determines whether a cache hit, cache miss, stale generated artifact, or missing generation step can explain the PR-versus-push difference.

5. **Test and workflow-equivalence agent**

   - Compares PR and push workflow paths and defines evidence proving the correction on clean state.

6. **Independent final-verification agent**

   - Reviews the correction after implementation.

   - Must not own the primary workflow or script changes.

The parent agent must reconcile findings before edits, assign exclusive file ownership, and prevent overlapping modifications.

## Ordered Execution Plan

### Task 1: Capture Exact Failure Evidence

#### Allowed files or subsystem

Read-only GitHub Actions logs, workflow definitions, Git history, manifests, scripts, and Prisma configuration.

#### Required behavior

Establish:

- exact failed command;

- exact TypeScript errors;

- first missing generated artifact;

- Prisma CLI version;

- @prisma/client version;

- whether prisma generate ran;

- whether generation succeeded;

- whether generation ran before the first consumer;

- whether a cache restored generated output;

- differences between PR and push event paths;

- differences between PR-head and merge-commit dependency state;

- whether the merge commit introduced only documentation;

- whether CI depends on untracked local output.

Do not infer root cause from the final error alone.

#### Tests

Run safe read-only inspection commands and GitHub CLI log retrieval.

#### Done condition

One evidence-backed causal explanation is established, or the Session stops with an unresolved authority or environment report.

### Task 2: Reproduce the Clean-Runner Failure Locally or in an Equivalent Isolated Environment

#### Allowed files or subsystem

Existing repository scripts and authorized container or clean-worktree tooling.

#### Required behavior

Attempt to reproduce the workflow from a clean state without using generated files from the current developer workspace.

The reproduction must:

- use the committed lockfile;

- follow the workflow’s actual install and generation order;

- avoid public-provider test data;

- avoid production data;

- avoid modifying the schema;

- preserve the current working tree.

If Docker or equivalent infrastructure is unavailable, document the limitation and use GitHub Actions evidence without claiming a local reproduction.

#### Tests

Run the narrowest clean build needed to reproduce @patchpilot/database#build, followed by the authoritative broader command only after the root cause is understood.

#### Done condition

The failure is reproduced or conclusively explained through clean-runner evidence.

### Task 3: Implement the Smallest Reproducibility Correction

#### Allowed files or subsystem

Only the workflow, scripts, or package configuration proven responsible by Tasks 1 and 2.

#### Required behavior

Ensure required Prisma generation occurs deterministically before every consumer in the Integration release path.

The correction must:

- work from a clean checkout;

- work on cache miss;

- preserve lockfile determinism;

- preserve PR and push equivalence;

- avoid duplicate or conflicting generated clients;

- avoid relying on local untracked output;

- preserve existing package boundaries;

- preserve all product behavior;

- preserve migration count 28;

- keep the one authorized Playwright test reachable after the database build succeeds.

Do not add speculative generation commands to unrelated workflows.

#### Tests

Add or update the smallest repository-authorized workflow or script tests proving ordering and clean-state behavior.

#### Done condition

A clean environment can generate the Prisma client and build @patchpilot/database before integration and release-smoke execution.

### Task 4: Verify the Corrected Integration Path

#### Allowed files or subsystem

Existing build, database, integration, and Playwright commands.

#### Required behavior

Verify in order:

1. clean dependency installation or authoritative equivalent;

2. Prisma generation;

3. database-package typecheck or build;

4. database validation;

5. integration tests;

6. release-smoke browser installation;

7. one Playwright smoke test;

8. workflow lint.

Do not contact public providers.

#### Tests

Run the exact affected commands plus required repository gates.

#### Done condition

The previously failing path passes in the available local or isolated environment without relying on stale artifacts.

### Task 5: Reconcile Release Records

#### Allowed files or subsystem

Release readiness, latest checkpoint, current-state, and release-verification documentation.

#### Required behavior

Record:

- failed release-candidate run 42375461643;

- root cause;

- correction;

- verification evidence;

- absence of product-semantic change;

- continued tag prohibition until the corrective PR merges and the exact post-merge Integration run passes.

Do not mark v0.1.0 release ready solely from branch-local results.

#### Tests

Run documentation, formatting, links, and architecture-alignment checks.

#### Done condition

Release records accurately describe the blocker and the conditions for renewed release authorization.

### Task 6: Independent Final Verification

#### Allowed files or subsystem

Complete Session 8D diff and all evidence.

#### Required behavior

A fresh agent must verify:

- causal explanation is evidence-backed;

- correction is the smallest sufficient change;

- clean-runner behavior is deterministic;

- cache miss is safe;

- PR and push paths are aligned;

- no schema or migration changed;

- migration count remains 28;

- no product behavior changed;

- no runtime dependency was added;

- no additional Playwright test was added;

- no tag, release, or deployment occurred;

- neural-from-scratch was untouched.

#### Tests

Run the complete Verification section.

#### Done condition

No unresolved release blocker remains in the branch, and the parent agent produces the Session handoff.

## Out of Scope

Do not:

- change product functionality;

- change policy behavior;

- change queue or export semantics;

- change the ADR 0051 22-column contract;

- change tenant or authorization behavior;

- change the Prisma schema;

- create migration 29;

- modify frozen migrations;

- add a runtime dependency;

- perform broad dependency upgrades;

- add another Playwright test;

- weaken CI;

- skip Integration on push;

- remove the release smoke test;

- treat a cache hit as proof of correctness;

- tag v0.1.0;

- create a GitHub Release;

- deploy;

- access or modify neural-from-scratch.

## Stop Conditions

Stop and report if:

1. The parent of the spec-only commit does not equal origin/main.

2. The working tree contains unrelated changes.

3. The failure cannot be tied to run 42375461643.

4. The failing SHA differs from 2a1329039c93499db7859f902973eaf8a745f377.

5. A product-code change appears necessary.

6. A Prisma schema change appears necessary.

7. Migration 29 appears necessary.

8. A broad dependency upgrade appears necessary.

9. PR and push paths intentionally differ under accepted authority that this Session may not change.

10. A fix would weaken or skip Integration.

11. A fix would remove or bypass the Playwright smoke test.

12. Public-provider contact is required.

13. Production or customer data is required.

14. v0.1.0 exists locally or remotely.

15. neural-from-scratch appears in the investigation or change set.

## Verification

Run the repository-authorized equivalents of:

- clean Prisma generation;

- @patchpilot/database typecheck or build;

- pnpm format:check;

- pnpm lint;

- pnpm typecheck;

- pnpm test:unit;

- pnpm test:integration;

- pnpm db:validate;

- pnpm build;

- pnpm workflows:lint;

- the one authorized Playwright smoke test;

- migration-integrity validation;

- frozen-migration-count validation;

- architecture-alignment checks;

- documentation and relative-link checks;

- dependency review if manifests or lockfile changed;

- git diff --check;

- git status --short --branch.

Report local and CI evidence separately.

Before handoff confirm:

- no Prisma schema change;

- no migration change;

- migration count remains 28;

- no product behavior changed;

- no unauthorized dependency change;

- no tag or GitHub Release exists;

- no deployment occurred;

- neural-from-scratch was not accessed or modified.

Recommended Conventional Commit:

fix(ci): make Prisma generation deterministic

Do not create the commit automatically.

## Handoff Requirements

Return:

1. Outcome

2. Base commit, branch, and working-tree state

3. Multi-agent execution summary

4. Failed-run evidence

5. Root cause

6. PR-versus-push comparison

7. Clean-runner reproduction

8. Correction implemented

9. Files changed

10. Prisma and build-order verification

11. Integration and Playwright evidence

12. Migration, schema, dependency, and lockfile impact

13. Release-record reconciliation

14. Every command run and result

15. Independent verification

16. Residual risks

17. Remaining release blockers

18. Proposed Conventional Commit

19. Proposed pull-request title and summary

20. Required post-merge verification

Final verdict:

- CORRECTION READY FOR PRINCIPAL ARCHITECT REVIEW

- RELEASE BLOCKER REMAINS

Explicitly confirm:

- no automatic commit or push;

- no pull request created automatically;

- no tag or GitHub Release created;

- no deployment;

- migration count remains 28;

- neural-from-scratch untouched.

End with exactly one:

SESSION 8D READY FOR PRINCIPAL ARCHITECT REVIEW BEFORE COMMIT

or:

SESSION 8D RELEASE BLOCKER REQUIRES PRINCIPAL ARCHITECT REVIEW