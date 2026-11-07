**Execution contract for this session only. It authorizes only the work it names. It is subordinate to repository security rules, accepted ADRs, frozen migrations, and docs/project/[current-state.md](http://current-state.md). If those disagree with this spec, stop and report the conflict. This file is not a checkpoint and is not an ADR.**

**# Session 8E: PatchPilot v0.1.0 Release Authorization Closure**

**## Identity**

**- Session ID: Session 8E**

**- Mission: Record the successful post-merge Session 8D integration evidence, close the remaining PatchPilot v0.1.0 release-verification condition, and authorize the eventual synchronized post-Session-8E** `main` **commit for the operator-controlled** `v0.1.0` **tag.**

**- Base commit: The parent of the spec-only commit that introduces this file. Before editing release documentation,** `git rev-parse HEAD^` **must equal** `git rev-parse origin/main`**.**

**- Verified Session 8D commit:** `d39422660b1acc764bbe7e24b512298edabcb55f`

**- Verified Integration run:** `42388760406`

**- Verified Integration job:** `128451675222`

**- Session 8D pull request:** `#111`

**- Expected frozen migration count: 28**

**- Branch prefix:** `release/session-8e-v0.1.0-authorization`

**- Change type: Release authorization documentation only.**

**- Branch size: One pull-request-sized branch.**

**- Automatic Git actions: Cursor must not commit, push, create a pull request, create or push a tag, publish a GitHub Release, deploy, or modify Git history.**

**## Architectural Outcome**

**Session 8E must close the release authorization condition identified before the successful Session 8D post-merge workflow existed.**

**The durable release record must establish that:**

**- the failed prior candidate remains disqualified;**

**- Session 8D corrected the Prisma generation race;**

**- Integration passed on the exact Session 8D merge commit;**

**- the corrected workflow succeeded from a cache-miss state;**

**- database integration tests and the authorized Playwright smoke test passed;**

**- no product behavior changed;**

**- migration count remains 28;**

**- the ADR 0051 CSV contract remains exactly 22 columns;**

**- no release blocker remains;**

**- the final tag must target synchronized** `main` **after Session 8E merges and all required protected checks pass.**

**Session 8E does not create** `v0.1.0`**. It creates the final durable authorization record required before the operator-controlled tag and GitHub Release procedure.**

**## Invariants**

**### Product and architecture**

**- No product code changes.**

**- No API changes.**

**- No web changes.**

**- No domain or database behavior changes.**

**- No queue, export, policy, Finding, evidence, review, KEV, or advisory semantics change.**

**- ADR 0051 remains authoritative.**

**- The export CSV contract remains exactly 22 columns.**

**- Missing priority remains distinct from P4.**

**- Human assessment remains distinct from deterministic priority.**

**- Export remains capped at 150 Findings.**

**- Export audit records creation, not confirmed client receipt.**

**- Automatic recalculation remains withheld.**

**- Autonomous remediation remains withheld.**

**### Database and migrations**

**- No Prisma schema change.**

**- No migration 29.**

**- Frozen migrations 1 through 28 remain byte-for-byte unchanged.**

**- All frozen migration digests must match.**

**- Frozen migration count remains 28.**

**### Dependencies and workflows**

**- No dependency change.**

**- No package-manifest change.**

**- No lockfile change.**

**- No workflow change.**

**- No test change.**

**- No Dockerfile or Compose change.**

**- The Session 8D generate-before-Turbo correction remains unchanged.**

**- Successful workflow evidence must be cited accurately and must not be described as a local pass.**

**### Release control**

**-** `v0.1.0` **must remain absent locally and remotely.**

**- No GitHub Release may be created.**

**- No deployment may occur.**

**- Session 8E must not publish the built-in policy.**

**- The final release tag must target synchronized** `main` **after this Session merges and its required protected checks pass.**

**- The final tag SHA is not known while this branch is open and must not be invented or written as a placeholder.**

**### Repository boundaries**

**-** `patchpilot` **is the only repository in scope.**

**-** `neural-from-scratch` **must not be accessed, inspected, copied from, or modified.**

**- No secret, credential, tenant data, raw SBOM, raw advisory payload, local environment file, cache, coverage output, or editor artifact may enter the change set.**

**## Governing Authority**

**Before editing, Cursor must reread:**

**- all applicable** `AGENTS.md` **files;**

**- repository security rules;**

**-** `docs/project/current-state.md`**;**

**- the latest project checkpoint;**

**-** `docs/releases/v0.1.0-readiness.md`**;**

**-** `docs/releases/v0.1.0-verification.md`**;**

**-** `docs/releases/v0.1.0-checklist.md`**;**

**-** `docs/releases/v0.1.0-release-notes.md`**;**

**- Session 8D release-blocker and corrective records;**

**- ADR 0045;**

**- ADR 0047;**

**- ADR 0048;**

**- ADR 0049;**

**- ADR 0050;**

**- ADR 0051;**

**- the frozen migration registry;**

**- GitHub Actions workflows relevant to the release;**

**- GitHub Actions run** `42388760406`**;**

**- Session 8D pull request #111.**

**## Assumed Repository State**

**Before editing, prove:**

**- Session 8D PR #111 is merged.**

**-** `origin/main` **is** `d39422660b1acc764bbe7e24b512298edabcb55f`**.**

**- The parent of the Session 8E spec-only commit equals** `origin/main`**.**

**- The working tree is clean after the spec-only commit.**

**- Session 8D merge commit is** `d39422660b1acc764bbe7e24b512298edabcb55f`**.**

**- Required PR checks on #111 passed.**

**- Push Integration run** `42388760406` **targets that exact SHA.**

**- Integration run** `42388760406` **is completed successfully.**

**- Prisma Client v6.19.3 was generated before database consumers.**

**-** `@patchpilot/database:build` **ran as a cache miss and passed.**

**- Turbo reported 16 successful tasks out of 16.**

**- Database integration reported 72 passed test files and 771 passed tests.**

**- Chromium installation completed.**

**- The one authorized Playwright smoke test passed.**

**- CI, Integration, CodeQL, Container Build, SBOM, and Scorecard push workflows succeeded on the exact Session 8D SHA.**

**- Dependency Review passed on PR #111 and remains a pull-request-only workflow.**

**- Migration count remains 28.**

**- No migration 29 exists.**

**- ADR 0051 and the serializer retain the same 22-column CSV contract.**

**- No local or remote** `v0.1.0` **tag exists.**

**- No GitHub Release for** `v0.1.0` **exists.**

**- Existing release records still withhold authorization only because they predate the successful post-merge Integration run.**

**If any material assumption is false, stop and report the conflict.**

**## Allowed Change Surface**

**Permitted:**

**-** `docs/specs/session-8e.md`**;**

**-** `docs/releases/v0.1.0-readiness.md`**;**

**-** `docs/releases/v0.1.0-verification.md`**;**

**-** `docs/releases/v0.1.0-checklist.md`**;**

**-** `docs/releases/v0.1.0-release-notes.md` **only if a factual pre-release statement must be clarified;**

**- latest project checkpoint;**

**-** `docs/project/current-state.md`**;**

**- release runbook only if required to reflect final authorization sequencing.**

**Not permitted:**

**- product code;**

**- tests;**

**- workflows;**

**- package manifests;**

**- lockfile;**

**- schema;**

**- migrations;**

**- Dockerfiles;**

**- Compose files;**

**- runtime configuration;**

**- tag creation;**

**- GitHub Release creation;**

**- deployment.**

**## Multi-Agent Execution Model**

**Cursor Plan is the lead release-authorization orchestrator.**

**Use Grok 4.7 Extra High for synthesis, conflict resolution, independent final verification, and the release recommendation.**

**Delegate parallel read-only work to:**

**1. Git and release-identity agent**

   **- Confirms Session 8D merge identity, synchronized** `main`**, tag absence, and branch-base correctness.**

**2. GitHub Actions evidence agent**

   **- Confirms run** `42388760406`**, job** `128451675222`**, exact SHA binding, successful Prisma generation, database build, integration tests, browser installation, and Playwright result.**

**3. Architecture and migration agent**

   **- Confirms no product-semantic change, migration count 28, frozen migration integrity, no schema change, and the 22-column CSV contract.**

**4. Release-document consistency agent**

   **- Identifies the exact stale release statements that must be closed.**

**5. Independent final-verification agent**

   **- Reviews the completed release-authorization record.**

   **- Must not author the primary release-document updates.**

   **- Must not perform the parent agent’s primary synthesis.**

**The parent agent must reconcile findings before edits, assign exclusive document ownership, and prevent concurrent edits.**

**## Ordered Execution Plan**

**### Task 1: Confirm Session 8D Release Evidence**

**#### Allowed files or subsystem**

**Read-only Git state, GitHub Actions evidence, pull-request evidence, release records, migration registry, and accepted ADRs.**

**#### Required behavior**

**Confirm every assumed repository-state item.**

**Explicitly verify:**

**- exact Session 8D merge SHA;**

**- exact Integration run and job;**

**- workflow conclusion;**

**- Prisma generation ordering;**

**- database build success;**

**- cache-miss behavior;**

**- integration-test counts;**

**- Playwright installation and result;**

**- all required workflow conclusions;**

**- Dependency Review PR-only behavior;**

**- tag and GitHub Release absence.**

**#### Tests**

**Run safe read-only Git and GitHub CLI commands.**

**#### Done condition**

**The successful Session 8D post-merge evidence is complete and attributable to the exact commit.**

**### Task 2: Close the Release-Verification Record**

**#### Allowed files or subsystem**

`docs/releases/v0.1.0-verification.md` **and, if required for factual consistency,** `docs/releases/v0.1.0-readiness.md`**.**

**#### Required behavior**

**Record:**

**- the disqualified candidate** `2a1329039c93499db7859f902973eaf8a745f377`**;**

**- failed run** `42375461643`**;**

**- Session 8D root cause;**

**- Session 8D correction;**

**- corrected candidate** `d39422660b1acc764bbe7e24b512298edabcb55f`**;**

**- Session 8D PR #111;**

**- successful Integration run** `42388760406`**;**

**- Integration job** `128451675222`**;**

**- generate-before-Turbo ordering;**

**- cache-miss database build success;**

**- 16 of 16 Turbo tasks;**

**- 72 passed database test files;**

**- 771 passed database tests;**

**- one passed Playwright smoke test;**

**- all required workflow evidence;**

**- migration count 28;**

**- no product-semantic change;**

**- exact 22-column CSV contract;**

**- absence of remaining release blockers.**

**Set the release-verification verdict according to repository conventions to:**

`RELEASE READY WITH DOCUMENTED RESIDUALS`

**The record must state that the eventual tag may target synchronized** `main` **only after Session 8E merges and all required protected checks pass.**

**Do not claim that the tag already exists.**

**#### Tests**

**Run documentation, link, formatting, and architecture-alignment checks.**

**#### Done condition**

**The durable verification record accurately authorizes the post-Session-8E synchronized** `main` **commit for the operator-controlled release procedure.**

**### Task 3: Close the Release Checklist**

**#### Allowed files or subsystem**

`docs/releases/v0.1.0-checklist.md`**.**

**#### Required behavior**

**Complete only checklist items proven by committed or GitHub Actions evidence.**

**Mark the post-merge Integration requirement complete with:**

**- corrected candidate SHA;**

**- Integration run URL or ID;**

**- successful conclusion;**

**- Prisma generation evidence;**

**- database test evidence;**

**- Playwright evidence.**

**Leave tag, GitHub Release, and deployment items unchecked because those actions have not occurred.**

**Do not mark client receipt of exports, shared deployment publication, or production deployment as complete unless the checklist explicitly requires and proves those events.**

**#### Tests**

**Run documentation consistency checks.**

**#### Done condition**

**The checklist distinguishes completed release authorization from future operator actions.**

**### Task 4: Reconcile Current State and Release Notes**

**#### Allowed files or subsystem**

`docs/project/current-state.md`**, latest checkpoint, release notes, and release runbook only where factual reconciliation is required.**

**#### Required behavior**

**Ensure the documentation consistently states:**

**- Session 8D corrected deterministic Prisma generation;**

**- successful post-merge Integration now exists;**

**- the release candidate is authorized with documented residuals;**

**- migration count remains 28;**

**- CSV contract contains 22 columns;**

**- no product behavior changed;**

**-** `v0.1.0` **is not yet tagged;**

**- the GitHub Release does not yet exist;**

**- deployment has not occurred;**

**- tagging must target synchronized** `main` **after Session 8E merges and protected checks pass.**

**Do not rewrite historical records to imply the failed prior candidate was successful.**

**#### Tests**

**Run documentation, links, formatting, and architecture-alignment checks.**

**#### Done condition**

**All release documents describe one coherent current state and release sequence.**

**### Task 5: Independent Final Verification**

**#### Allowed files or subsystem**

**Complete Session 8E diff and all gathered evidence.**

**#### Required behavior**

**A fresh agent must verify:**

**- GitHub Actions evidence is tied to the corrected candidate;**

**- no PR evidence is misrepresented as push evidence;**

**- Dependency Review is identified accurately as PR-only;**

**- no product, test, workflow, schema, migration, dependency, or lockfile file changed;**

**- migration count remains 28;**

**- 22-column CSV authority remains intact;**

**- no release blocker remains;**

**- tag and GitHub Release are still absent;**

**- final tag authorization is conditional on the post-Session-8E synchronized** `main` **SHA and successful protected checks;**

**- no deployment occurred;**

**-** `neural-from-scratch` **was not accessed or modified.**

**#### Tests**

**Run every command in the Verification section.**

**#### Done condition**

**The independent reviewer confirms the documentation-only authorization is truthful and complete.**

**## Out of Scope**

**Do not:**

**- modify product code;**

**- modify tests;**

**- modify workflows;**

**- modify Prisma generation;**

**- modify package manifests;**

**- modify the lockfile;**

**- modify the Prisma schema;**

**- create migration 29;**

**- alter frozen migrations;**

**- alter queue or export semantics;**

**- alter the 22-column CSV contract;**

**- alter authorization or tenant behavior;**

**- add dependencies;**

**- update dependencies;**

**- rerun or dispatch GitHub Actions merely to create different evidence;**

**- create or push** `v0.1.0`**;**

**- create a GitHub Release;**

**- deploy;**

**- publish the built-in policy into a shared deployment;**

**- access or modify** `neural-from-scratch`**.**

**## Stop Conditions**

**Stop and report if:**

**1. The parent of the spec-only commit does not equal** `origin/main`**.**

**2. The working tree contains unrelated changes.**

**3. Session 8D PR #111 is not merged.**

**4. Session 8D merge SHA differs from** `d39422660b1acc764bbe7e24b512298edabcb55f`**.**

**5. Integration run** `42388760406` **does not target that exact SHA.**

**6. Integration run** `42388760406` **is not completed successfully.**

**7. Prisma generation, database build, integration tests, browser installation, or Playwright did not complete successfully.**

**8. A required workflow on the corrected candidate failed, was cancelled, timed out, or remains incomplete.**

**9. Migration count is not 28.**

**10. A frozen migration digest differs.**

**11. Migration 29 exists.**

**12. A product, test, workflow, schema, migration, dependency, or lockfile correction appears necessary.**

**13. ADR 0051 and the serializer do not retain the same 22-column contract.**

**14.** `v0.1.0` **already exists locally or remotely.**

**15. A GitHub Release for** `v0.1.0` **already exists.**

**16. The release records contain a material contradiction that cannot be corrected inside documentation only.**

**17.** `neural-from-scratch` **appears in the investigation or change set.**

**## Verification**

**Run:**

**-** `pnpm format:check`

**-** `pnpm lint`

**-** `pnpm typecheck`

**-** `pnpm test:unit`

**-** `pnpm test:integration`

**-** `pnpm db:validate`

**-** `pnpm build`

**-** `pnpm workflows:lint`

**- the repository-authorized Playwright command;**

**- migration-integrity validation;**

**- frozen-migration-count validation;**

**- documentation and relative-link checks;**

**- architecture-alignment checks;**

**- license-report verification;**

**- dependency-security verification;**

**-** `git diff --check`**;**

**-** `git status --short --branch`**.**

**Protected GitHub Actions evidence tied to the corrected candidate may satisfy expensive or infrastructure-dependent gates.**

**When relying on CI evidence, record:**

**- workflow;**

**- job;**

**- result;**

**- commit SHA;**

**- run ID or URL;**

**- whether evidence came from push or pull request.**

**Do not claim a local pass when evidence came from GitHub Actions.**

**Before handoff, confirm:**

**- no product file changed;**

**- no test or workflow changed;**

**- no schema or migration changed;**

**- migration count remains 28;**

**- no dependency or lockfile changed;**

**- no tag exists;**

**- no GitHub Release exists;**

**- no deployment occurred;**

**-** `neural-from-scratch` **was not accessed or modified.**

**Recommended Conventional Commit:**

`docs(release): authorize PatchPilot v0.1.0`

**Do not create the commit automatically.**

**## Handoff Requirements**

**Return:**

**1. Outcome**

**2. Base commit, branch, and working-tree state**

**3. Multi-agent execution summary**

**4. Corrected release-candidate identity**

**5. Session 8D PR evidence**

**6. Post-merge Integration evidence**

**7. Prisma generation and cache-miss evidence**

**8. Database integration evidence**

**9. Playwright evidence**

**10. Complete protected-workflow evidence**

**11. Migration and schema integrity**

**12. Architecture and product-scope confirmation**

**13. Release-verification record changes**

**14. Release-checklist changes**

**15. Current-state and release-note reconciliation**

**16. Files changed**

**17. Every command run and result**

**18. Evidence taken from push CI**

**19. Evidence taken from PR CI**

**20. Independent verification**

**21. Accepted residual risks**

**22. Remaining operational prerequisites**

**23. Release blockers, if any**

**24. Exact release recommendation**

**25. Proposed Conventional Commit**

**26. Proposed pull-request title and summary**

**27. Required post-merge tag and GitHub Release procedure**

**Final verdict:**

**-** `RELEASE AUTHORIZED WITH DOCUMENTED RESIDUALS`

**-** `RELEASE NOT AUTHORIZED`

**-** `BLOCKED BY MISSING EVIDENCE`

**Explicitly confirm:**

**- no product code changed;**

**- no test or workflow changed;**

**- no dependency installed or updated;**

**- no automatic commit or push;**

**- no pull request created automatically;**

**- no tag or GitHub Release created;**

**- no deployment;**

**- migration count remains 28;**

**-** `neural-from-scratch` **untouched.**

**End with exactly one:**

`SESSION 8E READY FOR PRINCIPAL ARCHITECT REVIEW BEFORE COMMIT`

**or:**

`SESSION 8E RELEASE BLOCKER REQUIRES PRINCIPAL ARCHITECT REVIEW`