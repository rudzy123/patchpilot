Execution contract for this session only. It authorizes only the work it names. It is subordinate to repository security rules, accepted ADRs, frozen migrations, and docs/project/[current-state.md](http://current-state.md). If those disagree with this spec, stop and report the conflict. This file is not a checkpoint and is not an ADR.

# **Session 8A: Release Export Architecture**

## **Identity**

- **Session ID:** Session 8A
- **Mission:** Establish the accepted architectural authority for deterministic, tenant-safe, auditable CSV and JSON remediation-queue exports, and reconcile the release-state documentation needed before Session 8B.
- **Base commit SHA:** 9a0e736cdd959ba1630ec545fec9ecd3bbb780f2
- **Expected frozen migration count:** 28
- **Branch prefix:** docs/session-8a-export-architecture
- **Change type:** Architecture and documentation only.
- **Commit boundary:** One Conventional Commit and one pull-request-sized branch.
- **Automatic Git actions:** Cursor must not commit, push, create a pull request, tag, release, or merge.

## **Invariants**

At the end of Session 8A:

- No product route, serializer, UI control, worker, or export implementation exists.
- No schema or migration has changed.
- Frozen migration count remains 28.
- Existing remediation-queue authorization remains owner and admin through the accepted permission pair.
- Tenant identity continues to come from authoritative server context.
- The remediation queue remains the only authorized cross-asset Finding list.
- The existing deterministic queue comparator remains authoritative.
- Missing calculations remain distinct from P4.
- Incomparable calculations remain outside the ranked section.
- Human assessment remains distinct from calculated priority.
- Export is defined as a deliberate audited operation, not an ordinary queue read.
- Export does not invoke calculation, correlation, Finding creation, policy publication, or lifecycle mutation.
- Historical evidence, calculations, reviews, advisories, and queue inputs remain immutable.
- Session 8B remains responsible for implementation, Playwright, licensing evidence, dependency triage, and release closure.
- neural-from-scratch remains untouched.

The governing decisions include ADRs 0014, 0019, 0038, 0045, 0047, 0048, and 0049, plus all applicable repository security rules.

## **Assumed Repository State**

Before editing, reread:

- docs/project/[current-state.md](http://current-state.md);
- the latest project checkpoint;
- docs/adr/[README.md](http://README.md);
- ADR 0014;
- ADR 0019;
- ADR 0038;
- ADR 0045;
- ADR 0047;
- ADR 0048;
- ADR 0049;
- priority-weight validation V-0001;
- the remediation-queue architecture and tests;
- the frozen migration registry.

Expected state:

- HEAD^ of this spec-only commit equals origin/main.
- origin/main is 9a0e736cdd959ba1630ec545fec9ecd3bbb780f2.
- Working tree is clean after the spec commit.
- Frozen migration count is 28.
- All 28 migration digests match the frozen registry.
- ADR 0048 is Accepted and currently withholds export.
- ADR 0014 requires an append-only audit event for export.
- Queue reads remain unaudited and paginated rather than snapshot-based.
- V-0001 is validated_with_residuals.
- The exact built-in engine and policy pair is admitted.
- Controlled priority routes remain fail-closed until deployment-local policy publication succeeds.
- docs/project/[current-state.md](http://current-state.md) contains stale text concerning R13 and the present priority-composition state.
- No v0.1.0 tag exists.

If any expected state is false, stop and report the conflict.

## **Allowed Change Surface**

Permitted:

- one new ADR authorizing the release-export architecture;
- ADR 0048 amendment or supersession notation required by repository conventions;
- ADR index;
- docs/project/[current-state.md](http://current-state.md);
- latest project checkpoint;
- architecture and release documentation;
- risk-register text concerning R13 only where the committed evidence proves it stale;
- docs/specs/[session-8a.md](http://session-8a.md);
- documentation tests and link checks.

Not permitted:

- API changes;
- web changes;
- domain or application services;
- export serializers;
- contracts;
- permissions code;
- audit writers;
- workers;
- Playwright;
- schema;
- migrations;
- dependencies;
- lockfile;
- release tag or GitHub Release.

No new migration is authorized.

## **Execution Plan**

### **Task 1: Verify Repository Authority**

#### **Files**

Read the assumed-state documents, ADRs, queue implementation, audit authority, migration registry, and current-state document.

#### **Behavior**

Confirm:

- base commit;
- clean branch state;
- migration count 28;
- frozen migration integrity;
- current queue authorization;
- current queue read model;
- ADR 0048’s export prohibition;
- ADR 0014’s export-audit requirement;
- policy-validation and publication state;
- absence of v0.1.0.

#### **Tests**

Run only repository-state, documentation, and migration-integrity checks.

#### **Done condition**

The repository evidence supports the remainder of this contract without contradiction.

### **Task 2: Create the Export Architecture ADR**

#### **Files**

Create the next available ADR number according to repository conventions and update the ADR index.

#### **Behavior**

Authorize a distinct remediation-queue export operation with these decisions:

- Export is a separate audited operation, not ordinary queue pagination.
- Export uses the existing remediation-queue permission pair.
- Only owner and admin may export.
- Server-side tenant context is authoritative.
- One database REPEATABLE READ transaction produces one coherent export snapshot.
- The snapshot includes the ranked, incomparable, and not_calculated sections.
- Existing queue membership, comparability, and ordering remain authoritative.
- Export must not introduce a second comparator or second Finding-list model.
- The export has an explicit repository-defined row cap.
- Exceeding the cap fails safely rather than truncating silently.
- JSON uses a versioned envelope.
- CSV uses stable documented columns.
- CSV neutralizes formula-leading cells.
- Calculated priority and human assessment remain separate.
- Missing calculation is never P4.
- Export produces one append-only export.created audit event.
- The audit and export record selection follow one explicit transaction and failure model.
- Failed export creation must not leave a successful audit claim.
- Export does not calculate priority or mutate product state.
- No new schema or migration is required.
- No scheduled, anonymous, public, worker-generated, or startup-generated export is authorized.
- Session 8B will implement the decision.

The ADR must define the exact row cap using repository and MVP operational evidence. Do not leave the value unspecified.

The ADR must state whether it amends or partially supersedes ADR 0048’s no-export sentence while preserving the rest of ADR 0048.

#### **Tests**

Run ADR-format, documentation-link, and consistency checks.

#### **Done condition**

One accepted architectural decision defines the complete export authority needed by Session 8B without authorizing product code in Session 8A.

### **Task 3: Reconcile Release-State Documentation**

#### **Files**

Update only the allowed current-state, checkpoint, architecture, risk-register, and ADR-index documents.

#### **Behavior**

Correct stale statements so the repository distinguishes:

- composed priority workflow;
- admitted policy identity;
- deployment-local policy publication;
- fail-closed behavior before publication;
- validated-with-residuals status;
- export architecture accepted but not yet implemented;
- Session 8B as the implementation and release-closure Session.

Do not claim that a repository merge publishes policy into a deployment database.

Do not claim that policy validation proves affectedness, exploitability, or universal accuracy.

#### **Tests**

Run documentation consistency, formatting, and link checks.

#### **Done condition**

All affected documents describe one coherent implemented, activated, and still-withheld state.

### **Task 4: Independent Verification**

#### **Files**

No planned edits beyond narrow documentation corrections inside the allowed surface.

#### **Behavior**

Assign an independent agent to verify:

- ADR 0048 is amended or superseded correctly;
- its non-export queue semantics remain intact;
- ADR 0014 audit requirements are satisfied by the new decision;
- row cap and snapshot isolation are explicit;
- permission and tenant boundaries are explicit;
- no schema or migration is authorized;
- no product implementation entered the branch;
- R13 and publication wording is truthful;
- migration count remains 28;
- neural-from-scratch remains untouched.

#### **Tests**

Run all verification commands below.

#### **Done condition**

No architecture contradiction or unapproved implementation remains.

## **Out of Scope**

Do not add:

- export routes;
- serializers;
- web controls;
- contracts;
- export audit implementation;
- a second queue use case;
- a second comparator;
- calculation on export;
- queued or scheduled exports;
- public exports;
- anonymous downloads;
- client-authorized organization selection;
- Playwright;
- dependency changes;
- license report;
- Dependabot triage;
- changelog release closure;
- v0.1.0 tag;
- GitHub Release;
- migration 29;
- schema changes;
- any change to neural-from-scratch.

## **Stop Conditions**

Stop and report if:

1. HEAD^ does not equal origin/main.
2. origin/main is not 9a0e736cdd959ba1630ec545fec9ecd3bbb780f2.
3. The working tree contains unrelated changes.
4. Migration count is not 28.
5. A frozen migration digest differs.
6. Accepted ADR authority conflicts with this contract beyond ADR 0048’s known export prohibition.
7. The export architecture requires a schema change.
8. A safe coherent snapshot cannot be defined using the existing persistence boundary.
9. The export audit cannot be expressed through existing audit authority without schema change.
10. The task requires product-code implementation.
11. The row cap cannot be justified from repository or MVP operational evidence.
12. A security rule conflicts with this contract.
13. The work cannot fit in one documentation PR.
14. neural-from-scratch appears in the change set.

Do not redesign the Session after a stop condition.

## **Verification**

Pass means these commands succeed:

- pnpm format:check
- pnpm lint
- pnpm typecheck
- pnpm test:unit
- pnpm test:integration
- pnpm build
- pnpm workflows:lint
- the repository documentation and link checks;
- the repository migration-integrity check;
- the repository frozen-migration count check.

If repository rules permit narrowed gates for a documentation-only PR, run those authoritative gates plus every gate required by CI. Report exactly what was run.

Also verify:

- git diff --check;
- migration count remains 28;
- no frozen migration changed;
- no schema changed;
- no dependency or lockfile changed;
- no product file changed;
- no tag or release was created;
- neural-from-scratch was not accessed or modified.

One Conventional Commit:

docs(architecture): authorize remediation queue exports

One pull-request-sized branch.

Do not commit automatically.

## **Handoff Requirements**

Return:

1. Outcome
2. Base commit, branch, and final HEAD
3. Repository authority reviewed
4. Export ADR decision
5. ADR 0048 disposition
6. Snapshot, row-cap, authorization, and audit decisions
7. Documentation reconciliation
8. Files changed
9. Migration, schema, dependency, and lockfile impact
10. Every verification command and actual result
11. Independent verification
12. Scope compliance
13. Residual risks
14. Proposed Conventional Commit
15. Proposed pull-request title and summary
16. Recommended Session 8B prerequisites

Confirm:

- no product code changed;
- no commit or push occurred automatically;
- no PR, tag, or release was created automatically;
- migration count remains 28;
- neural-from-scratch was untouched.

End with:

SESSION 8A READY FOR PRINCIPAL ARCHITECT REVIEW BEFORE COMMIT