# Secure development plan

How PatchPilot will design, review, and test security-sensitive change for v0.1. This is process architecture, not a claim that CI already exists or that the product is certified.

Navigation: [AGENTS.md](../../AGENTS.md). Reviews: [review checklist](../development/review-checklist.md). Reporting: [SECURITY.md](../../SECURITY.md).

## Rule precedence

1. Repository-wide security and tenancy rules always apply.
2. Closer instructions may add constraints.
3. Closer instructions must not weaken tenancy, authorization, secret handling, or audit.

When documents conflict, keep the stricter security interpretation and record it in the change description or an ADR.

## Before implementation

1. Read AGENTS.md, applicable `.cursor/rules`, MVP scope, and this security set.
2. If the change touches a trust boundary, jobs, scoring, evidence, or tenant data, treat it as **significant**.
3. Write or update an ADR when required ([ADR README](../adr/README.md)).
4. Stay inside [MVP scope](../product/mvp-scope.md) or label future work.

Do not scaffold applications or add dependencies unless the task asks. This architecture phase does not install packages.

## During implementation (once code exists)

1. Zod validation at boundaries.
2. Organization scope on every tenant-owned operation.
3. Outbox + idempotent jobs; no I/O in DB transactions.
4. Tests with the change: tenancy, replay, and security regressions **without** exploit payloads.
5. Structured redacted logs and metrics for significant features.
6. Operational failure plan for new job types.
7. No secrets in git, images, or client bundles.

## Review

Authors complete the [review checklist](../development/review-checklist.md). Reviewers verify:

- Layering (no Prisma in handlers/domain)
- Tenancy and IDOR
- SBOM and intel provenance
- Policy version and factors on new scores
- Evidence not cascade-deleted
- Honest product claims (no compliance/exploit theater)

Architecture PRs include or precede ADRs.

## Testing

Follow [testing strategy](../architecture/testing-strategy.md). Required security tests cannot be skipped without a tracked reason.

## Pipeline (when GitHub Actions exists)

Required checks in [branching strategy](../development/branching-strategy.md): lint, TypeScript strict, Vitest, Playwright when web UI changes, secret scanning / dependency review when those workflows exist, build of touched apps.

Until CI exists, report **actual** local command results. Do not claim checks passed if they were not run.

## Vulnerability handling

- Private report via SECURITY.md.
- Public PRs must not include working exploits.
- Fixes get regression tests.
- Development adapters stay disabled in production configs.

## Optional AI (future)

If AI is added: user-supplied credentials, disabled by default, no authoritative scores, explicit data-flow ADR before sending SBOM/finding text to a provider.

## Related documents

- [Security controls](security-controls.md)
- [Definition of done](../development/definition-of-done.md)
- [Release principles](../development/release-principles.md)
