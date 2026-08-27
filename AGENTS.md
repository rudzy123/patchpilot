# PatchPilot agent and contributor guide

This is the central navigation document for coding agents and human contributors.

PatchPilot is a production-minded, self-hosted platform for software asset inventory, CycloneDX SBOM processing, vulnerability correlation, explainable environmental risk, remediation tracking, and audit-preserving evidence. The product must remain fully useful without an AI provider.

Read this file before editing. Then read the Cursor rules and documents that apply to the files you will change.

## Rule precedence

1. Repository-wide security, tenancy, and authorization rules in this file and in [`.cursor/rules/security.mdc`](.cursor/rules/security.mdc) always apply.
2. Instructions closer to a file (narrower Cursor rules, directory guides, or file-level comments) may **add** constraints.
3. Closer instructions **must not silently weaken** repository-wide security, tenancy, authorization, secret handling, or audit rules.
4. If two instructions conflict, keep the stricter security and tenancy interpretation and record the conflict in the change description or an ADR.

Do not treat product, styling, or convenience guidance as permission to bypass deny-by-default authorization, organization scoping, input validation, or secret handling.

## Current repository state

The Session 3 **development foundation** and Session 4 CI/governance are in place. Session 5 adds the PostgreSQL tenant schema, repository adapters, migrations, and database integration tests. Session 6 Batch 1 accepts [ADR 0019](docs/adr/0019-local-password-sessions.md) (local passwords, opaque sessions, CSRF, interim permissions) and typed auth configuration. `packages/auth` installs `argon2@0.45.1`. Session 6 Batch 2 persists `LocalCredential`, opaque `Session` rows (digest-only), and audit actor columns (`anonymous`, restored `actorUserId`). Hashing, session use cases, and fail-closed login abuse control exist in `packages/auth` (Redis adapter in `apps/api`). Session 6 Fastify authentication routes are implemented: `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`, `GET /auth/organizations`, and `POST /auth/select-organization` (cookies, Origin, CSRF, JSON-only mutations, no-store, audit, login limiter). Registration, invitation, password reset, session listing, remote revoke, and the web login UI are **not** implemented. Product APIs, live SBOM ingestion, live vulnerability-provider calls, and risk-scoring logic are **not** implemented. v0.1 architecture, security design, and operational runbooks exist under `docs/architecture/`, `docs/security/`, and `docs/runbooks/`. ADRs 0001–0019 are **Accepted**. The layout below is the modular monolith. Do not invent a different topology without an accepted ADR.

## Target repository layout

```text
apps/
  web/                         # Next.js App Router (placeholder landing + /health)
  api/                         # Fastify TypeScript API (health + auth routes)

  worker/                      # Node.js TypeScript workers (empty job registry)
packages/
  config/                      # typed configuration; only place that may read process.env
  auth/                        # argon2 hashing, session use cases, permissions
  contracts/
  database/                    # Prisma adapters, tenant schema, repository implementations
  domain/                      # Result/error taxonomy; persistence ports; no Prisma types
  integrations/                # Object-storage and Redis ports; MinIO adapter deferred
  logger/
  observability/
  policy-engine/               # empty boundary
  sbom/                        # empty boundary
  test-utils/
  vulnerability-intelligence/  # empty boundary
  eslint-config/
  typescript-config/
docs/
  adr/
  architecture/
  product/
  runbooks/
  security/
deploy/
  compose/
  containers/
examples/
  sample-sboms/
  vulnerable-apps/
```

Begin as a modular monolith with separately deployable `web`, `api`, and `worker` applications. Do not introduce microservices without a measured need and an accepted ADR.

## Document map

| Topic | Document |
| --- | --- |
| Product vision and MVP | [docs/product/vision.md](docs/product/vision.md), [docs/product/mvp-scope.md](docs/product/mvp-scope.md), [docs/product/non-goals.md](docs/product/non-goals.md) |
| Users and language | [docs/product/target-users.md](docs/product/target-users.md), [docs/product/glossary.md](docs/product/glossary.md) |
| Definition of done | [docs/development/definition-of-done.md](docs/development/definition-of-done.md) |
| Local setup | [docs/development/local-setup.md](docs/development/local-setup.md), [environment variables](docs/development/environment-variables.md), [testing](docs/development/testing.md), [troubleshooting](docs/development/troubleshooting.md) |
| Git, reviews, releases | [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/commit-guidelines.md](docs/development/commit-guidelines.md), [docs/development/review-checklist.md](docs/development/review-checklist.md), [docs/development/pull-request-process.md](docs/development/pull-request-process.md), [docs/development/release-principles.md](docs/development/release-principles.md), [docs/development/release-strategy.md](docs/development/release-strategy.md) |
| CI and repository governance | [docs/development/ci.md](docs/development/ci.md), [docs/development/dependency-management.md](docs/development/dependency-management.md), [docs/development/branch-protection.md](docs/development/branch-protection.md), [docs/development/repository-settings.md](docs/development/repository-settings.md), [docs/development/artifact-retention.md](docs/development/artifact-retention.md) |
| Architecture | [docs/architecture/README.md](docs/architecture/README.md) |
| Security design | [docs/security/README.md](docs/security/README.md) |
| Operational runbooks | [docs/runbooks/README.md](docs/runbooks/README.md) |
| Architecture decisions | [docs/adr/README.md](docs/adr/README.md) |
| Open architecture decisions | [docs/architecture/open-decisions.md](docs/architecture/open-decisions.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Vulnerability disclosure | [SECURITY.md](SECURITY.md) |
| Conduct | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| License | [LICENSE](LICENSE) (Apache License 2.0) |

## Cursor rules

| Rule | When it applies |
| --- | --- |
| [architecture.mdc](.cursor/rules/architecture.mdc) | Always: layering, dependencies, identifiers, time, transactions |
| [security.mdc](.cursor/rules/security.mdc) | Always: the ten security-sensitive areas (canonical) |
| [git-workflow.mdc](.cursor/rules/git-workflow.mdc) | Always: branches, commits, pull requests |
| [testing.mdc](.cursor/rules/testing.mdc) | Tests and fixtures |
| [database.mdc](.cursor/rules/database.mdc) | Prisma, migrations, persistence |
| [api.mdc](.cursor/rules/api.mdc) | Fastify API |
| [frontend.mdc](.cursor/rules/frontend.mdc) | Next.js web app |
| [workers.mdc](.cursor/rules/workers.mdc) | Workers, queue, outbox |
| [integrations.mdc](.cursor/rules/integrations.mdc) | External providers and feeds |
| [documentation.mdc](.cursor/rules/documentation.mdc) | Docs, ADRs, runbooks |

## Security-sensitive areas

Treat these as in-scope for threat modeling and review on every related change. Canonical rules: [architecture.mdc](.cursor/rules/architecture.mdc) and [security.mdc](.cursor/rules/security.mdc). Terms: [docs/product/glossary.md](docs/product/glossary.md).

1. Tenant isolation
2. SBOM handling
3. Vulnerability-intelligence provenance
4. External integrations
5. Background-job idempotency
6. Sensitive log redaction
7. Credential storage
8. Risk-score explainability
9. Audit integrity
10. Development versus production configurations

## Architectural invariants

Do not copy or weakly restate `security.mdc` here. If this file and a rule disagree, keep the stricter security and tenancy interpretation.

- Modular monolith only (`web`, `api`, `worker` share packages/schema). No microservices without an accepted ADR.
- Application **layer** (use cases) lives in `packages/`. Fastify handlers and Next.js are presentation. Next.js is not a second API.
- Deny by default. Tenant-owned data is scoped to the authorized organization, not a client-supplied id.
- Untrusted: SBOMs, archives, webhooks, feeds, headers, URLs, files, external API responses. Validate with Zod at boundaries.
- `process.env` only in `packages/config`. No hardcoded secrets. Canonical log redaction is in `security.mdc`.
- Outbox for durable work; at-least-once; idempotent handlers and relays, org-scoped for tenant work.
- Intelligence is versioned with provenance. Priorities are explainable and policy-versioned. AI must not set authoritative scores.
- Append-only audit for security- and remediation-sensitive operations. No cascade-delete of evidence.

AI features, if added later, are optional explanation and drafting aids. Users must supply their own API key or local compatible endpoint at runtime. API keys must never be hardcoded. The first usable release must work with AI disabled. GitHub and other source-control integrations are not MVP.

## Agent workflow

Before editing:

1. Read this file and applicable files under [`.cursor/rules/`](.cursor/rules/).
2. Inspect the existing repository. Application shells exist; do not assume product features exist.
3. Summarize current state, assumptions, plan, security-sensitive changes, expected files, and ambiguities.
4. Stay inside the requested scope.

During implementation:

1. Work in small coherent batches. Do not rewrite unrelated files.
2. Add or update tests with implementation.
3. Create new database migrations rather than editing applied migrations.
4. Do not add dependencies without explaining why they are required.
5. Prefer established standards and libraries over custom security mechanisms.
6. Run appropriate checks after each coherent batch.
7. Do not scaffold applications or product functionality unless the task explicitly asks for them.

After implementation:

1. List created and modified files.
2. Explain important decisions.
3. Report executed commands and their actual results. Do not claim that commands passed unless they were executed.
4. Identify untested areas, remaining risks, and follow-up work.
5. Suggest one focused Conventional Commit message.
6. Do not describe work as production-ready merely because tests pass.

## Git and reviews

Use short-lived feature branches and [Conventional Commits](docs/development/commit-guidelines.md). Open a pull request. Do not push directly to `main`. Required checks and review expectations are defined in [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/ci.md](docs/development/ci.md), and [docs/development/review-checklist.md](docs/development/review-checklist.md).

Do not file security vulnerabilities as public issues. Follow [SECURITY.md](SECURITY.md).
