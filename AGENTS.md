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

Application packages, manifests, and runtime code are not scaffolded yet. The layout below is the **target** modular monolith. Do not invent a different topology without an accepted ADR.

## Target repository layout

```text
apps/
  web/                         # Next.js App Router
  api/                         # Fastify TypeScript API
  worker/                      # Node.js TypeScript workers
packages/
  auth/
  config/                      # typed configuration; only place that may read process.env
  contracts/
  database/                    # Prisma and persistence adapters
  domain/
  integrations/
  logger/
  observability/
  policy-engine/
  sbom/
  test-utils/
  vulnerability-intelligence/
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
| Git, reviews, releases | [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/commit-guidelines.md](docs/development/commit-guidelines.md), [docs/development/review-checklist.md](docs/development/review-checklist.md), [docs/development/release-principles.md](docs/development/release-principles.md) |
| Architecture decisions | [docs/adr/README.md](docs/adr/README.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Vulnerability disclosure | [SECURITY.md](SECURITY.md) |
| Conduct | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| License | [LICENSE](LICENSE) (Apache License 2.0) |

## Cursor rules

| Rule | When it applies |
| --- | --- |
| [architecture.mdc](.cursor/rules/architecture.mdc) | Always: layering, dependencies, identifiers, time, transactions |
| [security.mdc](.cursor/rules/security.mdc) | Always: tenancy, authz, secrets, untrusted input, logging redaction |
| [git-workflow.mdc](.cursor/rules/git-workflow.mdc) | Always: branches, commits, pull requests |
| [testing.mdc](.cursor/rules/testing.mdc) | Tests and fixtures |
| [database.mdc](.cursor/rules/database.mdc) | Prisma, migrations, persistence |
| [api.mdc](.cursor/rules/api.mdc) | Fastify API |
| [frontend.mdc](.cursor/rules/frontend.mdc) | Next.js web app |
| [workers.mdc](.cursor/rules/workers.mdc) | Workers, queue, outbox |
| [integrations.mdc](.cursor/rules/integrations.mdc) | External providers and feeds |
| [documentation.mdc](.cursor/rules/documentation.mdc) | Docs, ADRs, runbooks |

## Architectural invariants

- Separate presentation, application, domain, and infrastructure.
- Domain and application code must not depend on Fastify, Next.js, Prisma, Redis, BullMQ, MinIO, or vendor SDKs.
- Fastify route handlers may parse input and invoke application use cases. They may not contain business logic. The Next.js app talks to the API and must not embed domain logic or persistence.
- Access external providers only through interfaces and adapters.
- Scope every tenant-owned operation to an organization. Never treat a client-supplied `organizationId` as sufficient authorization.
- Deny access by default.
- Validate untrusted input with Zod at system boundaries.
- Treat SBOMs, archives, webhook payloads, vulnerability feeds, headers, URLs, files, and external API responses as untrusted.
- Read `process.env` only inside the typed configuration package.
- Never hardcode secrets, credentials, tokens, API keys, private URLs, or environment-specific values.
- Never log authorization headers, cookies, API tokens, GitHub tokens, raw SBOMs, private source code, or complete vulnerability feed payloads.
- Persist timestamps in UTC. Use UUIDs or another opaque identifier.
- Use database transactions for state transitions. Do not perform network, queue, or object-storage calls inside those transactions.
- Use a transactional outbox for reliable background work. Assume at-least-once delivery. Make every job handler idempotent.
- Preserve vulnerability-intelligence provenance. Do not silently overwrite intelligence records.
- Version the risk-scoring policy. Persist the policy version and contributing factors for each calculated priority. Risk scores must be explainable. AI must not determine authoritative risk scores.
- Separate observed facts from calculated conclusions. Do not claim compliance, certification, exploitability, or remediation without supporting evidence.
- Use append-only audit events for security-sensitive and remediation-sensitive operations. Avoid cascading deletion of evidentiary data.

AI features, if added later, are optional explanation and drafting aids. Users must supply their own API key or local compatible endpoint at runtime. API keys must never be hardcoded. The first usable release must work with AI disabled.

## Agent workflow

Before editing:

1. Read this file and applicable files under [`.cursor/rules/`](.cursor/rules/).
2. Inspect the existing repository. Do not assume applications already exist.
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

Use short-lived feature branches and [Conventional Commits](docs/development/commit-guidelines.md). Open a pull request. Do not push directly to `main`. Required checks and review expectations are defined in [docs/development/branching-strategy.md](docs/development/branching-strategy.md) and [docs/development/review-checklist.md](docs/development/review-checklist.md).

Do not file security vulnerabilities as public issues. Follow [SECURITY.md](SECURITY.md).
