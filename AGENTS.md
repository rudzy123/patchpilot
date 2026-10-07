# PatchPilot agent and contributor guide

PatchPilot is a self-hosted platform for software asset inventory, CycloneDX SBOM processing, vulnerability intelligence, and, later, explainable risk and remediation. The product must remain useful without an AI provider.

This file is a router. It is not the capability checkpoint and it is not a session diary.

Current checkpoint: [docs/project/current-state.md](docs/project/current-state.md).

Historical checkpoints: [docs/project/checkpoint-ledger.md](docs/project/checkpoint-ledger.md). That ledger is append-only and is not an authority source.

## Rule precedence

1. Repository-wide security, tenancy, and authorization rules in this file and in [.cursor/rules/security.mdc](.cursor/rules/security.mdc) always apply.
2. Instructions closer to a file may add constraints.
3. Closer instructions must not weaken repository-wide security, tenancy, authorization, secret handling, or audit rules.
4. If two instructions conflict, keep the stricter security and tenancy interpretation and record the conflict in the change description or an ADR.

Product, styling, or convenience guidance is not permission to bypass deny-by-default authorization, organization scoping, input validation, or secret handling.

## Source-of-truth hierarchy

Use this order when documents disagree:

1. Committed production runtime behavior
2. Frozen database schema and migrations
3. Accepted ADRs
4. Tested domain contracts
5. [docs/project/current-state.md](docs/project/current-state.md)
6. Architecture documents
7. This router
8. README and public positioning
9. The checkpoint ledger and other historical session reports

Do not treat schema existence as user-visible capability. Do not treat an exported factory as production composition. Do not treat a Proposed ADR as rejected code, or as accepted policy.

## Repository structure

Modular monolith. Separately deployable `web`, `api`, and `worker` apps share packages and schema. Do not split into independently owned services without an accepted ADR.

| Path | Role |
| --- | --- |
| `apps/web` | Next.js. Talks to the API. Not a second domain API. |
| `apps/api` | Fastify. Parse HTTP, apply authn context, call use cases. |
| `apps/worker` | Job wiring and adapters. |
| `packages/config` | The only package that reads `process.env`. |
| `packages/domain` | Use cases and ports. No Prisma, Fastify, or Next.js. |
| `packages/database` | Prisma adapters. |
| `packages/vulnerability-intelligence` | Intelligence contracts and uncomposed OSV, evaluator, and provenance code. |
| `packages/integrations` | Storage and provider adapters. |
| `packages/sbom` | CycloneDX parse. |
| `packages/auth` | Passwords, sessions, permissions. |
| `packages/policy-engine` | Empty boundary until scoring is authorized. |
| `docs/adr` | Decision records. |
| `docs/architecture` | Subsystem design. |
| `docs/runbooks` | Operator procedures. |
| `docs/project` | Current checkpoint and historical ledger. |

Ports are interfaces. Adapters are infrastructure. Domain depends on ports, not vendor SDKs. Apps may depend on packages. Packages must not depend on apps.

## Security invariants

Canonical detail is [.cursor/rules/security.mdc](.cursor/rules/security.mdc). These product invariants are the ones agents most often miss:

- Deny access by default. Tenant-owned operations use the authorized organization from session or membership context. A client-supplied `organizationId` is not authorization.
- Advisory intelligence is global or instance owned. Findings derived from it are tenant owned.
- Read `process.env` only in `packages/config`. Never hardcode secrets, tokens, or private URLs.
- MVP accepts CycloneDX JSON only. Do not execute SBOM content or fetch document URLs by default.
- Persist original SBOM bytes. Parse a copy. Record the upload, then parse through the outbox. No network or object-storage I/O inside a database transaction.
- Production OSV acquisition is disabled. `INTELLIGENCE_OSV_ENABLED=true` is rejected. Halt release is not enablement.
- The OSV implementation foundation is implemented and production uncomposed. Historical canary tools are operator only and unregistered.
- CISA KEV synchronization is production composed when enabled. KEV is not affectedness authority.
- Tests must not contact `storage.googleapis.com` or `osv.dev`.
- Synthetic evidence is not product evidence. `unknown` is not `unaffected`. An `affected` result is not Finding authority.
- Real product-eligible evaluation count remains 0. Product-evidence eligibility composition is not product matching. In the accepted zero-eligibility state it invokes no product evaluator and writes no product match row.
- Finding creation from match evidence is a controlled, production-uncomposed transaction. Safe inspection and explanation are implemented and production uncomposed. Lifecycle transitions remain unavailable. Do not describe a user-facing Finding product as operational.
- Match-evaluation evidence and advisory revisions are immutable. Do not update or delete audit rows in place. Do not cascade-delete evidence.
- Protected provider identities stay off public reads. Optional AI, if it ever exists, is never authoritative.
- GitHub and other source-control integrations are not MVP.
- Do not claim compliance, certification, exploitability, or remediation without supporting evidence.

Security-sensitive changes need regression tests without exploit payloads. Tenant-isolation and job-replay tests are required for those features.

## Session and branch workflow

Branch from up-to-date `main`. Use short-lived branches: `feat/`, `fix/`, `docs/`, `chore/`, `test/`, `refactor/`, `ci/`, `security/`. Delete the branch after merge. Never force-push `main`.

Do not record the current branch name in this file. Branch names are transient. The checkpoint document may name an open alignment only until that pull request merges; its lasting text describes the merged state.

Sessions are planning checkpoints. A session number does not authorize provider contact, catalog activation, matching, Finding creation, or production OSV.

Full policy: [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/commit-guidelines.md](docs/development/commit-guidelines.md), [docs/development/review-checklist.md](docs/development/review-checklist.md).

Conventional Commits. Do not commit secrets, `.env` files, or real SBOMs.

## Migration rules

The current frozen migration count is in [docs/project/current-state.md](docs/project/current-state.md) and must agree with `FROZEN_MIGRATIONS` in `packages/database/src/integration-database.ts`.

Do not edit a frozen migration. SQL corrections are forward-only. Historical checkpoint text may cite an older count only when it labels that count as historical.

Opaque IDs are UUIDs until an accepted ADR chooses another scheme. Persist timestamps in UTC. Tenant-owned idempotency includes the organization.

## Quality gates

Local equivalents of CI: `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test:unit`, `pnpm test:integration`, `pnpm build`, and `pnpm workflows:lint`.

Do not describe the tree as production-ready because checks passed. Do not merge with skipped tests unless a tracked reason is documented.

## Documentation responsibilities

| Document | Responsibility |
| --- | --- |
| [docs/project/current-state.md](docs/project/current-state.md) | Checkpoint: composed, uncomposed, test-only, placeholder, blocked |
| This file | Routing, hierarchy, invariants, workflow, gates, links |
| ADRs | Lasting decisions. Status changes are maintainer decisions |
| Architecture docs | Subsystem design. They follow the checkpoint when status differs |
| Runbooks | Procedures for composed behavior or explicitly operator-only tools |
| README | Public maturity and setup |
| [docs/project/checkpoint-ledger.md](docs/project/checkpoint-ledger.md) | Historical, append-only, not authoritative |

When runtime reachability or the frozen migration count changes, update the checkpoint in the same pull request. Do not copy the checkpoint into this router.

## Links

- [Current state](docs/project/current-state.md)
- [Checkpoint ledger](docs/project/checkpoint-ledger.md)
- [ADR index](docs/adr/README.md)
- [Architecture](docs/architecture/README.md)
- [Runbooks](docs/runbooks/README.md)
- [Security design](docs/security/README.md)
- [MVP scope](docs/product/mvp-scope.md)
- [Glossary](docs/product/glossary.md)
- [Local setup](docs/development/local-setup.md)
- [CI](docs/development/ci.md)
- [Vulnerability reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Document map

| Topic | Document |
| --- | --- |
| Product vision and MVP | [docs/product/vision.md](docs/product/vision.md), [docs/product/mvp-scope.md](docs/product/mvp-scope.md), [docs/product/non-goals.md](docs/product/non-goals.md) |
| Definition of done | [docs/development/definition-of-done.md](docs/development/definition-of-done.md) |
| Open decisions | [docs/architecture/open-decisions.md](docs/architecture/open-decisions.md) |
| Product-evidence provenance | [docs/architecture/product-evidence-provenance.md](docs/architecture/product-evidence-provenance.md) |

## Agent workflow

Before editing, read the checkpoint and the rules that apply to the files you will change. Inspect the repository. Stay inside the requested scope.

During implementation, work in small batches. Add or update tests with behavior changes. Create new migrations rather than editing applied ones. Do not add dependencies without explaining why.

After implementation, list created and modified files, important decisions, commands actually run, untested areas, and one Conventional Commit message. Do not claim a command passed unless it ran.

Do not file security vulnerabilities as public issues. Follow [SECURITY.md](SECURITY.md).
