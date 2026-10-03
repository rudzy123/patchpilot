# PatchPilot

Self-hosted vulnerability prioritization and remediation. The product must remain fully useful without an AI provider.

PatchPilot currently provides production-composed inventory, SBOM ingestion, and KEV intelligence foundations. Reviewed advisory approval and legal product-evidence verification are implemented but production uncomposed. Persistent product-eligible evaluation count is zero. Automatic matching and Finding creation remain unavailable. Production OSV acquisition remains disabled. Findings, prioritization, remediation, and verification are not operational.

The repository is a pnpm + Turborepo monorepo with `web`, `api`, and `worker` applications, shared packages, and local Compose for PostgreSQL, Redis, and MinIO. The capability checkpoint is [docs/project/current-state.md](docs/project/current-state.md).

## Start here

- [Local setup](docs/development/local-setup.md)
- [CI](docs/development/ci.md)
- [AGENTS.md](AGENTS.md) — central guide for contributors and coding agents
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose changes
- [SECURITY.md](SECURITY.md) — private vulnerability reporting
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Product vision](docs/product/vision.md) and [MVP scope](docs/product/mvp-scope.md)
- [Architecture](docs/architecture/README.md), [security design](docs/security/README.md), and [runbooks](docs/runbooks/README.md)
- [Architecture decision records](docs/adr/README.md) (0001–0026 and 0028–0029 Accepted; 0027, 0030, 0031, and 0032 Proposed)
- [License](LICENSE) — Apache License 2.0

Quick start after installing Node 24 and pnpm 11:

```bash
cp .env.example .env
pnpm install
pnpm infrastructure:up
pnpm db:generate
pnpm dev
```

In another terminal, the quality gates are `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test:unit`, `pnpm test:integration`, `pnpm build`, and `pnpm workflows:lint`.

`.env.example` values are development placeholders and are unfit for production.

PatchPilot does not confer regulatory compliance or certification by itself. See [non-goals](docs/product/non-goals.md).
