# PatchPilot

Self-hosted vulnerability prioritization and remediation. The product must remain fully useful without an AI provider.

This repository has a **development foundation**: a pnpm + Turborepo monorepo, application shells (`web`, `api`, `worker`), shared packages, and local Compose for PostgreSQL, Redis, and MinIO. Product workflows are not implemented yet.

## Start here

- [Local setup](docs/development/local-setup.md)
- [CI](docs/development/ci.md)
- [AGENTS.md](AGENTS.md) — central guide for contributors and coding agents
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose changes
- [SECURITY.md](SECURITY.md) — private vulnerability reporting
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Product vision](docs/product/vision.md) and [MVP scope](docs/product/mvp-scope.md)
- [Architecture](docs/architecture/README.md), [security design](docs/security/README.md), and [runbooks](docs/runbooks/README.md)
- [Architecture decision records](docs/adr/README.md) (Accepted for v0.1)
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
