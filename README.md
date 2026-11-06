# PatchPilot

Self-hosted vulnerability prioritization and remediation. The product must remain fully useful without an AI provider.

PatchPilot currently provides production-composed inventory, SBOM ingestion, and KEV intelligence foundations. Reviewed advisory approval and legal product-evidence verification are implemented but production uncomposed. Persistent product-eligible evaluation count is zero. Automatic matching and automatic Finding creation remain unavailable. Owner POST /findings, owner or admin GET /findings/:findingId, and owner or admin GET /findings/:findingId/latest-observation are composed in the API. The latest-observation route is read only, requires finding:inspect, and does not change creation inspection. Members and viewers are denied. The independent latest-observation web section is implemented on `/findings/:findingId`. Owners and admins may view it. Members and viewers may not. Creation fallback and the latest legal repeated observation are reachable. The section stays independent of creation inspection. Aggregate language remains non-lifecycle. A latest-observation error does not erase creation inspection. Latest-observation data stays ephemeral. Controlled Finding Latest-Observation Reachability Session 2-R reviewed the independent web section. Branch closure reviewed the reachable read-only workflow. Repeated-observation writes, observation history, and Finding lifecycle behavior remain unavailable. Owner or admin GET /assets/:assetId/controlled-finding-targets is composed and read-only. Acknowledgements come from the authoritative qualifying set. POST /findings still revalidates them and remains owner-only. Discovery does not grant creation authority. Production OSV acquisition remains disabled. Explainable priority calculation, the controlled remediation queue, and priority review are implemented. They stay inactive in a deployment until an operator publishes the admitted builtin there. Owners and admins can export that queue as JSON or CSV from `POST /remediation-queue/export` and from `/remediation-queue`. The export does not calculate priority. v0.1.0 is prepared and not tagged. Remediation tasks and verification are not operational.

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

Local development and the self-hosted application profile are different Compose projects. `pnpm infrastructure:up` starts PostgreSQL, Redis, and MinIO only. Application containers, migrate, and the no-write bootstrap are in [self-hosted deployment](docs/runbooks/self-hosted-deployment.md). A healthy container stack still has no first user, does not publish the admitted builtin priority policy, and needs operator HTTPS before a browser can log in. Priority routes stay 503 until an operator runs the publication command in that deployment.

`.env.example` values are development placeholders and are unfit for production.

PatchPilot does not confer regulatory compliance or certification by itself. See [non-goals](docs/product/non-goals.md).
