# Contributing to PatchPilot

Thank you for helping improve PatchPilot.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).

Start with [AGENTS.md](AGENTS.md). It is the navigation document for both humans and coding agents.

## Before you start

1. Read [AGENTS.md](AGENTS.md) and the applicable files under [`.cursor/rules/`](.cursor/rules/).
2. Read the product scope: [vision](docs/product/vision.md), [MVP](docs/product/mvp-scope.md), and [non-goals](docs/product/non-goals.md).
3. Check whether an [ADR](docs/adr/README.md) is required. Architecture and security design live in [docs/architecture](docs/architecture/README.md) and [docs/security](docs/security/README.md).
4. Search existing issues and pull requests before duplicating work.

Application shells and shared packages exist. Do not add product functionality (auth, SBOM processing, scoring, remediation, GitHub, or AI) unless a task explicitly asks for it.

## Development workflow

1. Create a short-lived branch from an up-to-date `main`. See [branching strategy](docs/development/branching-strategy.md).
2. Make a focused change. Preserve layering and security rules.
3. Add or update tests with the change.
4. Use [Conventional Commits](docs/development/commit-guidelines.md).
5. Open a pull request and complete the [review checklist](docs/development/review-checklist.md).
6. Meet the [definition of done](docs/development/definition-of-done.md).

Do not commit secrets, credentials, tokens, API keys, private URLs, raw production SBOMs, or environment-specific values. Example files must be clearly fake.

## Pull requests

Every pull request should:

- Explain why the change is needed.
- Stay within MVP scope, or label future work as future work.
- Include tests for significant behavior.
- Update docs, ADRs, runbooks, or threat-model notes when behavior or operations change.
- Pass the required pull-request checks listed in [branching strategy](docs/development/branching-strategy.md).

Security-sensitive changes need explicit review against [`.cursor/rules/security.mdc`](.cursor/rules/security.mdc) and [SECURITY.md](SECURITY.md).

## Architecture decisions

Propose lasting technical choices as Architecture Decision Records. Follow [docs/adr/README.md](docs/adr/README.md) and the [template](docs/adr/template.md). Do not merge a topology, tenancy, scoring, or persistence change that conflicts with an accepted ADR.

## Security issues

Do **not** open a public issue, discussion, or pull request that discloses a vulnerability. Report it privately using [SECURITY.md](SECURITY.md).

## Questions about product claims

PatchPilot helps operators inventory assets, process SBOMs, prioritize work, and keep evidence. It does not, by itself, confer regulatory compliance, certification, exploitability proof, or proof that remediation is complete. Do not add those claims to docs, UI copy, or reports.
