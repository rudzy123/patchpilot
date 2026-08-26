# ADR 0002: pnpm and Turborepo monorepo

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

The target layout is multiple apps and packages with shared TypeScript types. We need a single lockfile, filtered installs, and task graph for lint/test/build once code exists. This ADR records the toolchain; it does not install it in the architecture phase.

## Decision

Use **pnpm** workspaces and **Turborepo** for the TypeScript monorepo. Apps may depend on packages; packages must not depend on apps. Strict TypeScript settings stay enabled.

## Alternatives considered

- **npm/yarn workspaces** without Turbo: workable; weaker task scheduling.
- **Nx**: heavier default surface.
- **Polyrepo**: rejected; would duplicate schema and security rules.

## Consequences

Contributors use pnpm. CI (when added) will invoke Turbo pipelines. Generated `node_modules` layout follows pnpm.

## Security and tenancy

Lockfile is a supply-chain control. Do not commit secrets. Dependency additions need explanation in PRs. This ADR does not weaken tenancy.

## Operational failure plan

Corrupt store or lockfile drift: regenerate from committed lockfile; do not "fix" production with unpinned installs.

## Follow-up

Scaffolding task will add `pnpm-workspace.yaml` and `turbo.json`. No packages installed in this phase.
