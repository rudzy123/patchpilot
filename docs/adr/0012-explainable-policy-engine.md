# ADR 0012: Explainable versioned policy engine

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Scores must be explainable, replayable, and honest. AI must not set authoritative scores. **Priority** and **risk score** remain synonyms until a later ADR ([OD-7](../architecture/open-decisions.md)).

## Decision

Implement a deterministic **policy engine** in `packages/policy-engine` with **no I/O** and **no import of `packages/domain`**. Domain defines a port; the worker injects the implementation. Each **RiskCalculation** stores policy version, **`policyDefinitionSha256`**, `inputFingerprint`, contributing factors, intel source record ids, **priority**, **priorityBand**, due-date recommendation, and escalation recommendation. Recalculation inserts a new row; history is not erased. Organization overrides publish a new tenant-owned policy version and do not mutate historical results. Distinguish **vulnerability severity** (observed from intel) from **remediation priority** (calculated). Default policy does not auto-score compensating-control prose or task completion.

## Alternatives considered

- **Opaque single number**: rejected by product principles.
- **LLM scoring**: rejected; non-authoritative AI is future and optional.
- **In-place score update**: destroys evidence.

## Consequences

Policy bugs ship as new versions. Release notes mention policy version when behavior changes. Comparisons of two findings use stored factors.

## Security and tenancy

Org overrides are tenant-owned. Builtin policies are global. Engine cannot fetch URLs.

## Operational failure plan

Bad policy publish: operators roll forward with a new version, not by rewriting rows.

## Follow-up

Golden tests for factor catalogs. UI copy review for claims.
