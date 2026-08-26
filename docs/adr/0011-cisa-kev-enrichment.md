# ADR 0011: CISA KEV enrichment

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

The MVP journey enriches applicable findings with CISA Known Exploited Vulnerabilities data. Product language forbids treating KEV as proof of exploitation in the user's environment.

## Decision

Import CISA **KEV** as a **snapshot** (worker outbound HTTPS) and **enrich** findings that have a matching CVE. Store why it matched (catalog identity, retrieved-at, hash). KEV is not a correlation range matcher and not **priority** by itself. Removal from a later snapshot is additive history; new **RiskCalculation** reflects current listing. Do not silently overwrite snapshots.

## Alternatives considered

- **KEV as the only intel**: insufficient package matching.
- **Live fetch per finding on user request**: latency, rate limits, and request-path egress.

## Consequences

Enrichment depends on snapshot freshness (default threshold 24 hours). UI must label KEV as catalog enrichment.

## Security and tenancy

Shared catalog. Tenant findings reference CVE/catalog records without copying other orgs' findings.

## Operational failure plan

Fetch failure: keep last snapshot; mark stale; do not drop findings.

## Follow-up

Tests: listed, unlisted, and snapshot change recalculation.
