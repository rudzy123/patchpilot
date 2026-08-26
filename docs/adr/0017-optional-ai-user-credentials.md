# ADR 0017: Optional AI with user-supplied credentials only

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

The product must remain fully useful without an AI provider. Authoritative scores from a model are a non-goal. Hardcoded API keys are forbidden.

## Decision

**v0.1 ships with AI disabled.** Optional AI, if added later, may draft explanations or tickets only. It **must never** set authoritative **priority**. Users supply their own API key or local compatible endpoint at runtime. Keys are never hardcoded, never in client bundles, never enabled by development defaults in production. Sending SBOM originals or Restricted evidence to a model requires a future ADR. The first usable release works with AI disabled.

## Alternatives considered

- **Bundled vendor key**: rejected.
- **AI-required MVP**: rejected by vision and non-goals.
- **Model-set scores with human display**: rejected.

## Consequences

No AI dependency in Compose. Future UI must label drafts as non-authoritative.

## Security and tenancy

AI data leakage is a listed threat. Tenant isolation still applies: no using org A's key on org B's data. Decrypt keys only in an adapter.

## Operational failure plan

AI endpoint down: core journey continues. Misconfiguration must not disable scoring.

## Follow-up

Do not implement AI in MVP. If product later requests it, add data-flow and redaction tests first.
