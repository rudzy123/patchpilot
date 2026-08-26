# Architecture decision records

ADRs record lasting technical choices for PatchPilot: context, decision, consequences, and security impact.

## When to write an ADR

Write an ADR before merging a change that:

- Splits or joins deployable units (for example, leaving the modular monolith).
- Chooses or changes persistence, queue, object-storage, or auth topology.
- Defines tenancy, RBAC, or credential-encryption approach.
- Versions or changes risk-scoring policy structure.
- Adopts a vulnerability-intelligence source or matching algorithm that operators will depend on.
- Introduces an external provider, webhook, or outbound fetch class (SSRF surface).
- Changes audit, retention, or evidence-deletion policy.

If you are unsure, write a short Proposed ADR. Lightweight implementation details do not need an ADR.

## Process

1. Copy [template.md](template.md) to `docs/adr/NNNN-short-title.md` using the next unused four-digit number.
2. Set status to **Proposed** and open a pull request (or include the ADR in the implementing PR).
3. Reviewers check alignment with [AGENTS.md](../../AGENTS.md) and [`.cursor/rules/`](../../.cursor/rules/).
4. A maintainer merges with status **Accepted** (or **Rejected** with rationale).
5. A later ADR may set this one to **Superseded** and link both ways.

Closer implementation notes may add detail. They must not silently weaken accepted security or tenancy decisions.

## Status

| Status | Meaning |
| --- | --- |
| Proposed | Under review |
| Accepted | In force |
| Rejected | Considered and not taken |
| Superseded | Replaced by a newer ADR |

## Index

List accepted ADRs here as they land. None exist yet. Decisions that still need an ADR before implementation include authn/authz, tenancy/RBAC, intelligence sources and matching, scoring policy structure, object-storage port, outbox/queue topology, and credential encryption.
