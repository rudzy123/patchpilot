# Architecture and security risk register

Prioritized risks for PatchPilot's v0.1 **architecture phase**. Likelihood and impact are qualitative (H/M/L). This is not a quantitative FAIR analysis and not a residual-risk acceptance for a certified program.

Status values: `open`, `mitigated-in-design`, `accepted`, `watch`.

Mitigated-in-design means documents specify controls; **runtime residual remains until code, tests, and operations exist**.

## Priority order

| ID | Risk | L | I | Priority | Status | Treatment |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | Cross-tenant IDOR or missing org predicate | M | H | P0 | mitigated-in-design | [tenant-isolation.md](../architecture/tenant-isolation.md); required tests |
| R2 | Malicious or huge SBOM exhausts API/worker | H | H | P0 | mitigated-in-design | Limits, quarantine, no URL fetch |
| R3 | Object storage public or guessable keys | M | H | P0 | mitigated-in-design | Private bucket; org-prefixed content-addressed keys |
| R4 | Job replay duplicates findings/audit or ignores org | M | H | P0 | mitigated-in-design | Outbox, idempotency, reload org |
| R5 | Development adapters enabled in production | M | H | P0 | mitigated-in-design | Config gating; tests |
| R6 | Prototype pollution / parser crash loops | M | H | P1 | mitigated-in-design | Depth limits, time-box, DLQ |
| R7 | Package/ecosystem confusion in correlation | M | H | P1 | mitigated-in-design | No fuzzy match; no ecosystem guess |
| R8 | Poisoned or stale intel silently trusted | M | M | P1 | mitigated-in-design | Provenance, freshness UI, additive records |
| R9 | XSS via component names | M | H | P1 | mitigated-in-design | Escape; no raw JSON; CSP when web exists |
| R10 | CSRF on session cookie | M | H | P1 | mitigated-in-design | SameSite + CSRF token (OD-1 still open for auth ADR) |
| R11 | Secret or SBOM logging | M | H | P1 | mitigated-in-design | Canonical redaction tests |
| R12 | Audit UPDATE/DELETE or cascade evidence loss | L | H | P1 | mitigated-in-design | Insert-only; FK policy |
| R13 | Incorrect priority / false "fixed" | M | H | P1 | mitigated-in-design | Factors, policy version, rescan ≠ task complete |
| R14 | SSRF via future URL fetch or mis-allowlist | L | H | P1 | mitigated-in-design | No SBOM fetch; allowlists |
| R15 | Authn mechanism underspecified (passwords, OIDC, lockout) | H | M | P1 | open | [OD-1](../architecture/open-decisions.md); needs ADR before implement |
| R16 | Credential KEK management weak or lost | M | H | P1 | open | [OD-4](../architecture/open-decisions.md) |
| R17 | Redis exposed to network → queue injection | M | H | P1 | mitigated-in-design | Network isolation; still operator duty |
| R18 | Backup exposure | M | H | P1 | accepted | Operator control; documented |
| R19 | Instance operator reads all DBs | H | H | P2 | accepted | Honest self-host model; no app bypass |
| R20 | Supply-chain / CI compromise | M | H | P2 | watch | Process; lockfile later |
| R21 | OSV rate limit blocks correlation | M | M | P2 | mitigated-in-design | Backoff, cache, degraded integration |
| R22 | Org policy override mistakes ranking | M | M | P2 | mitigated-in-design | Immutable versions; history kept |
| R23 | Duplicate SHA-256 handling across assets | L | M | P2 | mitigated-in-design | Duplicate only same org+asset |
| R24 | Finding identity ignores version (two versions, one finding) | M | M | P2 | accepted | Documented; change needs ADR |
| R25 | No inbound webhook yet but future forgery | L | H | P2 | watch | Dormant C10; GitHub not MVP |
| R26 | Optional AI leakage | L | H | P2 | mitigated-in-design | Disabled; ADR 0017 |
| R27 | Teams unused → later confused authz | L | L | P3 | watch | OD-11; owners are not authz |
| R28 | Go CLI later skips API authz | L | H | P3 | watch | CLI deferred; must call API |
| R29 | DoS of public feeds (external) | L | L | P3 | accepted | Out of product scope |
| R30 | Compliance theater in UI copy | M | M | P2 | mitigated-in-design | Review checklist; non-goals |

## P0 meaning

P0 items must have tests and review on the first implementing PR for that area. Architecture alone does not close them.

## Open architecture decisions that drive risk

See [open-decisions.md](../architecture/open-decisions.md). Highest coupling:

- **OD-1** Authentication (R10, R15)
- **OD-4** KEK (R16)
- **OD-10** Instance operator identity (R19)
- **OD-15** Matching (R7)

## Related documents

- [Threat model](threat-model.md)
- [Unresolved architecture decisions](../architecture/open-decisions.md)
