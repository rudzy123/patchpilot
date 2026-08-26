# Runbook: dependency alert

Use this when GitHub Dependabot, Dependency Review, or an advisory flags a PatchPilot dependency. This is about **this repository's** supply chain, not customer findings inside PatchPilot.

## Immediate actions

1. Read the advisory severity, affected package, and whether a patched version exists.
2. Do not paste full vulnerability write-ups that include exploit payloads into a public issue.
3. Do not auto-merge.

## Response

| Severity | Default action |
| --- | --- |
| Critical / high | Upgrade or replace before merge when a fix exists. If no fix exists, document residual risk and consider removing the package |
| Moderate / low | Schedule with the next dependency PR; still require CI |
| License-only | Do not invent a legal conclusion. Seek qualified review if Apache-2.0 compatibility is unclear |

Dependency Review fails the pull request at **high**. Maintainers may still reject moderate issues after reading the diff.

## After the upgrade

1. `pnpm install` (update the lockfile if needed).
2. Run unit tests and any integration tests the package can affect.
3. Confirm the lockfile change matches the intended packages only.

## Related

- [Dependency security](../security/dependency-security.md)
- [Dependency management](../development/dependency-management.md)
