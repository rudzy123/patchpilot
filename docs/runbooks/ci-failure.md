# Runbook: CI failure

Use this when a GitHub Actions workflow or a local quality gate fails. Do not paste tokens, `.env` files, or raw SBOM contents into tickets.

## Immediate actions

1. Identify the exact check name (`CI / Quality`, `Integration / Integration`, and so on).
2. Open the failed step log. Confirm whether the failure is install, format, lint, type, unit, Prisma, build, services, or a security job.
3. Reproduce locally with the same command when possible (`pnpm format:check`, `pnpm lint`, `pnpm test:unit`, `pnpm test:integration`, `pnpm workflows:lint`).
4. Do not add `continue-on-error`, `|| true`, or skipped tests to hide the failure.

## Classify

| Class | Typical cause | Next step |
| --- | --- | --- |
| Frozen lockfile | `pnpm-lock.yaml` out of date | Re-install locally and commit the lockfile |
| Format/lint/types | Local tree not formatted or a real defect | Fix the smallest durable change |
| Unit | Deterministic test failure | Fix product or test; do not sleep |
| Integration | Service unhealthy or URL/port mismatch | Confirm health; keep ports `55432` / `16379` / `19000` |
| Prisma | Schema invalid or migrate deploy failed | `pnpm db:validate`; inspect migration SQL without logging `DATABASE_URL` |
| Workflows | actionlint error | Fix YAML; do not pin `main` action refs |
| CodeQL / dependency review / Scorecard | New finding or advisory | Follow the security runbooks |
| Fork permission | Missing secret on `pull_request` | Expected: PR CI must not need repository secrets |

## Integration services

GitHub fails the job if service-container health checks do not pass. Locally, `pnpm infrastructure:up` uses Compose `--wait`. After `pnpm infrastructure:down`, `pnpm infrastructure:status` prints an empty table and exits 0.

## Related

- [CI](../development/ci.md)
- [Local infrastructure failure](local-infrastructure-failure.md)
- [Troubleshooting](../development/troubleshooting.md)
