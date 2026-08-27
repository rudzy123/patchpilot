# Operational runbooks

These runbooks are the v0.1 **operational failure plans** for security-sensitive pipelines. Session 5 persists the database schema; product pipelines (SBOM ingest, intel sync, job relay) are not implemented yet. Treat product runbooks as the intended response once those features exist.

They do not include exploit payloads. They do not claim compliance.

| Runbook | When to use |
| --- | --- |
| [SBOM ingestion failure](sbom-ingestion-failure.md) | Upload, parse, quarantine, or orphan-object problems |
| [Vulnerability sync failure](vulnerability-sync-failure.md) | OSV or CISA KEV refresh stale, rate-limited, or inconsistent |
| [Database migration failure](database-migration-failure.md) | Migrate deploy fails or `_prisma_migrations` is inconsistent |
| [Database constraint failure](database-constraint-failure.md) | Check, unique, FK, or append-only trigger rejection |
| [Outbox backlog](outbox-backlog.md) | Unpublished or stuck outbox events |
| [Background job failure](background-job-failure.md) | Queue lag, poison jobs, lease expiry, replay |
| [Tenant isolation incident](tenant-isolation-incident.md) | Suspected cross-organization read or write |
| [Audit integrity failure](audit-integrity-failure.md) | Missing, altered, or cascade-deleted audit or evidence |
| [Local infrastructure failure](local-infrastructure-failure.md) | PostgreSQL, Redis, or MinIO Compose will not start or stay healthy |
| [CI failure](ci-failure.md) | GitHub Actions or local quality gates fail |
| [Dependency alert](dependency-alert.md) | Dependabot or Dependency Review flags a package |
| [Secret exposure](secret-exposure.md) | Credential in git, logs, or artifacts |
| [Code scanning finding](code-scanning-finding.md) | CodeQL or Scorecard alert |

Related architecture: [reliability](../architecture/reliability-model.md), [tenant isolation](../architecture/tenant-isolation.md), [audit](../architecture/audit-model.md).
