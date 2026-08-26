# Operational runbooks

These runbooks are the v0.1 **operational failure plans** for security-sensitive pipelines. The development foundation includes application shells and local Compose; product pipelines (SBOM ingest, intel sync, jobs) are not implemented yet. Treat product runbooks as the intended response once those features exist.

They do not include exploit payloads. They do not claim compliance.

| Runbook | When to use |
| --- | --- |
| [SBOM ingestion failure](sbom-ingestion-failure.md) | Upload, parse, quarantine, or orphan-object problems |
| [Vulnerability sync failure](vulnerability-sync-failure.md) | OSV or CISA KEV refresh stale, rate-limited, or inconsistent |
| [Background job failure](background-job-failure.md) | Queue lag, poison jobs, lease expiry, replay |
| [Tenant isolation incident](tenant-isolation-incident.md) | Suspected cross-organization read or write |
| [Audit integrity failure](audit-integrity-failure.md) | Missing, altered, or cascade-deleted audit or evidence |
| [Local infrastructure failure](local-infrastructure-failure.md) | PostgreSQL, Redis, or MinIO Compose will not start or stay healthy |

Related architecture: [reliability](../architecture/reliability-model.md), [tenant isolation](../architecture/tenant-isolation.md), [audit](../architecture/audit-model.md).
