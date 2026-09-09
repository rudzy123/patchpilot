# Operational runbooks

These runbooks are the v0.1 **operational failure plans** for security-sensitive pipelines.

The SBOM ingestion pipeline, the outbox relay, `sbom.ingest`, and scheduled CISA KEV import are implemented, so [SBOM ingestion failure](sbom-ingestion-failure.md), [outbox backlog](outbox-backlog.md), [background job failure](background-job-failure.md), and [vulnerability sync failure](vulnerability-sync-failure.md) describe live behavior. Authenticated provider-status GET routes exist; they are not anonymous. Correlation, scoring, a dashboard, manual sync/retry, and a detailed operator SyncRun API are not implemented.

OSV runtime remains disabled. Session 12 Batch 9 adds typed `INTELLIGENCE_OSV_ACQUISITION_HALT` (default halted) and bounded operational observability for the uncomposed disabled runtime. Session 12 Batch 9-R reviewed those halt and observability controls: missing configuration remains halted; halt false does not enable OSV; event sinks cannot change domain results. Those controls do not start a scheduler, job, or provider request. Accepted [ADR 0028](../adr/0028-osv-runtime-enablement-architecture-and-safety.md) contains operational **outlines** for a future OSV runtime. Accepted [ADR 0029](../adr/0029-first-real-provider-osv-canary-authorization-and-safety.md) adds first-canary procedures in [osv-canary.md](osv-canary.md). Session 13 Batch 2F implements an uncomposed executable preflight whose success (`canary_execution_preflight_passed_provider_contact_not_authorized`) is not permission to contact a provider. Session 13 Batch 2F-R independently reviewed that preflight. Session 13 Batch 2-R independently reviewed the combined operational-control chain. Production worker, API, scheduler, queue, health, seed, and migration composition do not register the command, preflight, controllers, listing-only execution bridge, provider-contact authorization service, or provider-contact authorization persistence adapters. Session 13 Batch 3A implements an uncomposed listing-only execution bridge (`createOsvCanaryListingOnlyExecutionBridge`) against a scripted provider port only. Session 13 Batch 3A-R independently reviewed that bridge. Session 13 Batch 3B implements uncomposed listing-only provider-contact authorization evaluation (`createOsvListingProviderContactAuthorizationService`); after other gates pass it fails closed with `persistence_required` and does not mint in-memory authority. Session 13 Batch 3B-P adds schema-only distinct listing-only provider-contact authorization persistence. Session 13 Batch 3B-A implements uncomposed issuance, inspection, consumption, and revocation adapters; production composition does not construct them; successful consumption does not authorize provider contact. Next is Session 13 Batch 3B-A-R. Real-provider capability does not exist. Do not contact `storage.googleapis.com` or `osv.dev` from these runbooks.

Three recoveries currently require direct database or bucket work by an instance operator, because no API covers them: requeueing a `failed` ingestion, releasing a `quarantined` one, and cleaning up orphan objects.

They do not include exploit payloads. They do not claim compliance.

| Runbook | When to use |
| --- | --- |
| [SBOM ingestion failure](sbom-ingestion-failure.md) | Upload, parse, quarantine, or orphan-object problems |
| [Vulnerability sync failure](vulnerability-sync-failure.md) | OSV or CISA KEV refresh stale, rate-limited, or inconsistent |
| [OSV first-provider canary procedures](osv-canary.md) | Session 13 Batch 3B-A-R reviewed uncomposed listing-only provider-contact authorization adapters (command, preflight, controllers, scripted bridge, authorization service, and persistence adapters remain production-unregistered; successful consumption does not authorize provider contact; Batch 3B-R then Batch 3C) |
| [Database migration failure](database-migration-failure.md) | Migrate deploy fails or `_prisma_migrations` is inconsistent |
| [Database constraint failure](database-constraint-failure.md) | Check, unique, FK, or append-only trigger rejection |
| [Outbox backlog](outbox-backlog.md) | Unpublished or stuck outbox events |
| [Background job failure](background-job-failure.md) | Queue lag, poison jobs, lease expiry, replay |
| [Tenant isolation incident](tenant-isolation-incident.md) | Suspected cross-organization read or write |
| [Audit integrity failure](audit-integrity-failure.md) | Missing, altered, or cascade-deleted audit or evidence |
| [Authentication failure](authentication-failure.md) | Login, session, CSRF, cookie, or login-limiter problems |
| [CI failure](ci-failure.md) | GitHub Actions or local quality gates fail |
| [Dependency alert](dependency-alert.md) | Dependabot or Dependency Review flags a package |
| [Secret exposure](secret-exposure.md) | Credential in git, logs, or artifacts |
| [Code scanning finding](code-scanning-finding.md) | CodeQL or Scorecard alert |

Related architecture: [reliability](../architecture/reliability-model.md), [tenant isolation](../architecture/tenant-isolation.md), [audit](../architecture/audit-model.md).
