# Security controls

This catalog maps v0.1 controls to architecture. It does not claim ISO 27001, SOC 2, or other compliance mappings.

Canonical rules: [security.mdc](../../.cursor/rules/security.mdc). Threats: [threat-model.md](threat-model.md).

## Control families

### C1 Deny-by-default authorization

- Membership-derived **authorized organization**.
- Roles in [tenant isolation](../architecture/tenant-isolation.md).
- No client-supplied org id as authority.
- No cross-organization operator bypass.

### C2 Input validation

- Zod (or equivalent) at HTTP and adapter boundaries.
- CycloneDX allowlist before full parse.
- Size, depth, string, component, and edge limits.

### C3 Untrusted SBOM handling

- JSON only; no archives; no execution; no URL fetch.
- Original bytes hashed SHA-256 and stored privately.
- Parse a copy; derived graph does not replace evidence.

### C4 Tenant-scoped persistence

- `organizationId` on tenant rows; required repository arguments.
- Org-prefixed object keys.
- Org-scoped idempotency.

### C5 Intelligence provenance

- Source, `retrievedAt`, source identity, payload hash.
- Additive/versioned writes; retain conflicts.
- Match method stored on correlation/observation.

### C6 Explainable scoring

- Versioned **RiskPolicy**.
- Full contributing factors on each **RiskCalculation**.
- No AI authoritative scores.
- Severity snapshot distinct from **priority**.

### C7 Audit integrity

- Append-only **AuditEvent**.
- Same transaction as PostgreSQL state change.
- No cascade-delete of evidence.

### C8 Secrets and config

- `process.env` only in `packages/config`.
- Encrypted **ExternalCredential** at rest; decrypt in adapter.
- Development adapters unselectable in production.

### C9 SSRF and egress

- Allowlisted OSV/KEV hosts.
- Blocked link-local and metadata ranges.
- Timeouts and response size limits.

### C10 Webhook readiness (dormant)

- No listeners in v0.1.
- Future: signatures, replay window, unsigned denied, 1:1 installation mapping.

### C11 Session and CSRF ([ADR 0019](../adr/0019-local-password-sessions.md))

- Opaque server-side PostgreSQL sessions; SHA-256 domain-separated token digests.
- Production `__Host-` `HttpOnly` / `Secure` / `SameSite=Lax` cookies.
- Synchronizer CSRF token plus exact Origin validation on mutations.
- Fail-closed Redis login rate limits; `trustProxy` remains false.
- In-memory HTTP rate limiting on `/auth` via `@fastify/rate-limit` (direct socket peer IP; no Redis).

### C12 Injection and XSS

- Parameterized ORM.
- Escaped UI; untrusted component strings.
- Stable error taxonomy (no stack or other-org existence leak).

### C13 Jobs

- Transactional outbox. API writes outbox rows; the **worker relay** publishes to Redis/BullMQ.
- At-least-once with idempotent handlers.
- Reload org from persistence; poison quarantine; DLQ.

### C14 Observability redaction

- Correlation ids without secrets.
- Canonical redaction list.
- Health endpoints without dumps.

### C15 Supply chain (process)

- Lockfiles when apps exist.
- Private vulnerability reporting.
- No exploit payloads in tests or PRs.

### C16 Rate limiting

- Stricter limits on auth, upload, export.
- Auth HTTP: in-memory `@fastify/rate-limit` on `/auth` routes, keyed by direct socket peer IP. Does not trust `X-Forwarded-For`. Authenticated reads and logout do not require Redis.
- Login: Redis-backed, fail-closed, direct peer IP plus account digest ([ADR 0019](../adr/0019-local-password-sessions.md)). The HTTP limiter is additional coarse protection and does not replace Redis.
- Outbound feed rate limits.

## Error taxonomy (API)

`validation`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `rate_limited`, `unprocessable_evidence`, `internal`.

`not_found` vs `forbidden` must not enable org enumeration beyond what membership already allows.

## Mapping to threat themes

| Threat theme | Primary controls |
| --- | --- |
| IDOR / tenancy | C1, C4, tests |
| Malicious / huge / deep SBOM | C2, C3, C13, C16 |
| Feeds and SSRF | C5, C9, C8 |
| XSS / CSRF / SQLi | C11, C12 |
| Secrets / logs | C8, C14 |
| Audit / evidence | C7, C3 |
| Jobs / races | C13 |
| Scoring honesty | C6 |
| Dev adapters | C8 |
| AI later | ADR 0017, C6, C8 |

## Mapping to required tests

Control catalog → numbered tests in [testing-strategy.md](../architecture/testing-strategy.md). Cross-tenant procedure detail is in [tenant-isolation.md](../architecture/tenant-isolation.md). Threat-model rows also list a **Test** column.

| Control | Required tests (minimum) |
| --- | --- |
| C1 Deny-by-default authorization | 1, 2, 4, 15 |
| C2 Input validation | 5, 12, 13 |
| C3 Untrusted SBOM handling | 5, 12, 14, 20 |
| C4 Tenant-scoped persistence | 1, 2, 4, 15, 17, 21 |
| C5 Intelligence provenance | 6, 11, 21 |
| C6 Explainable scoring | 7, 16, 19 |
| C7 Audit integrity | 8 |
| C8 Secrets and config | 9, 10 |
| C9 SSRF and egress | 14 (no URL fetch / no I/O in transactions); adapter allowlist tests when HTTP adapters exist |
| C10 Webhook readiness (dormant) | None in v0.1 (no listeners). When added: signature + replay tests |
| C11 Session and CSRF | API authorization suite in testing-strategy (CSRF/session/role matrix) |
| C12 Injection and XSS | 5 (parser); UI XSS when web exists (Playwright + escape tests) |
| C13 Jobs | 3, 4, 14, 18, 20 |
| C14 Observability redaction | 9 |
| C15 Supply chain (process) | No exploit payloads; lockfile when apps exist |
| C16 Rate limiting | 5 (upload size/reject); outbound 429 classified as retryable in worker tests | |

## Related documents

- [Secure development plan](secure-development-plan.md)
- [Privacy model](privacy-model.md)
