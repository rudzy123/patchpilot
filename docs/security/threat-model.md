# Threat model

This threat model covers PatchPilot v0.1 as a **self-hosted modular monolith** processing untrusted SBOMs and shared vulnerability catalogs. It is a design aid, not a certification, penetration-test report, or proof of exploitability.

In scope: the ten security-sensitive areas in [AGENTS.md](../../AGENTS.md). Out of scope: vulnerabilities in the user's scanned applications that PatchPilot merely reports; DoS against public OSV/KEV as a service PatchPilot does not operate.

Report product vulnerabilities privately per [SECURITY.md](../../SECURITY.md). Do not publish exploit payloads here.

## Assets to protect

| Asset | Class | Why it matters |
| --- | --- | --- |
| Original SBOM bytes | Restricted | Source graph, internal package names |
| Findings and exports | Confidential | Operational risk data |
| External credentials and session secrets | Restricted | Account and integration takeover |
| Audit trail | Confidential | Integrity of "who decided" |
| Shared intel snapshots | Internal/Restricted raw | Poisoned feeds distort **priority** |
| Policy definitions | Internal/Confidential | Silent score change |
| Object-storage keys | Restricted | Evidence theft |

## Actors

| Actor | Intent |
| --- | --- |
| Anonymous internet user | Attack exposed HTTP if the operator publishes it |
| Authenticated user in org A | IDOR into org B; raise own privileges |
| Malicious insider in org A | Exfiltrate SBOMs; alter audit if possible; accept risk fraudulently |
| Instance operator | Infrastructure privilege; must not gain a silent app-level cross-org bypass |
| Malicious SBOM author | Parser DoS, SSRF, XSS stored in component names, graph explosion |
| Compromised OSV/KEV path | Wrong correlation, false KEV |
| Compromised CI or dependency | Backdoor in PatchPilot itself |
| Queue attacker (if Redis exposed) | Replay, inject jobs |

## Trust boundaries

See [trust boundaries](../architecture/trust-boundaries.md). Primary HTTP boundary is `apps/api`. Workers trust PostgreSQL more than Redis payloads.

## STRIDE-style findings (v0.1)

Each subsection states the threat, impact, and the **designed mitigation**. Residual risk is in the [risk register](risk-register.md).

### IDOR

**Threat:** Caller supplies another organization's asset, SBOM, finding, export, or credential UUID.

**Impact:** Cross-tenant read or mutate.

**Mitigation:** Deny by default; repository methods require `organizationId` from membership; lookup-by-id is insufficient; tests required ([tenant isolation](../architecture/tenant-isolation.md)).

### Broken tenant isolation

**Threat:** Missing `WHERE organization_id`; global unique hash shared across orgs; job payload org trusted; object key is digest-only.

**Impact:** Systematic data leak.

**Mitigation:** Org-prefixed object keys; org-scoped uniqueness; reload aggregates in workers; no cross-org operator API without ADR.

### Malicious SBOMs

**Threat:** Hostile JSON: unexpected types, huge strings, script-like names, `externalReferences` URLs, prototype keys.

**Impact:** XSS in UI, SSRF if fetched, parser crash, prototype pollution.

**Mitigation:** CycloneDX JSON only; no URL fetch; schema and depth limits; quarantine poison; treat names as untrusted text; no `eval`.

### Oversized JSON

**Threat:** Multi-gigabyte body or missing Content-Length stream.

**Impact:** Memory exhaustion (DoS).

**Mitigation:** 20 MiB default cap counted while streaming; reject before parse.

### Deeply nested JSON

**Threat:** Nesting that blows stack or schema walker.

**Impact:** Worker crash, restart loops.

**Mitigation:** Max depth 32; time-boxed parse; poison → quarantine not infinite retry.

### Dependency explosion

**Threat:** Tens of millions of edges or duplicated bom-refs.

**Impact:** DB fill, correlation hang.

**Mitigation:** Max 10,000 components and 50,000 edges; reject ingestion.

### Package-name confusion

**Threat:** Match `npm/foo` to `PyPI/foo`.

**Impact:** False findings or missed findings presented as fact.

**Mitigation:** Ecosystem required; no fuzzy name match ([OD-15](../architecture/open-decisions.md)).

### Ecosystem confusion

**Threat:** Guess ecosystem when SBOM omitted it.

**Impact:** Wrong OSV queries; false correlation.

**Mitigation:** Do not guess; skip correlation; may contribute to `inconclusive` on compare if identity cannot be formed.

### Version-range manipulation

**Threat:** Attacker-controlled SBOM versions to avoid or force OSV range hits; poisoned intel ranges.

**Impact:** False absence or false presence.

**Mitigation:** Record match method and source record id; version is observed from SBOM; intel ranges come from additive source records; UI separates facts from conclusions. Residual: garbage-in, garbage-out from the uploader's SBOM.

### Poisoned vulnerability feeds

**Threat:** Compromised OSV/KEV content or MITM.

**Impact:** Incorrect correlation and KEV enrichment; wrong **priority**.

**Mitigation:** HTTPS, allowlists, payload hashes, additive versions, retain conflicts, freshness display, no silent overwrite. Residual: public catalogs can be wrong.

### Compromised provider credentials

**Threat:** Stolen **ExternalCredential** or instance cloud keys.

**Impact:** Feed or storage abuse; if GitHub were connected, repo access (GitHub is not MVP).

**Mitigation:** Encrypt at rest; decrypt in adapter; no client bundles; rotate/revoke states; OSV/KEV v0.1 typically unauthenticated public HTTP. Storage credentials are operator secrets.

### Webhook forgery

**Threat:** Forged inbound webhook mutates tenant data.

**Impact:** Confused deputy.

**Mitigation:** **No inbound webhooks in v0.1.** Future: signatures required, unsigned denied.

### Webhook replay

**Threat:** Replay a valid signed body.

**Impact:** Duplicate processing or stale commands.

**Mitigation:** Not applicable until webhooks exist; future: delivery id + timestamp window.

### SSRF

**Threat:** Fetch SBOM URLs, license URLs, user-controlled intel endpoints, link-local metadata.

**Impact:** Cloud credential theft, internal scan.

**Mitigation:** No SBOM URL fetch; adapter allowlists; block link-local/metadata; timeouts and size limits; no user-controlled internal URLs.

### SQL injection

**Threat:** String-concatenated SQL on untrusted names.

**Impact:** Database compromise.

**Mitigation:** Prisma parameterized queries; no raw SQL with user strings; Zod at edges.

### XSS

**Threat:** Component name `"><script>` stored and rendered.

**Impact:** Session theft from org users.

**Mitigation:** Default framework escaping; never `dangerouslySetInnerHTML` for SBOM fields; CSP when web is scaffolded; don't dump raw JSON.

### CSRF

**Threat:** Cross-site POST using session cookie.

**Impact:** Upload, accept risk, export as the user.

**Mitigation:** `SameSite=Lax` + synchronizer token on mutations ([OD-1](../architecture/open-decisions.md)).

### Credential leakage

**Threat:** Secrets in images, docs, client JS, error messages.

**Impact:** Takeover.

**Mitigation:** Config package only; no hardcoded secrets; error taxonomy without stack internals in production.

### Secret logging

**Threat:** Authorization header or SBOM body in Pino/OTel.

**Impact:** Restricted data in log stores.

**Mitigation:** Canonical redaction; tests; no full feed payloads.

### Audit alteration

**Threat:** UPDATE/DELETE audit rows or cascade.

**Impact:** Lost accountability.

**Mitigation:** Insert-only; DB privileges; no cascade; tests.

### Object-storage exposure

**Threat:** Public bucket, guessable keys, list-all.

**Impact:** SBOM theft.

**Mitigation:** Private bucket; `org/{organizationId}/.../sha256/{hash}`; no public URLs; presign later needs ADR.

### Queue duplication

**Threat:** At-least-once double deliver.

**Impact:** Duplicate findings or audits.

**Mitigation:** Idempotent handlers, unique constraints including organization, replay tests.

### Race conditions

**Threat:** Concurrent ingest and intel refresh; concurrent acceptances.

**Impact:** Lost updates, duplicate findings.

**Mitigation:** Unique finding identity; append-only calculations; acceptance supersede rules; optional finding row version.

### Stale jobs

**Threat:** Worker crash leaves `running`; old job applies after archive.

**Impact:** Corruption or surprise mutation.

**Mitigation:** Visibility timeout; idempotency; reload state; dead-letter missing aggregates.

### Dependency compromise

**Threat:** Malicious npm package in PatchPilot's own tree.

**Impact:** Full instance compromise.

**Mitigation:** Lockfile, future dependency review in CI, minimize deps, no install during this architecture phase. Residual: supply chain.

### CI/CD compromise

**Threat:** Stolen GitHub credentials publish a backdoored image.

**Impact:** Operator runs attacker code.

**Mitigation:** Branch protection when available; no secrets in logs; [SECURITY.md](../../SECURITY.md). Residual: operator verifies images.

### Development adapters enabled in production

**Threat:** Fake auth or unrestricted HTTP selected.

**Impact:** Auth bypass, SSRF.

**Mitigation:** Config gating; tests that production config cannot construct those adapters.

### Backup exposure

**Threat:** Unencrypted dumps, world-readable snapshots.

**Impact:** All tenants on that instance.

**Mitigation:** Operator guidance; Restricted classification; no product-level public backup API.

### Insider threats

**Threat:** Org `owner` exports all SBOMs; instance operator reads Postgres.

**Impact:** Expected privilege, still harmful.

**Mitigation:** Role split; audit exports; no extra bypass; cannot prevent a motivated instance operator with disk access. Document honestly.

### Denial of service

**Threat:** Upload floods, expensive parse, intel refresh storms.

**Impact:** Availability.

**Mitigation:** Rate limits, size/depth/count limits, worker concurrency caps, circuit breaker on feeds.

### Incorrect risk prioritization

**Threat:** Policy bug, poisoned intel, missing factors.

**Impact:** Operators fix the wrong thing; false sense of safety.

**Mitigation:** Versioned policy, full factors, no AI scores, recalc without erasure, distinguish severity vs priority, honest UI copy.

### False remediation

**Threat:** Task `completed` shown as fixed; missing component treated as resolved when compare was `inconclusive`; older SBOM finishing last treated as current; versioned PURL used as finding identity.

**Impact:** Premature closure or duplicate findings that never resolve.

**Mitigation:** Finding `resolved` only with stored evidence (adequate `absent` or out-of-range) on the **current** ingestion (max `receivedAt` among `completed`); UI separates workflow from rescan; incomplete coverage → `inconclusive`; workflow states `risk_accepted`/`mitigated`/`false_positive` are not overwritten by inconclusive compare; identity is versionless + OSV id.

### AI data leakage (if optional AI is introduced later)

**Threat:** SBOM or findings sent to a third-party model; hardcoded keys; model sets scores.

**Impact:** Evidence exfil; unauthorized scoring.

**Mitigation:** AI disabled by default; user-supplied keys only; never authoritative scores; never send originals without explicit future ADR ([ADR 0017](../adr/0017-optional-ai-user-credentials.md)). v0.1 sends nothing to AI providers.

### Privilege escalation

**Threat:** `member` approves risk acceptance or rotates credentials.

**Impact:** Unauthorized residual-risk decisions or credential theft.

**Mitigation:** Role matrix in [tenant-isolation.md](../architecture/tenant-isolation.md); API tests.

### Duplicate or malicious bom-ref

**Threat:** Repeated or colliding `bom-ref` values to confuse the graph.

**Impact:** Wrong dependency edges; parser crash.

**Mitigation:** Duplicate `bom-ref` → `rejected`.

### Concurrent ingestion

**Threat:** Two SBOMs for one asset processed at once.

**Impact:** Races on finding current state.

**Mitigation:** Unique constraints; latest **completed** ingestion wins for compare; append-only calculations.

### Job lease theft / clock skew

**Threat:** Two workers run the same job after lease expiry.

**Impact:** Duplicate side effects if not idempotent.

**Mitigation:** Idempotent handlers; org-scoped unique keys.

### Missing provider data

**Threat:** OSV/KEV gap presented as "not vulnerable."

**Impact:** False safety.

**Mitigation:** Freshness display; no match ≠ proof of safety; KEV absence is not proof of non-exploitation.

### Open instance registration

**Threat:** Unauthenticated callers create organizations and upload SBOMs on an internet-exposed instance.

**Impact:** Shared-catalog query abuse, disk fill, unintended multi-tenant hosting.

**Mitigation:** First user on an empty instance only; later users invited ([OD-1](../architecture/open-decisions.md)). Residual until the authn ADR adds lockout.

### Incorrect vulnerability matching

**Threat:** Wrong ecosystem or range evaluation.

**Impact:** False findings or misses.

**Mitigation:** Adapter-based versions; no fuzzy match; record method; tests with fixtures.

### Incomplete SBOM coverage

**Threat:** Smaller new SBOM treated as full remediation.

**Impact:** False `resolved`.

**Mitigation:** Coverage heuristic → `inconclusive`; see [finding-lifecycle.md](../architecture/finding-lifecycle.md).

## Control table (material threats)

For each row: preventive / detective / recovery / test / residual / owner. Text above remains the narrative if the table is not rendered.

| Threat | Asset | Attack path | Impact | Preventive | Detective | Recovery | Test | Residual | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| IDOR | Findings, SBOMs | UUID in URL without membership | Cross-tenant read | Org predicate, deny default | Authz deny metrics | Isolation incident runbook | Cross-tenant tests | Until code exists | `packages/domain`, API |
| Broken tenancy | All tenant data | Missing WHERE; digest-only keys | Systematic leak | Prefixed keys; job reload | Anomalous org access | Isolate, rotate | Isolation + job tamper | Operator disk | Tenancy |
| Privilege escalation | Acceptance, creds | Role not checked | Bad accept / leak | Role matrix | Audit | Revoke session | API authz tests | Insider owner | Authz |
| Malicious SBOM | Parser, UI | Hostile JSON | XSS, crash, SSRF | No fetch, limits, escape | Quarantine metrics | Quarantine runbook | Parser tests | GIGO | `packages/sbom` |
| Oversized JSON | API memory | Huge body | DoS | 20 MiB proposal cap | 413 metrics | Rate limit | Size tests | Volumetric DoS | API |
| Deep JSON | Worker | Nesting | Crash loop | Depth 32 proposal | Quarantine | DLQ | Depth tests | Novel parser bugs | Parser |
| Component explosion | DB | Huge component list | Fill disk | 10k proposal | Reject metrics | Reject | Generated fixture | Tuned limits | Ingest |
| Edge explosion | DB | Huge deps | Hang | 50k proposal | Reject | Reject | Generated fixture | Tuned limits | Ingest |
| Bad bom-ref | Graph | Duplicates | Wrong graph | Reject duplicates | Reject | User re-upload | Fixture | — | Parser |
| Name/ecosystem confusion | Findings | Cross-eco match | False finding | No fuzzy match | Match method | Recalc | Near-miss fixtures | Uploader GIGO | Intel |
| Range manipulation | Findings | Crafted versions | False abs/pres | Record method; adapters | Factors | Recalc | Version fixtures | GIGO | Intel |
| Poisoned feeds | Catalog | MITM/compromise | Wrong priority | HTTPS, hashes, additive | Stale/degraded | Keep last good | Fixture conflicts | Public catalogs lie | Intel |
| Stolen provider/storage creds | Storage, feeds | Leak | Theft | Encrypt, config | Audit creds | Rotate | Redaction tests | Operator keys | Integrations |
| Webhook forgery/replay | Future | Fake callback | Confused deputy | No listeners in v0.1 | — | — | When added | Future | API |
| SSRF | Cloud metadata | URL fetch | Cred theft | No SBOM URLs; allowlist | Egress logs | Block | Adapter tests | Mis-allowlist | Integrations |
| SQLi | DB | Concat SQL | Takeover | Prisma | — | Restore | — | Raw SQL mistakes | Database |
| XSS | Sessions | Component names | Session theft | Escape, CSP later | — | Rotate | UI tests | New sinks | Web |
| CSRF | Mutations | Cross-site POST | Unwanted upload | SameSite + token | — | Revoke | API tests | OD-1 | API |
| Cred/secret logging | Logs | Header in Pino | Restricted leak | Redaction | Log review | Rotate | Redaction tests | Sink bypass | Logger |
| Audit alteration | Accountability | UPDATE audit | Lost history | Insert-only | Integrity runbook | Restore | Update-fail test | Superuser | Audit |
| Public bucket | SBOMs | ACL | Theft | Private + org keys | Cloud alerts | Make private | Adapter tests | Operator ACL | Storage |
| Queue duplication | Findings | At-least-once | Dup rows | Idempotency | Unique violations | No-op | Replay tests | — | Worker |
| Concurrent ingest | Finding state | Two SBOMs | Race | Constraints; completed wins | — | Recalc | Concurrency test | Rare races | Worker |
| Stale jobs / lease | Tenant data | Crash + double run | Dup/corrupt | Lease + idempotency | Stale metric | Replay | Lease tests | Clock skew | Worker |
| Dependency/CI compromise | Instance | Malicious npm/CI | RCE | Lockfile later | — | Rebuild | — | Supply chain | Process |
| Dev adapters in prod | Authn | Misconfig | Bypass | Config gate | Boot fail | Disable | Production-config test | Human error | Config |
| Backup exposure | All | Open dump | Mass leak | Operator encrypt | — | Rotate | — | Accepted operator | Deploy |
| Insider | Tenant data | Privileged user | Expected | Audit, roles | Audit | — | — | Cannot prevent | Product |
| DoS | Availability | Flood/parse | Outage | Limits, rates | Lag alerts | Shed load | Limit tests | Volumetric | API/worker |
| Missing intel | Priority | Gap | False safety | Freshness UI | Stale alert | Retry sync | Fixture | Feeds incomplete | Intel |
| Wrong matching | Findings | Adapter bug | False pos/neg | Adapters, tests | — | Recalc | Fixtures | Residual | Intel |
| Wrong priority | Queue | Policy bug | Wrong work | Versioned policy | Factor UI | New version | Golden tests | Weights arbitrary | Policy |
| False remediation | Finding state | Task complete; stale completion order | Premature close | Evidence rules; current=`receivedAt` | — | Reopen on present | State + race tests | Incomplete SBOMs | Findings |
| Incomplete coverage | Finding state | Sparse SBOM | False resolved | Coverage heuristic | Inconclusive | Re-upload | Coverage test | Heuristic | Findings |
| Open registration | Instance | Unauthenticated org create | Abuse | First-user only | Auth metrics | Disable signup | Authn tests | OD-1 lockout | Authn |
| AI leakage (later) | Restricted | Model API | Exfil | Disabled; ADR 0017 | — | Disable | — | If enabled later | Future |

## Related documents

- [Security controls](security-controls.md)
- [Risk register](risk-register.md)
- [SBOM ingestion](../architecture/sbom-ingestion.md)
