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

**Threat:** Task `completed` shown as fixed; missing component treated as resolved when compare was `inconclusive`.

**Impact:** Premature closure.

**Mitigation:** Finding `resolved` only from `absent` observation; UI separates workflow from rescan.

### AI data leakage (if optional AI is introduced later)

**Threat:** SBOM or findings sent to a third-party model; hardcoded keys; model sets scores.

**Impact:** Evidence exfil; unauthorized scoring.

**Mitigation:** AI disabled by default; user-supplied keys only; never authoritative scores; never send originals without explicit future ADR ([ADR 0017](../adr/0017-optional-ai-user-credentials.md)). v0.1 sends nothing to AI providers.

## Related documents

- [Security controls](security-controls.md)
- [Risk register](risk-register.md)
- [SBOM ingestion](../architecture/sbom-ingestion.md)
