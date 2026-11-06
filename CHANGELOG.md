# Changelog

## 0.1.0 — prepared, not tagged

Prepared on 2026-11-06. No git tag and no GitHub Release exist for this version.

- Owners and admins can export the remediation queue as JSON or CSV from `POST /remediation-queue/export` and from `/remediation-queue`.
- The export cap is 150 Findings. A larger population returns HTTP 409 and writes no audit row.
- One `export.created` audit row records counts, the policy reference, `asOf`, the cap, the byte length, and the response SHA-256. The file bytes are not stored.
- One Playwright release smoke runs inside the existing Integration job.
- The export does not calculate priority and does not add a migration. The frozen migration count stays 28.
