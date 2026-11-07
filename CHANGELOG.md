# Changelog

## 0.1.0

Published at 2026-11-07T18:51:28Z from annotated tag `v0.1.0`, targeting `73a9e9026de240d6e2702f2ac4dfe583978fafcb`. The GitHub Release is https://github.com/rudzy123/patchpilot/releases/tag/v0.1.0 and is the latest release. No deployment was performed. No release assets were attached manually. GitHub supplies the source archives.

- Owners and admins can export the remediation queue as JSON or CSV from `POST /remediation-queue/export` and from `/remediation-queue`.
- The export cap is 150 Findings. A larger population returns HTTP 409 and writes no audit row.
- One `export.created` audit row records counts, the policy reference, `asOf`, the cap, the byte length, and the response SHA-256. The file bytes are not stored.
- One Playwright release smoke runs inside the existing Integration job.
- The export does not calculate priority and does not add a migration. The frozen migration count stays 28.
