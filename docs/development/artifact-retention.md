# Artifact retention

GitHub Actions artifacts are visible to users who can read Actions logs for the repository. Treat them as **Internal** unless they contain Restricted material, in which case they must not be uploaded.

## Policy

| Artifact | Purpose | Contents | Sensitivity | Retention | When uploaded | Redaction |
| --- | --- | --- | --- | --- | --- | --- |
| Unit coverage | Not uploaded in this session | n/a | Coverage can include paths and fixture names | n/a | Never, until a coverage report is designed | Do not upload secrets or `.env` |
| Integration reports | Not uploaded in this session | Vitest writes to stdout | Low if logs stay redacted | n/a | Never | No connection strings |
| Playwright traces | Release smoke | Traces, screenshots, video | Can capture UI text; must not capture cookies, tokens, signed URLs, or SBOM bodies | Not uploaded | The one smoke runs inside Integration with trace, screenshot, and video off ([CI-DEFER-1](ci.md#ci-defer-1--separate-github-hosted-playwright-workflow)) | Do not upload. A separate E2E workflow is still forbidden |
| CodeQL SARIF | Code scanning | Query results | Internal source paths | GitHub code-scanning retention | Always on CodeQL runs | No secrets in source |
| Scorecard SARIF | Supply-chain posture | Check results; no secrets or SBOM bodies | Internal | 5 days (Actions artifact); also code scanning | `main`, schedule, `branch_protection_rule` | Not certification. External OpenSSF publication is disabled |
| Repository SBOM | PatchPilot's own dependency inventory | CycloneDX JSON | Internal package names and versions | 7 days | `main`, schedule, manual | Inspect for tokens; never include `.env` or customer SBOMs |
| Container images | Built by [Container build](ci.md#container-validation) to validate `deploy/docker/Dockerfile` | Local runner images for targets `api`, `worker`, `web`, and `migrate`. No registry push | Build logs can include the public `NEXT_PUBLIC_` values. They must not include registry credentials or `.env` files | n/a | Not uploaded | Do not log registry credentials. Do not upload image tarballs or provenance |

Artifact names include `github.run_id` and `github.run_attempt` so reruns do not collide.

## Never upload

- `.env` files
- Database volumes, MinIO data, Redis dumps
- Full application logs that may contain request bodies
- GitHub tokens, cookies, authorization headers, signed URLs
- Customer or sample product SBOMs beyond what already lives in git as fixtures
- Private source beyond the repository collaborators already have through git

Fork pull requests should not receive extra artifact access via `pull_request_target`. SBOM artifacts are produced on `main` and manual dispatch, not on untrusted pull requests, to reduce artifact poisoning.
