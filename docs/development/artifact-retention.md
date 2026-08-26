# Artifact retention

GitHub Actions artifacts are visible to users who can read Actions logs for the repository. Treat them as **Internal** unless they contain Restricted material, in which case they must not be uploaded.

## Policy

| Artifact | Purpose | Contents | Sensitivity | Retention | When uploaded | Redaction |
| --- | --- | --- | --- | --- | --- | --- |
| Unit coverage | Not uploaded in this session | n/a | Coverage can include paths and fixture names | n/a | Never, until a coverage report is designed | Do not upload secrets or `.env` |
| Integration reports | Not uploaded in this session | Vitest writes to stdout | Low if logs stay redacted | n/a | Never | No connection strings |
| Playwright traces | Future browser failures | Traces, screenshots, video | Can capture UI text; must not capture cookies, tokens, signed URLs, or SBOM bodies | 7 days | Failure only, when Playwright exists | Strip credentials before upload |
| CodeQL SARIF | Code scanning | Query results | Internal source paths | GitHub code-scanning retention | Always on CodeQL runs | No secrets in source |
| Scorecard SARIF | Supply-chain posture | Check results | Internal | 5 days (Actions artifact); also code scanning | `main` and schedule | Not a certification |
| Repository SBOM | PatchPilot dependency inventory | CycloneDX JSON | Internal package names and versions | 7 days | `main`, schedule, manual | Inspect for tokens; never include `.env` |
| Container metadata | Deferred | n/a | n/a | n/a | Not until images exist | Do not log registry credentials |

Artifact names include `github.run_id` and `github.run_attempt` so reruns do not collide.

## Never upload

- `.env` files
- Database volumes, MinIO data, Redis dumps
- Full application logs that may contain request bodies
- GitHub tokens, cookies, authorization headers, signed URLs
- Customer or sample product SBOMs beyond what already lives in git as fixtures
- Private source beyond the repository collaborators already have through git

Fork pull requests should not receive extra artifact access via `pull_request_target`. SBOM artifacts are produced on `main` and manual dispatch, not on untrusted pull requests, to reduce artifact poisoning.
