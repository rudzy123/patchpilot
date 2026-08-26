# Runbook: secret exposure

Use this when a secret, token, private key, or live credential may have entered git, CI logs, or an artifact.

## Immediate actions

1. **Rotate** the credential at its source (GitHub token, database password, object-storage key, and so on). Assume it is compromised once it has been pushed or logged.
2. Do not paste the secret into Slack, a public issue, or a pull-request comment.
3. If the value is in a GitHub secret-scanning alert, follow the GitHub UI to mark it rotated after rotation.

## Containment

- Remove the value from the working tree. `.env` is gitignored; never force-add it.
- If the secret is in git history, rotation still comes first. History rewrite of `main` is not a substitute for rotation and is not done without an explicit maintainer decision.
- Invalidate any artifact that may contain the value (Actions artifacts, logs).

## Follow-up

- Add a regression guard where practical (example values in tests, redaction tests) **without** committing the real secret.
- Report product vulnerabilities privately per [SECURITY.md](../../SECURITY.md).
- Review whether CI logged the value (integration job env should not be echoed).

## Related

- [Secret scanning](../security/secret-scanning.md)
- [CI security](../security/ci-security.md)
