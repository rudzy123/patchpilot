# Runbook: code scanning finding

Use this for GitHub code scanning alerts from CodeQL or OpenSSF Scorecard SARIF.

## Immediate actions

1. Open **Security → Code scanning** and read the alert, file, and query help.
2. Decide whether it is a true issue, an accepted risk, or a false positive.
3. Do **not** auto-dismiss alerts from a bot without a written reason.

## True issue

1. Fix in a pull request. Add a regression test when the defect is security-sensitive, without an exploit payload.
2. Keep the alert open until the fix is on `main` and code scanning has re-run.

## False positive

1. Record why the query does not apply (generated file, test fixture, unreachable in production config).
2. Prefer narrowing CodeQL `paths-ignore` only for generated or dependency trees already listed in `.github/codeql/codeql-config.yml`.
3. Do not disable a query globally to silence one alert.
4. A maintainer may dismiss in GitHub with a reason after that record exists.

## Scorecard

Scorecard findings are repository-posture checks (branch protection, token permissions, pinning). They are not proof of application security. Improving the GitHub settings in [repository-settings.md](../development/repository-settings.md) is often the fix. A low Scorecard result is not a certification failure because Scorecard is not a certification.

## Related

- [CI](../development/ci.md)
- [CI security](../security/ci-security.md)
