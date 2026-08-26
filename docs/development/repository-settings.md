# Repository settings

These GitHub settings **cannot** be fully expressed as files in the repository. This document is the checklist for a maintainer. **Do not assume a setting is enabled** unless you have verified it in the GitHub UI.

Repository: `rudzy123/patchpilot`.

## General

| Setting | Recommended value | Notes |
| --- | --- | --- |
| Default branch | `main` | Already in use |
| Allow merge commits | Optional | If enabled, do not also require linear history |
| Allow squash merging | Yes | Fits short-lived branches |
| Allow rebase merging | Optional | Compatible with linear history if squash is disabled |
| Automatically delete head branches | Yes | After merge |
| Discussions | Off unless a maintainer enables them later | Not required for Session 4 |
| Wiki | Off | Canonical docs live in `docs/` |

Visibility is the maintainer's choice. Scorecard `publish_results` is **false** in this repository regardless of visibility, and no OIDC permission is granted. Secret-scanning availability still depends on visibility and plan. This document does not claim the current visibility.

## Actions

| Setting | Recommended value |
| --- | --- |
| Actions permissions | Allow GitHub-owned actions and selected third-party actions used here (`ossf/scorecard-action`, `anchore/sbom-action`) |
| Fork pull-request workflows from first-time contributors | Require approval for first-time contributors |
| Workflow permissions for `GITHUB_TOKEN` | Read-only by default (workflows also set this in YAML) |
| Allow GitHub Actions to create and approve pull requests | No |

Do not add repository secrets for pull-request CI. Integration credentials are development placeholders in job `env`, not GitHub Secrets.

## Security

| Setting | Recommended value |
| --- | --- |
| Dependabot alerts | Enable |
| Dependabot security updates | Enable |
| Dependabot version updates | Configured via [`.github/dependabot.yml`](../../.github/dependabot.yml) |
| Secret scanning | Enable where the GitHub plan allows |
| Push protection | Enable where the GitHub plan allows |
| Private vulnerability reporting | Enable (already described in [SECURITY.md](../../SECURITY.md)) |
| Code scanning | Enable so CodeQL and Scorecard SARIF can upload |
| Vulnerability alerts (GitHub Advisory) | Enable |

Exact availability depends on whether the repository is public and on the GitHub plan. See [secret-scanning.md](../security/secret-scanning.md).

## Retention

GitHub's default Actions artifact retention may be 90 days. Workflows that upload artifacts set a shorter `retention-days` (5–7). Confirm the repository Actions retention is not increased without reviewing [artifact-retention.md](artifact-retention.md).

## Rulesets or classic branch protection

Apply the settings in [branch-protection.md](branch-protection.md) to `main`. Import [`.github/rulesets/protect-main.json`](../../.github/rulesets/protect-main.json) from **Settings → Rules → Rulesets → Import a ruleset**, then set enforcement to **Active** after confirming check names. Classic branch protection is acceptable if that is what the account provides.

## What files cannot do

CODEOWNERS, issue templates, Dependabot YAML, and workflows do **not** turn on secret scanning, push protection, private reporting, or required checks by themselves. A maintainer must click those settings.
