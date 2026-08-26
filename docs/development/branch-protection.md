# Branch protection

Protect `main` with a ruleset (preferred) or classic branch-protection rules. This is a recommendation. **It is not enabled by committing these files.**

## Recommended rules for `main`

| Rule | Recommendation | Single-maintainer note |
| --- | --- | --- |
| Require a pull request before merging | Yes | Still use PRs even if you are the only reviewer |
| Required approvals | 0 or 1 | 1 is healthier; 0 avoids deadlock when the author is the only maintainer. Do not require a second person who does not exist |
| Dismiss stale reviews | Yes, once a second reviewer exists | Optional while you are the only maintainer |
| Require review from CODEOWNERS | **No** for now | CODEOWNERS lists `@rudzy123`. Requiring code-owner review would block the owner from merging their own work. Enable later when another maintainer can approve |
| Require conversation resolution | Yes | |
| Require status checks | Yes, see list below | |
| Require branch to be up to date | Yes if it does not stall CI capacity | Merge queue is not justified yet |
| Require signed commits | No unless you already sign every commit reliably | Do not enable a rule you cannot keep |
| Block force pushes | Yes | Never force-push `main` |
| Block branch deletion | Yes | |
| Restrict direct pushes | Yes | Administrators included once recovery access is confirmed |
| Apply to administrators | Yes, after confirming you can still recover the repository (account access, not a destroyed laptop as the only 2FA device) | |
| Require linear history | Only if squash or rebase merging is the sole allowed method | |
| Require successful deployments | No | No deployment workflows exist |

## Required status checks

Require these **intended** names after Session 4 workflows have actually run on GitHub and the check names are confirmed. Do not copy a guessed pattern into a ruleset before that:

- `CI / Workflows`
- `CI / Quality`
- `Integration / Integration`
- `CodeQL / Analyze`
- `Dependency review / Dependency review`

Do **not** require:

- Scorecard (does not run on pull requests; not a PR gate)
- SBOM (does not run on pull requests; not a PR gate)
- Release dry run (manual `workflow_dispatch` only)
- E2E (no workflow until real Playwright tests exist)
- Container build (no workflow until reviewed runtime Dockerfiles exist)

Do not require checks that do not exist.

## Emergency recovery

If required checks or administrator enforcement lock out all maintainers:

1. Use another logged-in account or organization owner with repository admin, if one exists.
2. Temporarily relax administrator enforcement from GitHub support or a second admin, not by force-pushing `main`.
3. Restore the ruleset after the emergency.
4. Record the incident without publishing secrets.

There is currently one known maintainer (`rudzy123`). Keep recovery access (account 2FA backup, not only a single device) before applying "include administrators".
