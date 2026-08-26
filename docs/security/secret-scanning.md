# Secret scanning

Secret scanning reduces the chance that credentials land in git. It does **not** prove the repository contains no secrets.

## Preferred control

Use **GitHub secret scanning** and **push protection** when the repository plan provides them. Enable **private vulnerability reporting** as described in [SECURITY.md](../../SECURITY.md).

These are GitHub UI settings. They are not turned on by files in this repository. See [repository-settings.md](../development/repository-settings.md).

This session does **not** add a second hosted secret-scanning SaaS or upload the repository to an untrusted scanner. Duplicating several scanners without extra coverage would increase false positives and data sharing.

## Local options

Before pushing:

- Do not commit `.env` (gitignored). Use `.env.example` placeholders only.
- `git diff --check` and a careful `git diff` for tokens.
- Optional: run a local scanner you already trust on your workstation (for example gitleaks, if you install it yourself). Pin that tool yourself. Do not pipe secrets into chat logs.

There is no pre-commit hook framework in this repository yet. Do not skip hooks if they are added later.

## If a secret is found

Follow [secret-exposure.md](../runbooks/secret-exposure.md). GitHub should redact matched secrets in some UI surfaces; still assume logs may contain fragments. Never paste the full secret into an issue.

## History scanning

Full git-history scanning is not part of CI in this session (runtime cost and false-positive handling). If a secret is believed to be in history, rotate it and treat the history as compromised even after a later commit removes the string.
