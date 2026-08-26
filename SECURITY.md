# Security policy

## Reporting a vulnerability

**Do not open a public GitHub issue, discussion, pull request, or commit that discloses a security vulnerability.**

Report suspected vulnerabilities privately using GitHub's private vulnerability reporting for this repository:

1. Open the repository **Security** tab.
2. Choose **Report a vulnerability**.
3. Include impact, affected versions or commits, reproduction details needed for maintainers, and any logs you can share without secrets.

If private vulnerability reporting is not yet enabled on the repository, contact the project maintainers through a private GitHub channel and ask them to enable it. Do not include exploit details in a public comment, gist, screenshot, or issue.

Do not attach real customer SBOMs, credentials, session cookies, access tokens, or production logs that contain secrets.

## What to include

- A clear description of the issue and its impact.
- The component (`web`, `api`, `worker`, package name, or docs/config).
- Steps or a minimal fixture that maintainers can use to confirm the issue.
- Whether you believe the issue crosses organization boundaries, leaks evidence, or bypasses authorization.

Do not require maintainers to run untrusted binaries. Prefer a written reproduction against this repository.

## Maintainer response

Maintainers will acknowledge private reports as capacity allows and will keep reporter identity and unpublished details confidential. There is no guaranteed SLA yet; this project is early and self-hosted.

Please do not disclose the issue publicly until maintainers have published a fix or have coordinated disclosure with you.

## Scope

In scope:

- Authorization bypass, IDOR, and organization-boundary failures.
- Secret exposure in logs, images, docs, or source.
- SBOM upload, parsing, and storage issues that can cause data leak, path traversal, SSRF, or unsafe deserialization.
- Webhook forgery, replay, or confused-deputy issues in integrations.
- Injection, XSS, CSRF (where cookie sessions exist), and request-smuggling issues in PatchPilot software.
- Supply-chain issues in PatchPilot's own dependencies and build.

Out of scope unless they demonstrate a PatchPilot defect:

- Vulnerabilities in a user's scanned applications that PatchPilot merely reports.
- Denial of service against public vulnerability feeds PatchPilot consumes.
- Issues that require an already-compromised maintainer workstation or stolen GitHub credentials with no additional PatchPilot bug.

## Safe handling for contributors

- Never hardcode secrets or AI API keys.
- Never commit `.env` files, private keys, or live credentials.
- Redact authorization headers, cookies, tokens, raw SBOMs, private source, and full feed payloads from logs and issue text.
- Keep development-only adapters disabled in production configurations.
- Add a regression test when fixing a security defect, without publishing a ready-to-use exploit.

## Coordinated fixes

Security fixes should land through a private or limited-disclosure path when GitHub Security Advisories are available. Public pull requests must not include working exploit payloads. After a fix is released, maintainers may publish a summary that omits unnecessary exploit detail.
