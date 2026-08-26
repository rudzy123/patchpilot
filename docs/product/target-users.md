# Target users

PatchPilot is built for people who own software risk but do not want a closed SaaS-only workflow.

## Individual developers and maintainers

They register a small number of assets, upload SBOMs from local builds or CI, and want a clear, explainable queue of what to fix first. They need a short path: create an organization, add an asset, upload, review findings, record what they did.

## Small businesses and nonprofits

They often lack a dedicated security team. They need least-privilege defaults, understandable language, and exports they can show to a board, funder, or customer without claiming certifications PatchPilot does not provide.

## Engineering teams

They need organization boundaries, assignment of remediation work, re-scan after a release, and a history of who accepted risk or applied a compensating control. They care that scores stay stable enough to plan sprints and that policy versions are recorded.

## Larger organizations

They need the same core journey plus stronger audit evidence, clearer separation of facts from conclusions, and operational controls (rate limits, encrypted integration credentials, retention policy). They may later connect more intelligence sources; that is future work unless an accepted ADR and MVP revision say otherwise.

## Shared expectations

All users:

- Self-host PatchPilot and keep SBOMs and evidence under their control.
- Can operate the product with no AI provider configured.
- Must not be told that a finding is “exploitable,” “compliant,” or “fully remediated” unless PatchPilot has stored supporting evidence for that claim.

Personas are descriptive. They do not expand [MVP scope](mvp-scope.md). Features that only a large enterprise would need (advanced SSO suites, GRC modules, automatic patch deployment) are [non-goals](non-goals.md) or future work.
