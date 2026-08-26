# Release principles

PatchPilot aims to be production-**minded** from the first usable release: operable, auditable, and honest about what it does not prove.

Passing CI does not, by itself, mean a release is production-ready.

## When we may tag a release

A tagged release should:

- Complete the [MVP journey](../product/mvp-scope.md) or a previously documented subset that operators can actually run end to end.
- Meet [definition of done](definition-of-done.md) for included features.
- Ship database migrations that apply cleanly from the previous tag.
- Record the scoring **policy version** in release notes when scoring behavior changes.
- Include known limitations (feed freshness, supported CycloneDX versions, AI disabled).
- Avoid claiming compliance, certification, or guaranteed exploitability.

## Versioning

- Follow Semantic Versioning once `0.1.0` or later is tagged.
- `0.x` may break APIs; still document `BREAKING CHANGE` commits.
- Policy version is independent of the application version and must appear in finding evidence.

## Configuration and secrets

- Release artifacts must not contain credentials, default admin passwords, or AI keys.
- Production configuration must not enable development adapters.
- Operators provide their own secrets at runtime.

## Rollback and evidence

- Prefer additive migrations. Do not destroy evidentiary tables as a rollback strategy.
- Object-storage keys for original SBOMs should remain retrievable for the retention period.
- If a scoring bug is fixed, new calculations use a new policy version; do not silently rewrite historical scores.

## Communication

- Release notes list user-visible changes, security fixes (without exploit detail), and operator actions (migrations, config).
- Security issues are handled per [SECURITY.md](../../SECURITY.md) before a public detailed write-up.
