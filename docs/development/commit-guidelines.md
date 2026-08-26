# Commit guidelines

PatchPilot uses [Conventional Commits](https://www.conventionalcommits.org/).

## Format

```text
type(scope): short summary

Optional body explaining why, not a file dump.

Optional footer:
BREAKING CHANGE: description
Refs: #123
```

- Subject in **imperative mood** (`add`, `fix`, `reject`), roughly 72 characters or less.
- `type` is required. `scope` is optional but preferred when the area is clear.
- Do not end the subject with a period.
- One logical change per commit when practical.

## Types

| Type | When |
| --- | --- |
| `feat` | User-visible or domain capability |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting; no behavior change |
| `refactor` | Behavior-preserving code change |
| `perf` | Performance |
| `test` | Tests only |
| `build` | Packaging, pnpm, Turbo |
| `ci` | GitHub Actions |
| `chore` | Maintenance that is none of the above |
| `revert` | Revert a previous commit |

## Scopes

Use a single lowercase scope when it helps reviewers:

`web`, `api`, `worker`, `db`, `auth`, `sbom`, `policy`, `intel`, `security`, `docs`, `compose`.

Examples:

```text
feat(sbom): validate CycloneDX JSON before persist
fix(api): authorize findings from membership context
docs: add MVP non-goals
chore: add repository constitution
```

## Breaking changes

Mark breaking API, schema, or policy changes with `!` and a footer:

```text
feat(api)!: require idempotency key on SBOM upload

BREAKING CHANGE: clients must send Idempotency-Key on POST /sboms.
```

Policy version bumps that change scores are breaking for operators even if HTTP paths stay the same. Call that out in the body.

## Forbidden

- Secrets, live credentials, customer SBOMs, or `.env` files.
- Generated noise unrelated to the change.
- `--no-verify` unless explicitly requested.
- Rewriting published `main` history.
