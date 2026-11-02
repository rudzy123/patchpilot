# Offline npm OSV import

The deployment-local command decided by [ADR 0046](../adr/0046-offline-npm-osv-import.md) imports one non-recursive directory of npm GHSA OSV JSON files into the instance advisory model.

The command, migration 27, and `scripts/run-offline-npm-osv-import.mjs` are not in the tree. Do not invent an invocation and do not point a shell script at PostgreSQL. Production OSV acquisition stays disabled. `INTELLIGENCE_OSV_ENABLED=true` stays rejected. `intelligence.osv.sync` stays unregistered.

When the script is installed, build `@patchpilot/database` before the first invocation. The wrapper runs `packages/database/dist/offline-npm-osv-import-command-main.js`. A missing build writes `offline_npm_osv_import_not_built` and exits 1.

Imported rows are not proof an asset is affected. The command writes no Finding, Product Match Evidence, Vulnerability binding, approval, or P1 to P4 calculation. A directory is not a complete OSV catalog. Files that are absent are not withdrawals and do not delete revisions.

## Invocation

The command uses the same server configuration as the API, including `DATABASE_URL`. It does not print that location and it does not accept a second database setting.

```text
pnpm offline-npm-osv-import -- --directory <directory> --correlation-id <correlation-id>
pnpm offline-npm-osv-import -- help
```

`<correlation-id>` is a canonical lowercase UUID. One invocation processes one directory. The directory's entries must already be the JSON files. A parent directory that contains an `npm` subdirectory is rejected, because the command does not recurse.

`<directory>` is the operator's host path. Names inside it are single path segments. The command rejects symlinks, directories, devices, `..`, absolute entry names, a second path segment, names that contain `:`, and hidden names. It also rejects unknown flags and any flag that would enable OSV or fetch a URL.

There is no prompt. Organization roles and `advisory_submit_local` cannot invoke the command. Host execution is the authority. This does not close OD-10.

## Exit codes

Standard output for a completed attempt is one JSON object. `help` writes usage to standard error and writes no JSON. Success writes no standard error. A failure writes one stable token and no stack, path, or document text.

| Exit | Meaning | Token on stderr |
| --- | --- | --- |
| 0 | Directory accepted and no file outcome is `failed` | none |
| 1 | File, batch, or terminal transaction failed, or the outcome is uncertain | `offline_npm_osv_import_failed` |
| 3 | Command or directory rejected before a file transaction | `offline_npm_osv_import_directory_rejected` |
| 7 | Database setting missing or malformed, or PostgreSQL unavailable before a commit | `offline_npm_osv_import_database_unavailable` |

`help` exits 0 and is distinguished by usage text with no result JSON.

Exit 0 can still list `rejected` files. Read `accepted`, `skipped`, `rejected`, and `failed` in the summary. `skipped` means `already_applied`. The summary includes advisory ids only when they already match the advisory-id grammar. It has no file path and no document text.

## Commit uncertainty

The command does not retry. `database_unavailable`, `transaction_aborted`, and `internal_failure` leave acknowledgement uncertain when a transaction may have committed.

Run the same directory again. Use a new correlation id when the previous terminal audit did not commit. The batch identity is the manifest SHA-256, so a committed batch is replayed. A committed file becomes `already_applied` and does not insert a second revision, alias, range, explicit version, provenance row, or file audit event. A rolled-back file can still apply once.

A crash after some file commits leaves those revisions visible. There is no generation switch to hide them. A crash before the terminal audit leaves the batch and the committed revisions in place. The re-run writes the terminal audit.

Repeating a correlation id for the same batch does not insert a second terminal audit. Repeating it for a different directory is `immutable_conflict` and processes no files.

## Failure

| Condition | Response |
| --- | --- |
| Directory contains a symlink, subdirectory, device, hidden name, or more than 1,000 files | Exit 3. No batch row |
| A regular file is larger than 1,048,576 bytes | Exit 3. No batch row |
| Database configuration missing or malformed | Exit 7. No write |
| PostgreSQL unavailable before commit | Exit 7. No automatic retry |
| Malformed JSON, duplicate keys, license failure, mixed ecosystem, or empty affectedness | That file rolls back and counts as `rejected`. Earlier files stay committed |
| Same bytes and agreeing fields | `already_applied`. No second revision |
| Same digest and disagreeing fields | `immutable_conflict`. No write for that file. Do not update the stored row |
| Two current tips for one GHSA package | File rolls back with `malformed_persisted_state`. Repair with a forward revision |
| Worker-sized file stalls the process | Stop the process. The 5-second parser budget is not enforced. Re-run replays committed files |

Audit events are inserted by the persistence transaction. The command does not report success for a file before that transaction commits.

## What not to do

Do not set `INTELLIGENCE_OSV_ENABLED`. Do not register `intelligence.osv.sync`. Do not fetch `references`, PURLs, or `osv.dev`. Do not treat the directory as a full catalog. Do not delete or update revisions to remove an advisory that was left out of the directory. Do not mark an imported revision reviewed, and do not approve it through the maintainer API to make it product evidence. Offline rows stay ineligible for product evaluation.

A client `organizationId` inside a JSON object changes nothing. It is not stored and it does not select a tenant.
