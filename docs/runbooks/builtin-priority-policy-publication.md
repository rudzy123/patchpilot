# Built-in priority policy publication

The deployment-local command is the only production writer for builtin `patchpilot.builtin.v0` version 2. It is explicit. API startup, the web, the worker, the scheduler, the queue, the development seed, and migration startup do not invoke it.

[ADR 0047](../adr/0047-controlled-priority-activation.md) is Accepted. [V-0001](../security/priority-weight-validation.md) is `validated_with_residuals`, and `ADMITTED_PRIORITY_POLICY_PAIRS` admits that one pair: `@patchpilot/policy-engine@1` and definition SHA-256 `7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7`. The command writes the builtin row only when an operator runs it in that deployment. It exits 2 and writes nothing for any other pair. Owner `POST /findings/:findingId/risk-calculations` and `GET /findings/:findingId/priority` return 503 until that publication. API, web, worker, seed, and migration startup do not run this command. This repository does not publish a deployment database.

The command does not accept a definition, a hash, or an allowlist override. It does not set `Finding.dueAt` or `Finding.currentRiskCalculationId`. It does not create a Finding, a RemediationTask, or a priority review.

Build `@patchpilot/database` before the first invocation. The script runs `packages/database/dist/builtin-priority-policy-publication-command-main.js`. If that file is missing, the script exits 1.

## Invocation

The command uses the same server configuration as the API, including `DATABASE_URL`. It does not print that location. A missing or malformed database setting is a persistence failure. The allowlist is checked before the database is opened, so a pair that is not admitted does not require a reachable database. The admitted V-0001 pair continues to the database.

```text
pnpm publish-builtin-priority-policy -- --correlation-id <correlation-id>
pnpm publish-builtin-priority-policy -- help
```

`<correlation-id>` is a canonical lowercase UUID. `help` writes usage to standard error, writes no JSON, and exits 0. Any other flag is `invalid_command`.

## Exit codes

Standard output for a completed attempt is one JSON object. The object does not include the policy definition or its hash. `help` is the exception and writes no JSON.

| Exit | Meaning |
| --- | --- |
| 0 | The builtin row was inserted, or the stored row is an exact replay. Replay writes no second audit row. |
| 1 | The database package is not built, or the command is invalid. |
| 2 | The engine version and definition hash are not on the production allowlist. Nothing is written. |
| 3 | A stored builtin row has a different definition, id, scope, or status. Nothing is updated or deleted. |
| 4 | Persistence failed. A partial policy row is not left committed. |

One insert writes one `risk_policy.published` audit row. The actor type is `system`. Organization, user, and membership are null. The audit payload names the policy id, key, version, and schema version. It does not include the definition body.

Do not edit a published row to repair a conflict. A different definition needs a new policy version and a new validation entry.
