# Built-in priority policy publication

The deployment-local command is the only production writer for builtin `patchpilot.builtin.v0` version 2. It is explicit. API startup, the web, the worker, the scheduler, the queue, the development seed, and migration startup do not invoke it.

[ADR 0047](../adr/0047-controlled-priority-activation.md) is Accepted. The production allowlist is empty while V-0001 in [priority weight validation](../security/priority-weight-validation.md) is unsigned. The command then exits 2 and writes nothing. Owner `POST /findings/:findingId/risk-calculations` and `GET /findings/:findingId/priority` return 503 until a signed `validated` or `validated_with_residuals` pair is mirrored into `ADMITTED_PRIORITY_POLICY_PAIRS` and an operator runs this command.

The command does not accept a definition, a hash, or an allowlist override. It does not set `Finding.dueAt` or `Finding.currentRiskCalculationId`. It does not create a Finding, a RemediationTask, or a priority review.

Build `@patchpilot/database` before the first invocation. The script runs `packages/database/dist/builtin-priority-policy-publication-command-main.js`. If that file is missing, the script exits 1.

## Invocation

The command uses the same server configuration as the API, including `DATABASE_URL`. It does not print that location. A missing or malformed database setting is a persistence failure. The allowlist is checked before the database is opened, so an unsigned pair does not require a reachable database.

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
