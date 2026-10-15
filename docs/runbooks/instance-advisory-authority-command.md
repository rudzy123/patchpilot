# Instance advisory authority command

The deployment-local command is the sole supported writer for instance advisory authority grants. It also disables and re-enables one existing User. It is explicit. Application startup, seed, migration, the API, and the web do not invoke it.

Advisory submission persistence is constructed only by the API submission route. An authenticated User with advisory_submit_local can submit through the API. Independent approval is composed only by the API approval route and remains eligibility only. POST /intelligence/maintainer-reviewed-advisories/:revisionId/approval is implemented in the API process. The command does not issue an approval capability, generate Product Match Evidence, or create a Finding. Organization roles cannot invoke or control it. No grants are seeded.

Instance Advisory Authority Foundation Session 3-R reviewed the deployment-local command. Instance Advisory Authority Foundation branch closure reviewed this branch. Instance Advisory Authority Foundation pull request #92 is merged. Maintainer-reviewed advisory submission contracts and the submission authority boundary are implemented and production uncomposed. Advisory submission persistence is constructed only by the API submission route. POST /intelligence/maintainer-reviewed-advisories is implemented in the API process. An authenticated User with advisory_submit_local can submit through the API. Independent approval is composed only by the API approval route. Internal capability issuance stays private to that approval transaction. Approval remains eligibility only. POST /intelligence/maintainer-reviewed-advisories/:revisionId/approval is implemented in the API process. No approval web UI exists. Approval creates eligibility only. Product Match Evidence generation remains unavailable. Organization roles remain irrelevant. Instance advisory grants remain the required authority. API startup is the only production composition for the two mutation routes. Maintainer-Reviewed Advisory Production Composition Session 3-R reviewed the uncomposed approval and capability transaction. Maintainer-Reviewed Advisory Production Composition Session 4 implements the two API routes. Session 4-R reviewed the protected API. Branch closure is next.

Build `@patchpilot/database` before the first invocation. The script runs `packages/database/dist/instance-advisory-authority-command-main.js`.

## Invocation

The command uses the same server configuration as the API, including `DATABASE_URL`. It does not print that location and it does not accept a second database setting. A missing or malformed database setting fails before any write.

```text
pnpm instance-advisory-authority -- grant --user-id <user-id> --authority <authority> --correlation-id <correlation-id>
pnpm instance-advisory-authority -- revoke --user-id <user-id> --expected-grant-id <grant-id> --expected-authority <authority> --correlation-id <correlation-id>
pnpm instance-advisory-authority -- disable-user --user-id <user-id> --correlation-id <correlation-id>
pnpm instance-advisory-authority -- enable-user --user-id <user-id> --correlation-id <correlation-id>
pnpm instance-advisory-authority -- help
```

`<user-id>`, `<grant-id>`, and `<correlation-id>` are canonical lowercase UUIDs. The target is an existing `User.id`. Email, username, organization, membership, role, and permission are rejected.

`<authority>` is exactly one of:

- `advisory_submit_local`
- `advisory_approve_for_product_evaluation`

Issuance is the deployment-local command. The operator cannot select another issuance classification. There is no prompt. One invocation performs one operation for one User.

Canonical `User.id` is the only separation principal. Another session, membership, organization, email, or display name does not make that User someone else. PatchPilot cannot prove that two User accounts are controlled by two different people, and it does not match email or display name to try. Grant `advisory_submit_local` and `advisory_approve_for_product_evaluation` only to accounts controlled by different people. One person controlling both accounts is an accepted operational residual, not a solved identity check.

Revoke names the expected active grant and its authority. That identity distinguishes a first revocation, exact replay, a missing grant, and a replaced grant.

## Exit codes

Standard output for a completed attempt is one JSON object. `help` writes usage to standard error and writes no JSON.

| Exit | Meaning | Outcomes |
| --- | --- | --- |
| 0 | New mutation committed | `granted`, `revoked`, `user_disabled`, `user_enabled` |
| 1 | Internal failure | `internal_failure`, `transaction_aborted`, `malformed_persisted_state` |
| 2 | Exact replay | `already_applied` |
| 3 | Invalid command | `invalid_command` |
| 4 | Not found | `user_absent`, `grant_absent` |
| 5 | Conflict | `active_grant_conflict`, `expected_grant_mismatch`, `active_authority_mismatch`, `immutable_conflict`, `concurrency_conflict` |
| 6 | Authority or User-state rejection | `user_inactive`, `authority_required` |
| 7 | Database unavailable | `database_unavailable` |

`help` also exits 0 and is distinguished by usage text with no result JSON.

The JSON field `acknowledgement` is `committed`, `replayed`, `unchanged`, or `uncertain`.

## Commit uncertainty

`database_unavailable`, `transaction_aborted`, and `internal_failure` use `acknowledgement: uncertain`. The command does not retry. Run the same command again. The persistence transaction classifies the retry: a committed first operation becomes `already_applied`, and a rolled-back attempt can still apply once. Exact replay does not insert a second grant, a second audit event, or a repeated User status change.

A different correlation id does not create a second grant or a second audit event when the stored operation already matches.

## Failure

| Condition | Response |
| --- | --- |
| Database configuration missing or malformed | Exit 7. No write |
| PostgreSQL unavailable | Exit 7. No automatic retry |
| User does not exist | Exit 4, `user_absent`. The command does not create the User |
| Active grant for the other authority | Exit 5, `active_grant_conflict`. The command does not replace it |
| Revoke of a grant that was never issued | Exit 4, `grant_absent`. This is not replay |
| Revoke of a replaced grant | Exit 5, `expected_grant_mismatch`. This is not replay |
| Malformed grant rows | Exit 1, `malformed_persisted_state`. No write |

Audit events are inserted by the persistence transaction. The command does not insert them and does not report success before commit acknowledgement.

## Nonauthority

The command does not list grants or Users. It does not search by email or display name. It does not change passwords, sessions, memberships, or organization roles. Re-enable restores User active-state eligibility only. It does not create a grant or reactivate a revoked grant.
