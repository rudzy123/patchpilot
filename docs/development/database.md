# Database development

PostgreSQL is the system of record ([ADR 0005](../adr/0005-postgresql-prisma.md)). Prisma schema and adapters live in `packages/database`. Domain ports live in `packages/domain`.

## Commands

| Command | Purpose |
| --- | --- |
| `pnpm db:validate` | Prisma schema validate |
| `pnpm db:generate` | Generate Prisma Client |
| `pnpm db:migrate` | Interactive `prisma migrate dev` (local) |
| `pnpm db:migrate:deploy` | Apply committed migrations non-interactively |
| `pnpm db:reset` | Destructive reset; refused in production and without confirmation |
| `pnpm db:seed` | Idempotent synthetic development seed; refused in production |

`DATABASE_URL` is never printed by these scripts.

## Destructive command guards

`pnpm db:reset` requires all of:

1. `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` is not `production`
2. `NODE_ENV` is not `production` (belt-and-suspenders; not a grant by itself)
3. Host is loopback (`127.0.0.1`, `localhost`, or `::1`)
4. Database name matches `patchpilot` or `patchpilot_<label>`
5. `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE=true`

Do not infer safety from `NODE_ENV` alone. CI cleanup must target only isolated CI databases.

`pnpm infrastructure:down` does **not** delete Docker volumes.

## Seed safety

`pnpm db:seed` loads server config and inserts clearly synthetic organizations, users, and a synthetic vulnerability identity (`PATCHPILOT-SYNTH-VULN-1`). It is idempotent. It does not seed passwords, tokens, or live provider data. Production deployment environment rejects it.

## UTC and IDs

Persist timestamps as `timestamptz`. Generate UUIDs in PostgreSQL (`gen_random_uuid()`).

## Integration tests

API, worker, and database integration suites create disposable databases on the local Compose or CI PostgreSQL server. They do not use the persistent `patchpilot` development database. The server URL in `DATABASE_URL` is a template for host, port, and credentials. See [testing.md](testing.md#integration-database-isolation) for the isolation grain, migration deployment, and cleanup contract.

The test env record from `createFoundationTestEnv` still carries `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE=true` so creation is allowed only against loopback. `NODE_ENV=production` or `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production` disables the lifecycle even if that record is non-production. Production runtime configuration is unchanged.

## Related documents

- [Migrations](migrations.md)
- [Database model](../architecture/database-model.md)
