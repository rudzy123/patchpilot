# Troubleshooting local development

Start with [local-setup.md](local-setup.md). For Compose health failures see [local-infrastructure-failure.md](../runbooks/local-infrastructure-failure.md).

## Node or pnpm version mismatch

`.nvmrc` is `24`. `package.json` engines are `node: ^24.0.0` and `pnpm: ^11.24.0`. Corepack should install pnpm 11.24.0 from `packageManager`.

```bash
nvm use
corepack enable
pnpm -v
```

`engineStrict: true` in `pnpm-workspace.yaml` rejects other Node majors.

## `pnpm install` fails

- Use Node 24. CI-style `CI=true pnpm install` freezes the lockfile; local first installs need a writable lockfile.
- Native optional builds: `msgpackr-extract` and `unrs-resolver` are allowlisted in `pnpm-workspace.yaml`.
- ESLint 9 is deprecated but retained for `eslint-config-next` 16 peer compatibility.

## Typecheck or tests cannot resolve workspace packages

Package `exports` point at `dist/`. Turbo `typecheck`, `test:unit`, and `build` depend on `^build`. Run `pnpm build` or the Turbo task from the root rather than a package in isolation after a clean checkout.

## Vitest `kill EACCES`

This environment needs `pool: 'threads'` (and `fileParallelism: false`) in Vitest configs. The default forks pool can fail with `kill EACCES` in restricted sandboxes.

## API ready returns 503

`GET /health/ready` checks **PostgreSQL only**. Start Compose (`pnpm infrastructure:up`) and confirm `DATABASE_URL` matches the published Postgres port.

## Worker exits immediately

The worker process checks PostgreSQL and Redis before accepting work. There is no HTTP port. If either dependency is down, the process prints a startup error to stderr and exits.

## Next.js cannot resolve `./file.js`

The web app uses the Next.js bundler. Import application modules without a `.js` extension. Workspace packages still use NodeNext `.js` specifiers against `dist/`.

## Production config rejected locally

If `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`, placeholder credentials, pretty logs, wildcard CORS, and `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS=true` are rejected. Use `development` or `test` for Compose credentials.

## Prisma commands fail

`pnpm db:*` runs in `@patchpilot/database`. `db:migrate` and `db:reset` need a reachable `DATABASE_URL`. `db:generate` and `db:validate` do not need a live database. The only model is the technical `SchemaFoundation` placeholder.

## Ports already in use

Override `PATCHPILOT_POSTGRES_PORT`, `PATCHPILOT_REDIS_PORT`, `PATCHPILOT_MINIO_API_PORT`, and `PATCHPILOT_MINIO_CONSOLE_PORT`, then update `DATABASE_URL`, `REDIS_URL`, and `OBJECT_STORAGE_ENDPOINT` to match. Bindings are `127.0.0.1` only.
