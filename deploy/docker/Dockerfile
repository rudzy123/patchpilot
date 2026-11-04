# syntax=docker/dockerfile:1

# Node 24 matches .nvmrc. The digest is the multi-arch index for
# node:24-bookworm-slim (Node 24.22.2) resolved on 2026-11-04.
ARG NODE_IMAGE=node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c

FROM ${NODE_IMAGE} AS base

WORKDIR /src

# Prisma selects the query engine from `openssl version`. bookworm-slim has
# libssl but not that binary, so generate would fall back to OpenSSL 1.1 and
# the runtime engine check for debian-openssl-3.0.x would fail.
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Shared by the migrate stage, which runs pnpm as the node user.
ENV COREPACK_HOME=/opt/corepack

RUN corepack enable

FROM base AS deps

ENV CI=true

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY apps/worker/package.json apps/worker/package.json
COPY packages/auth/package.json packages/auth/package.json
COPY packages/config/package.json packages/config/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/database/package.json packages/database/package.json
COPY packages/domain/package.json packages/domain/package.json
COPY packages/eslint-config/package.json packages/eslint-config/package.json
COPY packages/integrations/package.json packages/integrations/package.json
COPY packages/logger/package.json packages/logger/package.json
COPY packages/observability/package.json packages/observability/package.json
COPY packages/policy-engine/package.json packages/policy-engine/package.json
COPY packages/sbom/package.json packages/sbom/package.json
COPY packages/test-utils/package.json packages/test-utils/package.json
COPY packages/typescript-config/package.json packages/typescript-config/package.json
COPY packages/vulnerability-intelligence/package.json packages/vulnerability-intelligence/package.json

# packageManager in package.json selects pnpm@11.24.0. No npm global install.
RUN corepack prepare --activate \
  && pnpm install --frozen-lockfile \
  && chmod -R a+rX /opt/corepack

FROM deps AS build

COPY . .

# Next.js 16.3.8 replaces the bracket reads in packages/config/src/public.ts
# with string literals in the server bundle. Runtime environment changes do
# not affect the built server. These values are public. Omit the args to keep
# the defaults in the web package build script. Rebuild web for another origin.
ARG NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT
ARG NEXT_PUBLIC_API_BASE_URL

RUN if [ -z "${NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT:-}" ]; then unset NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT; fi \
  && if [ -z "${NEXT_PUBLIC_API_BASE_URL:-}" ]; then unset NEXT_PUBLIC_API_BASE_URL; fi \
  && NODE_ENV=production pnpm build

# pnpm 11.24 refuses deploy unless this command injects workspace packages.
# The flag is not written to pnpm-workspace.yaml.
RUN pnpm --filter @patchpilot/api --prod --config.inject-workspace-packages=true deploy /deploy/api \
  && pnpm --filter @patchpilot/worker --prod --config.inject-workspace-packages=true deploy /deploy/worker \
  && pnpm --filter @patchpilot/web --prod --config.inject-workspace-packages=true deploy /deploy/web

# Generate into each packed tree from the packed schema. No database URL is
# set. The Prisma CLI is removed before the runtime images copy these trees.
RUN node --input-type=module - <<'EOF'
import { createRequire } from 'node:module';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const deployRoots = ['/deploy/api', '/deploy/worker', '/deploy/web'];

function isPrismaPackage(directory) {
  const manifestPath = path.join(directory, 'package.json');
  if (!existsSync(manifestPath)) {
    return false;
  }
  try {
    return JSON.parse(readFileSync(manifestPath, 'utf8')).name === 'prisma';
  } catch {
    return false;
  }
}

function generatePackedClient(root) {
  const databaseRoot = realpathSync(path.join(root, 'node_modules/@patchpilot/database'));
  const distClient = path.join(databaseRoot, 'dist/client.js');
  const schema = path.join(databaseRoot, 'prisma/schema.prisma');
  if (!existsSync(distClient) || !existsSync(schema)) {
    throw new Error(`Packed database package is incomplete in ${root}`);
  }

  const require = createRequire(distClient);
  const clientPackage = path.dirname(require.resolve('@prisma/client/package.json'));
  const prismaPackage = path.dirname(require.resolve('prisma/package.json'));
  const scratch = mkdtempSync(path.join(tmpdir(), 'patchpilot-prisma-'));
  try {
    mkdirSync(path.join(scratch, 'prisma'), { recursive: true });
    mkdirSync(path.join(scratch, 'node_modules/@prisma'), { recursive: true });
    symlinkSync(schema, path.join(scratch, 'prisma/schema.prisma'));
    symlinkSync(prismaPackage, path.join(scratch, 'node_modules/prisma'));
    symlinkSync(clientPackage, path.join(scratch, 'node_modules/@prisma/client'));
    writeFileSync(
      path.join(scratch, 'package.json'),
      JSON.stringify({ name: 'patchpilot-prisma-generate', private: true }),
    );
    const env = { ...process.env };
    delete env.DATABASE_URL;
    const result = spawnSync(
      process.execPath,
      [
        path.join(prismaPackage, 'build/index.js'),
        'generate',
        '--schema',
        path.join(scratch, 'prisma/schema.prisma'),
      ],
      { cwd: scratch, env, stdio: 'inherit' },
    );
    if (result.status !== 0) {
      throw new Error(`prisma generate failed for ${root}`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  const generatedDir = path.resolve(clientPackage, '../../.prisma/client');
  const generated = path.join(generatedDir, 'index.js');
  const engine = path.join(generatedDir, 'libquery_engine-debian-openssl-3.0.x.so.node');
  if (!generated.startsWith(`${root}${path.sep}`) || !existsSync(generated) || !existsSync(engine)) {
    const present = existsSync(generatedDir) ? readdirSync(generatedDir).join(', ') : 'missing directory';
    throw new Error(`Prisma client was not generated inside ${root} (${present})`);
  }
}

function removePrismaCli(root) {
  const removals = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink() || !entry.isDirectory()) {
        if (entry.name === 'prisma' && path.basename(directory) === '.bin') {
          removals.push(full);
        } else if (entry.isSymbolicLink() && entry.name === 'prisma' && path.basename(directory) === 'node_modules') {
          removals.push(full);
        }
        continue;
      }
      if (entry.name === 'prisma' && isPrismaPackage(full)) {
        removals.push(full);
        continue;
      }
      walk(full);
    }
  };
  walk(root);
  for (const target of removals) {
    rmSync(target, { recursive: true, force: true });
  }
}

function assertNoPrismaCli(root) {
  const leftovers = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      const parentName = path.basename(directory);
      if (
        entry.name === 'prisma' &&
        (parentName === '.bin' || (entry.isSymbolicLink() && parentName === 'node_modules'))
      ) {
        leftovers.push(full);
      }
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (!entry.isDirectory()) {
        continue;
      }
      if (entry.name === 'prisma' && isPrismaPackage(full)) {
        leftovers.push(full);
        continue;
      }
      walk(full);
    }
  };
  walk(root);
  if (leftovers.length > 0) {
    throw new Error(`Prisma CLI remains in ${root}: ${leftovers.join(', ')}`);
  }
}

function assertPortable(root) {
  const envFiles = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        const link = readlinkSync(full);
        if (path.isAbsolute(link)) {
          throw new Error(`absolute symlink escapes the deploy tree: ${full} -> ${link}`);
        }
        continue;
      }
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (entry.name === '.env' || entry.name.startsWith('.env.')) {
        envFiles.push(full);
      }
    }
  };
  walk(root);
  if (envFiles.length > 0) {
    throw new Error(`deploy tree contains env files: ${envFiles.join(', ')}`);
  }
}

for (const root of ['/deploy/api', '/deploy/worker']) {
  generatePackedClient(root);
  removePrismaCli(root);
  assertNoPrismaCli(root);
}

for (const root of deployRoots) {
  assertPortable(root);
  assertNoPrismaCli(root);
}

if (!existsSync('/deploy/api/dist/server.js') || lstatSync('/deploy/api/dist').isSymbolicLink()) {
  throw new Error('api deploy is missing a packed dist/server.js');
}
if (!existsSync('/deploy/worker/dist/main.js')) {
  throw new Error('worker deploy is missing dist/main.js');
}
if (!existsSync('/deploy/web/.next/BUILD_ID') || !existsSync('/deploy/web/next.config.ts')) {
  throw new Error('web deploy is missing the Next.js build output or next.config.ts');
}
if (existsSync('/deploy/web/.next/cache')) {
  throw new Error('web deploy included .next/cache');
}
if (!existsSync('/deploy/web/node_modules/next/dist/bin/next')) {
  throw new Error('web deploy is missing the next start binary');
}
EOF

FROM base AS api

ENV NODE_ENV=production
ENV API_HOST=0.0.0.0

COPY --from=build --chown=node:node /deploy/api /app

USER node

WORKDIR /app

EXPOSE 3001

CMD ["node", "dist/server.js"]

FROM base AS worker

ENV NODE_ENV=production

COPY --from=build --chown=node:node /deploy/worker /app

USER node

WORKDIR /app

CMD ["node", "dist/main.js"]

FROM base AS web

ENV NODE_ENV=production

COPY --from=build --chown=node:node /deploy/web /app

USER node

WORKDIR /app

EXPOSE 3000

CMD ["node", "node_modules/next/dist/bin/next", "start", "--port", "3000", "--hostname", "0.0.0.0"]

FROM base AS migrate

COPY --from=deps --chown=node:node /src /src
COPY --from=deps --chown=node:node /opt/corepack /opt/corepack
COPY --chown=node:node packages/database/prisma /src/packages/database/prisma
COPY --chown=node:node scripts/run-database-command.mjs /src/scripts/run-database-command.mjs

USER node

WORKDIR /src

CMD ["pnpm", "db:migrate:deploy"]
