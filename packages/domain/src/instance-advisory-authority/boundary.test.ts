/**
 * Public surface, framework boundary, and production exclusion for Session 1.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as domainPublic from '../index.js';
import * as authoritySurface from './index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../..');

const SKIPPED = new Set([
  'node_modules',
  'dist',
  '.next',
  'coverage',
  'generated',
  '.git',
  '.turbo',
]);

const BANNED_SOURCE =
  /@prisma\/client|\bPrisma\b|from 'fastify'|from "fastify"|from 'next'|from "next"|from 'ioredis'|from "ioredis"|from 'bullmq'|from "bullmq"|@aws-sdk|process\.env|\beval\s*\(|new Function|import\s*\(|from 'node:fs'|from 'node:https'|from 'node:http'|from 'node:net'|from 'node:child_process'|setTimeout|setInterval/;

const PUBLIC_VALUE_EXPORTS = [
  'INSTANCE_ADVISORY_ACTIVE_GRANT_INVARIANTS',
  'INSTANCE_ADVISORY_AUDIT_ACTIONS',
  'INSTANCE_ADVISORY_AUDIT_FORBIDDEN_PAYLOAD_FIELDS',
  'INSTANCE_ADVISORY_AUDIT_REPLAY',
  'INSTANCE_ADVISORY_AUTHORITIES',
  'INSTANCE_ADVISORY_AUTHORITY_COMMAND_ACKNOWLEDGEMENTS',
  'INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT',
  'INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES',
  'INSTANCE_ADVISORY_AUTHORITY_COMMAND_RESULT_SCHEMA_VERSION',
  'INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION',
  'INSTANCE_ADVISORY_AUTHORITY_COMMAND_USAGE',
  'INSTANCE_ADVISORY_AUTHORITY_EXECUTION_BOUNDARY',
  'INSTANCE_ADVISORY_AUTHORITY_INVARIANTS',
  'INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION',
  'INSTANCE_ADVISORY_AUTHORITY_OPERATIONS',
  'INSTANCE_ADVISORY_AUTHORITY_POWERS',
  'INSTANCE_ADVISORY_AUTHORIZATION_EXTERNAL_COLLAPSE',
  'INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION',
  'INSTANCE_ADVISORY_AUTHORIZATION_READ_OUTCOMES',
  'INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION',
  'INSTANCE_ADVISORY_CONCURRENT_GRANT_CONTRACT',
  'INSTANCE_ADVISORY_DISABLEMENT_CONTRACT',
  'INSTANCE_ADVISORY_GRANT_AUDIT_SUBJECT_TYPE',
  'INSTANCE_ADVISORY_GRANT_EXCLUDED_IDENTITY_FIELDS',
  'INSTANCE_ADVISORY_GRANT_IDENTITY_FIELDS',
  'INSTANCE_ADVISORY_GRANT_LIFECYCLE_STATES',
  'INSTANCE_ADVISORY_ISSUANCE_CLASSIFICATIONS',
  'INSTANCE_ADVISORY_MUTATION_TRANSACTION_REQUIREMENTS',
  'INSTANCE_ADVISORY_PERSISTENCE_INVARIANTS',
  'INSTANCE_ADVISORY_PRINCIPAL_EXCLUDED_FIELDS',
  'INSTANCE_ADVISORY_PRODUCT_NONAUTHORITY',
  'INSTANCE_ADVISORY_PROHIBITED_COMMAND_FIELDS',
  'INSTANCE_ADVISORY_REENABLEMENT_CONTRACT',
  'INSTANCE_ADVISORY_REGRANT_CONTRACT',
  'INSTANCE_ADVISORY_REJECTED_AUTHORITIES',
  'INSTANCE_ADVISORY_REJECTED_GRANT_LIFECYCLE_STATES',
  'INSTANCE_ADVISORY_REJECTED_ISSUANCE_CLASSIFICATIONS',
  'INSTANCE_ADVISORY_REVOCATION_CONTRACT',
  'INSTANCE_ADVISORY_REVOCATION_REPLAY',
  'INSTANCE_ADVISORY_SEPARATION_RESIDUAL',
  'INSTANCE_ADVISORY_TENANT_NONAUTHORITY',
  'INSTANCE_ADVISORY_USER_ABSENCE_DISCLOSURE',
  'INSTANCE_ADVISORY_USER_AUDIT_SUBJECT_TYPE',
  'canonicalInstanceAdvisoryPrincipalId',
  'classifyInstanceAdvisoryAuthorityCommand',
  'classifyInstanceAdvisoryAuthorization',
  'classifyInstanceAdvisoryConcurrentGrantReread',
  'classifyInstanceAdvisoryConcurrentRevocationReread',
  'classifyInstanceAdvisoryGrantLifecycleMutation',
  'collapseInstanceAdvisoryAuthorizationForExternalBoundary',
  'compareInstanceAdvisoryPrincipals',
  'executeInstanceAdvisoryAuthorityDeploymentCommand',
  'instanceAdvisoryAuditIntent',
  'instanceAdvisoryAuthorityCommandAcknowledgement',
  'instanceAdvisoryAuthorityCommandExitCode',
  'instanceAdvisoryGrantLifecycle',
  'isCanonicalInstanceAdvisoryPrincipalId',
  'isInstanceAdvisoryAuthority',
  'isInstanceAdvisoryAuthorityCommandOutcome',
  'isInstanceAdvisoryAuthorityOperation',
  'isInstanceAdvisoryIssuanceClassification',
  'parseInstanceAdvisoryAuthorizationReadRequest',
  'parseInstanceAdvisoryAuthorityArgv',
  'parseInstanceAdvisoryAuthorityCommand',
  'presentInstanceAdvisoryAuthorityCommandResult',
] as const;

function walk(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (SKIPPED.has(entry)) {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      walk(fullPath, files);
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

function isProductionSource(filePath: string): boolean {
  return /\.(ts|tsx|mjs)$/.test(filePath) && !/\.test\.(ts|tsx|mjs)$/.test(filePath);
}

describe('instance advisory authority public surface', () => {
  it('exports only the closed contract surface', () => {
    expect(Object.keys(authoritySurface).sort()).toEqual([...PUBLIC_VALUE_EXPORTS].sort());
    const names = Object.keys(authoritySurface);
    expect(names.filter((name) => /rbac|issuer|prisma|reset|factory|callback/i.test(name))).toEqual(
      [],
    );
    expect(names).not.toContain('issueApprovalCapability');
    expect(names).not.toContain('createInstanceAdvisoryAuthorityGrant');
  });

  it('stays off the domain barrel', () => {
    expect(Object.keys(domainPublic)).not.toContain('parseInstanceAdvisoryAuthorityCommand');
    expect(Object.keys(domainPublic)).not.toContain('INSTANCE_ADVISORY_AUTHORITIES');
    const barrel = readFileSync(path.join(repoRoot, 'packages/domain/src/index.ts'), 'utf8');
    expect(barrel).not.toContain('instance-advisory-authority');
    expect(barrel).not.toContain('advisory_submit_local');
    const packageJson = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/domain/package.json'), 'utf8'),
    ) as { exports: Record<string, { import: string }> };
    expect(packageJson.exports['./instance-advisory-authority']).toEqual({
      types: './dist/instance-advisory-authority/index.d.ts',
      import: './dist/instance-advisory-authority/index.js',
    });
  });
});

describe('instance advisory authority framework boundary', () => {
  it('keeps contract sources free of frameworks, I/O, timers, and environment access', () => {
    const files = readdirSync(here).filter(
      (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const source = readFileSync(path.join(here, name), 'utf8');
      expect(source, name).not.toMatch(BANNED_SOURCE);
      expect(source, name).not.toContain('@patchpilot/database');
      expect(source, name).not.toContain('prisma.');
      expect(source, name).not.toContain('node:child_process');
    }
  });
});

describe('instance advisory authority production exclusion', () => {
  it('is not composed by API, web, worker, seed, or database production sources', () => {
    const roots = [
      'apps/api',
      'apps/web',
      'apps/worker',
      'packages/database/src',
      'packages/database/prisma',
      'packages/auth/src',
    ].map((root) => path.join(repoRoot, root));
    const allowed = new Set([
      'packages/database/src/instance-advisory-authority-persistence.ts',
      'packages/database/src/instance-advisory-authority-command-main.ts',
      'packages/database/prisma/schema.prisma',
      'packages/database/prisma/migrations/20261014120000_instance_advisory_authority_grant/migration.sql',
    ]);
    const forbidden = [
      'instance-advisory-authority',
      'instance_advisory_authority_command_v1',
      'advisory_submit_local',
      'advisory_approve_for_product_evaluation',
      'deployment_local_command',
      'parseInstanceAdvisoryAuthorityCommand',
    ];
    const offenders: string[] = [];
    for (const root of roots) {
      for (const filePath of walk(root).filter(isProductionSource)) {
        const relative = path.relative(repoRoot, filePath);
        if (allowed.has(relative)) {
          continue;
        }
        const source = readFileSync(filePath, 'utf8');
        if (forbidden.some((needle) => source.includes(needle))) {
          offenders.push(relative);
        }
      }
    }
    expect(offenders).toEqual([]);
    const databaseIndex = readFileSync(
      path.join(repoRoot, 'packages/database/src/index.ts'),
      'utf8',
    );
    expect(databaseIndex).not.toContain('instance-advisory-authority');
    const databasePackage = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/database/package.json'), 'utf8'),
    ) as { exports: Record<string, unknown> };
    expect(databasePackage.exports['./instance-advisory-authority']).toBeUndefined();
  });

  it('is absent from startup, queue, seed, and migration entrypoints', () => {
    const files = [
      'apps/api/src/server.ts',
      'apps/api/src/app.ts',
      'apps/web/app/layout.tsx',
      'apps/worker/src/main.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/worker/src/bullmq-outbox-publisher.ts',
      'packages/database/src/seed/run.ts',
      'packages/database/src/seed/development.ts',
      'packages/auth/src/permissions.ts',
    ];
    const forbidden = [
      'instance-advisory-authority',
      'advisory_submit_local',
      'advisory_approve_for_product_evaluation',
    ];
    for (const relative of files) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      expect(
        forbidden.some((needle) => source.includes(needle)),
        relative,
      ).toBe(false);
    }
  });
});
