/**
 * Approval adapter boundary. PostgreSQL behavior is proved separately.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Prisma, type PrismaClient } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import {
  MAINTAINER_REVIEWED_ADVISORY_APPROVAL_LOCK_ORDER,
  classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure,
  createMaintainerReviewedAdvisoryApprovalApplicationPersistence,
} from './maintainer-reviewed-advisory-approval-application-persistence.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');
const REVIEWER = '22222222-2222-4222-8222-222222222222';
const REVISION = '33333333-3333-4333-8333-333333333333';
const CORRELATION = '990e8400-e29b-41d4-a716-446655440099';

function clientThatMustNotStart(): PrismaClient {
  return {
    $transaction: () => {
      throw new Error('transaction started');
    },
  } as unknown as PrismaClient;
}

describe('maintainer-reviewed advisory approval adapter boundary', () => {
  it('locks the reviewer before the revision and does not lock the revision table', () => {
    expect(MAINTAINER_REVIEWED_ADVISORY_APPROVAL_LOCK_ORDER.slice(0, 4)).toEqual([
      'validate_command',
      'lock_reviewer_user',
      'lock_instance_advisory_grants',
      'lock_advisory_revision',
    ]);
    const source = readFileSync(
      path.join(here, 'maintainer-reviewed-advisory-approval-application-persistence.ts'),
      'utf8',
    );
    expect(source).toContain('FOR UPDATE');
    expect(source).not.toContain('LOCK TABLE');
    expect(source).not.toContain('INSERT INTO "finding"');
    expect(source).not.toContain('INSERT INTO "finding_observation"');
    expect(source).not.toContain('INSERT INTO "product_match_evaluation_evidence"');
    expect(source).not.toContain('concurrency_conflict');
    expect(source).not.toContain('maintainer-reviewed-advisory-submission');
    expect(source).toContain('sealMaintainerReviewedAdvisoryApprovalCapability');
    expect(source).not.toContain('createReviewerCapabilityIssuer');
  });

  it('stays out of the database package barrel and application entrypoints', () => {
    const files = [
      'packages/database/src/index.ts',
      'apps/api/src/server.ts',
      'apps/api/src/app.ts',
      'apps/web/app/layout.tsx',
      'apps/worker/src/main.ts',
      'apps/worker/src/queue-job-router.ts',
      'packages/database/src/seed/run.ts',
      'packages/database/src/instance-advisory-authority-command-main.ts',
    ];
    for (const relative of files) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      expect(source).not.toContain(
        'createMaintainerReviewedAdvisoryApprovalApplicationPersistence',
      );
      expect(source).not.toContain('maintainer-reviewed-advisory-approval-application');
      expect(source).not.toContain('sealMaintainerReviewedAdvisoryApprovalCapability');
    }
  });

  it('rejects reviewer identity, purpose, and capability material before a transaction', async () => {
    const persistence =
      createMaintainerReviewedAdvisoryApprovalApplicationPersistence(clientThatMustNotStart());
    const legal = {
      commandName: 'approve_maintainer_reviewed_advisory_v1' as const,
      trustedReviewerUserId: REVIEWER,
      advisoryRevisionId: REVISION,
      correlationId: CORRELATION,
    };
    const withOrganization = { ...legal, organizationId: REVIEWER };
    const withPurpose = { ...legal, approvalPurpose: 'other' };
    const withCapability = { ...legal, capabilityId: REVISION };
    expect(await persistence.approve(withOrganization)).toEqual({
      outcome: 'invalid_command',
    });
    expect(await persistence.approve(withPurpose)).toEqual({
      outcome: 'invalid_command',
    });
    expect(await persistence.approve(withCapability)).toEqual({
      outcome: 'invalid_command',
    });
    expect(
      await persistence.approve({
        ...legal,
        trustedReviewerUserId: 'not-a-user',
      }),
    ).toEqual({ outcome: 'authority_required' });
  });

  it('translates persistence failures without SQL or a concurrency outcome', () => {
    const classified = [
      classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(
        new Error('code: "23505" duplicate'),
      ),
      classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(
        new Error('SQLSTATE 40001 serialization'),
      ),
      classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(
        new Error('reviewer_capability_expired'),
      ),
      classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(new Error('ECONNREFUSED')),
      classifyMaintainerReviewedAdvisoryApprovalPersistenceFailure(
        new Prisma.PrismaClientKnownRequestError('unique', {
          code: 'P2002',
          clientVersion: 'test',
        }),
      ),
    ];
    expect(classified).toEqual([
      'uniqueness',
      'transaction_aborted',
      'capability_expired',
      'database_unavailable',
      'uniqueness',
    ]);
    expect(JSON.stringify(classified)).not.toContain('concurrency_conflict');
    expect(JSON.stringify(classified)).not.toContain('reviewer_capability');
  });
});
