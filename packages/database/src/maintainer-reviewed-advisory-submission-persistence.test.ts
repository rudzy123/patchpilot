/**
 * Submission adapter boundary. PostgreSQL behavior is proved separately.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  MAINTAINER_REVIEWED_ACCEPTED_SPDX,
  MAINTAINER_REVIEWED_ADVISORY_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_ID,
  MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_VERSION,
} from '@patchpilot/vulnerability-intelligence';
import {
  parseMaintainerReviewedAdvisorySubmissionCommand,
  prepareMaintainerReviewedAdvisorySubmission,
  toMaintainerReviewedAdvisorySubmissionPersistenceCommand,
  type MaintainerReviewedAdvisorySubmissionPersistenceCommand,
} from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-submission';
import { describe, expect, it } from 'vitest';

import {
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_LOCK_ORDER,
  classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure,
  createMaintainerReviewedAdvisorySubmissionPersistence,
} from './maintainer-reviewed-advisory-submission-persistence.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');
const SUBMITTER = 'abcdef01-2345-4678-89ab-cdef01234567';

function license() {
  return {
    policyId: MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_ID,
    policyVersion: MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_VERSION,
    spdxLicenseId: MAINTAINER_REVIEWED_ACCEPTED_SPDX,
    productUse: 'permitted_for_internal_matching',
    modification: 'permitted',
    redistribution: 'permitted',
    notice: 'required',
    contentProvenance: 'maintainer_original',
    decision: 'accepted',
  };
}

function command(): MaintainerReviewedAdvisorySubmissionPersistenceCommand {
  const parsed = parseMaintainerReviewedAdvisorySubmissionCommand({
    schemaVersion: MAINTAINER_REVIEWED_ADVISORY_SCHEMA_VERSION,
    advisoryFamilyId: 'FAMILY-ADAPTER-0001',
    revisionNumber: 1,
    vulnerabilityId: '550e8400-e29b-41d4-a716-446655440000',
    aliases: ['CVE-2026-99999'],
    packageEcosystem: 'npm',
    packageName: 'left-pad',
    packageUrl: null,
    affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] }],
    withdrawal: 'not_withdrawn',
    supersedesRevisionId: null,
    sourceLicenseDecision: license(),
    authorIdentity: SUBMITTER,
    submissionCorrelationId: '990e8400-e29b-41d4-a716-446655440099',
  });
  if (!parsed.ok) {
    throw new Error('expected command');
  }
  const prepared = prepareMaintainerReviewedAdvisorySubmission(SUBMITTER, parsed.command);
  if (!prepared.ok) {
    throw new Error('expected preparation');
  }
  return toMaintainerReviewedAdvisorySubmissionPersistenceCommand(prepared.prepared);
}

function clientThatMustNotStart(): PrismaClient {
  return {
    $transaction: () => {
      throw new Error('transaction started');
    },
  } as unknown as PrismaClient;
}

describe('maintainer-reviewed advisory submission adapter boundary', () => {
  it('keeps the lock prefix aligned with user disablement and grant revocation', () => {
    expect(MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_LOCK_ORDER.slice(0, 4)).toEqual([
      'validate_command',
      'enable_transaction_local_submission_setting',
      'lock_submitter_user',
      'lock_instance_advisory_grants',
    ]);
  });

  it('derives fingerprints inside the transaction and does not use the OSV replay helper', () => {
    const source = readFileSync(
      path.join(here, 'maintainer-reviewed-advisory-submission-persistence.ts'),
      'utf8',
    );
    expect(source).toContain('localMaintainerReviewedSubmissionReplayFingerprint');
    expect(source).toContain("set_config(${SUBMISSION_SETTING}, 'on', true)");
    expect(source).not.toContain('advisoryRevisionReplayFingerprint');
    expect(source).toContain('INSERT INTO "advisory_revision_range_event"');
    expect(source).not.toContain('osv_source_license_registry');
    expect(source).not.toContain('osv_generation_bound_retrieval_policy');
    expect(source).not.toContain('patchpilot.instance_advisory_authority_grant');
    expect(source).not.toContain('parseInstanceAdvisoryAuthorityCommand');
    expect(source).not.toContain('createInstanceAdvisoryAuthorityPersistence');
    expect(source).not.toContain('patchpilot.instance_advisory_user_status');
    expect(source).not.toContain('concurrency_conflict');
    expect(source).not.toContain('INSERT INTO "finding"');
    expect(source).not.toContain('INSERT INTO "finding_observation"');
    expect(source).not.toContain('INSERT INTO "maintainer_reviewed_advisory_approval"');
    expect(source).not.toContain('INSERT INTO "reviewer_capability_issuance"');
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
    ];
    for (const relative of files) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      expect(source).not.toContain('createMaintainerReviewedAdvisorySubmissionPersistence');
      expect(source).not.toContain('maintainer-reviewed-advisory-submission');
    }
  });

  it('rejects caller fingerprints, extra authority fields, and unparseable principals before a transaction', async () => {
    const persistence =
      createMaintainerReviewedAdvisorySubmissionPersistence(clientThatMustNotStart());
    const legal = command();
    const extra = { ...legal, organizationId: '11111111-1111-4111-8111-111111111111' };
    expect(await persistence.submit(extra)).toEqual({ outcome: 'invalid_command' });
    expect(
      await persistence.submit({
        ...legal,
        fingerprints: { ...legal.fingerprints, contentFingerprint: 'a'.repeat(64) },
      }),
    ).toEqual({ outcome: 'internal_failure' });
    expect(
      await persistence.submit({
        ...legal,
        trustedSubmitterUserId: 'not-a-user',
      }),
    ).toEqual({ outcome: 'authority_required' });
    expect(JSON.stringify(await persistence.submit(extra))).not.toContain('organizationId');
  });

  it('translates persistence failures without SQL or a concurrency outcome', () => {
    const classified = [
      classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(
        new Error('code: "23505" duplicate'),
      ),
      classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(
        new Error('SQLSTATE 40001 serialization'),
      ),
      classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(new Error('ECONNREFUSED')),
      classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(
        new Prisma.PrismaClientKnownRequestError('unique', {
          code: 'P2002',
          clientVersion: 'test',
        }),
      ),
      classifyMaintainerReviewedAdvisorySubmissionPersistenceFailure(
        new Error('constraint advisory_revision'),
      ),
    ];
    expect(classified).toEqual([
      'uniqueness',
      'transaction_aborted',
      'database_unavailable',
      'uniqueness',
      'internal_failure',
    ]);
    expect(JSON.stringify(classified)).not.toContain('concurrency_conflict');
    expect(JSON.stringify(classified)).not.toContain('advisory_revision');
  });
});
