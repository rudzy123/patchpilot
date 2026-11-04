import { describe, expect, it, vi } from 'vitest';

import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
} from './persistence-port.js';
import { PRIORITY_CALCULATION_ENGINE_VERSION } from './catalog.js';
import { encodeRemediationQueueCursor } from './remediation-queue-cursor.js';
import {
  createReadRemediationQueueUseCase,
  type ReadRemediationQueueDependencies,
} from './remediation-queue.js';
import type {
  RemediationQueuePersistencePort,
  RemediationQueueRawRow,
  RemediationQueueReadResult,
} from './remediation-queue-port.js';

const USER = '11111111-1111-4111-8111-111111111111';
const ORG = '33333333-3333-4333-8333-333333333333';
const MEMBERSHIP = '44444444-4444-4444-8444-444444444444';
const ASSET = '22222222-2222-4222-8222-222222222222';
const FINDING = '55555555-5555-4555-8555-555555555551';
const POLICY = '55555555-5555-4555-8555-555555555555';
const HASH = 'ab'.repeat(32);
const OTHER_HASH = 'cd'.repeat(32);
const AT = '2026-11-04T18:00:00.000Z';

function actor(role: 'owner' | 'admin' | 'member' | 'viewer') {
  return {
    userId: USER,
    sessionId: 'session-1',
    organizationId: ORG,
    membershipId: MEMBERSHIP,
    role,
  };
}

function command(
  role: 'owner' | 'admin' | 'member' | 'viewer',
  overrides: Record<string, unknown> = {},
) {
  return {
    actor: actor(role),
    command: {
      section: 'ranked',
      limit: 20,
      cursor: null,
      ...overrides,
    },
  };
}

function rankedRow(overrides: Partial<RemediationQueueRawRow> = {}): RemediationQueueRawRow {
  return {
    findingId: FINDING,
    assetId: ASSET,
    assetName: 'queue <asset>',
    componentName: 'reviewed-npm-widget',
    componentVersion: '1.1.0',
    vulnerabilityPublicId: 'OSV-1',
    firstObservedAt: AT,
    section: 'ranked',
    humanReview: { status: 'none', priorReviewExists: false },
    calculation: {
      riskPolicyId: POLICY,
      policyKey: BUILTIN_PRIORITY_POLICY_KEY,
      policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
      policyDefinitionSha256: HASH,
      calculatedAt: AT,
      calculationEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      priorityText: '68',
      priority: 68,
      priorityBand: 'P2',
      escalationRecommended: false,
      kevListed: true,
      severityText: '100',
      severityPercent: 100,
      storedKevGenerationId: null,
      lastObservedAt: AT,
      assetUpdatedAt: AT,
    },
    ...overrides,
  };
}

function pageResult(
  rows: readonly RemediationQueueRawRow[],
  counts = { ranked: rows.length, incomparable: 0, not_calculated: 0 },
  findingCount = counts.ranked + counts.incomparable + counts.not_calculated,
): RemediationQueueReadResult {
  return {
    kind: 'page',
    asOf: AT,
    publishedPolicyId: POLICY,
    publishedPolicyKey: BUILTIN_PRIORITY_POLICY_KEY,
    publishedPolicyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
    publishedDefinition: { schemaVersion: 2 },
    activeKevGenerationId: null,
    counts,
    findingCount,
    rows,
    hasMore: false,
  };
}

function dependencies(read: RemediationQueuePersistencePort['readRemediationQueue']): {
  dependencies: ReadRemediationQueueDependencies;
  findPublished: ReturnType<typeof vi.fn>;
  readQueue: ReturnType<typeof vi.fn>;
} {
  const findPublished = vi.fn(async () => ({
    kind: 'found' as const,
    policy: {
      id: POLICY,
      policyKey: BUILTIN_PRIORITY_POLICY_KEY,
      version: BUILTIN_PRIORITY_POLICY_VERSION,
      definition: { schemaVersion: 2 },
    },
  }));
  const readQueue = vi.fn(read);
  return {
    findPublished,
    readQueue,
    dependencies: {
      persistence: {
        findPublishedBuiltinPriorityPolicy: findPublished,
        readRemediationQueue: readQueue,
      },
      admittedPairs: [
        {
          engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
          policyDefinitionSha256: HASH,
          validationEntryId: 'V-test',
        },
      ],
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition: () => HASH,
    },
  };
}

describe('read remediation queue', () => {
  it('returns one ranked row and keeps the asset name unchanged', async () => {
    const { dependencies: deps } = dependencies(async () => pageResult([rankedRow()]));
    const result = await createReadRemediationQueueUseCase(deps).execute(command('owner'));
    expect(result.kind).toBe('page');
    if (result.kind !== 'page') {
      return;
    }
    expect(result.page.rows).toEqual([
      expect.objectContaining({
        assetName: 'queue <asset>',
        priorityBand: 'P2',
        priority: 68,
        humanReview: { status: 'none', priorReviewExists: false },
      }),
    ]);
    expect(result.page.reference.policyDefinitionSha256).toBe(HASH);
    const row = result.page.rows[0];
    expect(row).not.toHaveProperty('dueDateRecommendationDays');
  });

  it('denies members and viewers and ignores a caller organization', async () => {
    const { dependencies: deps, readQueue } = dependencies(async () => pageResult([]));
    const member = await createReadRemediationQueueUseCase(deps).execute(command('member'));
    const viewer = await createReadRemediationQueueUseCase(deps).execute(command('viewer'));
    const crossed = await createReadRemediationQueueUseCase(deps).execute({
      ...command('owner'),
      organizationId: '99999999-9999-4999-8999-999999999999',
    });
    expect(member).toEqual({ kind: 'unauthorized' });
    expect(viewer).toEqual({ kind: 'unauthorized' });
    expect(crossed).toEqual({ kind: 'unauthorized' });
    expect(readQueue).not.toHaveBeenCalled();
  });

  it('does not read Findings when the published policy is not admitted', async () => {
    const { dependencies: deps, readQueue } = dependencies(async () => pageResult([]));
    const blocked = {
      ...deps,
      admittedPairs: [],
    };
    const result = await createReadRemediationQueueUseCase(blocked).execute(command('admin'));
    expect(result).toEqual({ kind: 'priority_policy_unavailable' });
    expect(readQueue).not.toHaveBeenCalled();
  });

  it('fails closed when a ranked row has no calculation or the counts do not partition', async () => {
    const missing = dependencies(async () =>
      pageResult([{ ...rankedRow(), calculation: null }], {
        ranked: 1,
        incomparable: 0,
        not_calculated: 0,
      }),
    );
    const broken = await createReadRemediationQueueUseCase(missing.dependencies).execute(
      command('owner'),
    );
    expect(broken).toEqual({ kind: 'unavailable' });

    const counts = dependencies(async () =>
      pageResult([rankedRow()], { ranked: 1, incomparable: 0, not_calculated: 0 }, 2),
    );
    const mismatched = await createReadRemediationQueueUseCase(counts.dependencies).execute(
      command('owner'),
    );
    expect(mismatched).toEqual({ kind: 'unavailable' });
  });

  it('rejects a malformed cursor and a cursor for another section or hash', async () => {
    const { dependencies: deps, readQueue } = dependencies(async () => pageResult([rankedRow()]));
    const useCase = createReadRemediationQueueUseCase(deps);
    const malformed = await useCase.execute(command('owner', { cursor: '%%%' }));
    expect(malformed).toEqual({ kind: 'invalid_command' });
    const otherSection = encodeRemediationQueueCursor({
      section: 'not_calculated',
      policyDefinitionSha256: HASH,
      engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      firstObservedAt: AT,
      findingId: FINDING,
    });
    const staleSection = await useCase.execute(command('owner', { cursor: otherSection }));
    expect(staleSection).toEqual({ kind: 'stale_cursor' });
    const otherHash = encodeRemediationQueueCursor({
      section: 'ranked',
      policyDefinitionSha256: OTHER_HASH,
      engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      priorityText: '68',
      escalationRecommended: false,
      kevListed: true,
      severityText: '100',
      firstObservedAt: AT,
      findingId: FINDING,
    });
    const staleHash = await useCase.execute(command('owner', { cursor: otherHash }));
    expect(staleHash).toEqual({ kind: 'stale_cursor' });
    expect(readQueue).not.toHaveBeenCalled();
  });

  it('keeps not_calculated rows free of band fields and marks incomparable rows', async () => {
    const notCalculated = dependencies(async (query) => {
      if (query.section === 'not_calculated') {
        return pageResult(
          [
            {
              ...rankedRow(),
              section: 'not_calculated',
              calculation: null,
            },
          ],
          { ranked: 0, incomparable: 0, not_calculated: 1 },
        );
      }
      return pageResult([], { ranked: 0, incomparable: 0, not_calculated: 1 });
    });
    const absent = await createReadRemediationQueueUseCase(notCalculated.dependencies).execute(
      command('owner', { section: 'not_calculated' }),
    );
    expect(absent.kind).toBe('page');
    if (absent.kind === 'page') {
      expect(absent.page.rows[0]).toEqual({
        findingId: FINDING,
        assetId: ASSET,
        assetName: 'queue <asset>',
        componentName: 'reviewed-npm-widget',
        componentVersion: '1.1.0',
        vulnerabilityPublicId: 'OSV-1',
        humanReview: { status: 'none', priorReviewExists: false },
      });
    }

    const base = rankedRow();
    const calculation = base.calculation;
    if (calculation === null) {
      throw new Error('ranked fixture includes a calculation');
    }
    const incomparable = dependencies(async () =>
      pageResult(
        [
          {
            ...rankedRow({ section: 'incomparable' }),
            calculation: {
              ...calculation,
              policyDefinitionSha256: OTHER_HASH,
            },
          },
        ],
        { ranked: 0, incomparable: 1, not_calculated: 0 },
      ),
    );
    const compared = await createReadRemediationQueueUseCase(incomparable.dependencies).execute(
      command('owner', { section: 'incomparable' }),
    );
    expect(compared.kind).toBe('page');
    if (compared.kind === 'page') {
      expect(compared.page.rows[0]).toEqual(
        expect.objectContaining({ comparisonMessage: 'recalculation required for comparison' }),
      );
    }
  });
});
