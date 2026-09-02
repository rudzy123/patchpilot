import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { ORGANIZATION_CONTEXT_REQUIRED, PERMISSION_DENIED } from '../assets/errors.js';
import { INTELLIGENCE_READ_PERMISSION } from './constants.js';
import { INTELLIGENCE_STATUS_INCONSISTENT, INTELLIGENCE_STATUS_UNAVAILABLE } from './errors.js';
import type { CisaKevStatusSnapshot, IntelligenceStatusActor } from './provider-status.js';
import {
  createIntelligenceStatusQueryUseCase,
  type IntelligenceProviderStatusReadPort,
  type IntelligenceStatusReadResult,
} from './status-query.js';

const NOW = new Date('2026-09-02T12:00:00.000Z');
const SUCCESS_AT = new Date('2026-08-31T16:00:00.000Z');
const THRESHOLD = 259_200;
const GENERATION_ID = '11111111-1111-4111-8111-111111111111';

function actor(
  permissions: readonly string[] = [INTELLIGENCE_READ_PERMISSION],
  organizationId: string | null = 'org-1',
): IntelligenceStatusActor {
  return {
    userId: 'user-1',
    sessionId: 'session-1',
    organizationId,
    membershipId: organizationId === null ? null : 'membership-1',
    permissions,
  };
}

function acceptedSnapshot(): CisaKevStatusSnapshot {
  return {
    sourceState: 'enabled',
    lastSuccessfulSyncAt: SUCCESS_AT,
    lastAttemptAt: SUCCESS_AT,
    lastFailureAt: null,
    lastFailureCode: null,
    activeGenerationId: GENERATION_ID,
    generation: {
      state: 'active',
      catalogVersion: '2026.08.31',
      catalogReleasedAt: SUCCESS_AT,
      expectedEntryCount: 1687,
    },
  };
}

function fakePort(
  result: IntelligenceStatusReadResult | (() => Promise<IntelligenceStatusReadResult>),
): IntelligenceProviderStatusReadPort & { calls: number; wrote: boolean } {
  const port = {
    calls: 0,
    wrote: false,
    async loadCisaKevStatus(): Promise<IntelligenceStatusReadResult> {
      port.calls += 1;
      return typeof result === 'function' ? result() : result;
    },
  };
  return port;
}

describe('intelligence status query', () => {
  it('synthesizes OSV without a database read', async () => {
    const status = fakePort({ kind: 'found', snapshot: acceptedSnapshot() });
    const query = createIntelligenceStatusQueryUseCase({
      status,
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const result = await query.get({ actor: actor(), provider: 'osv' });
    expect(result.ok).toBe(true);
    expect(status.calls).toBe(0);
    expect(status.wrote).toBe(false);
    if (result.ok) {
      expect(result.value.provider).toBe('osv');
      expect(result.value.healthStatus).toBe('deferred');
      expect(result.value.lastAttemptAt).toBeNull();
      expect(result.value.lastSafeFailureCode).toBeNull();
    }
  });

  it('loads CISA once for the list and orders cisa_kev then osv', async () => {
    const status = fakePort({ kind: 'found', snapshot: acceptedSnapshot() });
    const query = createIntelligenceStatusQueryUseCase({
      status,
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const listed = await query.list({ actor: actor() });
    expect(status.calls).toBe(1);
    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.value.providers.map((item) => item.provider)).toEqual(['cisa_kev', 'osv']);
      expect(listed.value.providers[0]?.healthStatus).toBe('current');
      expect(listed.value.providers[1]?.healthStatus).toBe('deferred');
    }
  });

  it('returns identical payloads for two organization memberships', async () => {
    const status = fakePort({ kind: 'found', snapshot: acceptedSnapshot() });
    const query = createIntelligenceStatusQueryUseCase({
      status,
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const first = await query.get({
      actor: { ...actor(), organizationId: 'org-a', membershipId: 'mem-a' },
      provider: 'cisa_kev',
    });
    const second = await query.get({
      actor: { ...actor(), organizationId: 'org-b', membershipId: 'mem-b' },
      provider: 'cisa_kev',
    });
    expect(first).toEqual(second);
    expect(JSON.stringify(first)).not.toContain('org-a');
    expect(JSON.stringify(second)).not.toContain('org-b');
  });

  it('denies missing organization context and unrelated read permissions', async () => {
    const status = fakePort({ kind: 'found', snapshot: acceptedSnapshot() });
    const query = createIntelligenceStatusQueryUseCase({
      status,
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    expect(
      await query.get({ actor: actor([INTELLIGENCE_READ_PERMISSION], null), provider: 'osv' }),
    ).toEqual({ ok: false, error: ORGANIZATION_CONTEXT_REQUIRED });
    expect(await query.get({ actor: actor(['integration:read']), provider: 'osv' })).toEqual({
      ok: false,
      error: PERMISSION_DENIED,
    });
    expect(status.calls).toBe(0);
  });

  it('maps missing source and database failure to unavailable and pointer issues to inconsistent', async () => {
    const missing = createIntelligenceStatusQueryUseCase({
      status: fakePort({ kind: 'missing_source' }),
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const unavailable = createIntelligenceStatusQueryUseCase({
      status: fakePort({ kind: 'unavailable' }),
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const inconsistent = createIntelligenceStatusQueryUseCase({
      status: fakePort({ kind: 'inconsistent' }),
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    const throwing = createIntelligenceStatusQueryUseCase({
      status: fakePort(async () => {
        throw new Error('database down');
      }),
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
    });
    expect(await missing.get({ actor: actor(), provider: 'cisa_kev' })).toEqual({
      ok: false,
      error: INTELLIGENCE_STATUS_UNAVAILABLE,
    });
    expect(await unavailable.get({ actor: actor(), provider: 'cisa_kev' })).toEqual({
      ok: false,
      error: INTELLIGENCE_STATUS_UNAVAILABLE,
    });
    expect(await inconsistent.get({ actor: actor(), provider: 'cisa_kev' })).toEqual({
      ok: false,
      error: INTELLIGENCE_STATUS_INCONSISTENT,
    });
    expect(await throwing.get({ actor: actor(), provider: 'cisa_kev' })).toEqual({
      ok: false,
      error: INTELLIGENCE_STATUS_UNAVAILABLE,
    });
  });

  it('does not mutate status while reading enabled, disabled, and historical states', async () => {
    const status = fakePort({
      kind: 'found',
      snapshot: {
        sourceState: 'disabled',
        lastSuccessfulSyncAt: SUCCESS_AT,
        lastAttemptAt: SUCCESS_AT,
        lastFailureAt: null,
        lastFailureCode: null,
        activeGenerationId: GENERATION_ID,
        generation: {
          state: 'active',
          catalogVersion: '2026.08.31',
          catalogReleasedAt: SUCCESS_AT,
          expectedEntryCount: 1687,
        },
      },
    });
    const warnings: string[] = [];
    const query = createIntelligenceStatusQueryUseCase({
      status,
      kevEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: () => NOW,
      logger: {
        warn(_bindings, message) {
          warnings.push(message);
        },
      },
    });
    const result = await query.get({ actor: actor(), provider: 'cisa_kev' });
    expect(result.ok).toBe(true);
    expect(status.wrote).toBe(false);
    expect(status.calls).toBe(1);
    expect(warnings).toEqual(['KEV runtime enablement differs from persisted source state']);
    if (result.ok) {
      expect(result.value.runtimeEnabled).toBe(true);
      expect(result.value.healthStatus).toBe('current');
    }
  });

  it('keeps status-query and provider-status free of provider I/O and Finding imports', () => {
    const directory = path.dirname(fileURLToPath(import.meta.url));
    for (const fileName of ['status-query.ts', 'provider-status.ts', 'public-failure-codes.ts']) {
      const source = readFileSync(path.join(directory, fileName), 'utf8');
      expect(source).not.toMatch(
        /ioredis|bullmq|@aws-sdk|S3Client|undici|\bfetch\s*\(|https\.request/,
      );
      expect(source).not.toContain('createCisaKevSynchronizationService');
      expect(source).not.toContain('FindingRepository');
      expect(source).not.toContain('FindingObservationRepository');
      expect(source).not.toContain('VulnerabilityRepository');
      expect(source).not.toContain('ComponentRepository');
    }
  });
});
