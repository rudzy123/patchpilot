import type { RemediationQueueResponse } from '@patchpilot/contracts';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { isAuthRequestError } from '../../lib/auth-api';
import { QUEUE_COMPARISON_MESSAGE, QUEUE_POLICY_UNAVAILABLE } from '../../lib/remediation-queue';
import {
  createFakeAuthApi,
  ownerOrganizationFixture,
  sessionFixture,
} from '../../test/auth-fixtures';
import { renderWithAuth } from '../../test/render-with-auth';

import { RemediationQueuePageClient } from './remediation-queue-page-client';

const FINDING = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const SECOND = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const ASSET = '44444444-4444-4444-8444-444444444444';
const POLICY = '55555555-5555-4555-8555-555555555555';
const HASH = 'ab'.repeat(32);
const AS_OF = '2026-11-04T18:00:00.000Z';

function page(
  section: RemediationQueueResponse['section'],
  vulnerabilityPublicId: string,
  nextCursor: string | null = null,
): RemediationQueueResponse {
  const identity = {
    findingId: section === 'ranked' ? FINDING : SECOND,
    assetId: ASSET,
    assetName: 'widget <untrusted>',
    componentName: 'reviewed-npm-widget',
    componentVersion: '1.1.0',
    vulnerabilityPublicId,
    humanReview: { status: 'none' as const, priorReviewExists: false as const },
  };
  const shared = {
    schemaVersion: 'remediation_queue_v1' as const,
    asOf: AS_OF,
    reference: {
      policyKey: 'patchpilot.builtin.v0' as const,
      policyVersion: 2 as const,
      policyDefinitionSha256: HASH,
      engineVersion: '@patchpilot/policy-engine@1' as const,
    },
    counts: { ranked: 1, incomparable: 1, not_calculated: 1 },
    limit: 20,
    nextCursor,
  };
  if (section === 'not_calculated') {
    return { ...shared, section, rows: [identity] };
  }
  const calculated = {
    ...identity,
    priorityBand: 'P2' as const,
    priority: 60,
    policy: {
      riskPolicyId: POLICY,
      policyKey: 'patchpilot.builtin.v0',
      policyVersion: 2,
      policyDefinitionSha256: HASH,
    },
    calculatedAt: AS_OF,
    inputsChanged: { status: 'none_detected' as const, signals: [] },
  };
  if (section === 'incomparable') {
    return {
      ...shared,
      section,
      rows: [{ ...calculated, comparisonMessage: QUEUE_COMPARISON_MESSAGE }],
    };
  }
  return { ...shared, section, rows: [calculated] };
}

describe('remediation queue page', () => {
  it('keeps the three sections separate for an owner', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: ownerOrganizationFixture })),
      readRemediationQueue: vi.fn(async (query: { section: RemediationQueueResponse['section'] }) =>
        page(query.section, `OSV-${query.section}`),
      ),
    });
    renderWithAuth(<RemediationQueuePageClient />, { authApi });
    const ranked = await screen.findByRole('region', { name: 'Ranked' });
    expect(within(ranked).getByRole('link', { name: 'OSV-ranked' })).toHaveAttribute(
      'href',
      `/findings/${FINDING}`,
    );
    expect(screen.getAllByText('widget <untrusted>').length).toBeGreaterThan(0);
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    const incomparable = screen.getByRole('region', { name: 'Not comparable' });
    const notCalculated = screen.getByRole('region', { name: 'Not calculated' });
    expect(within(ranked).queryByText(QUEUE_COMPARISON_MESSAGE)).not.toBeInTheDocument();
    expect(within(incomparable).getByText(QUEUE_COMPARISON_MESSAGE)).toBeInTheDocument();
    expect(within(notCalculated).getByText(/no stored calculation/)).toBeInTheDocument();
    expect(within(notCalculated).queryByText(/P2/)).not.toBeInTheDocument();
    expect(authApi.readRemediationQueue).toHaveBeenCalledTimes(3);
  });

  it('does not request the queue for a member', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture()),
    });
    renderWithAuth(<RemediationQueuePageClient />, { authApi });
    expect(await screen.findByText('Permission denied.')).toBeInTheDocument();
    expect(authApi.readRemediationQueue).not.toHaveBeenCalled();
  });

  it('clears every section when the priority policy is unavailable', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: ownerOrganizationFixture })),
      readRemediationQueue: vi.fn(
        async (query: { section: RemediationQueueResponse['section'] }) => {
          if (query.section === 'ranked') {
            throw { status: 503, code: 'internal', message: QUEUE_POLICY_UNAVAILABLE };
          }
          return page(query.section, 'OSV-1');
        },
      ),
    });
    renderWithAuth(<RemediationQueuePageClient />, { authApi });
    expect(await screen.findByText(QUEUE_POLICY_UNAVAILABLE)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText('widget <untrusted>')).not.toBeInTheDocument();
    });
  });

  it('refetches a section once when the next page cursor is stale', async () => {
    const user = userEvent.setup();
    const calls: string[] = [];
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () => sessionFixture({ organization: ownerOrganizationFixture })),
      readRemediationQueue: vi.fn(
        async (query: { section: RemediationQueueResponse['section']; cursor?: string }) => {
          calls.push(`${query.section}:${query.cursor ?? ''}`);
          if (query.section === 'ranked' && query.cursor === undefined) {
            return page('ranked', 'OSV-1', 'cursor-1');
          }
          if (query.section === 'ranked' && query.cursor === 'cursor-1') {
            throw {
              status: 409,
              code: 'conflict',
              message: 'The page cursor is no longer current.',
            };
          }
          return page(query.section, 'OSV-NEXT');
        },
      ),
    });
    renderWithAuth(<RemediationQueuePageClient />, { authApi });
    await screen.findByRole('button', { name: 'Load more' });
    await user.click(screen.getByRole('button', { name: 'Load more' }));
    await waitFor(() => {
      expect(calls).toContain('ranked:');
      expect(calls).toContain('ranked:cursor-1');
      expect(calls.filter((call) => call === 'ranked:').length).toBe(2);
    });
    expect(isAuthRequestError({ status: 409, code: 'conflict', message: 'stale' })).toBe(true);
  });
});
