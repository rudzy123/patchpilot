import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';

import {
  CSRF_TOKEN_FIXTURE,
  createFakeAuthApi,
  ownerOrganizationFixture,
  publicOrganizationFixture,
  sessionFixture,
} from '../../../test/auth-fixtures';
import { FINDING_ID } from '../../../test/finding-fixtures';
import { renderWithAuth } from '../../../test/render-with-auth';

import { FindingPrioritySection } from './finding-priority-section';

function ownerApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture({ organization: ownerOrganizationFixture })),
    ...overrides,
  });
}

describe('FindingPrioritySection', () => {
  it('shows Not calculated and posts an empty body for an owner', async () => {
    const authApi = ownerApi({
      calculateFindingPriority: vi.fn(async () => ({
        schemaVersion: 'finding_risk_calculation_v1' as const,
        status: 'calculated' as const,
        findingId: FINDING_ID,
        riskCalculationId: '12121212-1212-4212-8212-121212121212',
        calculationReason: 'initial' as const,
      })),
    });
    renderWithAuth(<FindingPrioritySection findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('Not calculated')).toBeInTheDocument();
    expect(screen.queryByText('P4')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Calculate priority' }));
    expect(await screen.findByText('Not calculated')).toBeInTheDocument();
    expect(authApi.calculateFindingPriority).toHaveBeenCalledWith(FINDING_ID, CSRF_TOKEN_FIXTURE);
    expect(window.localStorage.length).toBe(0);
  });

  it('withholds the calculate control from an admin', async () => {
    const authApi = createFakeAuthApi({
      readSession: vi.fn(async () =>
        sessionFixture({ organization: { ...publicOrganizationFixture, role: 'admin' } }),
      ),
    });
    renderWithAuth(<FindingPrioritySection findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('Not calculated')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Calculate priority' })).not.toBeInTheDocument();
  });

  it('shows policy unavailability without the not-calculated text', async () => {
    const authApi = ownerApi({
      readFindingPriority: vi.fn(async () => {
        throw {
          status: 503,
          code: 'internal',
          message: 'Priority policy is unavailable.',
        };
      }),
    });
    renderWithAuth(<FindingPrioritySection findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByRole('alert')).toHaveTextContent('Priority policy is unavailable.');
    expect(screen.queryByText('Not calculated')).not.toBeInTheDocument();
  });

  it('posts an owner review and keeps the calculated band when the review fails', async () => {
    const reason = 'working-band-note';
    const authApi = ownerApi({
      readFindingPriority: vi.fn(async () => calculatedPriority()),
      recordFindingPriorityReview: vi.fn(async () => {
        throw { status: 400, code: 'validation', message: 'Invalid request.' };
      }),
    });
    renderWithAuth(<FindingPrioritySection findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByText('P2')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: reason } });
    fireEvent.click(screen.getByRole('button', { name: 'Record review' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid request.');
    expect(screen.getByText('P2')).toBeInTheDocument();
    expect(authApi.recordFindingPriorityReview).toHaveBeenCalledWith(
      FINDING_ID,
      CSRF_TOKEN_FIXTURE,
      {
        riskCalculationId: '12121212-1212-4212-8212-121212121212',
        supersedesReviewId: null,
        decision: 'accepted',
        reason,
      },
    );
  });
});

function calculatedPriority() {
  return {
    schemaVersion: 'finding_priority_v1' as const,
    status: 'calculated' as const,
    findingId: FINDING_ID,
    calculation: {
      riskCalculationId: '12121212-1212-4212-8212-121212121212',
      calculatedAt: '2026-11-04T18:00:00.000Z',
      calculationReason: 'initial' as const,
      engineVersion: '@patchpilot/policy-engine@1',
      riskPolicyId: '55555555-5555-4555-8555-555555555555',
      policyKey: 'patchpilot.builtin.v0',
      policyVersion: 2,
      policyDefinitionSha256: 'ab'.repeat(32),
      priority: 60,
      priorityBand: 'P2' as const,
      escalationRecommendation: false,
      escalationReasons: [],
      dueDateRecommendationDays: 30,
      factors: [],
      rules: [],
    },
    comparability: 'reference' as const,
    inputsChanged: { status: 'none_detected' as const, signals: [] },
    review: { status: 'none' as const, priorReviewExists: false as const },
  };
}
