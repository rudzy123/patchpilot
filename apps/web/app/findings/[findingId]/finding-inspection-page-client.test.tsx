import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';

import { OrganizationSelector } from '../../../components/organization-selector';
import {
  ASSET_ID,
  createFakeAuthApi,
  ownerOrganizationFixture,
  publicOrganizationFixture,
  secondOrganizationFixture,
  sessionFixture,
} from '../../../test/auth-fixtures';
import { FINDING_ID, inspectionFixture } from '../../../test/finding-fixtures';
import { renderWithAuth } from '../../../test/render-with-auth';
import { navigationMocks } from '../../../test/router-mock';

import { FindingInspectionPageClient } from './finding-inspection-page-client';

function ownerApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture({ organization: ownerOrganizationFixture })),
    inspectControlledFinding: vi.fn(async () => inspectionFixture),
    ...overrides,
  });
}

describe('FindingInspectionPageClient', () => {
  it('renders only the safe projection for an owner', async () => {
    const authApi = ownerApi();
    const { container } = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi,
    });

    expect(await screen.findByRole('heading', { level: 1, name: 'Finding' })).toBeInTheDocument();
    expect(await screen.findByText('<script>asset</script>')).toBeInTheDocument();
    expect(screen.getByText('<component>')).toBeInTheDocument();
    expect(screen.getByText('<namespace>')).toBeInTheDocument();
    expect(screen.getByText('npm')).toBeInTheDocument();
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(screen.getByText('Open')).toBeInTheDocument();
    expect(screen.getByText('<version>')).toBeInTheDocument();
    expect(screen.getByText('Omitted distinct versions: 2')).toBeInTheDocument();
    expect(screen.getByText('Distinct affected versions: 4')).toBeInTheDocument();
    expect(screen.getByText('2026-08-28T13:00:00.000Z UTC')).toBeInTheDocument();
    expect(screen.getByText(/finding_creation_policy_v1 version 1/)).toBeInTheDocument();
    expect(screen.getByText('Historical')).toBeInTheDocument();
    expect(screen.getByText(/independent approval/)).toBeInTheDocument();
    expect(screen.getByText(/unavailable in this workflow/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open asset' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_ID}`,
    );
    expect(screen.getByRole('link', { name: 'Review controlled Finding targets' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_ID}/findings/targets`,
    );
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(
      screen.queryByRole('button', { name: /assign|suppress|remediat|verify|risk/i }),
    ).not.toBeInTheDocument();
    expect(authApi.inspectControlledFinding).toHaveBeenCalledWith(FINDING_ID);
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
  });

  it('lets an admin inspect and withholds the projection from member and viewer', async () => {
    const adminApi = createFakeAuthApi({
      readSession: vi.fn(async () =>
        sessionFixture({
          organization: { ...publicOrganizationFixture, role: 'admin' },
        }),
      ),
      inspectControlledFinding: vi.fn(async () => inspectionFixture),
    });
    const adminView = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi: adminApi,
    });
    expect(await screen.findByText('Historical')).toBeInTheDocument();
    expect(adminApi.inspectControlledFinding).toHaveBeenCalledTimes(1);
    adminView.unmount();

    for (const role of ['member', 'viewer'] as const) {
      const authApi = createFakeAuthApi({
        readSession: vi.fn(async () =>
          sessionFixture({ organization: { ...publicOrganizationFixture, role } }),
        ),
      });
      const view = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
        authApi,
      });
      expect(
        await screen.findByText(
          'Controlled Finding targets are unavailable for your role in this organization.',
        ),
      ).toBeInTheDocument();
      await waitFor(() => {
        expect(authApi.inspectControlledFinding).not.toHaveBeenCalled();
      });
      expect(screen.queryByText('<component>')).not.toBeInTheDocument();
      view.unmount();
    }
  });

  it('shows not found for an absent Finding and for an invalid id without a request', async () => {
    const missing = ownerApi({
      inspectControlledFinding: vi.fn(async () => {
        throw { status: 404, code: 'not_found', message: 'Not found.' };
      }),
    });
    const missingView = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi: missing,
    });
    expect(await screen.findByRole('alert')).toHaveTextContent('Not found.');
    expect(screen.queryByText('<component>')).not.toBeInTheDocument();
    missingView.unmount();

    const invalid = ownerApi();
    renderWithAuth(<FindingInspectionPageClient findingId="not-a-uuid" />, { authApi: invalid });
    expect(await screen.findByRole('alert')).toHaveTextContent('Not found.');
    expect(invalid.inspectControlledFinding).not.toHaveBeenCalled();
  });

  it('shows the same unavailable state for an inspection 403 without partial data', async () => {
    const authApi = ownerApi({
      inspectControlledFinding: vi.fn(async () => {
        throw {
          status: 403,
          code: 'forbidden',
          message: 'denied',
          requestId: 'req',
          correlationId: 'corr',
        };
      }),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(
      await screen.findByText(
        'Controlled Finding targets are unavailable for your role in this organization.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText('<script>asset</script>')).not.toBeInTheDocument();
  });

  it('shows temporary unavailability with safe request identifiers', async () => {
    const authApi = ownerApi({
      inspectControlledFinding: vi.fn(async () => {
        throw {
          status: 503,
          code: 'internal',
          message: 'Finding operator is temporarily unavailable.',
          requestId: 'req-503',
          correlationId: 'corr-503',
        };
      }),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily unavailable');
    expect(screen.getByRole('alert')).toHaveTextContent('Request ID: req-503');
    expect(screen.getByRole('alert')).toHaveTextContent('Correlation ID: corr-503');
    expect(screen.queryByText(/SELECT/)).not.toBeInTheDocument();
  });

  it('uses neutral copy for unusable evidence and ignores a stale organization response', async () => {
    const unusable = ownerApi({
      inspectControlledFinding: vi.fn(async () => {
        throw {
          status: 422,
          code: 'unprocessable_evidence',
          message: 'The evidence cannot be used for this request.',
          requestId: 'req-422',
          correlationId: 'corr-422',
        };
      }),
    });
    const unusableView = renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, {
      authApi: unusable,
    });
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The evidence cannot be used for this request.',
    );
    expect(screen.queryByText('<component>')).not.toBeInTheDocument();
    expect(screen.queryByText(/temporarily unavailable/)).not.toBeInTheDocument();
    unusableView.unmount();

    let resolveFirst: ((value: typeof inspectionFixture) => void) | undefined;
    let calls = 0;
    const ownerB = { ...secondOrganizationFixture, role: 'owner' as const };
    const authApi = ownerApi({
      listOrganizations: vi.fn(async () => ({
        organizations: [ownerOrganizationFixture, ownerB],
      })),
      selectOrganization: vi.fn(async () => sessionFixture({ organization: ownerB })),
      inspectControlledFinding: vi.fn(() => {
        calls += 1;
        if (calls === 1) {
          return new Promise<typeof inspectionFixture>((resolve) => {
            resolveFirst = resolve;
          });
        }
        return Promise.resolve({
          ...inspectionFixture,
          asset: { ...inspectionFixture.asset, displayName: 'Second organization asset' },
        });
      }),
    });
    renderWithAuth(
      <>
        <OrganizationSelector onSelected={() => undefined} />
        <FindingInspectionPageClient findingId={FINDING_ID} />
      </>,
      { authApi },
    );
    await waitFor(() => {
      expect(authApi.inspectControlledFinding).toHaveBeenCalledTimes(1);
    });
    fireEvent.change(screen.getByLabelText('Organization'), { target: { value: ownerB.id } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('Second organization asset')).toBeInTheDocument();
    resolveFirst?.(inspectionFixture);
    await waitFor(() => {
      expect(screen.queryByText('<script>asset</script>')).not.toBeInTheDocument();
    });
    expect(navigationMocks.push).not.toHaveBeenCalled();
  });

  it('uses the session-expired page for 401', async () => {
    const authApi = ownerApi({
      inspectControlledFinding: vi.fn(async () => {
        throw { status: 401, code: 'unauthorized', message: 'expired' };
      }),
    });
    renderWithAuth(<FindingInspectionPageClient findingId={FINDING_ID} />, { authApi });
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/session-expired');
    });
  });
});
