import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { OrganizationSelector } from '../../../../../components/organization-selector';
import {
  ASSET_ID,
  CSRF_TOKEN_FIXTURE,
  createFakeAuthApi,
  ownerOrganizationFixture,
  publicOrganizationFixture,
  secondOrganizationFixture,
  sessionFixture,
} from '../../../../../test/auth-fixtures';
import {
  COMPONENT_ID_2,
  EVIDENCE_A,
  EVIDENCE_B,
  FINDING_ID,
  VULNERABILITY_ID_2,
  acknowledgementFixture,
  discoveryPage,
  eligibleCandidate,
  existingCandidate,
  replayCandidate,
} from '../../../../../test/finding-fixtures';
import { renderWithAuth } from '../../../../../test/render-with-auth';
import { navigationMocks } from '../../../../../test/router-mock';

import { ControlledFindingTargetsPageClient } from './controlled-finding-targets-page-client';

const SECRET_ID = 'SHOULD-NOT-APPEAR';

function ownerApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () => sessionFixture({ organization: ownerOrganizationFixture })),
    listControlledFindingTargets: vi.fn(async () => discoveryPage([eligibleCandidate()])),
    ...overrides,
  });
}

function adminApi(overrides: Parameters<typeof createFakeAuthApi>[0] = {}) {
  return createFakeAuthApi({
    readSession: vi.fn(async () =>
      sessionFixture({
        organization: { ...publicOrganizationFixture, role: 'admin' },
      }),
    ),
    listControlledFindingTargets: vi.fn(async () =>
      discoveryPage([eligibleCandidate(), replayCandidate(), existingCandidate()]),
    ),
    ...overrides,
  });
}

describe('ControlledFindingTargetsPageClient', () => {
  it('loads one candidate page for an owner and renders versions as text', async () => {
    const authApi = ownerApi();
    const { container } = renderWithAuth(
      <ControlledFindingTargetsPageClient assetId={ASSET_ID} />,
      { authApi },
    );

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Controlled Finding targets' }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole('heading', { level: 2, name: 'Eligible for creation' }),
    ).toBeInTheDocument();
    const assetNav = screen.getByRole('navigation', { name: 'Asset' });
    expect(assetNav).toHaveTextContent('Assets');
    expect(assetNav.querySelector('a[href="/assets"]')).not.toBeNull();
    expect(screen.getByRole('link', { name: 'Payments' })).toHaveAttribute(
      'href',
      `/assets/${ASSET_ID}`,
    );
    expect(screen.queryByRole('link', { name: 'Findings' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(
      screen.getByRole('heading', { level: 2, name: 'Eligible for creation' }),
    ).toBeInTheDocument();
    expect(screen.getByText('1.0.0')).toBeInTheDocument();
    expect(screen.getByText('2.0.0')).toBeInTheDocument();
    expect(screen.getByText('Affected occurrence count: 2')).toBeInTheDocument();
    expect(screen.getByText('Other occurrence count: 4')).toBeInTheDocument();
    expect(screen.getByText('Omitted distinct versions: 3')).toBeInTheDocument();
    expect(screen.getByText('Distinct affected versions: 5')).toBeInTheDocument();
    expect(screen.getByText('The affected-version summary is truncated.')).toBeInTheDocument();
    expect(screen.getByText('Evidence records in this acknowledgement: 2')).toBeInTheDocument();
    expect(authApi.listControlledFindingTargets).toHaveBeenCalledWith(ASSET_ID);
    expect(authApi.getAsset).toHaveBeenCalledWith(ASSET_ID);
    expect(container.querySelector('script')).toBeNull();
    expect(
      screen.queryByRole('button', { name: /select all|create all/i }),
    ).not.toBeInTheDocument();
  });

  it('lets an admin review acknowledgements without a creation control', async () => {
    const user = userEvent.setup();
    const authApi = adminApi();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });

    expect(
      await screen.findByRole('heading', { name: 'Exact replay available' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Finding already recorded')).toBeInTheDocument();
    expect(screen.getByText(/Updating it is not available here/)).toBeInTheDocument();
    expect(screen.getAllByText('Creation requires an owner.')).toHaveLength(2);
    expect(screen.queryByRole('button', { name: /Review creation/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Review exact replay/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Open Finding' })).not.toBeInTheDocument();
    expect(screen.queryByText(EVIDENCE_A)).not.toBeInTheDocument();

    const disclosures = screen.getAllByRole('button', { name: 'Show evidence identifiers' });
    expect(disclosures[0]).toHaveAttribute('aria-expanded', 'false');
    const firstDisclosure = disclosures[0];
    if (firstDisclosure === undefined) {
      throw new Error('missing disclosure');
    }
    await user.click(firstDisclosure);
    expect(firstDisclosure).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText(EVIDENCE_A)).toBeInTheDocument();
    expect(screen.getByText(EVIDENCE_B)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: EVIDENCE_A })).not.toBeInTheDocument();
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
  });

  it('shows members and viewers an unavailable state without a data request', async () => {
    for (const role of ['member', 'viewer'] as const) {
      const authApi = createFakeAuthApi({
        readSession: vi.fn(async () =>
          sessionFixture({
            organization: { ...publicOrganizationFixture, role },
          }),
        ),
      });
      const view = renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, {
        authApi,
      });
      expect(
        await screen.findByText(
          'Controlled Finding targets are unavailable for your role in this organization.',
        ),
      ).toBeInTheDocument();
      await waitFor(() => {
        expect(authApi.listControlledFindingTargets).not.toHaveBeenCalled();
        expect(authApi.getAsset).not.toHaveBeenCalled();
      });
      view.unmount();
    }
  });

  it('does not request targets for an invalid asset id', async () => {
    const authApi = ownerApi();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId="not-a-uuid" />, { authApi });
    expect(await screen.findByRole('alert')).toHaveTextContent('Asset not found.');
    expect(authApi.listControlledFindingTargets).not.toHaveBeenCalled();
    expect(authApi.getAsset).not.toHaveBeenCalled();
  });

  it('states an empty page and an oversized count without calling the asset safe', async () => {
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () => discoveryPage([], null, 4)),
    });
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    expect(
      await screen.findByText(/No controlled Finding targets are available for this asset/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Omitted targets: 4/)).toBeInTheDocument();
    expect(screen.queryByText(/no vulnerabilities/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/asset is safe/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/no risk/i)).not.toBeInTheDocument();
  });

  it('submits one exact acknowledgement after confirmation and links the created Finding', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const candidate = eligibleCandidate('<img src=x onerror=alert(1)>');
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () => discoveryPage([candidate])),
      createControlledFinding: vi.fn(async () => ({
        status: 'created' as const,
        findingId: FINDING_ID,
      })),
    });
    const user = userEvent.setup();
    const { container } = renderWithAuth(
      <ControlledFindingTargetsPageClient assetId={ASSET_ID} />,
      { authApi },
    );

    await user.click(
      await screen.findByRole('button', {
        name: 'Review creation for <img src=x onerror=alert(1)>',
      }),
    );
    const dialog = screen.getByRole('dialog', {
      name: 'Create Finding for <img src=x onerror=alert(1)>',
    });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAccessibleDescription(/point-in-time/);
    expect(dialog).toHaveTextContent('Vulnerability identifier:');
    expect(dialog).toHaveTextContent(candidate.acknowledgement.vulnerabilityId);
    expect(dialog).toHaveTextContent('The server revalidates this evidence set');
    expect(dialog).toHaveTextContent('refuses the request and records nothing');
    expect(screen.getByText(EVIDENCE_A)).toBeInTheDocument();
    expect(screen.getByText(EVIDENCE_B)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole('button', { name: 'Create Finding for <img src=x onerror=alert(1)>' }),
    );
    expect(await screen.findByRole('status')).toHaveTextContent('One Finding was created.');
    expect(screen.getByRole('link', { name: 'Open Finding' })).toHaveAttribute(
      'href',
      `/findings/${FINDING_ID}`,
    );
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(1);
    expect(authApi.createControlledFinding.mock.calls[0]?.[0]).toEqual(candidate.acknowledgement);
    expect(authApi.createControlledFinding.mock.calls[0]?.[0]).not.toBe(candidate.acknowledgement);
    expect(screen.getByRole('status')).toHaveFocus();
    expect(authApi.createControlledFinding.mock.calls[0]?.[1]).toBe(CSRF_TOKEN_FIXTURE);
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    setItem.mockRestore();
  });

  it('confirms exact replay and links the already recorded Finding', async () => {
    const candidate = replayCandidate('CVE-2024-0002');
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () => discoveryPage([candidate])),
      createControlledFinding: vi.fn(async () => ({
        status: 'already_applied' as const,
        findingId: FINDING_ID,
      })),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });

    await user.click(
      await screen.findByRole('button', { name: 'Review exact replay for CVE-2024-0002' }),
    );
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('A second Finding should not be created');
    expect(dialog).toHaveTextContent(candidate.acknowledgement.vulnerabilityId);
    expect(screen.getByText(/will not create a duplicate/)).toBeInTheDocument();
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
    await user.click(
      screen.getByRole('button', {
        name: 'Submit exact replay acknowledgement for CVE-2024-0002',
      }),
    );
    expect(await screen.findByRole('status')).toHaveTextContent(
      'This Finding was already recorded with the same creation lineage.',
    );
    expect(screen.getByRole('link', { name: 'Open Finding' })).toHaveAttribute(
      'href',
      `/findings/${FINDING_ID}`,
    );
    expect(screen.queryByText(/duplicate error/i)).not.toBeInTheDocument();
    expect(authApi.createControlledFinding.mock.calls[0]?.[0]).toEqual(candidate.acknowledgement);
  });

  it('keeps an existing Finding free of an acknowledgement, creation action, and inspection link', async () => {
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () => discoveryPage([existingCandidate()])),
    });
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    expect(await screen.findByText('Finding already recorded')).toBeInTheDocument();
    expect(screen.queryByText(/Evidence records/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Review/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Open Finding' })).not.toBeInTheDocument();
    expect(screen.getByText('CVE-2024-0003')).toBeInTheDocument();
    expect(screen.getByText(COMPONENT_ID_2)).toBeInTheDocument();
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
  });

  it('traps dialog focus and returns it to the invoking button', async () => {
    const authApi = ownerApi();
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    const review = await screen.findByRole('button', {
      name: 'Review creation for CVE-2024-0001',
    });
    await user.click(review);
    const heading = screen.getByRole('heading', {
      level: 2,
      name: 'Create Finding for CVE-2024-0001',
    });
    expect(heading).toHaveFocus();
    expect(review.closest('[inert]')).not.toBeNull();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    await user.tab({ shift: true });
    expect(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' })).toHaveFocus();
    await user.keyboard('{Escape}');
    await waitFor(() => {
      expect(review).toHaveFocus();
    });
    expect(review.closest('[inert]')).toBeNull();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
  });

  it('ignores Escape and a repeated click while creation is in flight', async () => {
    let finish: ((value: { status: 'created'; findingId: string }) => void) | undefined;
    const authApi = ownerApi({
      createControlledFinding: vi.fn(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      ),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    const confirm = screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' });
    await user.click(confirm);
    await waitFor(() => {
      expect(confirm).toBeDisabled();
    });
    fireEvent.click(confirm);
    await user.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(1);
    finish?.({ status: 'created', findingId: FINDING_ID });
    expect(await screen.findByText('One Finding was created.')).toBeInTheDocument();
  });

  it('does not resubmit a stale acknowledgement and requires a new review after refresh', async () => {
    const authApi = ownerApi({
      createControlledFinding: vi.fn(async () => {
        throw {
          status: 409,
          code: 'conflict',
          message: 'The request conflicts with the current evidence.',
          requestId: 'req-stale',
          correlationId: 'corr-stale',
        };
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    await user.click(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' }));
    expect(
      await screen.findByText('The request conflicts with the current evidence.'),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Refresh the targets and review the new acknowledgement/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Refresh targets' }));
    await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' });
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(1);
    expect(authApi.listControlledFindingTargets).toHaveBeenLastCalledWith(ASSET_ID);
  });

  it('keeps one acknowledgement for a deliberate retry and does not retry automatically', async () => {
    const candidate = eligibleCandidate();
    let attempts = 0;
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () => discoveryPage([candidate])),
      createControlledFinding: vi.fn(async () => {
        attempts += 1;
        if (attempts === 1) {
          throw {
            status: 503,
            code: 'internal',
            message: 'down',
            requestId: 'req-u',
            correlationId: 'corr-u',
          };
        }
        return { status: 'already_applied' as const, findingId: FINDING_ID };
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    await user.click(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' }));
    const uncertainty = await screen.findByRole('alert');
    expect(uncertainty).toHaveTextContent('Creation result could not be confirmed');
    expect(uncertainty).toHaveTextContent('Request ID: req-u');
    expect(uncertainty).toHaveTextContent('Correlation ID: corr-u');
    expect(screen.queryByText(/failed/i)).not.toBeInTheDocument();
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' }));
    expect(await screen.findByRole('status')).toHaveTextContent('already recorded');
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(2);
    expect(authApi.createControlledFinding.mock.calls[0]?.[0]).toEqual(candidate.acknowledgement);
    expect(authApi.createControlledFinding.mock.calls[1]?.[0]).toBe(
      authApi.createControlledFinding.mock.calls[0]?.[0],
    );
  });

  it('submits the reviewed acknowledgement after the loaded evidence ids change', async () => {
    const acknowledgement = {
      ...acknowledgementFixture,
      expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B],
    };
    const candidate = eligibleCandidate('CVE-2024-0001', acknowledgement);
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () => discoveryPage([candidate])),
      createControlledFinding: vi.fn(async () => ({
        status: 'created' as const,
        findingId: FINDING_ID,
      })),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    acknowledgement.expectedProductMatchEvidenceIds.splice(0, 1);
    expect(screen.getByRole('dialog')).toHaveTextContent(EVIDENCE_A);
    expect(screen.getByRole('dialog')).toHaveTextContent(EVIDENCE_B);
    await user.click(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' }));
    expect(await screen.findByText('One Finding was created.')).toBeInTheDocument();
    expect(authApi.createControlledFinding.mock.calls[0]?.[0]).toEqual({
      ...acknowledgementFixture,
      expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_B],
    });
  });

  it('discards an uncertain acknowledgement when the operator refreshes', async () => {
    const authApi = ownerApi({
      createControlledFinding: vi.fn(async () => {
        throw new Error('truncated body');
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    await user.click(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' }));
    expect(await screen.findByText(/could not be confirmed/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Refresh targets' }));
    expect(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(1);
  });

  it('replaces pages with an in-memory cursor and discards the open acknowledgement', async () => {
    const second = eligibleCandidate('CVE-PAGE-2', {
      ...acknowledgementFixture,
      componentId: COMPONENT_ID_2,
      vulnerabilityId: VULNERABILITY_ID_2,
    });
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async (_assetId: string, query?: { cursor: string }) => {
        if (query?.cursor === 'cursor-b') {
          return discoveryPage([second], null);
        }
        return discoveryPage([eligibleCandidate('CVE-PAGE-1')], 'cursor-b');
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(await screen.findByRole('button', { name: 'Review creation for CVE-PAGE-1' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    const nextPage = screen.getByRole('button', { name: 'Next page' });
    expect(nextPage.closest('[inert]')).not.toBeNull();
    fireEvent.click(nextPage);
    expect(await screen.findByText('CVE-PAGE-2')).toBeInTheDocument();
    expect(screen.queryByText('CVE-PAGE-1')).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByText(EVIDENCE_A)).not.toBeInTheDocument();
    expect(authApi.listControlledFindingTargets).toHaveBeenCalledWith(ASSET_ID, {
      cursor: 'cursor-b',
    });
    expect(window.location.search).not.toContain('cursor');
    expect(navigationMocks.push).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Previous page' }));
    expect(await screen.findByText('CVE-PAGE-1')).toBeInTheDocument();
    expect(authApi.listControlledFindingTargets).toHaveBeenLastCalledWith(ASSET_ID);
  });

  it('resets a stale cursor to the first page without submitting', async () => {
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async (_assetId: string, query?: { cursor: string }) => {
        if (query?.cursor === 'cursor-b') {
          throw {
            status: 409,
            code: 'conflict',
            message: 'The page cursor is no longer current.',
            requestId: 'req-cursor',
            correlationId: 'corr-cursor',
          };
        }
        return discoveryPage([eligibleCandidate('CVE-PAGE-1')], 'cursor-b');
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await screen.findByRole('button', { name: 'Review creation for CVE-PAGE-1' });
    await user.click(screen.getByRole('button', { name: 'Next page' }));
    expect(await screen.findByText(/The page is no longer current/)).toBeInTheDocument();
    expect(await screen.findByText('CVE-PAGE-1')).toBeInTheDocument();
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
    expect(authApi.listControlledFindingTargets).toHaveBeenLastCalledWith(ASSET_ID);
  });

  it('drops tenant state when the organization changes and ignores a stale response', async () => {
    let resolveFirst: ((value: ReturnType<typeof discoveryPage>) => void) | undefined;
    let calls = 0;
    const ownerB = { ...secondOrganizationFixture, role: 'owner' as const };
    const authApi = ownerApi({
      listOrganizations: vi.fn(async () => ({
        organizations: [ownerOrganizationFixture, ownerB],
      })),
      selectOrganization: vi.fn(async () => sessionFixture({ organization: ownerB })),
      listControlledFindingTargets: vi.fn(() => {
        calls += 1;
        if (calls === 1) {
          return new Promise<ReturnType<typeof discoveryPage>>((resolve) => {
            resolveFirst = resolve;
          });
        }
        return Promise.resolve(discoveryPage([]));
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(
      <>
        <OrganizationSelector onSelected={() => undefined} />
        <ControlledFindingTargetsPageClient assetId={ASSET_ID} />
      </>,
      { authApi },
    );
    await waitFor(() => {
      expect(authApi.listControlledFindingTargets).toHaveBeenCalledTimes(1);
    });
    await user.selectOptions(screen.getByLabelText('Organization'), ownerB.id);
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(
      await screen.findByText(/No controlled Finding targets are available/),
    ).toBeInTheDocument();
    resolveFirst?.(discoveryPage([eligibleCandidate(SECRET_ID)]));
    await waitFor(() => {
      expect(screen.queryByText(SECRET_ID)).not.toBeInTheDocument();
    });
    expect(navigationMocks.push).not.toHaveBeenCalled();
  });

  it('closes confirmation and ignores a creation result from the previous organization', async () => {
    let finish: ((value: { status: 'created'; findingId: string }) => void) | undefined;
    const viewerOrg = secondOrganizationFixture;
    const authApi = ownerApi({
      listOrganizations: vi.fn(async () => ({
        organizations: [ownerOrganizationFixture, viewerOrg],
      })),
      selectOrganization: vi.fn(async () => sessionFixture({ organization: viewerOrg })),
      createControlledFinding: vi.fn(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      ),
    });
    const user = userEvent.setup();
    renderWithAuth(
      <>
        <OrganizationSelector onSelected={() => undefined} />
        <ControlledFindingTargetsPageClient assetId={ASSET_ID} />
      </>,
      { authApi },
    );
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    await user.click(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' }));
    const organizationSelect = screen.getByLabelText('Organization');
    expect(organizationSelect.closest('[inert]')).not.toBeNull();
    fireEvent.change(organizationSelect, { target: { value: viewerOrg.id } });
    await waitFor(() => {
      expect(organizationSelect).toHaveValue(viewerOrg.id);
    });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(
      await screen.findByText(
        'Controlled Finding targets are unavailable for your role in this organization.',
      ),
    ).toBeInTheDocument();
    finish?.({ status: 'created', findingId: FINDING_ID });
    await waitFor(() => {
      expect(screen.queryByRole('link', { name: 'Open Finding' })).not.toBeInTheDocument();
    });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByText(EVIDENCE_A)).not.toBeInTheDocument();
    expect(navigationMocks.push).not.toHaveBeenCalled();
  });

  it('shows the unavailable state for a discovery 403 without candidate data', async () => {
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () => {
        throw {
          status: 403,
          code: 'forbidden',
          message: 'denied',
          requestId: 'req',
          correlationId: 'corr',
        };
      }),
    });
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    expect(
      await screen.findByText(
        'Controlled Finding targets are unavailable for your role in this organization.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText('CVE-2024-0001')).not.toBeInTheDocument();
  });

  it('sends the operator to the session-expired page on 401 and does not retry', async () => {
    const authApi = ownerApi({
      createControlledFinding: vi.fn(async () => {
        throw { status: 401, code: 'unauthorized', message: 'expired' };
      }),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    await user.click(screen.getByRole('button', { name: 'Create Finding for CVE-2024-0001' }));
    await waitFor(() => {
      expect(navigationMocks.replace).toHaveBeenCalledWith('/session-expired');
    });
    expect(authApi.createControlledFinding).toHaveBeenCalledTimes(1);
  });

  it('does not submit an acknowledgement for a different asset', async () => {
    const authApi = ownerApi({
      listControlledFindingTargets: vi.fn(async () =>
        discoveryPage([
          eligibleCandidate('CVE-2024-0001', {
            ...acknowledgementFixture,
            assetId: '99999999-9999-4999-8999-999999999999',
          }),
        ]),
      ),
    });
    const user = userEvent.setup();
    renderWithAuth(<ControlledFindingTargetsPageClient assetId={ASSET_ID} />, { authApi });
    await user.click(
      await screen.findByRole('button', { name: 'Review creation for CVE-2024-0001' }),
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByText('The acknowledgement does not match this asset.')).toBeInTheDocument();
    expect(authApi.createControlledFinding).not.toHaveBeenCalled();
  });
});
