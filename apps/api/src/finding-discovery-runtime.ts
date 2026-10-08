/**
 * API-process composition for controlled Finding target discovery.
 * This module does not construct creation or inspection.
 */

import { createControlledFindingDiscoveryPersistence } from '@patchpilot/database/controlled-finding-discovery-persistence';
import {
  createControlledFindingDiscoveryApplication,
  type FindingDiscoveryApplicationResult,
} from '@patchpilot/domain/controlled-finding-discovery';

export type FindingDiscoveryExecuteInput = {
  readonly actor: {
    readonly userId: string;
    readonly sessionId: string;
    readonly organizationId: string | null;
    readonly membershipId: string | null;
    readonly role: 'owner' | 'admin' | 'member' | 'viewer' | null;
  };
  readonly assetId: unknown;
  readonly limit: unknown;
  readonly cursor: unknown;
};

export type FindingDiscoveryRuntime = {
  execute(input: FindingDiscoveryExecuteInput): Promise<FindingDiscoveryApplicationResult>;
};

export function composeControlledFindingDiscoveryRuntime(
  client: Parameters<typeof createControlledFindingDiscoveryPersistence>[0],
): FindingDiscoveryRuntime {
  const application = createControlledFindingDiscoveryApplication({
    discovery: createControlledFindingDiscoveryPersistence(client),
  });
  return {
    execute(input) {
      return application.execute(input);
    },
  };
}

export function denyFindingDiscoveryRuntime(): FindingDiscoveryRuntime {
  return {
    async execute() {
      return { status: 'authority_required' };
    },
  };
}
