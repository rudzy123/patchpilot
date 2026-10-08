/**
 * Controlled Finding target discovery application.
 * Construction performs no I/O. The read does not issue creation authority.
 */

import {
  parseControlledFindingOperatorActor,
  type ControlledFindingOperatorActor,
} from '../controlled-operator/actor.js';
import { decodeFindingDiscoveryCursor } from './cursor.js';
import { assembleFindingDiscoveryPage, type FindingDiscoveryPage } from './page.js';
import { FINDING_DISCOVERY_MAX_PAGE_SIZE, FINDING_DISCOVERY_MIN_PAGE_SIZE } from './policy.js';
import { roleGrantsControlledFindingDiscovery } from './permissions.js';
import type { FindingDiscoveryPort, FindingDiscoveryRead } from './port.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const READ_FAILURES = [
  'authority_rejected',
  'not_found',
  'stale_cursor',
  'database_unavailable',
  'internal_failure',
] as const;

export type FindingDiscoveryApplicationDependencies = {
  readonly discovery: FindingDiscoveryPort;
};

export type FindingDiscoveryApplicationInput = {
  readonly actor: ControlledFindingOperatorActor;
  readonly assetId: unknown;
  readonly limit: unknown;
  readonly cursor: unknown;
};

export type FindingDiscoveryApplicationResult =
  | { readonly status: 'page'; readonly page: FindingDiscoveryPage }
  | { readonly status: 'authority_required' }
  | { readonly status: 'invalid_request' }
  | { readonly status: 'not_found' }
  | { readonly status: 'stale_cursor' }
  | { readonly status: 'database_unavailable' }
  | { readonly status: 'malformed_persisted_state' }
  | { readonly status: 'internal_failure' };

export function createControlledFindingDiscoveryApplication(
  dependencies: FindingDiscoveryApplicationDependencies,
) {
  const discovery = dependencies.discovery;
  return {
    async execute(
      input: FindingDiscoveryApplicationInput,
    ): Promise<FindingDiscoveryApplicationResult> {
      try {
        return await executeDiscovery(discovery, input);
      } catch {
        return { status: 'internal_failure' };
      }
    },
  };
}

async function executeDiscovery(
  discovery: FindingDiscoveryPort,
  input: FindingDiscoveryApplicationInput,
): Promise<FindingDiscoveryApplicationResult> {
  const actor = parseControlledFindingOperatorActor(input.actor);
  if (actor === null || !roleGrantsControlledFindingDiscovery(actor.role)) {
    return { status: 'authority_required' };
  }
  if (typeof input.assetId !== 'string' || !UUID_LOWER_PATTERN.test(input.assetId)) {
    return { status: 'invalid_request' };
  }
  if (!isLimit(input.limit)) {
    return { status: 'invalid_request' };
  }
  const cursor = readCursor(input.cursor);
  if (cursor === 'invalid') {
    return { status: 'invalid_request' };
  }
  if (typeof discovery.read !== 'function') {
    return { status: 'internal_failure' };
  }
  let read: unknown;
  try {
    read = await discovery.read({
      organizationId: actor.organizationId,
      membershipId: actor.membershipId,
      actorId: actor.userId,
      assetId: input.assetId,
      cursor,
    });
  } catch {
    return { status: 'internal_failure' };
  }
  if (!isRead(read)) {
    return { status: 'internal_failure' };
  }
  if (read.status !== 'ready') {
    return { status: read.status === 'authority_rejected' ? 'authority_required' : read.status };
  }
  const assembled = assembleFindingDiscoveryPage({
    assetId: input.assetId,
    limit: input.limit,
    read,
  });
  if (assembled.status !== 'page') {
    return { status: assembled.status };
  }
  return { status: 'page', page: assembled.page };
}

function readCursor(
  value: unknown,
): { ingestionId: string; componentId: string; vulnerabilityId: string } | null | 'invalid' {
  if (value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    return 'invalid';
  }
  const decoded = decodeFindingDiscoveryCursor(value);
  if (!decoded.ok) {
    return 'invalid';
  }
  return decoded.cursor;
}

function isLimit(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= FINDING_DISCOVERY_MIN_PAGE_SIZE &&
    value <= FINDING_DISCOVERY_MAX_PAGE_SIZE
  );
}

function isRead(value: unknown): value is FindingDiscoveryRead {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const status = Object.getOwnPropertyDescriptor(value, 'status')?.value;
  if (status === 'ready') {
    return (
      Object.prototype.hasOwnProperty.call(value, 'pairs') &&
      Object.prototype.hasOwnProperty.call(value, 'pairSpaceContinues') &&
      Object.prototype.hasOwnProperty.call(value, 'ingestionId')
    );
  }
  return typeof status === 'string' && (READ_FAILURES as readonly string[]).includes(status);
}
