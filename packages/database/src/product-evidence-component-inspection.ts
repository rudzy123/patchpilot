/**
 * Narrow tenant-scoped component occurrence read for product-evidence
 * composition. Construction performs no I/O. The read does not select
 * Findings, envelopes, or provider identities.
 */

import type { Prisma, PrismaClient } from '@prisma/client';
import type {
  ProductEvidenceComponentInspection,
  ProductEvidenceComponentInspectionPort,
  ProductEvidenceComponentSnapshot,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient } from './guards.js';

const SHA256_HEX = /^[a-f0-9]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function createProductEvidenceComponentInspection(
  prisma: PrismaClient,
): ProductEvidenceComponentInspectionPort {
  if (!isRootPrismaClient(prisma)) {
    throw new Error('Product-evidence component inspection requires the root database client.');
  }
  return {
    async inspectTenantOccurrence(query): Promise<ProductEvidenceComponentInspection> {
      const organizationId = ownUuid(query, 'organizationId');
      const componentOccurrenceId = ownUuid(query, 'componentOccurrenceId');
      if (organizationId === null || componentOccurrenceId === null) {
        return { kind: 'rejected', code: 'malformed_persisted_state' };
      }
      try {
        return await prisma.$transaction(
          async (tx) => readOccurrence(tx, { organizationId, componentOccurrenceId }),
          {
            isolationLevel: 'RepeatableRead',
          },
        );
      } catch {
        return { kind: 'rejected', code: 'database_unavailable' };
      }
    },
  };
}

function ownUuid(query: unknown, key: string): string | null {
  if (typeof query !== 'object' || query === null) {
    return null;
  }
  const descriptor = Object.getOwnPropertyDescriptor(query, key);
  if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
    return null;
  }
  return typeof descriptor.value === 'string' && UUID_V4.test(descriptor.value)
    ? descriptor.value
    : null;
}

async function readOccurrence(
  tx: Prisma.TransactionClient,
  query: { readonly organizationId: string; readonly componentOccurrenceId: string },
): Promise<ProductEvidenceComponentInspection> {
  const occurrence = await tx.componentOccurrence.findFirst({
    where: {
      organizationId: query.organizationId,
      id: query.componentOccurrenceId,
    },
    select: {
      id: true,
      organizationId: true,
      assetId: true,
      sbomId: true,
      sbomIngestionId: true,
      componentId: true,
      version: true,
      versionKnown: true,
    },
  });
  if (occurrence === null) {
    return { kind: 'not_found' };
  }
  const component = await tx.component.findFirst({
    where: { organizationId: occurrence.organizationId, id: occurrence.componentId },
    select: {
      organizationId: true,
      identityKey: true,
      ecosystem: true,
      namespace: true,
      name: true,
      identityState: true,
    },
  });
  const sbom = await tx.sbom.findFirst({
    where: {
      organizationId: occurrence.organizationId,
      id: occurrence.sbomId,
      assetId: occurrence.assetId,
    },
    select: { organizationId: true, assetId: true, sha256: true },
  });
  if (
    component === null ||
    sbom === null ||
    component.organizationId !== occurrence.organizationId ||
    sbom.organizationId !== occurrence.organizationId ||
    sbom.assetId !== occurrence.assetId ||
    component.ecosystem === null ||
    component.name.length === 0 ||
    !SHA256_HEX.test(sbom.sha256)
  ) {
    return { kind: 'rejected', code: 'malformed_persisted_state' };
  }
  const snapshot: ProductEvidenceComponentSnapshot = {
    organizationId: occurrence.organizationId,
    componentOccurrenceId: occurrence.id,
    assetId: occurrence.assetId,
    sbomId: occurrence.sbomId,
    sbomIngestionId: occurrence.sbomIngestionId,
    componentId: occurrence.componentId,
    componentIdentityKey: component.identityKey,
    sbomSha256: sbom.sha256,
    ecosystem: component.ecosystem,
    namespace: component.namespace,
    name: component.name,
    rawObservedVersion: occurrence.version,
    versionKnown: occurrence.versionKnown,
    identityState: component.identityState,
  };
  return { kind: 'found', snapshot };
}
