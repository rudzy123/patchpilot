/**
 * Session 11 Batch 5D mapping from Prisma OSV rows to Batch 5B contracts.
 *
 * Mappers reconstruct contracts through committed constructors. They never
 * spread untrusted objects and never include provider body bytes.
 */

import type {
  OsvAdvisoryParserFailurePhase,
  OsvAdvisoryParserRetryability,
  OsvAdvisoryParserWarningCode,
  OsvAttachmentState,
  OsvClassificationStatus,
  OsvCompletenessDimension,
  OsvCompletenessStatus,
  OsvFamilyCandidateKind,
  OsvInventoryConvergenceStatus,
  OsvInventoryPassCompletenessStatus,
  OsvInventoryRunState,
  OsvObjectStorageKind,
  OsvObjectStorageRole,
  OsvParserAttemptResultState,
  OsvPresenceKind,
  OsvQuarantinePhase,
  OsvQuarantineReasonCode,
  OsvReconciliationDiscrepancyCode,
  OsvSourceIdentifier,
  OsvWorkerLifecycleOutcome,
} from '@prisma/client';
import {
  OSV_CATALOG_VERSION_SET_V1,
  createOsvAcquisitionCompleteness,
  createOsvActiveCatalogPointer,
  createOsvCatalogGeneration,
  createOsvFinalObjectLocator,
  createOsvInventoryObjectObservation,
  createOsvInventoryPrefixPass,
  createOsvInventoryRun,
  createOsvMatchingCompleteness,
  createOsvObjectAttachment,
  createOsvParsedAdvisoryRevision,
  createOsvParserAttempt,
  createOsvProviderBodySnapshot,
  createOsvProviderPresenceObservation,
  createOsvQuarantineRecord,
  createOsvTemporaryObjectLocator,
  reconcileOsvGenerationCounts,
  type OsvActiveCatalogPointer,
  type OsvCatalogGeneration,
  type OsvInventoryObjectObservation,
  type OsvInventoryRun,
  type OsvObjectAttachment,
  type OsvParsedAdvisoryRevision,
  type OsvParserAttempt,
  type OsvPersistenceResult,
  type OsvProviderBodySnapshot,
  type OsvProviderPresenceObservation,
  type OsvQuarantineRecord,
  type OsvReconciliationResult,
} from '@patchpilot/vulnerability-intelligence';

export class OsvAcquisitionMappingError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvAcquisitionMappingError';
  }
}

function requireOk<T>(result: OsvPersistenceResult<T>, label: string): T {
  if (!result.ok) {
    throw new OsvAcquisitionMappingError(`${label} mapping failed.`);
  }
  return result.value;
}

export function toIsoUtc(value: Date): string {
  return value.toISOString();
}

export function fromIsoUtc(value: string): Date {
  return new Date(value);
}

export type OsvFamilyColumns = {
  readonly familyKind: OsvFamilyCandidateKind;
  readonly familyValue: string | null;
};

export function familyToColumns(family: {
  readonly kind: 'known' | 'unknown_uppercase' | 'unclassifiable';
  readonly family?: string;
}): OsvFamilyColumns {
  if (family.kind === 'unclassifiable') {
    return { familyKind: 'unclassifiable', familyValue: null };
  }
  if (family.family === undefined) {
    throw new OsvAcquisitionMappingError('family mapping failed.');
  }
  return {
    familyKind: family.kind === 'known' ? 'known' : 'unknown_uppercase',
    familyValue: family.family,
  };
}

export type CompletenessRow = {
  readonly dimension: OsvCompletenessDimension;
  readonly status: OsvCompletenessStatus;
  readonly catalogGenerationId: string;
  readonly requiredCount: number;
  readonly observedCount: number;
  readonly discrepancyCodes: readonly OsvReconciliationDiscrepancyCode[];
};

export type CatalogGenerationRow = {
  readonly id: string;
  readonly scopeFingerprint: string;
  readonly providerIdentifier: string;
  readonly inventoryScope: string;
  readonly eligibleBodyScope: string;
  readonly sourceLicenseRegistry: string;
  readonly listingProtocol: string;
  readonly transportPolicy: string;
  readonly parserProtocol: string;
  readonly parserResourcePolicy: string;
  readonly schemaRevision: string;
  readonly schemaCommit: string;
  readonly metadataPolicy: string;
  readonly syncAlgorithm: string;
  readonly lifecycleState: OsvCatalogGeneration['lifecycleState'];
  readonly version: number;
  readonly createdAt: Date;
  readonly readyAt: Date | null;
  readonly activatedAt: Date | null;
  readonly supersededAt: Date | null;
  readonly failedAt: Date | null;
  readonly cancelledAt: Date | null;
  readonly quarantinedAt: Date | null;
  readonly completenessRows: readonly CompletenessRow[];
};

export function mapCatalogGeneration(row: CatalogGenerationRow): OsvCatalogGeneration {
  const byDimension = new Map(row.completenessRows.map((item) => [item.dimension, item]));
  const inventory = byDimension.get('inventory');
  const eligibleBody = byDimension.get('eligible_body');
  const parser = byDimension.get('parser');
  const parsedCatalog = byDimension.get('parsed_catalog');
  const matching = byDimension.get('matching');
  if (
    inventory === undefined ||
    eligibleBody === undefined ||
    parser === undefined ||
    parsedCatalog === undefined ||
    matching === undefined
  ) {
    throw new OsvAcquisitionMappingError('completeness mapping failed.');
  }
  return requireOk(
    createOsvCatalogGeneration({
      id: row.id,
      versionSet: {
        providerIdentifier: row.providerIdentifier,
        inventoryScope: row.inventoryScope,
        eligibleBodyScope: row.eligibleBodyScope,
        sourceLicenseRegistry: row.sourceLicenseRegistry,
        listingProtocol: row.listingProtocol,
        transportPolicy: row.transportPolicy,
        parserProtocol: row.parserProtocol,
        parserResourcePolicy: row.parserResourcePolicy,
        schemaRevision: row.schemaRevision,
        schemaCommit: row.schemaCommit,
        metadataPolicy: row.metadataPolicy,
        syncAlgorithm: row.syncAlgorithm,
      },
      lifecycleState: row.lifecycleState,
      completeness: {
        inventory: requireOk(
          createOsvAcquisitionCompleteness({
            dimension: 'inventory',
            status: inventory.status,
            catalogGenerationId: row.id,
            requiredCount: inventory.requiredCount,
            observedCount: inventory.observedCount,
            discrepancyCodes: [...inventory.discrepancyCodes],
          }),
          'inventory completeness',
        ),
        eligibleBody: requireOk(
          createOsvAcquisitionCompleteness({
            dimension: 'eligible_body',
            status: eligibleBody.status,
            catalogGenerationId: row.id,
            requiredCount: eligibleBody.requiredCount,
            observedCount: eligibleBody.observedCount,
            discrepancyCodes: [...eligibleBody.discrepancyCodes],
          }),
          'eligible-body completeness',
        ),
        parser: requireOk(
          createOsvAcquisitionCompleteness({
            dimension: 'parser',
            status: parser.status,
            catalogGenerationId: row.id,
            requiredCount: parser.requiredCount,
            observedCount: parser.observedCount,
            discrepancyCodes: [...parser.discrepancyCodes],
          }),
          'parser completeness',
        ),
        parsedCatalog: requireOk(
          createOsvAcquisitionCompleteness({
            dimension: 'parsed_catalog',
            status: parsedCatalog.status,
            catalogGenerationId: row.id,
            requiredCount: parsedCatalog.requiredCount,
            observedCount: parsedCatalog.observedCount,
            discrepancyCodes: [...parsedCatalog.discrepancyCodes],
          }),
          'parsed-catalog completeness',
        ),
        matching: requireOk(
          createOsvMatchingCompleteness({
            dimension: 'matching',
            status: 'not_in_scope',
            catalogGenerationId: row.id,
          }),
          'matching completeness',
        ),
      },
      version: row.version,
      createdAt: toIsoUtc(row.createdAt),
      readyAt: row.readyAt === null ? null : toIsoUtc(row.readyAt),
      activatedAt: row.activatedAt === null ? null : toIsoUtc(row.activatedAt),
      supersededAt: row.supersededAt === null ? null : toIsoUtc(row.supersededAt),
      failedAt: row.failedAt === null ? null : toIsoUtc(row.failedAt),
      cancelledAt: row.cancelledAt === null ? null : toIsoUtc(row.cancelledAt),
      quarantinedAt: row.quarantinedAt === null ? null : toIsoUtc(row.quarantinedAt),
    }),
    'catalog generation',
  );
}

export function versionSetColumns(): typeof OSV_CATALOG_VERSION_SET_V1 {
  return OSV_CATALOG_VERSION_SET_V1;
}

export type PrefixPassRow = {
  readonly inventoryRunId: string;
  readonly providerPrefix: string;
  readonly passNumber: number;
  readonly listingProtocol: string;
  readonly transportPolicy: string;
  readonly sourceLicenseRegistry: string;
  readonly inventoryScope: string;
  readonly pageCount: number;
  readonly responseByteCount: number;
  readonly acceptedItemCount: number;
  readonly listingRejectedCount: number;
  readonly terminalPageObserved: boolean;
  readonly completeness: OsvInventoryPassCompletenessStatus;
};

export type InventoryRunRow = {
  readonly id: string;
  readonly catalogGenerationId: string;
  readonly state: OsvInventoryRunState;
  readonly inventoryScope: string;
  readonly listingProtocol: string;
  readonly transportPolicy: string;
  readonly sourceLicenseRegistry: string;
  readonly passCount: number;
  readonly startedAt: Date;
  readonly completedAt: Date | null;
  readonly acceptedListedCount: number;
  readonly listingRejectedCount: number;
  readonly eligibleCount: number;
  readonly ineligibleCount: number;
  readonly legalReviewCount: number;
  readonly unknownCount: number;
  readonly ambiguousCount: number;
  readonly convergence: OsvInventoryConvergenceStatus;
  readonly prefixPasses: readonly PrefixPassRow[];
};

export function mapInventoryRun(row: InventoryRunRow): OsvInventoryRun {
  const prefixPasses = row.prefixPasses.map((pass) =>
    requireOk(
      createOsvInventoryPrefixPass({
        inventoryRunId: pass.inventoryRunId,
        providerPrefix: pass.providerPrefix,
        passNumber: pass.passNumber,
        listingProtocol: pass.listingProtocol,
        transportPolicy: pass.transportPolicy,
        sourceLicenseRegistry: pass.sourceLicenseRegistry,
        inventoryScope: pass.inventoryScope,
        pageCount: pass.pageCount,
        responseByteCount: pass.responseByteCount,
        acceptedItemCount: pass.acceptedItemCount,
        listingRejectedCount: pass.listingRejectedCount,
        terminalPageObserved: pass.terminalPageObserved,
        completeness: pass.completeness,
      }),
      'inventory prefix pass',
    ),
  );
  return requireOk(
    createOsvInventoryRun({
      id: row.id,
      catalogGenerationId: row.catalogGenerationId,
      state: row.state,
      inventoryScope: row.inventoryScope,
      listingProtocol: row.listingProtocol,
      transportPolicy: row.transportPolicy,
      sourceLicenseRegistry: row.sourceLicenseRegistry,
      passCount: row.passCount,
      startedAt: toIsoUtc(row.startedAt),
      completedAt: row.completedAt === null ? null : toIsoUtc(row.completedAt),
      acceptedListedCount: row.acceptedListedCount,
      listingRejectedCount: row.listingRejectedCount,
      classificationCounts: {
        eligible: row.eligibleCount,
        ineligible: row.ineligibleCount,
        legalReview: row.legalReviewCount,
        unknown: row.unknownCount,
        ambiguous: row.ambiguousCount,
      },
      convergence: row.convergence,
      prefixPasses,
    }),
    'inventory run',
  );
}

export type ObservationRow = {
  readonly inventoryRunId: string;
  readonly providerObjectKeyDigest: string;
  readonly providerGeneration: string;
  readonly providerPrefix: string;
  readonly declaredByteCount: number;
  readonly classificationStatus: OsvClassificationStatus;
  readonly sourceIdentifier: OsvSourceIdentifier | null;
  readonly etagMetadata: string | null;
  readonly md5HashMetadata: string | null;
};

export function mapObservation(row: ObservationRow): OsvInventoryObjectObservation {
  return requireOk(
    createOsvInventoryObjectObservation({
      inventoryRunId: row.inventoryRunId,
      providerObjectKeyDigest: row.providerObjectKeyDigest,
      providerGeneration: row.providerGeneration,
      providerPrefix: row.providerPrefix,
      declaredByteCount: row.declaredByteCount,
      classificationStatus: row.classificationStatus,
      sourceIdentifier: row.sourceIdentifier,
      etagMetadata: row.etagMetadata,
      md5HashMetadata: row.md5HashMetadata,
    }),
    'inventory observation',
  );
}

export type AttachmentRow = {
  readonly id: string;
  readonly storageKind: OsvObjectStorageKind;
  readonly role: OsvObjectStorageRole;
  readonly objectKey: string;
  readonly locatorContentSha256: string | null;
  readonly uploadId: string | null;
  readonly contentSha256: string;
  readonly byteCount: number;
  readonly contentType: string;
  readonly contentEncoding: string;
  readonly state: OsvAttachmentState;
};

export function mapAttachment(row: AttachmentRow): OsvObjectAttachment {
  const locator =
    row.role === 'temporary'
      ? requireOk(
          createOsvTemporaryObjectLocator({
            storageKind: row.storageKind,
            uploadId: row.uploadId,
          }),
          'temporary locator',
        )
      : requireOk(
          createOsvFinalObjectLocator({
            storageKind: row.storageKind,
            contentSha256: row.locatorContentSha256 ?? row.contentSha256,
          }),
          'final locator',
        );
  return requireOk(
    createOsvObjectAttachment({
      id: row.id,
      locator,
      contentSha256: row.contentSha256,
      byteCount: row.byteCount,
      contentType: row.contentType,
      contentEncoding: row.contentEncoding,
      state: row.state,
    }),
    'attachment',
  );
}

export type SnapshotRow = {
  readonly id: string;
  readonly providerObjectId: string;
  readonly providerObjectKeyDigest: string;
  readonly providerGeneration: string;
  readonly contentSha256: string;
  readonly receivedByteCount: number;
  readonly declaredByteCount: number;
  readonly contentType: string;
  readonly contentEncoding: string;
  readonly sourceIdentifier: OsvSourceIdentifier;
  readonly registryIdentifier: string;
  readonly eligibleBodyScope: string;
  readonly transportPolicy: string;
  readonly retrievedAt: Date;
  readonly classificationStatus: 'eligible';
  readonly attachment: AttachmentRow;
};

export function mapSnapshot(row: SnapshotRow): OsvProviderBodySnapshot {
  return requireOk(
    createOsvProviderBodySnapshot({
      id: row.id,
      providerObjectId: row.providerObjectId,
      providerObjectKeyDigest: row.providerObjectKeyDigest,
      providerGeneration: row.providerGeneration,
      contentSha256: row.contentSha256,
      receivedByteCount: row.receivedByteCount,
      declaredByteCount: row.declaredByteCount,
      contentType: row.contentType,
      contentEncoding: row.contentEncoding,
      sourceIdentifier: row.sourceIdentifier,
      registryIdentifier: row.registryIdentifier,
      eligibleBodyScope: row.eligibleBodyScope,
      transportPolicy: row.transportPolicy,
      retrievedAt: toIsoUtc(row.retrievedAt),
      attachment: mapAttachment(row.attachment),
      classificationStatus: row.classificationStatus,
    }),
    'body snapshot',
  );
}

export type ParserAttemptRow = {
  readonly id: string;
  readonly snapshotId: string;
  readonly protocolIdentifier: string;
  readonly schemaRevision: string;
  readonly schemaCommit: string;
  readonly resourcePolicy: string;
  readonly registryIdentifier: string;
  readonly sourceIdentifier: OsvSourceIdentifier;
  readonly inputSha256: string;
  readonly inputByteCount: number;
  readonly attemptNumber: number;
  readonly resultState: OsvParserAttemptResultState;
  readonly failureKind: string | null;
  readonly retryability: OsvAdvisoryParserRetryability | null;
  readonly phase: OsvAdvisoryParserFailurePhase | null;
  readonly warningCodes: readonly OsvAdvisoryParserWarningCode[];
  readonly workerLifecycleOutcome: OsvWorkerLifecycleOutcome;
  readonly parsedRevisionId: string | null;
  readonly correlationId: string;
  readonly startedAt: Date;
  readonly completedAt: Date;
};

export function mapParserAttempt(row: ParserAttemptRow): OsvParserAttempt {
  return requireOk(
    createOsvParserAttempt({
      id: row.id,
      snapshotId: row.snapshotId,
      protocolIdentifier: row.protocolIdentifier,
      schemaRevision: row.schemaRevision,
      schemaCommit: row.schemaCommit,
      resourcePolicy: row.resourcePolicy,
      registryIdentifier: row.registryIdentifier,
      sourceIdentifier: row.sourceIdentifier,
      inputSha256: row.inputSha256,
      inputByteCount: row.inputByteCount,
      attemptNumber: row.attemptNumber,
      resultState: row.resultState,
      failureKind: row.failureKind,
      warningCodes: [...row.warningCodes],
      workerLifecycleOutcome: row.workerLifecycleOutcome,
      parsedRevisionId: row.parsedRevisionId,
      correlationId: row.correlationId,
      startedAt: toIsoUtc(row.startedAt),
      completedAt: toIsoUtc(row.completedAt),
    }),
    'parser attempt',
  );
}

export type ParsedRevisionRow = {
  readonly id: string;
  readonly snapshotId: string;
  readonly parserAttemptId: string;
  readonly providerObjectId: string;
  readonly providerObjectKeyDigest: string;
  readonly providerGeneration: string;
  readonly documentIdentifier: string;
  readonly protocolIdentifier: string;
  readonly schemaRevision: string;
  readonly schemaCommit: string;
  readonly resourcePolicy: string;
  readonly registryIdentifier: string;
  readonly sourceIdentifier: OsvSourceIdentifier;
  readonly contentSha256: string;
  readonly parsedOutputSha256: string;
  readonly parsedTopLevelOsvId: string;
  readonly publishedAt: Date | null;
  readonly modifiedAt: Date | null;
  readonly withdrawnAt: Date | null;
  readonly aliasCount: number;
  readonly relatedCount: number;
  readonly affectedPackageCount: number;
  readonly rangeCount: number;
  readonly eventCount: number;
  readonly explicitVersionCount: number;
  readonly referenceCount: number;
  readonly creditCount: number;
  readonly severityCount: number;
  readonly normalizationState: string;
  readonly documentAttachment: AttachmentRow;
};

export function mapParsedRevision(row: ParsedRevisionRow): OsvParsedAdvisoryRevision {
  return requireOk(
    createOsvParsedAdvisoryRevision({
      id: row.id,
      snapshotId: row.snapshotId,
      parserAttemptId: row.parserAttemptId,
      providerObjectId: row.providerObjectId,
      providerObjectKeyDigest: row.providerObjectKeyDigest,
      providerGeneration: row.providerGeneration,
      documentIdentifier: row.documentIdentifier,
      protocolIdentifier: row.protocolIdentifier,
      schemaRevision: row.schemaRevision,
      schemaCommit: row.schemaCommit,
      resourcePolicy: row.resourcePolicy,
      registryIdentifier: row.registryIdentifier,
      sourceIdentifier: row.sourceIdentifier,
      contentSha256: row.contentSha256,
      parsedOutputSha256: row.parsedOutputSha256,
      parsedTopLevelOsvId: row.parsedTopLevelOsvId,
      publishedAt: row.publishedAt === null ? null : toIsoUtc(row.publishedAt),
      modifiedAt: row.modifiedAt === null ? null : toIsoUtc(row.modifiedAt),
      withdrawnAt: row.withdrawnAt === null ? null : toIsoUtc(row.withdrawnAt),
      structuralCounts: {
        aliasCount: row.aliasCount,
        relatedCount: row.relatedCount,
        affectedPackageCount: row.affectedPackageCount,
        rangeCount: row.rangeCount,
        eventCount: row.eventCount,
        explicitVersionCount: row.explicitVersionCount,
        referenceCount: row.referenceCount,
        creditCount: row.creditCount,
        severityCount: row.severityCount,
      },
      normalizationState: row.normalizationState,
      documentAttachment: mapAttachment(row.documentAttachment),
    }),
    'parsed revision',
  );
}

export type QuarantineRow = {
  readonly id: string;
  readonly catalogGenerationId: string;
  readonly providerObjectKeyDigest: string | null;
  readonly snapshotId: string | null;
  readonly parserAttemptId: string | null;
  readonly revisionId: string | null;
  readonly reasonCode: OsvQuarantineReasonCode;
  readonly originatingPhase: OsvQuarantinePhase;
  readonly recordedAt: Date;
};

export function mapQuarantine(row: QuarantineRow): OsvQuarantineRecord {
  return requireOk(
    createOsvQuarantineRecord({
      id: row.id,
      catalogGenerationId: row.catalogGenerationId,
      providerObjectKeyDigest: row.providerObjectKeyDigest,
      snapshotId: row.snapshotId,
      parserAttemptId: row.parserAttemptId,
      revisionId: row.revisionId,
      reasonCode: row.reasonCode,
      originatingPhase: row.originatingPhase,
      recordedAt: toIsoUtc(row.recordedAt),
    }),
    'quarantine',
  );
}

export type PresenceRow = {
  readonly catalogGenerationId: string;
  readonly providerObjectId: string;
  readonly providerObjectKeyDigest: string;
  readonly kind: OsvPresenceKind;
  readonly recordedAt: Date;
  readonly historicalSnapshotId: string | null;
  readonly historicalRevisionId: string | null;
};

export function mapPresence(row: PresenceRow): OsvProviderPresenceObservation {
  return requireOk(
    createOsvProviderPresenceObservation({
      catalogGenerationId: row.catalogGenerationId,
      providerObjectId: row.providerObjectId,
      providerObjectKeyDigest: row.providerObjectKeyDigest,
      kind: row.kind,
      recordedAt: toIsoUtc(row.recordedAt),
      historicalSnapshotId: row.historicalSnapshotId,
      historicalRevisionId: row.historicalRevisionId,
    }),
    'presence',
  );
}

export type PointerRow = {
  readonly scopeFingerprint: string;
  readonly generationId: string | null;
  readonly version: number;
  readonly updatedAt: Date;
};

export function mapPointer(row: PointerRow): OsvActiveCatalogPointer {
  return requireOk(
    createOsvActiveCatalogPointer({
      scopeFingerprint: row.scopeFingerprint,
      generationId: row.generationId,
      version: row.version,
      updatedAt: toIsoUtc(row.updatedAt),
    }),
    'active pointer',
  );
}

export type ReconciliationRow = {
  readonly catalogGenerationId: string;
  readonly acceptedListedCount: number;
  readonly eligibleCount: number;
  readonly ineligibleCount: number;
  readonly legalReviewCount: number;
  readonly unknownCount: number;
  readonly ambiguousCount: number;
  readonly listingRejectedCount: number;
  readonly attachedEligibleSnapshotCount: number;
  readonly missingEligibleSnapshotCount: number;
  readonly nonEligibleSnapshotCount: number;
  readonly parserSuccessCount: number;
  readonly parserFailureCount: number;
  readonly quarantinedSnapshotCount: number;
  readonly acceptedRevisionCount: number;
  readonly withdrawnRevisionCount: number;
  readonly membershipCount: number;
  readonly providerAbsentCount: number;
  readonly immutableConflictCount: number;
  readonly blockingQuarantineCount: number;
  readonly failClosedRetrievedBodyCount: number;
  readonly pinMismatchCount: number;
};

export function mapReconciliation(row: ReconciliationRow): OsvReconciliationResult {
  return requireOk(
    reconcileOsvGenerationCounts({
      catalogGenerationId: row.catalogGenerationId,
      acceptedListedCount: row.acceptedListedCount,
      eligibleCount: row.eligibleCount,
      ineligibleCount: row.ineligibleCount,
      legalReviewCount: row.legalReviewCount,
      unknownCount: row.unknownCount,
      ambiguousCount: row.ambiguousCount,
      listingRejectedCount: row.listingRejectedCount,
      attachedEligibleSnapshotCount: row.attachedEligibleSnapshotCount,
      missingEligibleSnapshotCount: row.missingEligibleSnapshotCount,
      nonEligibleSnapshotCount: row.nonEligibleSnapshotCount,
      parserSuccessCount: row.parserSuccessCount,
      parserFailureCount: row.parserFailureCount,
      quarantinedSnapshotCount: row.quarantinedSnapshotCount,
      acceptedRevisionCount: row.acceptedRevisionCount,
      withdrawnRevisionCount: row.withdrawnRevisionCount,
      membershipCount: row.membershipCount,
      providerAbsentCount: row.providerAbsentCount,
      immutableConflictCount: row.immutableConflictCount,
      blockingQuarantineCount: row.blockingQuarantineCount,
      failClosedRetrievedBodyCount: row.failClosedRetrievedBodyCount,
      pinMismatchCount: row.pinMismatchCount,
    }),
    'reconciliation',
  );
}

export function emptyCompletenessRows(catalogGenerationId: string): CompletenessRow[] {
  const base = {
    catalogGenerationId,
    requiredCount: 0,
    observedCount: 0,
    discrepancyCodes: [] as OsvReconciliationDiscrepancyCode[],
  };
  return [
    { ...base, dimension: 'inventory', status: 'not_started' },
    { ...base, dimension: 'eligible_body', status: 'not_started' },
    { ...base, dimension: 'parser', status: 'not_started' },
    { ...base, dimension: 'parsed_catalog', status: 'not_started' },
    {
      ...base,
      dimension: 'matching',
      status: 'not_in_scope',
    },
  ];
}
