/**
 * Session 13 Batch 3D-A / 3D-A-R PostgreSQL adapters for protected
 * listing-observation evidence. Insert-once ensure with inspect-before-encrypt
 * replay, public inspect that omits envelope BYTEA and key alias, authorized
 * protected reads via the injected cryptographic capability, review CAS, and
 * legal-hold CAS. Encryption uses a final ID snapshot before Prisma writes.
 *
 * Construction performs no I/O. Adapters do not contact a provider, enable
 * OSV, execute purge, or expose a generic envelope update. Production
 * composition does not construct this factory.
 */

import { randomUUID } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  OSV_PROTECTED_LISTING_EVIDENCE_ALGORITHM_ID,
  OSV_PROTECTED_LISTING_EVIDENCE_ASSOCIATED_DATA_ALGORITHM_ID,
  OSV_PROTECTED_LISTING_EVIDENCE_ASSOCIATED_DATA_POLICY_ID,
  OSV_PROTECTED_LISTING_EVIDENCE_ENCRYPTION_POLICY_ID,
  OSV_PROTECTED_LISTING_EVIDENCE_ENVELOPE_SCHEMA_VERSION,
  OSV_PROTECTED_LISTING_OBSERVATION_CANONICAL_ALGORITHM_ID,
  OSV_PROTECTED_LISTING_OBSERVATION_CLASSIFICATION_POLICY_ID,
  OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_OWNERSHIP,
  OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_POLICY_ID,
  OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_PURPOSE_ID,
  OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
  OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_SET_ALGORITHM_ID,
  OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_BUDGET,
  OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_POLICY,
  OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_PREFIX,
  OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_PROVIDER,
  OSV_PROTECTED_LISTING_OBSERVATION_LISTING_PROTOCOL,
  OSV_PROTECTED_LISTING_OBSERVATION_MAX_RECORDS,
  OSV_PROTECTED_LISTING_OBSERVATION_RETENTION_POLICY_ID,
  OSV_PROTECTED_LISTING_OBSERVATION_SOURCE_LICENSE_REGISTRY,
  isOsvListingObservationEvidenceEnsureCommand,
  isOsvListingObservationEvidenceInspectForRunQuery,
  isOsvListingObservationEvidenceInspectQuery,
  isOsvListingObservationEvidenceReadProtectedQuery,
  isOsvListingObservationEvidenceRecordReviewCommand,
  isOsvListingObservationEvidenceSetLegalHoldCommand,
  type OsvListingObservationEvidenceEnsureCommand,
  type OsvListingObservationEvidenceEnsureResult,
  type OsvListingObservationEvidenceInspectForRunQuery,
  type OsvListingObservationEvidenceInspectQuery,
  type OsvListingObservationEvidenceLegalHoldResult,
  type OsvListingObservationEvidencePersistencePort,
  type OsvListingObservationEvidencePersistenceRejectionCode,
  type OsvListingObservationEvidencePersistenceResult,
  type OsvListingObservationEvidenceProtectedReadResult,
  type OsvListingObservationEvidencePublicRecord,
  type OsvListingObservationEvidenceReadProtectedQuery,
  type OsvListingObservationEvidenceRecordReviewCommand,
  type OsvListingObservationEvidenceReviewResult,
  type OsvListingObservationEvidenceSetLegalHoldCommand,
  type OsvProtectedListingEvidenceCryptographicCapabilityPort,
  type OsvProtectedListingObservation,
  type OsvProtectedListingObservationEvidenceSet,
} from '@patchpilot/vulnerability-intelligence';
import {
  associatedDataContextsMatch,
  mapOsvProtectedListingEvidenceCiphertextEnvelopeForRestrictedPersistence,
  readOsvProtectedListingObservationEvidenceSetObservations,
  readOsvProtectedListingObservationInternalFields,
  reconstructOsvProtectedListingEvidenceAssociatedDataFromPersistedColumns,
  reconstructOsvProtectedListingEvidenceCiphertextEnvelopeFromRestrictedPersistence,
  releaseOsvProtectedListingEvidenceEnvelopePersistenceRecord,
  sourceFamilyKey,
  type OsvProtectedListingEvidenceEnvelopePersistenceRecord,
  type OsvProtectedListingObservationInternalFields,
} from '@patchpilot/vulnerability-intelligence/osv-listing-evidence-envelope-persistence';

import { isRootPrismaClient, type PrismaClientLike } from './guards.js';
import {
  isRestrictViolation,
  isUniqueViolation,
  translateListingObservationEvidenceFailure,
} from './osv-listing-observation-evidence-errors.js';
import {
  mapPublicEvidenceSet,
  OsvListingObservationEvidenceMappingError,
} from './osv-listing-observation-evidence-mappers.js';

const ROOT_CLIENT_REQUIRED =
  'OSV listing observation evidence persistence requires the root database client.';

const PUBLIC_SET_SELECT = {
  id: true,
  evidenceSchemaVersion: true,
  listingExecutionId: true,
  providerContactAuthorizationId: true,
  synchronizationRequestId: true,
  synchronizationRunId: true,
  provider: true,
  approvedPrefix: true,
  listingProtocolId: true,
  listingPolicyId: true,
  budgetProfileId: true,
  runtimeVersionSetFingerprint: true,
  pageOrdinal: true,
  canonicalEvidenceSetDigest: true,
  translatorObservationCount: true,
  acceptedObservationCount: true,
  protectedObservationCount: true,
  rejectedObservationCount: true,
  exactDuplicateCount: true,
  duplicateAmbiguityCount: true,
  immutableConflictCount: true,
  evidenceState: true,
  candidateSelectionReadiness: true,
  legalHoldActive: true,
  legalHoldClassification: true,
  rowRevision: true,
  capturedAt: true,
  reviewRecordedAt: true,
  observations: {
    select: {
      id: true,
      observationOrdinal: true,
      listingObservationIdentity: true,
      providerGeneration: true,
      declaredListingByteCount: true,
      sourceFamilyClassification: true,
      classificationStatus: true,
      duplicateClassification: true,
      immutableConflictClassification: true,
      candidateSelectionEligibility: true,
    },
    orderBy: { observationOrdinal: 'asc' as const },
  },
} satisfies Prisma.OsvListingObservationEvidenceSetSelect;

export type OsvListingObservationEvidencePersistenceAdapters =
  OsvListingObservationEvidencePersistencePort;

export type OsvListingObservationEvidencePersistenceDependencies = {
  readonly cryptographicCapability: OsvProtectedListingEvidenceCryptographicCapabilityPort;
};

export function createOsvListingObservationEvidencePersistence(
  client: PrismaClient,
  dependencies: OsvListingObservationEvidencePersistenceDependencies,
): OsvListingObservationEvidencePersistenceAdapters {
  if (client === null || client === undefined || !isRootPrismaClient(client)) {
    throw new OsvListingObservationEvidencePersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  if (
    typeof dependencies !== 'object' ||
    dependencies === null ||
    typeof dependencies.cryptographicCapability !== 'object' ||
    dependencies.cryptographicCapability === null
  ) {
    throw new OsvListingObservationEvidencePersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  return createOsvListingObservationEvidencePersistenceForClient(
    client,
    dependencies.cryptographicCapability,
  );
}

export function createOsvListingObservationEvidencePersistenceForClient(
  client: PrismaClientLike,
  cryptographicCapability: OsvProtectedListingEvidenceCryptographicCapabilityPort,
): OsvListingObservationEvidencePersistenceAdapters {
  return new PrismaOsvListingObservationEvidenceRepository(client, cryptographicCapability);
}

class OsvListingObservationEvidencePersistenceFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvListingObservationEvidencePersistenceFailure';
  }
}

function fail(
  code: OsvListingObservationEvidencePersistenceRejectionCode,
): OsvListingObservationEvidencePersistenceResult<never> {
  return { ok: false, code };
}

function mapCaught(error: unknown): OsvListingObservationEvidencePersistenceResult<never> {
  if (error instanceof OsvListingObservationEvidenceMappingError) {
    return fail('malformed_authority');
  }
  return fail(translateListingObservationEvidenceFailure(error));
}

function declaredSizeToSafeInteger(value: bigint): number {
  if (value < 0n || value > 1_048_576n) {
    throw new OsvListingObservationEvidenceMappingError('declared size mapping failed.');
  }
  return Number(value);
}

function requireClassificationStatus(
  value: string,
): 'eligible' | 'ineligible' | 'legal_review_required' | 'unknown' | 'ambiguous' {
  if (
    value === 'eligible' ||
    value === 'ineligible' ||
    value === 'legal_review_required' ||
    value === 'unknown' ||
    value === 'ambiguous'
  ) {
    return value;
  }
  throw new OsvListingObservationEvidenceMappingError('classification status mapping failed.');
}

function mapCryptoFailure(code: string): OsvListingObservationEvidencePersistenceRejectionCode {
  if (code === 'cancelled') {
    return 'cancelled';
  }
  if (code === 'reveal_purpose_unauthorized') {
    return 'reveal_purpose_unauthorized';
  }
  if (code === 'ciphertext_malformed' || code === 'authentication_failed') {
    return 'ciphertext_malformed';
  }
  if (code === 'binding_mismatch') {
    return 'binding_mismatch';
  }
  return 'internal_failure';
}

async function runSerializable<T>(
  client: PrismaClientLike,
  fn: (tx: PrismaClientLike) => Promise<T>,
): Promise<T> {
  if (isRootPrismaClient(client)) {
    return client.$transaction(async (tx) => fn(tx), {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
      maxWait: 2000,
      timeout: 15_000,
    });
  }
  return fn(client);
}

function persistableState(set: OsvProtectedListingObservationEvidenceSet): {
  readonly evidenceState: 'review_pending' | 'duplicate_ambiguous' | 'constructed';
  readonly candidateSelectionReadiness:
    | 'review_not_accepted'
    | 'ineligible_duplicate_ambiguity'
    | 'empty_page_not_candidate_ready'
    | 'metadata_complete_selection_not_authorized';
} {
  if (set.evidenceState === 'duplicate_ambiguous') {
    return {
      evidenceState: 'duplicate_ambiguous',
      candidateSelectionReadiness: 'ineligible_duplicate_ambiguity',
    };
  }
  if (set.translatorObservationCount === 0) {
    return {
      evidenceState: 'constructed',
      candidateSelectionReadiness: 'empty_page_not_candidate_ready',
    };
  }
  return {
    evidenceState: 'review_pending',
    candidateSelectionReadiness: 'review_not_accepted',
  };
}

function sameNaturalIdentity(
  existing: OsvListingObservationEvidencePublicRecord,
  set: OsvProtectedListingObservationEvidenceSet,
  rejectedObservationCount: number,
  exactDuplicateCount: number,
  duplicateAmbiguityCount: number,
): boolean {
  return (
    existing.listingExecutionId === set.listingExecutionId &&
    existing.providerContactAuthorizationId === set.providerContactAuthorizationId &&
    existing.synchronizationRequestId === set.synchronizationRequestId &&
    existing.synchronizationRunId === set.synchronizationRunId &&
    existing.provider === set.provider &&
    existing.approvedPrefix === set.approvedPrefix &&
    existing.listingProtocolId === set.listingProtocolVersion &&
    existing.listingPolicyId === set.listingPolicyId &&
    existing.budgetProfileId === set.budgetProfileId &&
    existing.runtimeVersionSetFingerprint === set.runtimeVersionSetFingerprint &&
    existing.canonicalEvidenceSetDigest === set.canonicalEvidenceSetDigest &&
    existing.translatorObservationCount === set.translatorObservationCount &&
    existing.acceptedObservationCount === set.acceptedObservationCount &&
    existing.protectedObservationCount === set.protectedObservationCount &&
    existing.rejectedObservationCount === rejectedObservationCount &&
    existing.exactDuplicateCount === exactDuplicateCount &&
    existing.duplicateAmbiguityCount === duplicateAmbiguityCount &&
    existing.immutableConflictCount === 0
  );
}

function persistableAccounting(
  set: OsvProtectedListingObservationEvidenceSet,
  observationCount: number,
): OsvListingObservationEvidencePersistenceResult<{
  readonly rejectedObservationCount: number;
  readonly exactDuplicateCount: number;
  readonly duplicateAmbiguityCount: number;
  readonly eventCount: number;
}> {
  if (observationCount > OSV_PROTECTED_LISTING_OBSERVATION_MAX_RECORDS) {
    return fail('overflow_set_rejected');
  }
  if (set.conflictCount !== 0) {
    return fail('conflict_set_rejected');
  }
  if (
    set.protectedObservationCount !== observationCount ||
    set.acceptedObservationCount !== observationCount ||
    set.translatorObservationCount < set.acceptedObservationCount ||
    set.translatorObservationCount > OSV_PROTECTED_LISTING_OBSERVATION_MAX_RECORDS ||
    set.duplicateCount > set.acceptedObservationCount ||
    set.eventCount < 0 ||
    set.eventCount > 16
  ) {
    return fail('overflow_set_rejected');
  }
  const rejectedObservationCount = set.translatorObservationCount - set.acceptedObservationCount;
  if (rejectedObservationCount < 0) {
    return fail('overflow_set_rejected');
  }
  if (set.evidenceState === 'duplicate_ambiguous') {
    if (set.duplicateCount < 1) {
      return fail('set_not_persistable');
    }
    return {
      ok: true,
      value: {
        rejectedObservationCount,
        exactDuplicateCount: set.duplicateCount,
        duplicateAmbiguityCount: 1,
        eventCount: set.eventCount,
      },
    };
  }
  if (set.duplicateCount !== 0) {
    return fail('set_not_persistable');
  }
  return {
    ok: true,
    value: {
      rejectedObservationCount,
      exactDuplicateCount: 0,
      duplicateAmbiguityCount: 0,
      eventCount: set.eventCount,
    },
  };
}

class PrismaOsvListingObservationEvidenceRepository implements OsvListingObservationEvidencePersistencePort {
  public constructor(
    private readonly client: PrismaClientLike,
    private readonly cryptographicCapability: OsvProtectedListingEvidenceCryptographicCapabilityPort,
  ) {}

  public async ensure(
    command: OsvListingObservationEvidenceEnsureCommand,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<OsvListingObservationEvidenceEnsureResult>
  > {
    if (!isOsvListingObservationEvidenceEnsureCommand(command)) {
      return fail('not_constructed');
    }
    const set = command.evidenceSet;
    const observations = readOsvProtectedListingObservationEvidenceSetObservations(set);
    if (!observations.ok) {
      return fail('not_constructed');
    }
    const accounting = persistableAccounting(set, observations.value.length);
    if (!accounting.ok) {
      return accounting;
    }
    try {
      const existing = await this.findConflictingOrMatching(this.client, set);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value !== null) {
        if (
          !sameNaturalIdentity(
            existing.value,
            set,
            accounting.value.rejectedObservationCount,
            accounting.value.exactDuplicateCount,
            accounting.value.duplicateAmbiguityCount,
          )
        ) {
          return fail('immutable_conflict');
        }
        const identitiesMatch = this.observationIdentitiesMatch(existing.value, observations.value);
        if (!identitiesMatch) {
          return fail('immutable_conflict');
        }
        return {
          ok: true,
          value: {
            status: 'already_applied',
            record: existing.value,
            encryptionCalls: 0,
            nonceGenerationCalls: 0,
            persistenceOccurred: false,
            providerContactOccurred: false,
            plaintextReturned: false,
            candidateSelectionAuthorized: false,
            bodyRetrievalAuthorized: false,
            batch4pPermitted: false,
          },
        };
      }
      const prerequisites = await this.validatePrerequisites(this.client, set);
      if (!prerequisites.ok) {
        return prerequisites;
      }
      const prepared = await this.protectObservations(set, observations.value, accounting.value);
      if (!prepared.ok) {
        return prepared;
      }
      try {
        const persisted = await runSerializable(this.client, async (tx) => {
          return this.insertEvidence(tx, set, prepared.value, prerequisites.value);
        });
        return {
          ok: true,
          value: {
            status: 'persisted',
            record: persisted,
            encryptionCalls: prepared.value.encryptionCalls,
            nonceGenerationCalls: prepared.value.encryptionCalls,
            persistenceOccurred: true,
            providerContactOccurred: false,
            plaintextReturned: false,
            candidateSelectionAuthorized: false,
            bodyRetrievalAuthorized: false,
            batch4pPermitted: false,
          },
        };
      } catch (error) {
        if (isUniqueViolation(error)) {
          const replay = await this.findConflictingOrMatching(this.client, set);
          if (!replay.ok) {
            return replay;
          }
          if (
            replay.value !== null &&
            sameNaturalIdentity(
              replay.value,
              set,
              accounting.value.rejectedObservationCount,
              accounting.value.exactDuplicateCount,
              accounting.value.duplicateAmbiguityCount,
            ) &&
            this.observationIdentitiesMatch(replay.value, observations.value)
          ) {
            return {
              ok: true,
              value: {
                status: 'already_applied',
                record: replay.value,
                encryptionCalls: prepared.value.encryptionCalls,
                nonceGenerationCalls: prepared.value.encryptionCalls,
                persistenceOccurred: false,
                providerContactOccurred: false,
                plaintextReturned: false,
                candidateSelectionAuthorized: false,
                bodyRetrievalAuthorized: false,
                batch4pPermitted: false,
              },
            };
          }
          return fail('immutable_conflict');
        }
        if (isRestrictViolation(error)) {
          return fail('state_conflict');
        }
        return mapCaught(error);
      } finally {
        for (const envelope of prepared.value.envelopes) {
          releaseOsvProtectedListingEvidenceEnvelopePersistenceRecord(envelope.record);
        }
      }
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async inspect(
    query: OsvListingObservationEvidenceInspectQuery,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<OsvListingObservationEvidencePublicRecord>
  > {
    if (!isOsvListingObservationEvidenceInspectQuery(query)) {
      return fail('not_constructed');
    }
    try {
      const row = await this.client.osvListingObservationEvidenceSet.findUnique({
        where: { id: query.evidenceSetId },
        select: PUBLIC_SET_SELECT,
      });
      if (row === null) {
        return fail('evidence_set_not_found');
      }
      return { ok: true, value: mapPublicEvidenceSet(row) };
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async inspectForRun(
    query: OsvListingObservationEvidenceInspectForRunQuery,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<OsvListingObservationEvidencePublicRecord>
  > {
    if (!isOsvListingObservationEvidenceInspectForRunQuery(query)) {
      return fail('not_constructed');
    }
    try {
      const row = await this.client.osvListingObservationEvidenceSet.findFirst({
        where: {
          synchronizationRequestId: query.synchronizationRequestId,
          synchronizationRunId: query.synchronizationRunId,
        },
        select: PUBLIC_SET_SELECT,
      });
      if (row === null) {
        return fail('evidence_set_not_found');
      }
      return { ok: true, value: mapPublicEvidenceSet(row) };
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async readProtected(
    query: OsvListingObservationEvidenceReadProtectedQuery,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<OsvListingObservationEvidenceProtectedReadResult>
  > {
    if (!isOsvListingObservationEvidenceReadProtectedQuery(query)) {
      return fail('not_constructed');
    }
    try {
      const observation = await this.client.osvListingObservationEvidence.findFirst({
        where: {
          id: query.observationId,
          evidenceSetId: query.evidenceSetId,
        },
        select: {
          id: true,
          evidenceSetId: true,
          listingExecutionId: true,
          providerContactAuthorizationId: true,
          synchronizationRequestId: true,
          synchronizationRunId: true,
          runtimeVersionSetFingerprint: true,
          providerGeneration: true,
          declaredListingByteCount: true,
          sourceFamilyClassification: true,
          classificationStatus: true,
          plaintextLengthAccounting: true,
          evidenceSet: {
            select: {
              evidenceState: true,
              synchronizationRequestId: true,
              synchronizationRunId: true,
            },
          },
        },
      });
      if (observation === null) {
        return fail('evidence_set_not_found');
      }
      if (observation.evidenceSet.evidenceState === 'purged') {
        return fail('state_conflict');
      }
      if (
        observation.synchronizationRequestId !== query.synchronizationRequestId ||
        observation.synchronizationRunId !== query.synchronizationRunId ||
        observation.evidenceSet.synchronizationRequestId !== query.synchronizationRequestId ||
        observation.evidenceSet.synchronizationRunId !== query.synchronizationRunId
      ) {
        return fail('binding_mismatch');
      }
      const envelope = await this.client.osvListingObservationEvidenceEnvelope.findFirst({
        where: {
          observationId: query.observationId,
          evidenceSetId: query.evidenceSetId,
          envelopeState: 'current',
        },
        select: {
          protectedIdentityEnvelope: true,
          opaqueKeyAlias: true,
          plaintextLengthAccounting: true,
          erasureState: true,
        },
      });
      if (envelope === null) {
        return fail('envelope_absent');
      }
      if (
        envelope.erasureState === 'cryptographically_erased' ||
        envelope.protectedIdentityEnvelope === null
      ) {
        return fail('envelope_erased');
      }
      const reconstructed =
        reconstructOsvProtectedListingEvidenceCiphertextEnvelopeFromRestrictedPersistence({
          protectedIdentityEnvelope: Uint8Array.from(envelope.protectedIdentityEnvelope),
          plaintextLengthAccounting: envelope.plaintextLengthAccounting,
          opaqueKeyAlias: envelope.opaqueKeyAlias,
        });
      if (!reconstructed.ok) {
        return fail(mapCryptoFailure(reconstructed.code));
      }
      const revealed =
        await this.cryptographicCapability.revealOsvListingObjectIdentityForAuthorizedPurpose({
          envelope: reconstructed.value,
          associatedDataContext: {
            evidenceSetId: observation.evidenceSetId,
            observationId: observation.id,
            listingExecutionId: observation.listingExecutionId,
            providerContactAuthorizationId: observation.providerContactAuthorizationId,
            synchronizationRequestId: observation.synchronizationRequestId,
            synchronizationRunId: observation.synchronizationRunId,
            providerGeneration: observation.providerGeneration,
            runtimeVersionSetFingerprint: observation.runtimeVersionSetFingerprint,
            declaredSizeBytes: declaredSizeToSafeInteger(observation.declaredListingByteCount),
            sourceFamilyClassification: observation.sourceFamilyClassification,
            classificationStatus: observation.classificationStatus,
          },
          authorization: {
            purpose: query.purpose,
            evidenceSetId: query.evidenceSetId,
            observationId: query.observationId,
            synchronizationRequestId: query.synchronizationRequestId,
            synchronizationRunId: query.synchronizationRunId,
          },
        });
      if (!revealed.ok) {
        return fail(mapCryptoFailure(revealed.code));
      }
      return {
        ok: true,
        value: {
          identity: revealed.value.identity,
          evidenceSetId: observation.evidenceSetId,
          observationId: observation.id,
          purposeAuthorized: true,
          decryptionExecuted: true,
          persistenceOccurred: false,
          providerContactAuthorized: false,
          bodyRetrievalAuthorized: false,
          matchingAuthorized: false,
          findingWritesAuthorized: false,
        },
      };
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async recordReview(
    command: OsvListingObservationEvidenceRecordReviewCommand,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<OsvListingObservationEvidenceReviewResult>
  > {
    if (!isOsvListingObservationEvidenceRecordReviewCommand(command)) {
      return fail('not_constructed');
    }
    try {
      const current = await this.client.osvListingObservationEvidenceSet.findUnique({
        where: { id: command.evidenceSetId },
        select: PUBLIC_SET_SELECT,
      });
      if (current === null) {
        return fail('evidence_set_not_found');
      }
      const mapped = mapPublicEvidenceSet(current);
      if (mapped.rowRevision !== command.expectedRowRevision) {
        return fail('stale_revision');
      }
      if (mapped.evidenceState === command.decision) {
        return { ok: true, value: { status: 'already_applied', record: mapped } };
      }
      if (mapped.evidenceState !== 'review_pending') {
        return fail('state_conflict');
      }
      const readiness =
        command.decision === 'review_accepted'
          ? 'metadata_complete_selection_not_authorized'
          : 'review_not_accepted';
      const updated = await this.client.$queryRaw<Array<{ id: string }>>`
        UPDATE "osv_listing_observation_evidence_set"
        SET
          "evidence_state" = ${command.decision}::"osv_listing_observation_evidence_set_state",
          "candidate_selection_readiness" = ${readiness}::"osv_listing_observation_set_candidate_readiness",
          "row_revision" = "row_revision" + 1,
          "review_recorded_at" = CURRENT_TIMESTAMP
        WHERE "id" = ${command.evidenceSetId}::uuid
          AND "evidence_state" = 'review_pending'::"osv_listing_observation_evidence_set_state"
          AND "row_revision" = ${command.expectedRowRevision}::bigint
        RETURNING "id"
      `;
      if (updated.length !== 1) {
        return fail('stale_revision');
      }
      const reloaded = await this.client.osvListingObservationEvidenceSet.findUnique({
        where: { id: command.evidenceSetId },
        select: PUBLIC_SET_SELECT,
      });
      if (reloaded === null) {
        return fail('evidence_set_not_found');
      }
      return {
        ok: true,
        value: { status: 'transitioned', record: mapPublicEvidenceSet(reloaded) },
      };
    } catch (error) {
      if (isRestrictViolation(error)) {
        return fail('state_conflict');
      }
      return mapCaught(error);
    }
  }

  public async setLegalHold(
    command: OsvListingObservationEvidenceSetLegalHoldCommand,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<OsvListingObservationEvidenceLegalHoldResult>
  > {
    if (!isOsvListingObservationEvidenceSetLegalHoldCommand(command)) {
      return fail('not_constructed');
    }
    try {
      const current = await this.client.osvListingObservationEvidenceSet.findUnique({
        where: { id: command.evidenceSetId },
        select: PUBLIC_SET_SELECT,
      });
      if (current === null) {
        return fail('evidence_set_not_found');
      }
      const mapped = mapPublicEvidenceSet(current);
      if (mapped.rowRevision !== command.expectedRowRevision) {
        return fail('stale_revision');
      }
      const alreadyActive =
        command.decision === 'legal_hold_active' &&
        mapped.legalHoldActive === true &&
        mapped.legalHoldClassification === 'legal_hold_active';
      const alreadyReleased =
        command.decision === 'hold_released' &&
        mapped.legalHoldActive === false &&
        mapped.legalHoldClassification === 'hold_released';
      if (alreadyActive || alreadyReleased) {
        return {
          ok: true,
          value: {
            status: 'already_applied',
            record: mapped,
            legalHoldActive: mapped.legalHoldActive,
            envelopeRedactionAuthorized: false,
            purgeAuthorized: false,
            revealAuthorized: false,
            providerContactAuthorized: false,
            bodyRetrievalAuthorized: false,
          },
        };
      }
      const applyPermitted =
        command.decision === 'legal_hold_active' &&
        mapped.legalHoldActive === false &&
        (mapped.legalHoldClassification === 'hold_absent' ||
          mapped.legalHoldClassification === 'hold_released');
      const releasePermitted =
        command.decision === 'hold_released' &&
        mapped.legalHoldActive === true &&
        mapped.legalHoldClassification === 'legal_hold_active';
      if (!applyPermitted && !releasePermitted) {
        return fail('state_conflict');
      }
      const updated =
        command.decision === 'legal_hold_active'
          ? await this.client.$queryRaw<Array<{ id: string }>>`
              UPDATE "osv_listing_observation_evidence_set"
              SET
                "legal_hold_active" = TRUE,
                "legal_hold_classification" = 'legal_hold_active'::"osv_listing_observation_legal_hold_classification",
                "row_revision" = "row_revision" + 1
              WHERE "id" = ${command.evidenceSetId}::uuid
                AND "row_revision" = ${command.expectedRowRevision}::bigint
                AND "legal_hold_active" = FALSE
                AND "legal_hold_classification" IN (
                  'hold_absent'::"osv_listing_observation_legal_hold_classification",
                  'hold_released'::"osv_listing_observation_legal_hold_classification"
                )
              RETURNING "id"
            `
          : await this.client.$queryRaw<Array<{ id: string }>>`
              UPDATE "osv_listing_observation_evidence_set"
              SET
                "legal_hold_active" = FALSE,
                "legal_hold_classification" = 'hold_released'::"osv_listing_observation_legal_hold_classification",
                "row_revision" = "row_revision" + 1
              WHERE "id" = ${command.evidenceSetId}::uuid
                AND "row_revision" = ${command.expectedRowRevision}::bigint
                AND "legal_hold_active" = TRUE
                AND "legal_hold_classification" = 'legal_hold_active'::"osv_listing_observation_legal_hold_classification"
              RETURNING "id"
            `;
      if (updated.length !== 1) {
        return fail('stale_revision');
      }
      const reloaded = await this.client.osvListingObservationEvidenceSet.findUnique({
        where: { id: command.evidenceSetId },
        select: PUBLIC_SET_SELECT,
      });
      if (reloaded === null) {
        return fail('evidence_set_not_found');
      }
      const record = mapPublicEvidenceSet(reloaded);
      return {
        ok: true,
        value: {
          status: 'transitioned',
          record,
          legalHoldActive: record.legalHoldActive,
          envelopeRedactionAuthorized: false,
          purgeAuthorized: false,
          revealAuthorized: false,
          providerContactAuthorized: false,
          bodyRetrievalAuthorized: false,
        },
      };
    } catch (error) {
      if (isRestrictViolation(error)) {
        return fail('state_conflict');
      }
      return mapCaught(error);
    }
  }

  private observationIdentitiesMatch(
    existing: OsvListingObservationEvidencePublicRecord,
    observations: readonly OsvProtectedListingObservation[],
  ): boolean {
    if (existing.observations.length !== observations.length) {
      return false;
    }
    for (const observation of observations) {
      const internals = readOsvProtectedListingObservationInternalFields(observation);
      if (!internals.ok) {
        return false;
      }
      const persisted = existing.observations.find(
        (row) => row.observationOrdinal === observation.observationOrdinal,
      );
      if (
        persisted === undefined ||
        persisted.listingObservationIdentity !== observation.listingObservationIdentity ||
        persisted.providerGeneration !== internals.value.providerGeneration ||
        persisted.declaredListingByteCount !== String(internals.value.declaredSizeBytes) ||
        persisted.sourceFamilyClassification !==
          sourceFamilyKey(internals.value.sourceFamily.familyCandidate) ||
        persisted.classificationStatus !== internals.value.sourceFamily.classificationStatus ||
        persisted.duplicateClassification !== observation.duplicateClassification ||
        persisted.immutableConflictClassification !== observation.immutableConflictClassification
      ) {
        return false;
      }
    }
    return true;
  }

  private async findConflictingOrMatching(
    client: PrismaClientLike,
    set: OsvProtectedListingObservationEvidenceSet,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<OsvListingObservationEvidencePublicRecord | null>
  > {
    const rows = await client.osvListingObservationEvidenceSet.findMany({
      where: {
        OR: [
          { listingExecutionId: set.listingExecutionId },
          { providerContactAuthorizationId: set.providerContactAuthorizationId },
          { synchronizationRequestId: set.synchronizationRequestId },
          { synchronizationRunId: set.synchronizationRunId },
        ],
      },
      select: PUBLIC_SET_SELECT,
      take: 5,
    });
    if (rows.length === 0) {
      return { ok: true, value: null };
    }
    if (rows.length === 5) {
      return fail('immutable_conflict');
    }
    const ids = new Set(rows.map((row) => row.id));
    if (ids.size !== 1) {
      return fail('immutable_conflict');
    }
    const first = rows[0];
    if (first === undefined) {
      return { ok: true, value: null };
    }
    return { ok: true, value: mapPublicEvidenceSet(first) };
  }

  private async validatePrerequisites(
    client: PrismaClientLike,
    set: OsvProtectedListingObservationEvidenceSet,
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<{
      readonly workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1';
      readonly leaseScope: string;
      readonly synchronizationReason: 'operator_canary';
    }>
  > {
    const authorization = await client.osvListingProviderContactAuthorization.findUnique({
      where: { id: set.providerContactAuthorizationId },
      select: {
        id: true,
        synchronizationRequestId: true,
        synchronizationRunId: true,
        approvedPrefix: true,
        listingProtocol: true,
        runtimeVersionSetFingerprint: true,
        workScope: true,
        leaseScope: true,
        synchronizationReason: true,
        canaryPolicyIdentifier: true,
        listingBudgetProfile: true,
      },
    });
    if (authorization === null) {
      return fail('authorization_not_found');
    }
    if (
      authorization.synchronizationRequestId !== set.synchronizationRequestId ||
      authorization.synchronizationRunId !== set.synchronizationRunId ||
      authorization.approvedPrefix !== set.approvedPrefix ||
      authorization.listingProtocol !== set.listingProtocolVersion ||
      authorization.runtimeVersionSetFingerprint !== set.runtimeVersionSetFingerprint ||
      authorization.canaryPolicyIdentifier !== set.listingPolicyId ||
      authorization.listingBudgetProfile !== set.budgetProfileId
    ) {
      return fail('binding_mismatch');
    }
    const request = await client.osvRuntimeSynchronizationRequest.findUnique({
      where: { id: set.synchronizationRequestId },
      select: {
        id: true,
        workScope: true,
        leaseScope: true,
        synchronizationReason: true,
        versionSetFingerprint: true,
      },
    });
    if (request === null) {
      return fail('request_not_found');
    }
    const run = await client.osvRuntimeSynchronizationRun.findUnique({
      where: { id: set.synchronizationRunId },
      select: {
        id: true,
        requestId: true,
        workScope: true,
        leaseScope: true,
        synchronizationReason: true,
        versionSetFingerprint: true,
      },
    });
    if (run === null) {
      return fail('run_not_found');
    }
    if (
      run.requestId !== set.synchronizationRequestId ||
      request.versionSetFingerprint !== set.runtimeVersionSetFingerprint ||
      run.versionSetFingerprint !== set.runtimeVersionSetFingerprint ||
      authorization.workScope !== request.workScope ||
      authorization.leaseScope !== request.leaseScope ||
      authorization.synchronizationReason !== request.synchronizationReason
    ) {
      return fail('binding_mismatch');
    }
    if (
      authorization.workScope !== 'osv_runtime_canary_scope_crates_io_rustsec_v1' ||
      authorization.synchronizationReason !== 'operator_canary'
    ) {
      return fail('binding_mismatch');
    }
    return {
      ok: true,
      value: {
        workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1',
        leaseScope: authorization.leaseScope,
        synchronizationReason: 'operator_canary',
      },
    };
  }

  private async protectObservations(
    set: OsvProtectedListingObservationEvidenceSet,
    observations: readonly OsvProtectedListingObservation[],
    accounting: {
      readonly rejectedObservationCount: number;
      readonly exactDuplicateCount: number;
      readonly duplicateAmbiguityCount: number;
      readonly eventCount: number;
    },
  ): Promise<
    OsvListingObservationEvidencePersistenceResult<{
      readonly evidenceSetId: string;
      readonly encryptionCalls: number;
      readonly accounting: typeof accounting;
      readonly rows: readonly {
        readonly observationId: string;
        readonly observation: (typeof observations)[number];
        readonly internals: OsvProtectedListingObservationInternalFields;
        readonly sourceFamilyClassification: string;
        readonly classificationStatus: OsvProtectedListingObservationInternalFields['sourceFamily']['classificationStatus'];
      }[];
      readonly envelopes: readonly {
        readonly observationId: string;
        readonly record: OsvProtectedListingEvidenceEnvelopePersistenceRecord;
      }[];
    }>
  > {
    const readiness =
      await this.cryptographicCapability.inspectProtectedEvidenceCryptographicReadiness();
    if (!readiness.ok) {
      return fail(mapCryptoFailure(readiness.code));
    }
    if (
      !readiness.value.encryptionPermitted ||
      readiness.value.plaintextFallbackConfigured !== false ||
      readiness.value.nonceCapabilityAvailable !== true
    ) {
      return fail('internal_failure');
    }
    const evidenceSetId = randomUUID();
    const snapshots: {
      readonly observationId: string;
      readonly observation: (typeof observations)[number];
      readonly internals: OsvProtectedListingObservationInternalFields;
      readonly sourceFamilyClassification: string;
      readonly classificationStatus: OsvProtectedListingObservationInternalFields['sourceFamily']['classificationStatus'];
      readonly associatedDataInput: {
        readonly evidenceSetId: string;
        readonly observationId: string;
        readonly listingExecutionId: string;
        readonly providerContactAuthorizationId: string;
        readonly synchronizationRequestId: string;
        readonly synchronizationRunId: string;
        readonly providerGeneration: string;
        readonly runtimeVersionSetFingerprint: string;
        readonly declaredSizeBytes: number;
        readonly sourceFamilyClassification: string;
        readonly classificationStatus: string;
      };
    }[] = [];
    for (const observation of observations) {
      if (
        observation.listingExecutionId !== set.listingExecutionId ||
        observation.providerContactAuthorizationId !== set.providerContactAuthorizationId ||
        observation.synchronizationRequestId !== set.synchronizationRequestId ||
        observation.synchronizationRunId !== set.synchronizationRunId ||
        observation.runtimeVersionSetFingerprint !== set.runtimeVersionSetFingerprint
      ) {
        return fail('binding_mismatch');
      }
      const internals = readOsvProtectedListingObservationInternalFields(observation);
      if (!internals.ok) {
        return fail('not_constructed');
      }
      const observationId = randomUUID();
      const sourceFamilyClassification = sourceFamilyKey(
        internals.value.sourceFamily.familyCandidate,
      );
      const associatedDataInput = {
        evidenceSetId,
        observationId,
        listingExecutionId: set.listingExecutionId,
        providerContactAuthorizationId: set.providerContactAuthorizationId,
        synchronizationRequestId: set.synchronizationRequestId,
        synchronizationRunId: set.synchronizationRunId,
        providerGeneration: internals.value.providerGeneration,
        runtimeVersionSetFingerprint: set.runtimeVersionSetFingerprint,
        declaredSizeBytes: internals.value.declaredSizeBytes,
        sourceFamilyClassification,
        classificationStatus: internals.value.sourceFamily.classificationStatus,
      };
      const admitted =
        reconstructOsvProtectedListingEvidenceAssociatedDataFromPersistedColumns(
          associatedDataInput,
        );
      if (!admitted.ok) {
        return fail('binding_mismatch');
      }
      snapshots.push({
        observationId,
        observation,
        internals: internals.value,
        sourceFamilyClassification,
        classificationStatus: internals.value.sourceFamily.classificationStatus,
        associatedDataInput,
      });
    }
    const envelopes: {
      observationId: string;
      record: OsvProtectedListingEvidenceEnvelopePersistenceRecord;
    }[] = [];
    let encryptionCalls = 0;
    const releasePrepared = (): void => {
      for (const envelope of envelopes) {
        releaseOsvProtectedListingEvidenceEnvelopePersistenceRecord(envelope.record);
      }
    };
    try {
      for (const snapshot of snapshots) {
        encryptionCalls += 1;
        const protectedValue = await this.cryptographicCapability.protectOsvListingObjectIdentity({
          protectedIdentity: snapshot.observation.protectedObjectIdentity,
          associatedDataContext: snapshot.associatedDataInput,
        });
        if (!protectedValue.ok) {
          releasePrepared();
          return fail(mapCryptoFailure(protectedValue.code));
        }
        const mapped = mapOsvProtectedListingEvidenceCiphertextEnvelopeForRestrictedPersistence(
          protectedValue.value.envelope,
        );
        if (!mapped.ok) {
          releasePrepared();
          return fail(mapCryptoFailure(mapped.code));
        }
        const reconstructedFromPrismaColumns =
          reconstructOsvProtectedListingEvidenceAssociatedDataFromPersistedColumns({
            evidenceSetId,
            observationId: snapshot.observationId,
            listingExecutionId: set.listingExecutionId,
            providerContactAuthorizationId: set.providerContactAuthorizationId,
            synchronizationRequestId: set.synchronizationRequestId,
            synchronizationRunId: set.synchronizationRunId,
            providerGeneration: snapshot.internals.providerGeneration,
            runtimeVersionSetFingerprint: set.runtimeVersionSetFingerprint,
            declaredSizeBytes: snapshot.internals.declaredSizeBytes,
            sourceFamilyClassification: snapshot.sourceFamilyClassification,
            classificationStatus: snapshot.classificationStatus,
          });
        const encryptedContext =
          reconstructOsvProtectedListingEvidenceAssociatedDataFromPersistedColumns(
            snapshot.associatedDataInput,
          );
        if (
          !reconstructedFromPrismaColumns.ok ||
          !encryptedContext.ok ||
          !associatedDataContextsMatch(reconstructedFromPrismaColumns.value, encryptedContext.value)
        ) {
          releasePrepared();
          return fail('binding_mismatch');
        }
        envelopes.push({ observationId: snapshot.observationId, record: mapped.value });
      }
      return {
        ok: true,
        value: {
          evidenceSetId,
          encryptionCalls,
          accounting,
          rows: snapshots.map((snapshot) => ({
            observationId: snapshot.observationId,
            observation: snapshot.observation,
            internals: snapshot.internals,
            sourceFamilyClassification: snapshot.sourceFamilyClassification,
            classificationStatus: snapshot.classificationStatus,
          })),
          envelopes,
        },
      };
    } catch (error) {
      releasePrepared();
      return mapCaught(error);
    }
  }

  private async insertEvidence(
    tx: PrismaClientLike,
    set: OsvProtectedListingObservationEvidenceSet,
    prepared: {
      readonly evidenceSetId: string;
      readonly accounting: {
        readonly rejectedObservationCount: number;
        readonly exactDuplicateCount: number;
        readonly duplicateAmbiguityCount: number;
        readonly eventCount: number;
      };
      readonly rows: readonly {
        readonly observationId: string;
        readonly observation: OsvProtectedListingObservation;
        readonly internals: OsvProtectedListingObservationInternalFields;
        readonly sourceFamilyClassification: string;
        readonly classificationStatus: string;
      }[];
      readonly envelopes: readonly {
        readonly observationId: string;
        readonly record: OsvProtectedListingEvidenceEnvelopePersistenceRecord;
      }[];
    },
    prerequisites: {
      readonly workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1';
      readonly leaseScope: string;
      readonly synchronizationReason: 'operator_canary';
    },
  ): Promise<OsvListingObservationEvidencePublicRecord> {
    const persisted = persistableState(set);
    const totalPlaintext = prepared.envelopes.reduce(
      (sum, envelope) => sum + envelope.record.plaintextLengthAccounting,
      0,
    );
    const totalEnvelope = prepared.envelopes.reduce(
      (sum, envelope) => sum + envelope.record.protectedIdentityEnvelope.byteLength,
      0,
    );
    await tx.osvListingObservationEvidenceSet.create({
      data: {
        id: prepared.evidenceSetId,
        evidenceSchemaVersion: OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
        evidencePolicyId: OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_POLICY_ID,
        purposeId: OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_PURPOSE_ID,
        ownership: OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_OWNERSHIP,
        listingExecutionId: set.listingExecutionId,
        providerContactAuthorizationId: set.providerContactAuthorizationId,
        synchronizationRequestId: set.synchronizationRequestId,
        synchronizationRunId: set.synchronizationRunId,
        provider: OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_PROVIDER,
        approvedPrefix: OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_PREFIX,
        listingProtocolId: OSV_PROTECTED_LISTING_OBSERVATION_LISTING_PROTOCOL,
        listingPolicyId: OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_POLICY,
        budgetProfileId: OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_BUDGET,
        workScope: prerequisites.workScope,
        leaseScope: prerequisites.leaseScope,
        synchronizationReason: prerequisites.synchronizationReason,
        runtimeVersionSetFingerprint: set.runtimeVersionSetFingerprint,
        sourceLicenseRegistryVersion: OSV_PROTECTED_LISTING_OBSERVATION_SOURCE_LICENSE_REGISTRY,
        classificationPolicyId: OSV_PROTECTED_LISTING_OBSERVATION_CLASSIFICATION_POLICY_ID,
        canonicalEvidenceSetAlgorithmId:
          OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_SET_ALGORITHM_ID,
        encryptionPolicyId: OSV_PROTECTED_LISTING_EVIDENCE_ENCRYPTION_POLICY_ID,
        associatedDataPolicyId: OSV_PROTECTED_LISTING_EVIDENCE_ASSOCIATED_DATA_POLICY_ID,
        associatedDataAlgorithmId: OSV_PROTECTED_LISTING_EVIDENCE_ASSOCIATED_DATA_ALGORITHM_ID,
        envelopeSchemaVersion: OSV_PROTECTED_LISTING_EVIDENCE_ENVELOPE_SCHEMA_VERSION,
        algorithmId: OSV_PROTECTED_LISTING_EVIDENCE_ALGORITHM_ID,
        retentionPolicyId: OSV_PROTECTED_LISTING_OBSERVATION_RETENTION_POLICY_ID,
        pageOrdinal: 1,
        canonicalEvidenceSetDigest: set.canonicalEvidenceSetDigest,
        translatorObservationCount: set.translatorObservationCount,
        acceptedObservationCount: set.acceptedObservationCount,
        protectedObservationCount: set.protectedObservationCount,
        rejectedObservationCount: prepared.accounting.rejectedObservationCount,
        exactDuplicateCount: prepared.accounting.exactDuplicateCount,
        duplicateAmbiguityCount: prepared.accounting.duplicateAmbiguityCount,
        immutableConflictCount: 0,
        totalProtectedKeyPlaintextBytes: BigInt(totalPlaintext),
        totalEnvelopeBytes: BigInt(totalEnvelope),
        totalCanonicalBytes: 0n,
        totalMetadataBytes: 0n,
        eventCount: prepared.accounting.eventCount,
        evidenceState: persisted.evidenceState,
        candidateSelectionReadiness: persisted.candidateSelectionReadiness,
        retentionOverdueClassification: 'not_overdue',
        legalHoldActive: false,
        legalHoldClassification: 'hold_absent',
        dependentAuthorizationsTerminal: false,
        candidateSelectionAuthorized: false,
        bodyRetrievalAuthorized: false,
        batch4pPermitted: false,
        paginationAuthorized: false,
        activationAuthorized: false,
        matchingAuthorized: false,
        findingWritesAuthorized: false,
        providerContactAuthorized: false,
        rowRevision: 1n,
      },
    });
    if (prepared.rows.length > 0) {
      await tx.osvListingObservationEvidence.createMany({
        data: prepared.rows.map((row) => {
          const envelope = prepared.envelopes.find(
            (item) => item.observationId === row.observationId,
          );
          if (envelope === undefined) {
            throw new OsvListingObservationEvidenceMappingError('envelope observation missing.');
          }
          return {
            id: row.observationId,
            evidenceSetId: prepared.evidenceSetId,
            listingExecutionId: set.listingExecutionId,
            providerContactAuthorizationId: set.providerContactAuthorizationId,
            synchronizationRequestId: set.synchronizationRequestId,
            synchronizationRunId: set.synchronizationRunId,
            provider: OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_PROVIDER,
            approvedPrefix: OSV_PROTECTED_LISTING_OBSERVATION_EXPECTED_PREFIX,
            listingProtocolId: OSV_PROTECTED_LISTING_OBSERVATION_LISTING_PROTOCOL,
            sourceLicenseRegistryVersion: OSV_PROTECTED_LISTING_OBSERVATION_SOURCE_LICENSE_REGISTRY,
            runtimeVersionSetFingerprint: set.runtimeVersionSetFingerprint,
            evidenceSchemaVersion: OSV_PROTECTED_LISTING_OBSERVATION_EVIDENCE_SCHEMA_VERSION,
            classificationPolicyId: OSV_PROTECTED_LISTING_OBSERVATION_CLASSIFICATION_POLICY_ID,
            observationCanonicalAlgorithmId:
              OSV_PROTECTED_LISTING_OBSERVATION_CANONICAL_ALGORITHM_ID,
            encryptionPolicyId: OSV_PROTECTED_LISTING_EVIDENCE_ENCRYPTION_POLICY_ID,
            associatedDataPolicyId: OSV_PROTECTED_LISTING_EVIDENCE_ASSOCIATED_DATA_POLICY_ID,
            associatedDataAlgorithmId: OSV_PROTECTED_LISTING_EVIDENCE_ASSOCIATED_DATA_ALGORITHM_ID,
            envelopeSchemaVersion: OSV_PROTECTED_LISTING_EVIDENCE_ENVELOPE_SCHEMA_VERSION,
            observationOrdinal: row.observation.observationOrdinal,
            listingObservationIdentity: row.observation.listingObservationIdentity,
            providerGeneration: row.internals.providerGeneration,
            declaredListingByteCount: BigInt(row.internals.declaredSizeBytes),
            sourceFamilyClassification: row.sourceFamilyClassification,
            classificationStatus: requireClassificationStatus(row.classificationStatus),
            duplicateClassification: row.observation.duplicateClassification,
            immutableConflictClassification: row.observation.immutableConflictClassification,
            candidateSelectionEligibility: row.observation.candidateSelectionEligibility,
            evidenceState: 'constructed',
            candidateSelectionAuthorized: false,
            bodyRetrievalAuthorized: false,
            batch4pPermitted: false,
            plaintextLengthAccounting: envelope.record.plaintextLengthAccounting,
            rowRevision: 1n,
          };
        }),
      });
      await tx.osvListingObservationEvidenceEnvelope.createMany({
        data: prepared.envelopes.map((envelope) => {
          const row = prepared.rows.find((item) => item.observationId === envelope.observationId);
          if (row === undefined) {
            throw new OsvListingObservationEvidenceMappingError('envelope observation missing.');
          }
          return {
            id: randomUUID(),
            observationId: envelope.observationId,
            evidenceSetId: prepared.evidenceSetId,
            providerGeneration: row.internals.providerGeneration,
            declaredListingByteCount: BigInt(row.internals.declaredSizeBytes),
            sourceFamilyClassification: row.sourceFamilyClassification,
            classificationStatus: requireClassificationStatus(row.classificationStatus),
            envelopeOrdinal: 1,
            envelopeSchemaVersion: envelope.record.envelopeSchemaVersion,
            cryptographicPolicyId: envelope.record.cryptographicPolicyId,
            algorithmId: envelope.record.algorithmId,
            associatedDataPolicyId: envelope.record.associatedDataPolicyId,
            opaqueKeyAlias: envelope.record.opaqueKeyAlias,
            keyVersionClassification: 'current',
            envelopeState: 'current',
            rotationState: 'current',
            erasureState: 'not_erased',
            plaintextLengthAccounting: envelope.record.plaintextLengthAccounting,
            ciphertextLengthAccounting: envelope.record.ciphertextLengthAccounting,
            protectedIdentityEnvelope: Buffer.from(envelope.record.protectedIdentityEnvelope),
            rowRevision: 1n,
          };
        }),
      });
    }
    const loaded = await tx.osvListingObservationEvidenceSet.findUnique({
      where: { id: prepared.evidenceSetId },
      select: PUBLIC_SET_SELECT,
    });
    if (loaded === null) {
      throw new OsvListingObservationEvidenceMappingError('persisted evidence set missing.');
    }
    return mapPublicEvidenceSet(loaded);
  }
}
