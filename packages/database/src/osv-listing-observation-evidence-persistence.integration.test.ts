/**
 * Session 13 Batch 3D-A protected listing-observation evidence adapters.
 * Disposable PostgreSQL. Synthetic identities and ephemeral test keys only.
 * Does not contact storage.googleapis.com or osv.dev.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  admitOsvProtectedListingObservation,
  constructOsvProtectedListingObservationEvidenceSet,
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationConsumePersistenceCommand,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryOperatorEnsureCommand,
  createOsvCanaryRunbookAcknowledgement,
  createOsvListingObservationEvidenceEnsureCommand,
  createOsvListingObservationEvidenceInspectForRunQuery,
  createOsvListingObservationEvidenceInspectQuery,
  createOsvListingObservationEvidenceReadProtectedQuery,
  createOsvListingObservationEvidenceRecordReviewCommand,
  createOsvListingObservationEvidenceSetLegalHoldCommand,
  OSV_LISTING_OBSERVATION_EVIDENCE_LEGAL_HOLD_AUTHORITY,
  createOsvListingProviderContactAuthorizationIssueCommand,
  createOsvListingProviderContactContainmentAcknowledgement,
  createOsvListingProviderContactDeploymentApproval,
  createOsvListingProviderContactEgressEvidence,
  createOsvListingProviderContactHaltProcedureAcknowledgement,
  createOsvListingProviderContactLegalApproval,
  createOsvListingProviderContactRetentionDisposition,
  createOsvListingProviderContactReviewerAssignment,
  createOsvListingProviderContactRunbookAcknowledgement,
  createOsvProtectedListingEvidenceCryptographicCapabilityFromPlatform,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  osvCanaryRuntimeVersionSetFingerprint,
  type OsvProtectedListingEvidenceCryptographicCapabilityPort,
  type OsvProtectedListingEvidencePlatformAeadPort,
  type OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle,
  type OsvProtectedListingEvidenceRuntimeKeyCapabilityPort,
  classifyOsvPreRetrieval,
  isOsvObjectKeyParsed,
  parseOsvObjectKey,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
import { createOsvListingObservationEvidencePersistence } from './osv-listing-observation-evidence-persistence.js';
import { createOsvListingProviderContactAuthorizationPersistence } from './osv-listing-provider-contact-authorization-persistence.js';
import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const ACK = '2026-09-08T11:00:00Z';
const LEGAL_ISSUED = '2026-09-08T10:00:00Z';
const LEGAL_REVALIDATE = '2099-09-09T10:00:00Z';
const FINGERPRINT = osvCanaryRuntimeVersionSetFingerprint();
const ARTIFACT = 'patchpilot.canary.artifact.1';
const CANARY_SCOPE = 'osv_runtime_canary_scope_crates_io_rustsec_v1';
const LEASE_SCOPE = 'osv_runtime_lease_scope_osv_gcs_public_export_v1';
const APPLICATION_TESTED = 'application_control_implemented_and_tested';
const DEPLOYMENT_CONFIGURED = 'deployment_control_configured';
const SYNTHETIC_KEY = 'crates.io/RUSTSEC-2000-0001.json';
const KEY_ALIAS = 'osv.listing.evidence.kitest1';

function expectOk<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly code: string },
  label: string,
): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function uuid(): string {
  return crypto.randomUUID();
}

function classificationFor(key: string) {
  const parsed = parseOsvObjectKey(key);
  if (!isOsvObjectKeyParsed(parsed)) {
    throw new Error('invalid_object_key');
  }
  return classifyOsvPreRetrieval(parsed);
}

function copyBytes(value: Uint8Array): Uint8Array {
  return Uint8Array.from(value);
}

function joinBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const joined = new Uint8Array(left.byteLength + right.byteLength);
  joined.set(left, 0);
  joined.set(right, left.byteLength);
  return joined;
}

function createTestCapability(keyMaterial: Uint8Array): {
  capability: OsvProtectedListingEvidenceCryptographicCapabilityPort;
  protectCount: () => number;
  nonceCount: () => number;
} {
  let protectCount = 0;
  let nonceCount = 0;
  const record = {
    alias: KEY_ALIAS,
    state: 'current' as const,
    keyMaterial: copyBytes(keyMaterial),
  };
  const handles = new WeakMap<object, typeof record>();
  const handle: OsvProtectedListingEvidenceRuntimeKeyCapabilityHandle = Object.freeze({
    kind: 'osv_protected_listing_evidence_key_capability_handle',
    keyState: 'current',
    encryptionPermitted: true,
    decryptionPermitted: true,
    keyVersionClassification: 'current',
    returnsRawKeyMaterial: false,
  });
  handles.set(handle, record);
  const keyCapability: OsvProtectedListingEvidenceRuntimeKeyCapabilityPort = {
    inspect() {
      return {
        ok: true,
        value: {
          currentKeyState: 'current',
          encryptionPermitted: true,
          decryptionPermitted: true,
          rotationStatus: 'current',
          returnsRawKeyMaterial: false,
          genericDecryptAuthority: false,
        },
      };
    },
    currentEncryptionCapability() {
      return { ok: true, value: handle };
    },
    approvedDecryptionCapability(keyReference) {
      if (keyReference !== KEY_ALIAS) {
        return { ok: false, code: 'unknown_key_reference' };
      }
      return { ok: true, value: handle };
    },
  };
  const aead: OsvProtectedListingEvidencePlatformAeadPort = {
    inspectAvailability() {
      return {
        ok: true,
        value: {
          algorithmId: 'aes-256-gcm',
          nonceBytes: 12,
          tagBytes: 16,
          keyBytes: 32,
          nonceCapabilityAvailable: true,
          callerSelectedNonce: false,
          callerSelectedAlgorithm: false,
        },
      };
    },
    generateNonce() {
      nonceCount += 1;
      return { ok: true, value: Uint8Array.from(randomBytes(12)) };
    },
    seal(request) {
      const stored = handles.get(request.keyHandle);
      if (stored === undefined) {
        return { ok: false, code: 'key_unavailable' };
      }
      const cipher = createCipheriv('aes-256-gcm', stored.keyMaterial, request.nonce, {
        authTagLength: 16,
      });
      cipher.setAAD(request.associatedData);
      const ciphertext = joinBytes(
        Uint8Array.from(cipher.update(request.plaintext)),
        Uint8Array.from(cipher.final()),
      );
      return {
        ok: true,
        value: {
          ciphertext,
          authenticationTag: Uint8Array.from(cipher.getAuthTag()),
          keyReference: stored.alias,
        },
      };
    },
    open(request) {
      const stored = handles.get(request.keyHandle);
      if (stored === undefined) {
        return { ok: false, code: 'key_unavailable' };
      }
      try {
        const decipher = createDecipheriv('aes-256-gcm', stored.keyMaterial, request.nonce, {
          authTagLength: 16,
        });
        decipher.setAAD(request.associatedData);
        decipher.setAuthTag(request.authenticationTag);
        const plaintext = joinBytes(
          Uint8Array.from(decipher.update(request.ciphertext)),
          Uint8Array.from(decipher.final()),
        );
        return { ok: true, value: plaintext };
      } catch {
        return { ok: false, code: 'authentication_failed' };
      }
    },
  };
  const inner = createOsvProtectedListingEvidenceCryptographicCapabilityFromPlatform({
    keyCapability,
    aead,
  });
  const capability: OsvProtectedListingEvidenceCryptographicCapabilityPort = {
    async protectOsvListingObjectIdentity(input) {
      protectCount += 1;
      return inner.protectOsvListingObjectIdentity(input);
    },
    revealOsvListingObjectIdentityForAuthorizedPurpose: (input) =>
      inner.revealOsvListingObjectIdentityForAuthorizedPurpose(input),
    reprotectOsvListingObjectIdentityForAuthorizedRotation: (input) =>
      inner.reprotectOsvListingObjectIdentityForAuthorizedRotation(input),
    inspectProtectedEvidenceCryptographicReadiness: () =>
      inner.inspectProtectedEvidenceCryptographicReadiness(),
  };
  return { capability, protectCount: () => protectCount, nonceCount: () => nonceCount };
}

describe(
  'session 13 Batch 3D-A OSV listing observation evidence adapters',
  { timeout: 180_000 },
  () => {
    let databaseName: string;
    let admin: PrismaClient;
    let prisma: PrismaClient;
    let canary: ReturnType<typeof createOsvCanaryAuthorizationPersistence>;
    let coordination: ReturnType<typeof createOsvRuntimeCoordinationPersistence>;
    let providerContact: ReturnType<typeof createOsvListingProviderContactAuthorizationPersistence>;

    beforeAll(async () => {
      const ephemeral = await createEphemeralDatabase('it');
      databaseName = ephemeral.databaseName;
      admin = ephemeral.admin;
      await deployMigrations(ephemeral.databaseUrl);
      prisma = new PrismaClient({
        datasources: { db: { url: ephemeral.databaseUrl } },
      });
      canary = createOsvCanaryAuthorizationPersistence(prisma);
      coordination = createOsvRuntimeCoordinationPersistence(prisma);
      providerContact = createOsvListingProviderContactAuthorizationPersistence(prisma);
    });

    afterAll(async () => {
      if (prisma !== undefined) {
        await prisma.$disconnect();
      }
      if (admin !== undefined && databaseName !== undefined) {
        await dropEphemeralDatabase(admin, databaseName);
      }
    });

    async function seedAuthority() {
      const operatorAttestationId = uuid();
      expectOk(
        await canary.operators.ensure(
          expectOk(
            createOsvCanaryOperatorEnsureCommand({
              operatorAttestationId,
              identityType: 'instance_operator',
              authenticationSource: 'local_host_control_of_one_shot_administrative_command',
              displayLabel: `canary-op-${operatorAttestationId.slice(0, 8)}`,
              provenanceIdentifier: 'configured_instance_operator_attestation_v1',
            }),
            'operator command',
          ),
        ),
        'operator ensure',
      );
      const sourceId = uuid();
      const legalDecisionId = uuid();
      expectOk(
        await canary.authorizations.ensure(
          expectOk(
            createOsvCanaryAuthorizationEnsureCommand({
              authorizationId: sourceId,
              operatorAttestationId,
              phase: 'listing_only',
              authorizationPurpose: 'initial_listing_compatibility',
              legalDecisionReference: expectOk(
                createOsvCanaryLegalDecisionReference({
                  decisionId: legalDecisionId,
                  sourceRegistryVersion: 'osv_source_license_registry_v1',
                  sourceIdentifier: 'rustsec_advisory_database',
                  family: 'RUSTSEC',
                  phase: 'listing_only',
                  permittedOperation: 'list_object_metadata',
                  issuedAt: LEGAL_ISSUED,
                  revalidationBoundaryAt: LEGAL_REVALIDATE,
                  responsibleRole:
                    'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
                  evidenceSetId: uuid(),
                }),
                'listing legal',
              ),
              runbookAcknowledgement: expectOk(
                createOsvCanaryRunbookAcknowledgement({
                  runbookSetIdentifier: 'osv_canary_runbook_set_v1',
                  runbookVersion: 'osv_canary_runbook_outlines_v1',
                  acknowledgedAt: ACK,
                  phase: 'listing_only',
                }),
                'runbook',
              ),
              haltControlAcknowledgement: expectOk(
                createOsvCanaryHaltControlAcknowledgement({ acknowledgedAt: ACK }),
                'halt',
              ),
              activationProhibitionAcknowledgement: expectOk(
                createOsvCanaryActivationProhibitionAcknowledgement(),
                'activation',
              ),
              automaticRetryProhibitionAcknowledgement: expectOk(
                createOsvCanaryAutomaticRetryProhibitionAcknowledgement(),
                'retry',
              ),
            }),
            'listing command',
          ),
        ),
        'listing ensure',
      );
      const payload = expectOk(
        createOsvRuntimeSyncJobPayload(
          createClosedOsvRuntimeSyncJobInput({
            synchronizationReason: 'operator_canary',
            requestedAt: '2026-09-08T12:00:00Z',
            correlationId: uuid(),
          }),
        ),
        'payload',
      );
      const request = expectOk(
        await coordination.requests.ensure(
          expectOk(
            createOsvRuntimeSynchronizationRequestEnsureCommand({
              payload,
              idempotency: expectOk(
                createOsvRuntimeJobIdempotencyIdentity({
                  workScope: payload.workScope,
                  reason: payload.synchronizationReason,
                  versionSetFingerprint: payload.versionSetFingerprint,
                  requestKind: 'operator_request',
                  schedulerWindowId: null,
                  operatorRequestId: uuid(),
                }),
                'idempotency',
              ),
              requestState: 'accepted',
            }),
            'request command',
          ),
        ),
        'request',
      );
      const run = expectOk(
        await coordination.runs.ensure(
          expectOk(
            createOsvRuntimeSynchronizationRunEnsureCommand({ requestId: request.request.id }),
            'run command',
          ),
        ),
        'run',
      );
      expectOk(
        await canary.authorizations.consume(
          expectOk(
            createOsvCanaryAuthorizationConsumePersistenceCommand({
              authorizationId: sourceId,
              operatorAttestationId,
              phase: 'listing_only',
              providerPrefix: 'crates.io/',
              canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              requestId: request.request.id,
              runId: run.run.id,
            }),
            'canary consume command',
          ),
        ),
        'canary consume',
      );
      const capturedAt = new Date('2026-09-08T11:30:00.000Z');
      const activePointer = uuid();
      const zeroFinding = uuid();
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: {
          id: uuid(),
          evidenceSchemaVersion: 'osv_canary_provider_free_preflight_attestation_v1',
          sourceCanaryAuthorizationId: sourceId,
          operatorIdentityId: operatorAttestationId,
          synchronizationRequestId: request.request.id,
          synchronizationRunId: run.run.id,
          phase: 'listing_only',
          providerIdentity: 'rustsec_advisory_database',
          approvedPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
          workScope: CANARY_SCOPE,
          leaseScope: LEASE_SCOPE,
          synchronizationReason: 'operator_canary',
          runtimeVersionSetFingerprint: FINGERPRINT,
          legalDecisionVersion: 'osv_listing_provider_contact_legal_approval_v1',
          egressEvidenceVersion: 'osv_listing_provider_contact_egress_evidence_v1',
          heartbeatPolicyIdentifier: 'osv_canary_runtime_controls_v1',
          deadlinePolicyIdentifier: 'osv_canary_runtime_controls_v1',
          activePointerBaselineIdentity: activePointer,
          zeroFindingBaselineIdentity: zeroFinding,
          outcome: 'canary_execution_preflight_passed_provider_contact_not_authorized',
          providerContactAuthorized: false,
          executionPermitted: false,
          acceptedForProviderContactAuth: true,
          capturedAt,
          createdAt: capturedAt,
        },
      });
      const issued = expectOk(
        await providerContact.issue(
          expectOk(
            createOsvListingProviderContactAuthorizationIssueCommand({
              providerContactAuthorizationId: uuid(),
              sourceCanaryAuthorizationId: sourceId,
              operatorAttestationId,
              synchronizationRequestId: request.request.id,
              synchronizationRunId: run.run.id,
              preflightEvidenceId: preflight.id,
              activePointerBaselineIdentity: activePointer,
              zeroFindingBaselineIdentity: zeroFinding,
              legalApproval: expectOk(
                createOsvListingProviderContactLegalApproval({
                  decisionId: uuid(),
                  sourceCanaryLegalDecisionId: legalDecisionId,
                  issuedAt: LEGAL_ISSUED,
                  revalidationBoundaryAt: LEGAL_REVALIDATE,
                  evidenceSetId: uuid(),
                  approvalRole:
                    'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
                  supersessionStatus: 'current',
                }),
                'legal',
              ),
              egressEvidence: expectOk(
                createOsvListingProviderContactEgressEvidence({
                  egressEvidenceId: uuid(),
                  reviewedAt: ACK,
                  reviewerRole: 'instance_operator_deployment_reviewer',
                  fixedHttpsHost: APPLICATION_TESTED,
                  defaultTlsPort: APPLICATION_TESTED,
                  fixedGcsApiPath: APPLICATION_TESTED,
                  fixedBucket: APPLICATION_TESTED,
                  fixedQueryGrammar: APPLICATION_TESTED,
                  redirectsRejected: APPLICATION_TESTED,
                  providerControlledCustomCaProhibited: APPLICATION_TESTED,
                  listingOnlyBodyRoutesProhibited: APPLICATION_TESTED,
                  callerSelectedProxyProhibited: DEPLOYMENT_CONFIGURED,
                  dnsPinningPolicy: DEPLOYMENT_CONFIGURED,
                  prohibitedAddressFiltering: DEPLOYMENT_CONFIGURED,
                  privateLoopbackLinkLocalMetadataDenied: DEPLOYMENT_CONFIGURED,
                  postConnectPeerVerification: DEPLOYMENT_CONFIGURED,
                  tlsCertificateVerification: DEPLOYMENT_CONFIGURED,
                  cloudMetadataAccessDenied: DEPLOYMENT_CONFIGURED,
                  providerConnectivityExercised: false,
                  dnsLookupCount: 0,
                  tlsConnectionCount: 0,
                  httpCount: 0,
                }),
                'egress',
              ),
              deploymentApproval: expectOk(
                createOsvListingProviderContactDeploymentApproval({
                  deploymentId: uuid(),
                  environmentClass: 'dedicated_instance_operator_process',
                  egressPolicyVersion: 'osv_listing_provider_contact_egress_evidence_v1',
                  runtimeArtifactVersion: ARTIFACT,
                  configurationFingerprint: FINGERPRINT,
                  providerTransportPolicy: 'osv_transport_policy_v1',
                  observabilityPolicy: 'osv_listing_provider_contact_observability_policy_v1',
                  runbookVersion: 'osv_listing_provider_contact_runbook_v1',
                  approvalRole: 'instance_operator_deployment_reviewer',
                  approvedAt: ACK,
                  invalidatesOnDeploymentChange: true,
                }),
                'deployment',
              ),
              haltProcedureAcknowledgement: expectOk(
                createOsvListingProviderContactHaltProcedureAcknowledgement({
                  acknowledgedAt: ACK,
                }),
                'halt procedure',
              ),
              runbookAcknowledgement: expectOk(
                createOsvListingProviderContactRunbookAcknowledgement({
                  runbookSetIdentifier: 'osv_listing_provider_contact_runbook_set_v1',
                  runbookVersion: 'osv_listing_provider_contact_runbook_v1',
                  acknowledgedAt: ACK,
                }),
                'provider runbook',
              ),
              containmentAcknowledgement: expectOk(
                createOsvListingProviderContactContainmentAcknowledgement({ acknowledgedAt: ACK }),
                'containment',
              ),
              reviewerAssignment: expectOk(
                createOsvListingProviderContactReviewerAssignment({
                  assignedAt: ACK,
                  requiredReviewRole: 'instance_canary_evidence_reviewer',
                }),
                'reviewer',
              ),
              retentionDisposition: expectOk(
                createOsvListingProviderContactRetentionDisposition({ acknowledgedAt: ACK }),
                'retention',
              ),
            }),
            'issue command',
          ),
        ),
        'issue',
      );
      return {
        requestId: request.request.id,
        runId: run.run.id,
        authorizationId: issued.record.providerContactAuthorizationId,
      };
    }

    function constructSet(authority: Awaited<ReturnType<typeof seedAuthority>>) {
      const listingExecutionId = uuid();
      const observation = expectOk(
        admitOsvProtectedListingObservation({
          listingExecutionId,
          providerContactAuthorizationId: authority.authorizationId,
          synchronizationRequestId: authority.requestId,
          synchronizationRunId: authority.runId,
          runtimeVersionSetFingerprint: FINGERPRINT,
          observationOrdinal: 1,
          providerObjectKey: SYNTHETIC_KEY,
          providerGeneration: '1',
          declaredSizeBytes: 128,
          classification: classificationFor(SYNTHETIC_KEY),
        }),
        'observation',
      );
      const evidenceSet = expectOk(
        constructOsvProtectedListingObservationEvidenceSet({
          listingExecutionId,
          providerContactAuthorizationId: authority.authorizationId,
          synchronizationRequestId: authority.requestId,
          synchronizationRunId: authority.runId,
          runtimeVersionSetFingerprint: FINGERPRINT,
          observations: [observation],
        }),
        'evidence set',
      );
      return { listingExecutionId, observation, evidenceSet };
    }

    it('persists a synthetic set without plaintext, then replays without encrypting', async () => {
      const authority = await seedAuthority();
      const { evidenceSet, observation } = constructSet(authority);
      const keyMaterial = Uint8Array.from(randomBytes(32));
      const { capability, protectCount, nonceCount } = createTestCapability(keyMaterial);
      const adapters = createOsvListingObservationEvidencePersistence(prisma, {
        cryptographicCapability: capability,
      });
      const first = expectOk(
        await adapters.ensure(
          expectOk(
            createOsvListingObservationEvidenceEnsureCommand({ evidenceSet }),
            'ensure command',
          ),
        ),
        'ensure',
      );
      expect(first.status).toBe('persisted');
      expect(first.encryptionCalls).toBe(1);
      expect(first.nonceGenerationCalls).toBe(1);
      expect(protectCount()).toBe(1);
      expect(nonceCount()).toBe(1);
      expect(first.record.evidenceState).toBe('review_pending');
      expect(first.record.candidateSelectionAuthorized).toBe(false);
      expect(first.record.observations).toHaveLength(1);
      const publicBlob = `${JSON.stringify(first)}\n${inspect(first, { depth: 8 })}`;
      expect(publicBlob).not.toContain(SYNTHETIC_KEY);
      expect(publicBlob).not.toContain('"ciphertext"');
      expect(publicBlob).not.toContain('"nonce"');
      expect(publicBlob).not.toContain('protectedIdentityEnvelope');
      expect(publicBlob).not.toContain(KEY_ALIAS);
      const envelopes = await prisma.osvListingObservationEvidenceEnvelope.findMany({
        where: { evidenceSetId: first.record.evidenceSetId },
      });
      expect(envelopes).toHaveLength(1);
      expect(envelopes[0]?.protectedIdentityEnvelope).not.toBeNull();
      const replay = expectOk(
        await adapters.ensure(
          expectOk(
            createOsvListingObservationEvidenceEnsureCommand({ evidenceSet }),
            'replay command',
          ),
        ),
        'replay',
      );
      expect(replay.status).toBe('already_applied');
      expect(replay.encryptionCalls).toBe(0);
      expect(replay.nonceGenerationCalls).toBe(0);
      expect(protectCount()).toBe(1);
      expect(nonceCount()).toBe(1);
      const inspected = expectOk(
        await adapters.inspect(
          expectOk(
            createOsvListingObservationEvidenceInspectQuery({
              evidenceSetId: first.record.evidenceSetId,
            }),
            'inspect command',
          ),
        ),
        'inspect',
      );
      expect(inspected.evidenceSetId).toBe(first.record.evidenceSetId);
      expect(JSON.stringify(inspected)).not.toContain(SYNTHETIC_KEY);
      const inspectedForRun = expectOk(
        await adapters.inspectForRun(
          expectOk(
            createOsvListingObservationEvidenceInspectForRunQuery({
              synchronizationRequestId: authority.requestId,
              synchronizationRunId: authority.runId,
            }),
            'inspect for run command',
          ),
        ),
        'inspect for run',
      );
      expect(inspectedForRun.evidenceSetId).toBe(first.record.evidenceSetId);
      const observationId = first.record.observations[0]?.observationId;
      expect(observationId).toBeDefined();
      const revealed = expectOk(
        await adapters.readProtected(
          expectOk(
            createOsvListingObservationEvidenceReadProtectedQuery({
              evidenceSetId: first.record.evidenceSetId,
              observationId: observationId ?? '',
              synchronizationRequestId: authority.requestId,
              synchronizationRunId: authority.runId,
              purpose: 'protected_evidence_incident_review',
            }),
            'read command',
          ),
        ),
        'read',
      );
      expect(revealed.providerContactAuthorized).toBe(false);
      expect(revealed.bodyRetrievalAuthorized).toBe(false);
      expect(inspect(revealed.identity)).not.toContain(SYNTHETIC_KEY);
      const reviewed = expectOk(
        await adapters.recordReview(
          expectOk(
            createOsvListingObservationEvidenceRecordReviewCommand({
              evidenceSetId: first.record.evidenceSetId,
              expectedRowRevision: first.record.rowRevision,
              decision: 'review_accepted',
            }),
            'review command',
          ),
        ),
        'review',
      );
      expect(reviewed.status).toBe('transitioned');
      expect(reviewed.record.evidenceState).toBe('review_accepted');
      expect(reviewed.record.candidateSelectionAuthorized).toBe(false);
      expect(reviewed.record.rowRevision).toBe('2');
      expect(reviewed.record.reviewRecordedAt).not.toBeNull();
      const stale = await adapters.recordReview(
        expectOk(
          createOsvListingObservationEvidenceRecordReviewCommand({
            evidenceSetId: first.record.evidenceSetId,
            expectedRowRevision: first.record.rowRevision,
            decision: 'review_accepted',
          }),
          'stale review command',
        ),
      );
      expect(stale.ok).toBe(false);
      if (!stale.ok) {
        expect(stale.code).toBe('stale_revision');
      }
      expect(observation.listingObservationIdentity).toBe(
        first.record.observations[0]?.listingObservationIdentity,
      );
    });

    it('does not encrypt when a conflicting natural identity already exists', async () => {
      const authority = await seedAuthority();
      const firstSet = constructSet(authority);
      const { capability, protectCount } = createTestCapability(Uint8Array.from(randomBytes(32)));
      const adapters = createOsvListingObservationEvidencePersistence(prisma, {
        cryptographicCapability: capability,
      });
      expectOk(
        await adapters.ensure(
          expectOk(
            createOsvListingObservationEvidenceEnsureCommand({ evidenceSet: firstSet.evidenceSet }),
            'first ensure',
          ),
        ),
        'first persist',
      );
      const afterFirst = protectCount();
      const conflictObservation = expectOk(
        admitOsvProtectedListingObservation({
          listingExecutionId: firstSet.listingExecutionId,
          providerContactAuthorizationId: authority.authorizationId,
          synchronizationRequestId: authority.requestId,
          synchronizationRunId: authority.runId,
          runtimeVersionSetFingerprint: FINGERPRINT,
          observationOrdinal: 1,
          providerObjectKey: 'crates.io/RUSTSEC-2000-0002.json',
          providerGeneration: '2',
          declaredSizeBytes: 64,
          classification: classificationFor('crates.io/RUSTSEC-2000-0002.json'),
        }),
        'conflict observation',
      );
      const conflictSet = expectOk(
        constructOsvProtectedListingObservationEvidenceSet({
          listingExecutionId: firstSet.listingExecutionId,
          providerContactAuthorizationId: authority.authorizationId,
          synchronizationRequestId: authority.requestId,
          synchronizationRunId: authority.runId,
          runtimeVersionSetFingerprint: FINGERPRINT,
          observations: [conflictObservation],
        }),
        'conflict set',
      );
      const conflict = await adapters.ensure(
        expectOk(
          createOsvListingObservationEvidenceEnsureCommand({ evidenceSet: conflictSet }),
          'conflict command',
        ),
      );
      expect(conflict.ok).toBe(false);
      if (!conflict.ok) {
        expect(conflict.code).toBe('immutable_conflict');
      }
      expect(protectCount()).toBe(afterFirst);
    });

    it('does not write rows when protection fails before the transaction', async () => {
      const authority = await seedAuthority();
      const { evidenceSet, listingExecutionId } = constructSet(authority);
      const { capability, protectCount, nonceCount } = createTestCapability(
        Uint8Array.from(randomBytes(32)),
      );
      const failing: OsvProtectedListingEvidenceCryptographicCapabilityPort = {
        inspectProtectedEvidenceCryptographicReadiness:
          capability.inspectProtectedEvidenceCryptographicReadiness,
        protectOsvListingObjectIdentity: async () => ({ ok: false, code: 'encryption_failed' }),
        revealOsvListingObjectIdentityForAuthorizedPurpose:
          capability.revealOsvListingObjectIdentityForAuthorizedPurpose,
        reprotectOsvListingObjectIdentityForAuthorizedRotation:
          capability.reprotectOsvListingObjectIdentityForAuthorizedRotation,
      };
      const adapters = createOsvListingObservationEvidencePersistence(prisma, {
        cryptographicCapability: failing,
      });
      const failed = await adapters.ensure(
        expectOk(
          createOsvListingObservationEvidenceEnsureCommand({ evidenceSet }),
          'failing ensure',
        ),
      );
      expect(failed.ok).toBe(false);
      expect(protectCount()).toBe(0);
      expect(nonceCount()).toBe(0);
      expect(
        await prisma.osvListingObservationEvidenceSet.count({
          where: { listingExecutionId },
        }),
      ).toBe(0);
    });

    it('rejects cross-run protected reads before copying envelope bytes', async () => {
      const authority = await seedAuthority();
      const { evidenceSet } = constructSet(authority);
      const { capability } = createTestCapability(Uint8Array.from(randomBytes(32)));
      const adapters = createOsvListingObservationEvidencePersistence(prisma, {
        cryptographicCapability: capability,
      });
      const first = expectOk(
        await adapters.ensure(
          expectOk(createOsvListingObservationEvidenceEnsureCommand({ evidenceSet }), 'ensure'),
        ),
        'ensure',
      );
      const observationId = first.record.observations[0]?.observationId ?? '';
      const crossRun = await adapters.readProtected(
        expectOk(
          createOsvListingObservationEvidenceReadProtectedQuery({
            evidenceSetId: first.record.evidenceSetId,
            observationId,
            synchronizationRequestId: uuid(),
            synchronizationRunId: uuid(),
            purpose: 'protected_evidence_incident_review',
          }),
          'cross-run read',
        ),
      );
      expect(crossRun.ok).toBe(false);
      if (!crossRun.ok) {
        expect(crossRun.code).toBe('binding_mismatch');
      }
    });

    it('applies legal hold with CAS and does not authorize redaction or reveal', async () => {
      const authority = await seedAuthority();
      const { evidenceSet } = constructSet(authority);
      const { capability } = createTestCapability(Uint8Array.from(randomBytes(32)));
      const adapters = createOsvListingObservationEvidencePersistence(prisma, {
        cryptographicCapability: capability,
      });
      const first = expectOk(
        await adapters.ensure(
          expectOk(createOsvListingObservationEvidenceEnsureCommand({ evidenceSet }), 'ensure'),
        ),
        'ensure',
      );
      const held = expectOk(
        await adapters.setLegalHold(
          expectOk(
            createOsvListingObservationEvidenceSetLegalHoldCommand({
              evidenceSetId: first.record.evidenceSetId,
              expectedRowRevision: first.record.rowRevision,
              decision: 'legal_hold_active',
              authorityClassification: OSV_LISTING_OBSERVATION_EVIDENCE_LEGAL_HOLD_AUTHORITY,
            }),
            'hold command',
          ),
        ),
        'hold',
      );
      expect(held.status).toBe('transitioned');
      expect(held.legalHoldActive).toBe(true);
      expect(held.envelopeRedactionAuthorized).toBe(false);
      expect(held.purgeAuthorized).toBe(false);
      expect(held.revealAuthorized).toBe(false);
      expect(held.record.rowRevision).toBe('2');
      const replayHold = expectOk(
        await adapters.setLegalHold(
          expectOk(
            createOsvListingObservationEvidenceSetLegalHoldCommand({
              evidenceSetId: first.record.evidenceSetId,
              expectedRowRevision: held.record.rowRevision,
              decision: 'legal_hold_active',
              authorityClassification: OSV_LISTING_OBSERVATION_EVIDENCE_LEGAL_HOLD_AUTHORITY,
            }),
            'hold replay',
          ),
        ),
        'hold replay',
      );
      expect(replayHold.status).toBe('already_applied');
      expect(replayHold.record.rowRevision).toBe('2');
      const stale = await adapters.setLegalHold(
        expectOk(
          createOsvListingObservationEvidenceSetLegalHoldCommand({
            evidenceSetId: first.record.evidenceSetId,
            expectedRowRevision: first.record.rowRevision,
            decision: 'hold_released',
            authorityClassification: OSV_LISTING_OBSERVATION_EVIDENCE_LEGAL_HOLD_AUTHORITY,
          }),
          'stale hold',
        ),
      );
      expect(stale.ok).toBe(false);
      if (!stale.ok) {
        expect(stale.code).toBe('stale_revision');
      }
      const released = expectOk(
        await adapters.setLegalHold(
          expectOk(
            createOsvListingObservationEvidenceSetLegalHoldCommand({
              evidenceSetId: first.record.evidenceSetId,
              expectedRowRevision: held.record.rowRevision,
              decision: 'hold_released',
              authorityClassification: OSV_LISTING_OBSERVATION_EVIDENCE_LEGAL_HOLD_AUTHORITY,
            }),
            'release command',
          ),
        ),
        'release',
      );
      expect(released.status).toBe('transitioned');
      expect(released.legalHoldActive).toBe(false);
      expect(released.record.legalHoldClassification).toBe('hold_released');
      expect(released.purgeAuthorized).toBe(false);
      await expect(
        prisma.osvListingObservationEvidenceSet.delete({
          where: { id: first.record.evidenceSetId },
        }),
      ).rejects.toThrow();
      expect(
        await prisma.osvListingObservationEvidenceSet.count({
          where: { id: first.record.evidenceSetId },
        }),
      ).toBe(1);
    });

    it('admits one concurrent winner for the same natural identity', async () => {
      const authority = await seedAuthority();
      const { evidenceSet } = constructSet(authority);
      const { capability, protectCount } = createTestCapability(Uint8Array.from(randomBytes(32)));
      const adapters = createOsvListingObservationEvidencePersistence(prisma, {
        cryptographicCapability: capability,
      });
      const firstCommand = expectOk(
        createOsvListingObservationEvidenceEnsureCommand({ evidenceSet }),
        'first command',
      );
      const secondCommand = expectOk(
        createOsvListingObservationEvidenceEnsureCommand({ evidenceSet }),
        'second command',
      );
      const [left, right] = await Promise.all([
        adapters.ensure(firstCommand),
        adapters.ensure(secondCommand),
      ]);
      const outcomes = [left, right].map((result) =>
        result.ok ? result.value.status : result.code,
      );
      expect(outcomes.filter((status) => status === 'persisted')).toHaveLength(1);
      expect(
        outcomes.filter((status) => status === 'already_applied' || status === 'immutable_conflict')
          .length,
      ).toBe(1);
      const winner = left.ok && left.value.status === 'persisted' ? left : right;
      if (!winner.ok || winner.value.status !== 'persisted') {
        throw new Error('concurrent persist produced no winner');
      }
      expect(
        await prisma.osvListingObservationEvidenceSet.count({
          where: { listingExecutionId: winner.value.record.listingExecutionId },
        }),
      ).toBe(1);
      expect(protectCount()).toBeGreaterThanOrEqual(1);
      expect(protectCount()).toBeLessThanOrEqual(2);
    });
  },
);
