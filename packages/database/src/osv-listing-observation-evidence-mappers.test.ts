import { describe, expect, it } from 'vitest';

import {
  mapPublicEvidenceSet,
  OsvListingObservationEvidenceMappingError,
} from './osv-listing-observation-evidence-mappers.js';

describe('OSV listing observation evidence public mapper', () => {
  it('omits envelope BYTEA and opaque key alias from public records', () => {
    const record = mapPublicEvidenceSet({
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
      listingExecutionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      providerContactAuthorizationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      synchronizationRequestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      synchronizationRunId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      provider: 'osv',
      approvedPrefix: 'crates.io/',
      listingProtocolId: 'osv_gcs_json_objects_list_v1',
      listingPolicyId: 'osv_disabled_first_provider_canary_policy_v1',
      budgetProfileId: 'osv_canary_listing_only_budget_v1',
      runtimeVersionSetFingerprint: 'a'.repeat(64),
      pageOrdinal: 1,
      canonicalEvidenceSetDigest: 'b'.repeat(64),
      translatorObservationCount: 0,
      acceptedObservationCount: 0,
      protectedObservationCount: 0,
      rejectedObservationCount: 0,
      exactDuplicateCount: 0,
      duplicateAmbiguityCount: 0,
      immutableConflictCount: 0,
      evidenceState: 'constructed',
      candidateSelectionReadiness: 'empty_page_not_candidate_ready',
      legalHoldActive: false,
      legalHoldClassification: 'hold_absent',
      rowRevision: 1n,
      capturedAt: new Date('2026-09-11T00:00:00.000Z'),
      reviewRecordedAt: null,
      observations: [],
    });
    expect(record.candidateSelectionAuthorized).toBe(false);
    expect(record.bodyRetrievalAuthorized).toBe(false);
    expect(JSON.stringify(record)).not.toContain('protectedIdentityEnvelope');
    expect(JSON.stringify(record)).not.toContain('opaqueKeyAlias');
    expect(JSON.stringify(record)).not.toContain('ciphertext');
  });

  it('fails closed when restricted envelope fields are present', () => {
    expect(() =>
      mapPublicEvidenceSet({
        id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
        listingExecutionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        providerContactAuthorizationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        synchronizationRequestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
        synchronizationRunId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        provider: 'osv',
        approvedPrefix: 'crates.io/',
        listingProtocolId: 'osv_gcs_json_objects_list_v1',
        listingPolicyId: 'osv_disabled_first_provider_canary_policy_v1',
        budgetProfileId: 'osv_canary_listing_only_budget_v1',
        runtimeVersionSetFingerprint: 'a'.repeat(64),
        pageOrdinal: 1,
        canonicalEvidenceSetDigest: 'b'.repeat(64),
        translatorObservationCount: 0,
        acceptedObservationCount: 0,
        protectedObservationCount: 0,
        rejectedObservationCount: 0,
        exactDuplicateCount: 0,
        duplicateAmbiguityCount: 0,
        immutableConflictCount: 0,
        evidenceState: 'constructed',
        candidateSelectionReadiness: 'empty_page_not_candidate_ready',
        legalHoldActive: false,
        legalHoldClassification: 'hold_absent',
        rowRevision: 1n,
        capturedAt: new Date('2026-09-11T00:00:00.000Z'),
        reviewRecordedAt: null,
        protectedIdentityEnvelope: Buffer.from([1, 2, 3]),
      } as never),
    ).toThrow(OsvListingObservationEvidenceMappingError);
  });

  it('fails closed on unknown enums, contradictory legal hold, and count mismatch', () => {
    const base = {
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
      listingExecutionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      providerContactAuthorizationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      synchronizationRequestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      synchronizationRunId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      provider: 'osv',
      approvedPrefix: 'crates.io/',
      listingProtocolId: 'osv_gcs_json_objects_list_v1',
      listingPolicyId: 'osv_disabled_first_provider_canary_policy_v1',
      budgetProfileId: 'osv_canary_listing_only_budget_v1',
      runtimeVersionSetFingerprint: 'a'.repeat(64),
      pageOrdinal: 1,
      canonicalEvidenceSetDigest: 'b'.repeat(64),
      translatorObservationCount: 0,
      acceptedObservationCount: 0,
      protectedObservationCount: 0,
      rejectedObservationCount: 0,
      exactDuplicateCount: 0,
      duplicateAmbiguityCount: 0,
      immutableConflictCount: 0,
      evidenceState: 'constructed',
      candidateSelectionReadiness: 'empty_page_not_candidate_ready',
      legalHoldActive: false,
      legalHoldClassification: 'hold_absent',
      rowRevision: 1n,
      capturedAt: new Date('2026-09-11T00:00:00.000Z'),
      reviewRecordedAt: null,
      observations: [],
    };
    expect(() =>
      mapPublicEvidenceSet({ ...base, evidenceState: 'totally_unknown' } as never),
    ).toThrow(OsvListingObservationEvidenceMappingError);
    expect(() =>
      mapPublicEvidenceSet({
        ...base,
        legalHoldActive: true,
        legalHoldClassification: 'hold_absent',
      }),
    ).toThrow(OsvListingObservationEvidenceMappingError);
    expect(() =>
      mapPublicEvidenceSet({
        ...base,
        translatorObservationCount: 2,
        acceptedObservationCount: 0,
        rejectedObservationCount: 0,
      }),
    ).toThrow(OsvListingObservationEvidenceMappingError);
    expect(() =>
      mapPublicEvidenceSet({
        ...base,
        findingId: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      } as never),
    ).toThrow(OsvListingObservationEvidenceMappingError);
  });
});
