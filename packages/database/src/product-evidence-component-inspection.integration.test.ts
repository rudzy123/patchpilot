/**
 * Disposable PostgreSQL proof for tenant-scoped component inspection.
 * Synthetic identifiers only. No product-eligible row is written.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  ADVISORY_REVISION_FINDING_CREATION,
  ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
  PRODUCT_EVIDENCE_COMPOSITION_REQUEST_SCHEMA_VERSION,
  PRODUCT_EVIDENCE_PROVENANCE_POLICY_ID,
  SUPERSESSION_NONE,
  componentEvidenceFingerprint,
  createProductEvidenceEligibilityComposition,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createProductEvidenceComponentInspection } from './product-evidence-component-inspection.js';
import {
  SHA_A,
  createAsset,
  createOrg,
  createProcessingIngestion,
  createSbom,
  resolvedComponent,
} from './sbom-test-fixture.js';

describe('product-evidence component inspection', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  });

  afterAll(async () => {
    await prisma?.$disconnect();
    if (admin !== undefined && databaseName !== '') {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('reads one tenant occurrence and hides another tenant', async () => {
    const org = await createOrg(prisma, `comp-${randomUUID().slice(0, 8)}`);
    const other = await createOrg(prisma, `other-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'asset-comp');
    const sbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-10-02T12:00:00.000Z'),
    });
    const ingestion = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbom.id,
      assetId: asset.id,
    });
    const componentInput = resolvedComponent({
      name: 'left-pad',
      bomRef: 'component-1',
      version: '1.2.3',
    });
    const component = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: componentInput.identityKey,
        purl: componentInput.versionlessPurl,
        ecosystem: 'npm',
        namespace: null,
        name: 'left-pad',
        identityState: 'resolved',
      },
    });
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        bomRef: 'component-1',
        version: '1.2.3',
        versionKnown: true,
      },
    });
    const reader = createProductEvidenceComponentInspection(prisma);
    const found = await reader.inspectTenantOccurrence({
      organizationId: org.id,
      componentOccurrenceId: occurrence.id,
    });
    expect(found.kind).toBe('found');
    if (found.kind !== 'found') {
      return;
    }
    expect(found.snapshot.organizationId).toBe(org.id);
    expect(found.snapshot.rawObservedVersion).toBe('1.2.3');
    expect(found.snapshot).not.toHaveProperty('findingId');
    const hidden = await reader.inspectTenantOccurrence({
      organizationId: other.id,
      componentOccurrenceId: occurrence.id,
    });
    expect(hidden.kind).toBe('not_found');

    const fingerprint = componentEvidenceFingerprint({
      organizationId: org.id,
      componentOccurrenceId: occurrence.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      componentId: component.id,
      componentIdentityKey: componentInput.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: 'left-pad',
      rawObservedVersion: '1.2.3',
      versionKnown: true,
      sbomSha256: SHA_A,
    });
    const before = await prisma.matchEvaluationEvidence.count();
    const service = createProductEvidenceEligibilityComposition({
      components: reader,
      revisions: {
        async inspectImmutableAdvisoryRevision() {
          return {
            kind: 'found',
            projection: {
              inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
              revisionId: '33333333-3333-4333-8333-333333333333',
              familyId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
              source: 'synthetic_fixture',
              advisoryId: 'SYNTHETICADV1',
              familyDigest: 'c'.repeat(64),
              revisionDigest: 'f'.repeat(64),
              contentFingerprint: 'd'.repeat(64),
              session14RangeFingerprint: 'e'.repeat(64),
              productRangeFingerprint: '4'.repeat(64),
              parserId: 'osv_advisory_parser_protocol_v1',
              parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
              advisorySchemaVersion: 'v1.9.0',
              advisorySchemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
              sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
              sourceLicensePolicyVersion: 'osv_source_license_registry_v1',
              spdxLicenseId: null,
              origin: 'synthetic_fixture',
              trustClassification: 'not_applicable_synthetic',
              revisionDisposition: 'synthetic',
              withdrawalClassification: 'not_withdrawn',
              quarantineClassification: 'not_quarantined',
              supersedesRevisionDigest: SUPERSESSION_NONE,
              retrievalClassification: 'synthetic_not_retrieved',
              ecosystem: 'npm',
              packageNamespace: null,
              packageName: 'left-pad',
              packageIdentityKey: 'npm\u001f\u001fleft-pad',
              replayFingerprint: 'a'.repeat(64),
              aliasCount: 0,
              cveAliasCount: 0,
              mappingCountClassification: 'none',
              createdAt: '2026-10-02T12:00:00.000Z',
              findingCreation: ADVISORY_REVISION_FINDING_CREATION,
              productEligibilityStored: false,
              catalogActivationStored: false,
            },
          };
        },
        async inspectReviewedAdvisoryVulnerabilityBinding() {
          throw new Error('binding must not be read for synthetic evidence');
        },
      },
      async readCatalogMembership() {
        return null;
      },
      async readActiveCatalogEvidence() {
        return null;
      },
    });
    const input = {
      requestSchemaVersion: PRODUCT_EVIDENCE_COMPOSITION_REQUEST_SCHEMA_VERSION,
      provenancePolicyId: PRODUCT_EVIDENCE_PROVENANCE_POLICY_ID,
      provenancePolicyVersion: 'osv_product_evidence_provenance_contract_v1',
      advisoryRevisionId: '33333333-3333-4333-8333-333333333333',
      expectedFamilyDigest: 'c'.repeat(64),
      expectedContentFingerprint: 'd'.repeat(64),
      expectedRangeFingerprint: 'e'.repeat(64),
      expectedProductRangeFingerprint: '4'.repeat(64),
      expectedRevisionDigest: 'f'.repeat(64),
      expectedSource: 'synthetic_fixture',
      expectedSourceRegistryVersion: 'osv_source_license_registry_v1',
      expectedLicensePolicyVersion: 'osv_source_license_registry_v1',
      expectedParserId: 'osv_advisory_parser_protocol_v1',
      expectedParserVersion: 'osv_advisory_parser_resource_policy_v1',
      expectedAdvisorySchemaVersion: 'v1.9.0',
      expectedAdvisorySchemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
      expectedTrustClassification: 'not_applicable_synthetic',
      expectedRevisionDisposition: 'synthetic',
      expectedWithdrawalClassification: 'not_withdrawn',
      expectedCatalogId: '55555555-5555-4555-8555-555555555555',
      expectedCatalogGenerationId: '66666666-6666-4666-8666-666666666666',
      expectedEcosystemRegistryVersion: 'osv_ecosystem_implementation_registry_contract_v1',
      expectedEvaluatorRegistryVersion: 'osv_evaluator_registry_contract_v1',
      expectedVulnerabilityId: '44444444-4444-4444-8444-444444444444',
      expectedBindingReplayFingerprint: '1'.repeat(64),
      organizationId: org.id,
      componentOccurrenceId: occurrence.id,
      expectedComponentEvidenceFingerprint: fingerprint,
      expectedPackageIdentityKey: 'npm\u001f\u001fleft-pad',
      expectedRawObservedVersion: '1.2.3',
      evaluationCorrelationId: '77777777-7777-4777-8777-777777777777',
    };
    const composed = await service.compose(input);
    expect(composed.eligibility).toBe('ineligible_synthetic');
    expect(composed.calls.evaluatorCalls).toBe(0);
    expect(composed.calls.persistenceCalls).toBe(0);
    expect(composed.calls.findingCalls).toBe(0);
    expect(composed.provenanceClassification).toBe('synthetic_fixture');
    expect(composed.evidenceReality).toBe('not_real_product_evidence');
    const replay = await service.compose(input);
    expect(replay.eligibility).toBe('ineligible_synthetic');
    expect(replay.calls.persistenceCalls).toBe(0);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(before);
    expect(await prisma.finding.count()).toBe(0);

    const cross = await service.compose({ ...input, organizationId: other.id });
    expect(cross.eligibility).toBe('ineligible_component');
    expect(cross.calls.revisionInspections).toBe(0);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(before);
  });
});
