/**
 * Disposable PostgreSQL proof for tenant-scoped component inspection.
 * Synthetic identifiers only. No product-eligible row is written.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  ADVISORY_REVISION_FINDING_CREATION,
  ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
  ADVISORY_REVISION_PERSISTENCE_COMMAND_SCHEMA_VERSION,
  ADVISORY_VULNERABILITY_BINDING_COMMAND_SCHEMA_VERSION,
  ADVISORY_VULNERABILITY_BINDING_INSPECTION_SCHEMA_VERSION,
  EXACT_MAPPING_METHOD,
  FIRST_ECOSYSTEM_EVALUATOR_VERSION,
  FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
  PRODUCT_EVIDENCE_COMPOSITION_REQUEST_SCHEMA_VERSION,
  PRODUCT_EVIDENCE_PROVENANCE_POLICY_ID,
  SELECTED_FIRST_ECOSYSTEM,
  SUPERSESSION_NONE,
  SYNTHETIC_PROVIDER_GENERATION,
  SYNTHETIC_RETRIEVAL_TOKEN,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyNpmPackageIdentityFromParts,
  componentEvidenceFingerprint,
  createProductEvidenceEligibilityComposition,
  productAffectedRangeFingerprint,
  productContentFingerprint,
  session14RangeFingerprint,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createAdvisoryRevisionPersistence } from './advisory-revision-persistence.js';
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

const COMMAND_RANGES = [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }] }];
const CANONICAL_RANGES = [
  {
    type: 'SEMVER' as const,
    events: [
      { name: 'introduced' as const, value: '0' },
      { name: 'fixed' as const, value: '1.2.3' },
    ],
  },
];
const PACKAGE_NAME = 'closure-pad';
const ADVISORY_ID = 'GHSA-SYNTH-0001-0099';
const CVE_ALIAS = 'CVE-2099-1099';

function revisionCommand(spec: {
  readonly source?: string;
  readonly advisoryId?: string;
  readonly origin?: string;
  readonly trustClassification?: string;
  readonly retrievalClassification?: string;
  readonly retrievalEvidenceId?: string;
  readonly spdxLicenseId?: string | null;
  readonly aliases?: readonly string[];
  readonly providerGeneration?: string;
}): Record<string, unknown> {
  const source = spec.source ?? 'synthetic_fixture';
  const advisoryId = spec.advisoryId ?? 'SYNTHETICADV1';
  const origin = spec.origin ?? 'synthetic_fixture';
  const spdxLicenseId = spec.spdxLicenseId === undefined ? null : spec.spdxLicenseId;
  const aliases = spec.aliases ?? [];
  const identity = classifyNpmPackageIdentityFromParts({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    observedNamespace: null,
    observedName: PACKAGE_NAME,
    observedIdentity: PACKAGE_NAME,
  });
  if (identity.classification !== 'valid') {
    throw new Error('synthetic package identity was rejected');
  }
  const session14 = session14RangeFingerprint(CANONICAL_RANGES, []);
  const content = productContentFingerprint({
    source,
    advisoryId,
    schemaVersion: 'v1.9.0',
    schemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
    withdrawalClassification: 'not_withdrawn',
    spdxLicenseId,
    aliases,
    session14RangeFingerprint: session14,
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    packageIdentityKey: identity.identityKey,
  });
  const product = productAffectedRangeFingerprint({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    packageIdentityKey: identity.identityKey,
    session14RangeFingerprint: session14,
    parserId: 'osv_advisory_parser_protocol_v1',
    parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
    matchingPolicyId: FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
    evaluatorVersion: FIRST_ECOSYSTEM_EVALUATOR_VERSION,
    schemaVersion: 'v1.9.0',
  });
  return {
    commandSchemaVersion: ADVISORY_REVISION_PERSISTENCE_COMMAND_SCHEMA_VERSION,
    source,
    advisoryId,
    providerGeneration: spec.providerGeneration ?? SYNTHETIC_PROVIDER_GENERATION,
    origin,
    trustClassification: spec.trustClassification ?? 'not_applicable_synthetic',
    withdrawalClassification: 'not_withdrawn',
    quarantineClassification: 'not_quarantined',
    supersedesRevisionDigest: SUPERSESSION_NONE,
    retrievalClassification: spec.retrievalClassification ?? 'synthetic_not_retrieved',
    retrievalEvidenceId: spec.retrievalEvidenceId ?? SYNTHETIC_RETRIEVAL_TOKEN,
    spdxLicenseId,
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    namespace: null,
    name: PACKAGE_NAME,
    observedIdentity: PACKAGE_NAME,
    affectedRanges: COMMAND_RANGES,
    explicitAffectedVersions: [],
    aliases,
    evaluatorVersion: FIRST_ECOSYSTEM_EVALUATOR_VERSION,
    matchingPolicyId: FIRST_ECOSYSTEM_MATCHING_POLICY_ID,
    contentFingerprint: content,
    session14RangeFingerprint: session14,
    productRangeFingerprint: product,
  };
}

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
    const absent = await reader.inspectTenantOccurrence({
      organizationId: org.id,
      componentOccurrenceId: randomUUID(),
    });
    const malformedOccurrence = await reader.inspectTenantOccurrence({
      organizationId: org.id,
      componentOccurrenceId: 'not-a-uuid',
    });
    expect(hidden).toEqual({ kind: 'not_found' });
    expect(absent).toEqual(hidden);
    expect(malformedOccurrence).toEqual({ kind: 'rejected', code: 'malformed_persisted_state' });
    expect(malformedOccurrence).not.toEqual(hidden);
    expect(JSON.stringify(hidden)).not.toContain(occurrence.id);
    expect(JSON.stringify(hidden)).not.toContain(org.id);
    expect(JSON.stringify(hidden)).not.toContain(other.id);

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
    expect(composed.eligibility, composed.failureCode ?? '').toBe('ineligible_synthetic');
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
    const absentCommand = await service.compose({
      ...input,
      componentOccurrenceId: randomUUID(),
    });
    expect(cross.eligibility).toBe('ineligible_component');
    expect(cross.failureCode).toBe('component_missing');
    expect(cross).toEqual(absentCommand);
    expect(cross.calls.revisionInspections).toBe(0);
    expect(JSON.stringify(cross)).not.toContain(occurrence.id);
    expect(JSON.stringify(cross)).not.toContain(org.id);
    expect(JSON.stringify(cross)).not.toContain(other.id);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(before);
    expect(JSON.stringify(composed)).not.toContain('left-pad');
    expect(JSON.stringify(composed)).not.toContain('SYNTHETICADV1');
    expect(JSON.stringify(composed)).not.toContain('postgres://');
  });

  it('proves composition against stored revisions on disposable PostgreSQL', async () => {
    const queries: string[] = [];
    const logging = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
      log: [{ emit: 'event', level: 'query' }],
    });
    logging.$on('query', (event) => {
      queries.push(`${event.query} ${event.params}`);
    });
    const loggingReader = createProductEvidenceComponentInspection(logging);
    try {
      queries.length = 0;
      const malformed = await loggingReader.inspectTenantOccurrence({
        organizationId: 'not-a-uuid',
        componentOccurrenceId: '22222222-2222-4222-8222-222222222222',
      });
      expect(malformed).toEqual({ kind: 'rejected', code: 'malformed_persisted_state' });
      expect(queries).toEqual([]);
      expect(JSON.stringify(malformed)).not.toContain('postgres://');
      expect(JSON.stringify(malformed)).not.toContain('SELECT');
    } finally {
      await logging.$disconnect();
    }

    const org = await createOrg(prisma, `closure-${randomUUID().slice(0, 8)}`);
    const other = await createOrg(prisma, `foreign-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'asset-closure');
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
    const purlInput = resolvedComponent({
      name: PACKAGE_NAME,
      bomRef: 'component-purl',
      version: '1.2.3',
    });
    const purlComponent = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: purlInput.identityKey,
        purl: purlInput.versionlessPurl,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        identityState: 'resolved',
      },
    });
    const purlOccurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: purlComponent.id,
        bomRef: 'component-purl',
        version: '1.2.3',
        versionKnown: true,
      },
    });
    const ecoComponent = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: `eco:npm\u001f\u001f${PACKAGE_NAME}`,
        purl: null,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        identityState: 'resolved',
      },
    });
    const ecoOccurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: ecoComponent.id,
        bomRef: 'component-eco',
        version: '1.2.3',
        versionKnown: true,
      },
    });
    const mismatched = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: 'purl:pkg:npm/other-pad',
        purl: `pkg:npm/${PACKAGE_NAME}`,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        identityState: 'resolved',
      },
    });
    const mismatchedOccurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: mismatched.id,
        bomRef: 'component-mismatch',
        version: '1.2.3',
        versionKnown: true,
      },
    });

    const reader = createProductEvidenceComponentInspection(prisma);
    const found = await reader.inspectTenantOccurrence({
      organizationId: org.id,
      componentOccurrenceId: purlOccurrence.id,
    });
    expect(found.kind).toBe('found');
    if (found.kind !== 'found') {
      return;
    }
    expect(found.snapshot.componentIdentityKey).toBe(`purl:${purlComponent.purl}`);
    expect(purlComponent.purl).toBe(`pkg:npm/${PACKAGE_NAME}`);
    const hidden = await reader.inspectTenantOccurrence({
      organizationId: other.id,
      componentOccurrenceId: purlOccurrence.id,
    });
    expect(hidden.kind).toBe('not_found');

    const revisions = createAdvisoryRevisionPersistence(prisma);
    const synthetic = await revisions.persistImmutableAdvisoryRevision(revisionCommand({}));
    expect(synthetic.kind).toBe('recorded');
    if (synthetic.kind !== 'recorded') {
      return;
    }
    const syntheticRow = await prisma.advisoryRevision.findUnique({
      where: { id: synthetic.projection.revisionId },
      select: {
        revisionDigest: true,
        familyDigest: true,
        contentFingerprint: true,
        session14RangeFingerprint: true,
        productRangeFingerprint: true,
        origin: true,
        advisoryId: true,
        packageIdentityKey: true,
      },
    });
    const syntheticInspected = await revisions.inspectImmutableAdvisoryRevision({
      inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
      revisionId: synthetic.projection.revisionId,
    });
    expect(syntheticInspected.kind).toBe('found');
    if (syntheticInspected.kind !== 'found') {
      return;
    }
    expect(syntheticInspected.projection.revisionDigest).toBe(syntheticRow?.revisionDigest);
    expect(syntheticInspected.projection.familyDigest).toBe(syntheticRow?.familyDigest);
    expect(syntheticInspected.projection.contentFingerprint).toBe(syntheticRow?.contentFingerprint);
    expect(syntheticInspected.projection.session14RangeFingerprint).toBe(
      syntheticRow?.session14RangeFingerprint,
    );
    expect(syntheticInspected.projection.productRangeFingerprint).toBe(
      syntheticRow?.productRangeFingerprint,
    );
    expect(syntheticInspected.projection.origin).toBe(syntheticRow?.origin);
    expect(syntheticInspected.projection.advisoryId).toBe('SYNTHETICADV1');
    expect(syntheticInspected.projection.packageIdentityKey).toBe(syntheticRow?.packageIdentityKey);

    const provider = await revisions.persistImmutableAdvisoryRevision(
      revisionCommand({
        source: 'github_advisory_database',
        advisoryId: ADVISORY_ID,
        origin: 'provider_derived',
        trustClassification: 'reviewed',
        providerGeneration: '17',
        retrievalClassification: 'recorded_reference',
        retrievalEvidenceId: '33333333-3333-4333-8333-333333333333',
        spdxLicenseId: 'CC-BY-4.0',
        aliases: [CVE_ALIAS],
      }),
    );
    expect(provider.kind).toBe('recorded');
    if (provider.kind !== 'recorded') {
      return;
    }
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `SYNTHETIC-CLOSURE-${randomUUID().slice(0, 8)}` },
      select: { id: true },
    });
    const bound = await revisions.persistReviewedAdvisoryVulnerabilityBinding({
      commandSchemaVersion: ADVISORY_VULNERABILITY_BINDING_COMMAND_SCHEMA_VERSION,
      revisionDigest: provider.projection.revisionDigest,
      advisoryId: ADVISORY_ID,
      vulnerabilityId: vulnerability.id,
      mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
      mappingMethod: EXACT_MAPPING_METHOD,
    });
    expect(bound.kind).toBe('recorded');
    if (bound.kind !== 'recorded') {
      return;
    }
    const bindingRow = await prisma.advisoryVulnerabilityBinding.findUnique({
      where: { id: bound.projection.bindingId },
      select: { vulnerabilityId: true, replayFingerprint: true },
    });
    const bindingInspected = await revisions.inspectReviewedAdvisoryVulnerabilityBinding({
      inspectionSchemaVersion: ADVISORY_VULNERABILITY_BINDING_INSPECTION_SCHEMA_VERSION,
      revisionDigest: provider.projection.revisionDigest,
    });
    expect(bindingInspected.kind).toBe('found');
    if (bindingInspected.kind !== 'found') {
      return;
    }
    expect(bindingInspected.projection.vulnerabilityId).toBe(vulnerability.id);
    expect(bindingInspected.projection.vulnerabilityId).toBe(bindingRow?.vulnerabilityId);
    expect(bindingInspected.projection.replayFingerprint).toBe(bindingRow?.replayFingerprint);
    expect(bindingInspected.projection.advisoryId).toBe(ADVISORY_ID);
    expect(bindingInspected.projection.revisionId).toBe(provider.projection.revisionId);
    const absentBinding = await revisions.inspectReviewedAdvisoryVulnerabilityBinding({
      inspectionSchemaVersion: ADVISORY_VULNERABILITY_BINDING_INSPECTION_SCHEMA_VERSION,
      revisionDigest: 'ab'.repeat(32),
    });
    expect(absentBinding.kind).toBe('not_found');

    const evidenceBefore = await prisma.matchEvaluationEvidence.count();
    const findingsBefore = await prisma.finding.count();
    const service = createProductEvidenceEligibilityComposition({
      components: reader,
      revisions,
      async readCatalogMembership() {
        return null;
      },
      async readActiveCatalogEvidence() {
        return null;
      },
    });
    const packageKey = synthetic.projection.packageIdentityKey;
    const purlFingerprint = componentEvidenceFingerprint({
      organizationId: org.id,
      componentOccurrenceId: purlOccurrence.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      componentId: purlComponent.id,
      componentIdentityKey: purlInput.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: PACKAGE_NAME,
      rawObservedVersion: '1.2.3',
      versionKnown: true,
      sbomSha256: SHA_A,
    });
    const syntheticInput = compositionRequest({
      organizationId: org.id,
      componentOccurrenceId: purlOccurrence.id,
      fingerprint: purlFingerprint,
      packageKey,
      revision: synthetic.projection,
      vulnerabilityId: vulnerability.id,
      bindingReplay: bound.projection.replayFingerprint,
    });
    const syntheticComposed = await service.compose(syntheticInput);
    expect(syntheticComposed.eligibility, syntheticComposed.failureCode ?? '').toBe(
      'ineligible_synthetic',
    );
    expect(syntheticComposed.calls.evaluatorCalls).toBe(0);
    expect(syntheticComposed.calls.persistenceCalls).toBe(0);
    expect(syntheticComposed.calls.bindingInspections).toBe(0);
    expect(syntheticComposed.calls.providerCalls).toBe(0);
    expect(syntheticComposed.calls.parserCalls).toBe(0);
    expect(syntheticComposed.calls.findingCalls).toBe(0);
    expect(syntheticComposed.evidenceReality).toBe('not_real_product_evidence');
    expectConfidential(syntheticComposed);
    const syntheticReplay = await service.compose(syntheticInput);
    expect(syntheticReplay.eligibility).toBe('ineligible_synthetic');
    expect(syntheticReplay.calls.persistenceCalls).toBe(0);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(evidenceBefore);

    const ecoFound = await reader.inspectTenantOccurrence({
      organizationId: org.id,
      componentOccurrenceId: ecoOccurrence.id,
    });
    expect(ecoFound.kind).toBe('found');
    if (ecoFound.kind !== 'found') {
      return;
    }
    expect(ecoFound.snapshot.componentIdentityKey).toBe(`eco:npm\u001f\u001f${PACKAGE_NAME}`);
    const ecoFingerprint = componentEvidenceFingerprint({
      organizationId: org.id,
      componentOccurrenceId: ecoOccurrence.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      componentId: ecoComponent.id,
      componentIdentityKey: ecoComponent.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: PACKAGE_NAME,
      rawObservedVersion: '1.2.3',
      versionKnown: true,
      sbomSha256: SHA_A,
    });
    const ecoComposed = await service.compose(
      compositionRequest({
        organizationId: org.id,
        componentOccurrenceId: ecoOccurrence.id,
        fingerprint: ecoFingerprint,
        packageKey,
        revision: synthetic.projection,
        vulnerabilityId: vulnerability.id,
        bindingReplay: bound.projection.replayFingerprint,
      }),
    );
    expect(ecoComposed.eligibility).toBe('ineligible_synthetic');
    expect(ecoComposed.calls.evaluatorCalls).toBe(0);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(evidenceBefore);

    const mismatchFingerprint = componentEvidenceFingerprint({
      organizationId: org.id,
      componentOccurrenceId: mismatchedOccurrence.id,
      assetId: asset.id,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      componentId: mismatched.id,
      componentIdentityKey: mismatched.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: PACKAGE_NAME,
      rawObservedVersion: '1.2.3',
      versionKnown: true,
      sbomSha256: SHA_A,
    });
    const mismatchComposed = await service.compose(
      compositionRequest({
        organizationId: org.id,
        componentOccurrenceId: mismatchedOccurrence.id,
        fingerprint: mismatchFingerprint,
        packageKey,
        revision: synthetic.projection,
        vulnerabilityId: vulnerability.id,
        bindingReplay: bound.projection.replayFingerprint,
      }),
    );
    expect(mismatchComposed.eligibility).toBe('ineligible_package_identity');
    expect(mismatchComposed.calls.revisionInspections).toBe(0);
    expect(mismatchComposed.calls.evaluatorCalls).toBe(0);
    expectConfidential(mismatchComposed);

    const conflictDigest = provider.projection.familyDigest.startsWith('a')
      ? 'b'.repeat(64)
      : 'a'.repeat(64);
    const conflict = await service.compose(
      compositionRequest({
        organizationId: org.id,
        componentOccurrenceId: purlOccurrence.id,
        fingerprint: purlFingerprint,
        packageKey,
        revision: provider.projection,
        vulnerabilityId: vulnerability.id,
        bindingReplay: bound.projection.replayFingerprint,
        familyDigest: conflictDigest,
      }),
    );
    expect(conflict.eligibility).toBe('immutable_conflict');
    expect(conflict.calls.evaluatorCalls).toBe(0);
    expect(conflict.calls.persistenceCalls).toBe(0);
    expect(conflict.calls.bindingInspections).toBe(0);
    expectConfidential(conflict);
    const conflictReplay = await service.compose(
      compositionRequest({
        organizationId: org.id,
        componentOccurrenceId: purlOccurrence.id,
        fingerprint: purlFingerprint,
        packageKey,
        revision: provider.projection,
        vulnerabilityId: vulnerability.id,
        bindingReplay: bound.projection.replayFingerprint,
        familyDigest: conflictDigest,
      }),
    );
    expect(conflictReplay.eligibility).toBe('immutable_conflict');
    expect(await prisma.matchEvaluationEvidence.count()).toBe(evidenceBefore);

    const catalogBlocked = await service.compose(
      compositionRequest({
        organizationId: org.id,
        componentOccurrenceId: purlOccurrence.id,
        fingerprint: purlFingerprint,
        packageKey,
        revision: provider.projection,
        vulnerabilityId: vulnerability.id,
        bindingReplay: bound.projection.replayFingerprint,
      }),
    );
    expect(catalogBlocked.eligibility).toBe('ineligible_catalog');
    expect(catalogBlocked.calls.bindingInspections).toBe(1);
    expect(catalogBlocked.calls.evaluatorCalls).toBe(0);
    expect(catalogBlocked.calls.persistenceCalls).toBe(0);
    expect(catalogBlocked.calls.providerCalls).toBe(0);
    expect(catalogBlocked.calls.parserCalls).toBe(0);
    expect(catalogBlocked.calls.findingCalls).toBe(0);
    expect(catalogBlocked.calls.catalogMutations).toBe(0);
    expect(catalogBlocked.findingAuthority).toBe(false);
    expect(catalogBlocked.suppressionAuthority).toBe(false);
    expect(catalogBlocked.outcome).toBeNull();
    expectConfidential(catalogBlocked);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(evidenceBefore);
    expect(await prisma.finding.count()).toBe(findingsBefore);
    const pointer = await prisma.$queryRaw<Array<{ count: bigint }>>`
      SELECT COUNT(*)::bigint AS count FROM "osv_active_catalog_pointer"
    `;
    expect(Number(pointer[0]?.count)).toBe(0);
  });

  it('keeps foreign, absent, and deleted occurrences on the same public result', async () => {
    const org = await createOrg(prisma, `indist-${randomUUID().slice(0, 8)}`);
    const other = await createOrg(prisma, `indist-other-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'asset-indist');
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
      bomRef: 'component-indist',
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
        bomRef: 'component-indist',
        version: '1.2.3',
        versionKnown: true,
      },
    });
    const queries: string[] = [];
    const logging = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
      log: [{ emit: 'event', level: 'query' }],
    });
    logging.$on('query', (event) => {
      queries.push(event.query);
    });
    const reader = createProductEvidenceComponentInspection(logging);
    let release: (() => void) | undefined;
    let markEntered: (() => void) | undefined;
    const entered = new Promise<void>((resolve) => {
      markEntered = resolve;
    });
    let holderFailed = false;
    const holder = prisma
      .$transaction(
        async (tx) => {
          await tx.$queryRaw`
            SELECT "id" FROM "component_occurrence"
            WHERE "id" = ${occurrence.id}::uuid
            FOR UPDATE
          `;
          markEntered?.();
          await new Promise<void>((resolve) => {
            release = resolve;
          });
        },
        { maxWait: 5_000, timeout: 20_000 },
      )
      .catch((error: unknown) => {
        holderFailed = true;
        markEntered?.();
        throw error;
      });
    await entered;
    expect(holderFailed).toBe(false);
    try {
      await logging.$queryRaw`SELECT 1`;
      queries.length = 0;
      const foreign = await reader.inspectTenantOccurrence({
        organizationId: other.id,
        componentOccurrenceId: occurrence.id,
      });
      const foreignSql = occurrenceQueries(queries);
      queries.length = 0;
      const absent = await reader.inspectTenantOccurrence({
        organizationId: other.id,
        componentOccurrenceId: randomUUID(),
      });
      const absentSql = occurrenceQueries(queries);
      expect(foreign).toEqual({ kind: 'not_found' });
      expect(absent).toEqual(foreign);
      expect(foreignSql).toEqual(absentSql);
      expect(foreignSql.length).toBeGreaterThan(0);
      expect(foreignSql.every(scopedOccurrenceWhere)).toBe(true);
      expect(JSON.stringify(foreign)).not.toContain(occurrence.id);
      expect(JSON.stringify(foreign)).not.toContain(org.id);
      expect(JSON.stringify(foreign)).not.toContain(other.id);
      const authorized = await reader.inspectTenantOccurrence({
        organizationId: org.id,
        componentOccurrenceId: occurrence.id,
      });
      expect(authorized.kind).toBe('found');
    } finally {
      release?.();
      await holder.catch(() => undefined);
      await logging.$disconnect();
    }

    await prisma.componentOccurrence.delete({ where: { id: occurrence.id } });
    const durable = createProductEvidenceComponentInspection(prisma);
    const deleted = await durable.inspectTenantOccurrence({
      organizationId: org.id,
      componentOccurrenceId: occurrence.id,
    });
    const deletedForeign = await durable.inspectTenantOccurrence({
      organizationId: other.id,
      componentOccurrenceId: occurrence.id,
    });
    const neverCreated = await durable.inspectTenantOccurrence({
      organizationId: other.id,
      componentOccurrenceId: randomUUID(),
    });
    expect(deleted).toEqual({ kind: 'not_found' });
    expect(deletedForeign).toEqual(deleted);
    expect(neverCreated).toEqual(deleted);
  });
});

function occurrenceQueries(queries: readonly string[]): string[] {
  return queries.filter((query) => query.toLowerCase().includes('component_occurrence'));
}

function scopedOccurrenceWhere(query: string): boolean {
  const normalized = query.toLowerCase().replace(/\s+/g, ' ');
  const index = normalized.lastIndexOf(' where ');
  if (index === -1) {
    return false;
  }
  const where = normalized.slice(index);
  return where.includes('organization_id') && where.includes('"id"');
}

function compositionRequest(input: {
  readonly organizationId: string;
  readonly componentOccurrenceId: string;
  readonly fingerprint: string;
  readonly packageKey: string;
  readonly revision: {
    readonly revisionId: string;
    readonly familyDigest: string;
    readonly contentFingerprint: string;
    readonly session14RangeFingerprint: string;
    readonly productRangeFingerprint: string;
    readonly revisionDigest: string;
    readonly source: string;
    readonly trustClassification: string;
    readonly revisionDisposition: string;
    readonly withdrawalClassification: string;
  };
  readonly vulnerabilityId: string;
  readonly bindingReplay: string;
  readonly familyDigest?: string;
}): Record<string, unknown> {
  return {
    requestSchemaVersion: PRODUCT_EVIDENCE_COMPOSITION_REQUEST_SCHEMA_VERSION,
    provenancePolicyId: PRODUCT_EVIDENCE_PROVENANCE_POLICY_ID,
    provenancePolicyVersion: 'osv_product_evidence_provenance_contract_v1',
    advisoryRevisionId: input.revision.revisionId,
    expectedFamilyDigest: input.familyDigest ?? input.revision.familyDigest,
    expectedContentFingerprint: input.revision.contentFingerprint,
    expectedRangeFingerprint: input.revision.session14RangeFingerprint,
    expectedProductRangeFingerprint: input.revision.productRangeFingerprint,
    expectedRevisionDigest: input.revision.revisionDigest,
    expectedSource: input.revision.source,
    expectedSourceRegistryVersion: 'osv_source_license_registry_v1',
    expectedLicensePolicyVersion: 'osv_source_license_registry_v1',
    expectedParserId: 'osv_advisory_parser_protocol_v1',
    expectedParserVersion: 'osv_advisory_parser_resource_policy_v1',
    expectedAdvisorySchemaVersion: 'v1.9.0',
    expectedAdvisorySchemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
    expectedTrustClassification: input.revision.trustClassification,
    expectedRevisionDisposition: input.revision.revisionDisposition,
    expectedWithdrawalClassification: input.revision.withdrawalClassification,
    expectedCatalogId: '55555555-5555-4555-8555-555555555555',
    expectedCatalogGenerationId: '66666666-6666-4666-8666-666666666666',
    expectedEcosystemRegistryVersion: 'osv_ecosystem_implementation_registry_contract_v1',
    expectedEvaluatorRegistryVersion: 'osv_evaluator_registry_contract_v1',
    expectedVulnerabilityId: input.vulnerabilityId,
    expectedBindingReplayFingerprint: input.bindingReplay,
    organizationId: input.organizationId,
    componentOccurrenceId: input.componentOccurrenceId,
    expectedComponentEvidenceFingerprint: input.fingerprint,
    expectedPackageIdentityKey: input.packageKey,
    expectedRawObservedVersion: '1.2.3',
    evaluationCorrelationId: '88888888-8888-4888-8888-888888888888',
  };
}

function expectConfidential(value: unknown): void {
  const text = JSON.stringify(value);
  expect(text).not.toContain(PACKAGE_NAME);
  expect(text).not.toContain(ADVISORY_ID);
  expect(text).not.toContain(CVE_ALIAS);
  expect(text).not.toContain('SYNTHETICADV1');
  expect(text).not.toContain('postgres://');
  expect(text).not.toContain('SELECT');
}
