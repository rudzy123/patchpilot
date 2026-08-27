export const organizationStatuses = ['active', 'archived'] as const;
export type OrganizationStatus = (typeof organizationStatuses)[number];

export const userStatuses = ['active', 'disabled'] as const;
export type UserStatus = (typeof userStatuses)[number];

export const membershipRoles = ['owner', 'admin', 'member', 'viewer'] as const;
export type MembershipRole = (typeof membershipRoles)[number];

export const membershipStatuses = ['active', 'revoked'] as const;
export type MembershipStatus = (typeof membershipStatuses)[number];

export const teamStatuses = ['active', 'archived'] as const;
export type TeamStatus = (typeof teamStatuses)[number];

export const environmentStatuses = ['active', 'archived'] as const;
export type EnvironmentStatus = (typeof environmentStatuses)[number];

export const environmentSensitivityClasses = ['production', 'non_production'] as const;
export type EnvironmentSensitivityClass = (typeof environmentSensitivityClasses)[number];

export const assetTypes = [
  'application',
  'service',
  'library',
  'container_image',
  'other',
] as const;
export type AssetType = (typeof assetTypes)[number];

export const assetLifecycleStatuses = ['active', 'archived'] as const;
export type AssetLifecycleStatus = (typeof assetLifecycleStatuses)[number];

export const businessCriticalities = ['critical', 'high', 'medium', 'low', 'unspecified'] as const;
export type BusinessCriticality = (typeof businessCriticalities)[number];

export const internetExposures = ['internet_facing', 'internal', 'unknown'] as const;
export type InternetExposure = (typeof internetExposures)[number];

export const assetDataClassifications = [
  'restricted',
  'confidential',
  'internal',
  'public',
  'unspecified',
] as const;
export type AssetDataClassification = (typeof assetDataClassifications)[number];

export const assetOwnerRoles = ['technical', 'business', 'security'] as const;
export type AssetOwnerRole = (typeof assetOwnerRoles)[number];

export const repositoryProviders = ['reserved'] as const;
export type RepositoryProvider = (typeof repositoryProviders)[number];

export const repositoryConnectionStatuses = ['not_configured'] as const;
export type RepositoryConnectionStatus = (typeof repositoryConnectionStatuses)[number];

export const sbomSpecificationTypes = ['cyclonedx'] as const;
export type SbomSpecificationType = (typeof sbomSpecificationTypes)[number];

export const sbomSpecificationVersions = ['1.4', '1.5', '1.6'] as const;
export type SbomSpecificationVersion = (typeof sbomSpecificationVersions)[number];

export const sbomSources = ['upload', 'reprocess'] as const;
export type SbomSource = (typeof sbomSources)[number];

export const sbomIngestionStates = [
  'accepted',
  'queued',
  'processing',
  'completed',
  'rejected',
  'quarantined',
  'failed',
  'duplicate',
] as const;
export type SbomIngestionState = (typeof sbomIngestionStates)[number];

export const sbomIngestionStages = [
  'validate',
  'parse',
  'persist_graph',
  'correlate',
  'enrich',
  'score',
] as const;
export type SbomIngestionStage = (typeof sbomIngestionStages)[number];

export const componentIdentityStates = ['resolved', 'ambiguous', 'unsupported'] as const;
export type ComponentIdentityState = (typeof componentIdentityStates)[number];

export const dependencyRelationshipTypes = ['depends_on'] as const;
export type DependencyRelationshipType = (typeof dependencyRelationshipTypes)[number];

export const vulnerabilityStatuses = ['active', 'withdrawn'] as const;
export type VulnerabilityStatus = (typeof vulnerabilityStatuses)[number];

export const vulnerabilitySources = ['osv', 'cisa_kev'] as const;
export type VulnerabilitySource = (typeof vulnerabilitySources)[number];

export const findingStates = [
  'open',
  'verification_pending',
  'risk_accepted',
  'mitigated',
  'false_positive',
  'resolved',
  'inconclusive',
] as const;
export type FindingState = (typeof findingStates)[number];

export const findingObservationResults = ['present', 'absent', 'inconclusive'] as const;
export type FindingObservationResult = (typeof findingObservationResults)[number];

export const riskPolicyStatuses = ['draft', 'published', 'retired'] as const;
export type RiskPolicyStatus = (typeof riskPolicyStatuses)[number];

export const riskCalculationReasons = [
  'initial',
  'rescan',
  'intel_refresh',
  'policy_change',
  'asset_change',
  'manual_recalc',
  'manual_override',
] as const;
export type RiskCalculationReason = (typeof riskCalculationReasons)[number];

export const remediationTaskStatuses = [
  'open',
  'assigned',
  'in_progress',
  'blocked',
  'completed',
  'cancelled',
] as const;
export type RemediationTaskStatus = (typeof remediationTaskStatuses)[number];

export const riskAcceptanceStatuses = ['active', 'expired', 'revoked', 'superseded'] as const;
export type RiskAcceptanceStatus = (typeof riskAcceptanceStatuses)[number];

export const evidenceKinds = [
  'sbom_object',
  'kev_match',
  'intel_record',
  'policy_snapshot',
  'compensating_control',
  'export_snapshot',
] as const;
export type EvidenceKind = (typeof evidenceKinds)[number];

export const riskPolicyScopes = ['builtin', 'organization'] as const;
export type RiskPolicyScope = (typeof riskPolicyScopes)[number];

export const auditActorTypes = ['user', 'system', 'instance_operator'] as const;
export type AuditActorType = (typeof auditActorTypes)[number];

export const auditRetentionCategories = ['security'] as const;
export type AuditRetentionCategory = (typeof auditRetentionCategories)[number];

export const integrationStates = ['disabled', 'enabled', 'degraded'] as const;
export type IntegrationState = (typeof integrationStates)[number];

export const integrationProviderKeys = ['osv', 'cisa_kev', 'reserved'] as const;
export type IntegrationProviderKey = (typeof integrationProviderKeys)[number];

export const externalCredentialStatuses = [
  'pending',
  'active',
  'rotating',
  'expired',
  'revoked',
  'failed_validation',
] as const;
export type ExternalCredentialStatus = (typeof externalCredentialStatuses)[number];

export const secretStorageProviders = ['encrypted_local', 'external_secret_manager'] as const;
export type SecretStorageProvider = (typeof secretStorageProviders)[number];

export const outboxEventStatuses = [
  'pending',
  'claimed',
  'processed',
  'failed',
  'dead_lettered',
] as const;
export type OutboxEventStatus = (typeof outboxEventStatuses)[number];

export const backgroundJobStatuses = [
  'pending',
  'queued',
  'running',
  'succeeded',
  'failed',
  'dead_lettered',
  'cancelled',
] as const;
export type BackgroundJobStatus = (typeof backgroundJobStatuses)[number];

export const idempotencyRecordStatuses = ['started', 'completed', 'conflict'] as const;
export type IdempotencyRecordStatus = (typeof idempotencyRecordStatuses)[number];

export const findingTerminalStates = ['resolved'] as const;
export const remediationTaskTerminalStatuses = ['completed', 'cancelled'] as const;
export const sbomIngestionTerminalStates = ['completed', 'rejected', 'duplicate'] as const;
export const riskAcceptanceTerminalStatuses = ['expired', 'revoked', 'superseded'] as const;
export const backgroundJobTerminalStatuses = ['succeeded', 'cancelled'] as const;
