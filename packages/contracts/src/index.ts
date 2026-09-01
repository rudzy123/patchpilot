import { z } from 'zod';

export {
  errorCodeSchema,
  errorEnvelopeSchema,
  type ErrorCode,
  type ErrorEnvelope,
} from './errors.js';
export {
  loginRequestSchema,
  membershipRoleSchema,
  organizationsResponseSchema,
  publicAuthOrganizationSchema,
  publicAuthUserSchema,
  selectOrganizationRequestSchema,
  sessionResponseSchema,
  type LoginRequest,
  type OrganizationsResponse,
  type PublicAuthOrganization,
  type PublicAuthUser,
  type SelectOrganizationRequest,
  type SessionResponse,
} from './auth.js';
export {
  archiveAssetRequestSchema,
  assetDetailSchema,
  assetExternalIdentifierSchema,
  assetIdParamSchema,
  assetListQuerySchema,
  assetListResponseSchema,
  assetOptionsQuerySchema,
  assetOwnerAssignmentSchema,
  assetSummarySchema,
  assetTagSchema,
  createAssetRequestSchema,
  encodeAssetListCursor,
  environmentOptionSchema,
  environmentOptionsResponseSchema,
  membershipOptionSchema,
  membershipOptionsResponseSchema,
  teamOptionSchema,
  teamOptionsResponseSchema,
  updateAssetRequestSchema,
  type ArchiveAssetRequest,
  type AssetDetail,
  type AssetIdParam,
  type AssetListQueryRequest,
  type AssetListResponse,
  type AssetOptionsQuery,
  type AssetOwnerAssignmentRequest,
  type AssetSummary,
  type CreateAssetRequest,
  type EnvironmentOption,
  type MembershipOption,
  type TeamOption,
  type UpdateAssetRequest,
} from './assets.js';
export {
  assetSbomIdParamSchema,
  assetSbomIngestionIdParamSchema,
  cursorPaginationQuerySchema,
  encodeSbomListCursor,
  graphCompletenessSchema,
  ingestionIdParamSchema,
  parseWarningCodeSchema,
  safeFailureCategorySchema,
  safeFailureCodeSchema,
  sbomDetailSchema,
  sbomIdParamSchema,
  sbomIngestionIdParamSchema,
  sbomIngestionStageSchema,
  sbomIngestionStateSchema,
  sbomIngestionStatusSchema,
  sbomIngestionSummarySchema,
  sbomListQuerySchema,
  sbomListResponseSchema,
  sbomSourceSchema,
  sbomSpecificationTypeSchema,
  sbomSummarySchema,
  sbomUploadAcceptedResponseSchema,
  supportedCycloneDxSpecificationVersionSchema,
  type AssetSbomIdParam,
  type AssetSbomIngestionIdParam,
  type GraphCompletenessContract,
  type IngestionIdParam,
  type SafeFailureCategoryContract,
  type SafeFailureCodeContract,
  type SbomDetail,
  type SbomIdParam,
  type SbomIngestionIdParam,
  type SbomIngestionStatus,
  type SbomIngestionSummary,
  type SbomListQueryRequest,
  type SbomListResponse,
  type SbomSummary,
  type SbomUploadAcceptedResponse,
  type SupportedCycloneDxSpecificationVersion,
} from './sboms.js';
export {
  INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL,
  INTELLIGENCE_PROVIDER_STATUS_PATH,
  INTELLIGENCE_PROVIDERS_PATH,
  expectedDisabledKevPublicStatus,
  expectedOsvPublicStatus,
  intelligenceDisplayName,
  intelligenceProviderDetailResponseSchema,
  intelligenceProviderHealthStatusSchema,
  intelligenceProviderImplementationStatusSchema,
  intelligenceProviderListResponseSchema,
  intelligenceProviderParamSchema,
  intelligenceProviderSchema,
  intelligenceProviderStatusSchema,
  intelligenceSafeFailureCodeSchema,
  type IntelligenceProviderContract,
  type IntelligenceProviderDetailResponse,
  type IntelligenceProviderHealthStatusContract,
  type IntelligenceProviderImplementationStatusContract,
  type IntelligenceProviderListResponse,
  type IntelligenceProviderParam,
  type IntelligenceProviderStatus,
} from './intelligence.js';

export const healthServiceSchema = z.enum(['api', 'web', 'worker']);

export const healthLiveResponseSchema = z.object({
  status: z.literal('live'),
  service: healthServiceSchema,
  timestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
    message: 'timestamp must be UTC ISO 8601',
  }),
  version: z.string().min(1).optional(),
});

export const healthCheckSchema = z.object({
  name: z.string().min(1),
  status: z.enum(['up', 'down']),
});

export const healthReadyResponseSchema = z.object({
  status: z.enum(['ready', 'not_ready']),
  service: healthServiceSchema,
  timestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
    message: 'timestamp must be UTC ISO 8601',
  }),
  version: z.string().min(1).optional(),
  checks: z.array(healthCheckSchema),
});

export type HealthLiveResponse = z.infer<typeof healthLiveResponseSchema>;
export type HealthReadyResponse = z.infer<typeof healthReadyResponseSchema>;
export type HealthCheck = z.infer<typeof healthCheckSchema>;
export type HealthService = z.infer<typeof healthServiceSchema>;

export function utcNowIso(): string {
  return new Date().toISOString();
}
