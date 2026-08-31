import {
  SHA256_HEX_PATTERN,
  SBOM_LIST_DEFAULT_LIMIT,
  SBOM_LIST_MAX_LIMIT,
  SBOM_LIST_MIN_LIMIT,
  SBOM_RAW_TEXT_MAX_LENGTH,
  SBOM_VERSION_LABEL_PATTERN,
  decodeSbomListCursor,
  encodeSbomListCursor,
  graphCompletenessValues,
  parseWarningCodes,
  safeFailureCategories,
  safeFailureCodes,
  session8IngestionStages,
  session8IngestionStates,
  sbomSources,
  sbomSpecificationTypes,
  sbomSpecificationVersions,
  type SbomListQuery,
} from '@patchpilot/domain';
import { z } from 'zod';

const utcTimestampSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
  message: 'timestamp must be UTC ISO 8601',
});

const sha256Schema = z.string().regex(SHA256_HEX_PATTERN, {
  message: 'sha256 must be 64 lowercase hexadecimal characters',
});

const parserVersionSchema = z.string().min(1).max(64).regex(SBOM_VERSION_LABEL_PATTERN);

function failWithMessage(ctx: z.RefinementCtx, message: string): typeof z.NEVER {
  ctx.addIssue({ code: 'custom', message });
  return z.NEVER;
}

export const sbomSpecificationTypeSchema = z.enum(sbomSpecificationTypes);
export const supportedCycloneDxSpecificationVersionSchema = z.enum(sbomSpecificationVersions);
export const sbomSourceSchema = z.enum(sbomSources);
export const graphCompletenessSchema = z.enum(graphCompletenessValues);
export const sbomIngestionStateSchema = z.enum(session8IngestionStates);
export const sbomIngestionStageSchema = z.enum(session8IngestionStages);
export const safeFailureCategorySchema = z.enum(safeFailureCategories);
export const safeFailureCodeSchema = z.enum(safeFailureCodes);
export const parseWarningCodeSchema = z.enum(parseWarningCodes);

export const sbomIdParamSchema = z.strictObject({
  sbomId: z.uuid(),
});

export const ingestionIdParamSchema = z.strictObject({
  ingestionId: z.uuid(),
});

export const assetSbomIdParamSchema = z.strictObject({
  assetId: z.uuid(),
  sbomId: z.uuid(),
});

export const sbomIngestionIdParamSchema = z.strictObject({
  sbomId: z.uuid(),
  ingestionId: z.uuid(),
});

export const assetSbomIngestionIdParamSchema = z.strictObject({
  assetId: z.uuid(),
  ingestionId: z.uuid(),
});

export const cursorPaginationQuerySchema = z.strictObject({
  limit: z.coerce.number().int().min(SBOM_LIST_MIN_LIMIT).max(SBOM_LIST_MAX_LIMIT).optional(),
  cursor: z.string().min(1).max(SBOM_RAW_TEXT_MAX_LENGTH).optional(),
});

export const sbomListQuerySchema = cursorPaginationQuerySchema.transform(
  (value, ctx): SbomListQuery => {
    const cursorResult =
      value.cursor === undefined ? undefined : decodeSbomListCursor(value.cursor);
    if (cursorResult !== undefined && !cursorResult.ok) {
      return failWithMessage(ctx, cursorResult.error.message);
    }

    const query: SbomListQuery = {
      limit: value.limit ?? SBOM_LIST_DEFAULT_LIMIT,
    };

    if (cursorResult !== undefined && cursorResult.ok) {
      query.cursor = cursorResult.value;
    }

    return query;
  },
);

export const sbomUploadAcceptedResponseSchema = z.strictObject({
  sbomId: z.uuid(),
  ingestionId: z.uuid(),
  assetId: z.uuid(),
  state: sbomIngestionStateSchema,
  specificationType: sbomSpecificationTypeSchema,
  sha256: sha256Schema,
  byteLength: z.number().int().positive(),
  source: sbomSourceSchema,
  receivedAt: utcTimestampSchema,
});

export const sbomIngestionSummarySchema = z.strictObject({
  id: z.uuid(),
  sbomId: z.uuid(),
  assetId: z.uuid(),
  state: sbomIngestionStateSchema,
  stage: sbomIngestionStageSchema.nullable(),
  graphCompleteness: graphCompletenessSchema.nullable(),
  componentCount: z.number().int().nonnegative().nullable(),
  dependencyEdgeCount: z.number().int().nonnegative().nullable(),
  warningCount: z.number().int().nonnegative().nullable(),
  parserVersion: parserVersionSchema,
  failureCategory: safeFailureCategorySchema.nullable(),
  failureCode: safeFailureCodeSchema.nullable(),
  startedAt: utcTimestampSchema.nullable(),
  completedAt: utcTimestampSchema.nullable(),
});

export const sbomIngestionStatusSchema = sbomIngestionSummarySchema;

export const sbomSummarySchema = z.strictObject({
  id: z.uuid(),
  assetId: z.uuid(),
  specificationType: sbomSpecificationTypeSchema,
  specificationVersion: supportedCycloneDxSpecificationVersionSchema.nullable(),
  sha256: sha256Schema,
  byteLength: z.number().int().positive(),
  source: sbomSourceSchema,
  receivedAt: utcTimestampSchema,
  capturedAt: utcTimestampSchema.nullable(),
  parserVersion: parserVersionSchema.nullable(),
  ingestionId: z.uuid(),
  state: sbomIngestionStateSchema,
  stage: sbomIngestionStageSchema.nullable(),
  graphCompleteness: graphCompletenessSchema.nullable(),
  componentCount: z.number().int().nonnegative().nullable(),
  dependencyEdgeCount: z.number().int().nonnegative().nullable(),
  warningCount: z.number().int().nonnegative().nullable(),
  failureCategory: safeFailureCategorySchema.nullable(),
  failureCode: safeFailureCodeSchema.nullable(),
});

export const sbomDetailSchema = sbomSummarySchema.safeExtend({
  currentIngestion: sbomIngestionSummarySchema,
});

export const sbomListResponseSchema = z.strictObject({
  items: z.array(sbomSummarySchema),
  nextCursor: z.string().min(1).nullable(),
});

export { encodeSbomListCursor };

export type SbomIdParam = z.infer<typeof sbomIdParamSchema>;
export type IngestionIdParam = z.infer<typeof ingestionIdParamSchema>;
export type AssetSbomIdParam = z.infer<typeof assetSbomIdParamSchema>;
export type SbomIngestionIdParam = z.infer<typeof sbomIngestionIdParamSchema>;
export type AssetSbomIngestionIdParam = z.infer<typeof assetSbomIngestionIdParamSchema>;
export type SbomListQueryRequest = z.infer<typeof sbomListQuerySchema>;
export type SbomUploadAcceptedResponse = z.infer<typeof sbomUploadAcceptedResponseSchema>;
export type SbomIngestionSummary = z.infer<typeof sbomIngestionSummarySchema>;
export type SbomIngestionStatus = z.infer<typeof sbomIngestionStatusSchema>;
export type SbomSummary = z.infer<typeof sbomSummarySchema>;
export type SbomDetail = z.infer<typeof sbomDetailSchema>;
export type SbomListResponse = z.infer<typeof sbomListResponseSchema>;
export type GraphCompletenessContract = z.infer<typeof graphCompletenessSchema>;
export type SupportedCycloneDxSpecificationVersion = z.infer<
  typeof supportedCycloneDxSpecificationVersionSchema
>;
export type SafeFailureCategoryContract = z.infer<typeof safeFailureCategorySchema>;
export type SafeFailureCodeContract = z.infer<typeof safeFailureCodeSchema>;
