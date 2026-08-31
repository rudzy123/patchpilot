import { createHash } from 'node:crypto';

import {
  SBOM_JSON_MAX_DEPTH_MAX,
  SBOM_JSON_MAX_DEPTH_MIN,
  SBOM_JSON_MAX_NODES_MAX,
  SBOM_JSON_MAX_NODES_MIN,
  SBOM_JSON_MAX_STRING_BYTES_MAX,
  SBOM_JSON_MAX_STRING_BYTES_MIN,
  SBOM_MAX_BOM_REF_BYTES_MAX,
  SBOM_MAX_BOM_REF_BYTES_MIN,
  SBOM_MAX_COMPONENTS_MAX,
  SBOM_MAX_COMPONENTS_MIN,
  SBOM_MAX_COMPONENT_NAME_CHARS_MAX,
  SBOM_MAX_COMPONENT_NAME_CHARS_MIN,
  SBOM_MAX_DEPENDENCY_EDGES_MAX,
  SBOM_MAX_DEPENDENCY_EDGES_MIN,
  SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MAX,
  SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MIN,
  SBOM_MAX_METADATA_TOOLS_MAX,
  SBOM_MAX_METADATA_TOOLS_MIN,
  SBOM_MAX_PROPERTIES_PER_COMPONENT_MAX,
  SBOM_MAX_PROPERTIES_PER_COMPONENT_MIN,
  SBOM_MAX_PURL_BYTES_MAX,
  SBOM_MAX_PURL_BYTES_MIN,
  SBOM_MAX_VERSION_CHARS_MAX,
  SBOM_MAX_VERSION_CHARS_MIN,
  SBOM_UPLOAD_MAX_BYTES_MAX,
  SBOM_UPLOAD_MAX_BYTES_MIN,
} from '@patchpilot/config';
import {
  SBOM_PARSER_RESULT_MAX_SERIALIZED_BYTES,
  SBOM_VERSION_LABEL_PATTERN,
  SHA256_HEX_PATTERN,
  componentIdentityStates,
  dependencyRelationshipTypes,
  err,
  graphCompletenessValues,
  isParserThreadFailureCode,
  ok,
  parseComponentVersion,
  parserThreadDisposition,
  parseWarningCodes,
  safeFailureCodes,
  sbomSpecificationVersions,
  validateNormalizedComponentGraph,
  type NormalizedComponent,
  type NormalizedComponentGraph,
  type Result,
  type SbomParserLimits,
} from '@patchpilot/domain';
import { z } from 'zod';

const utcTimestampSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/);
const sha256Schema = z.string().regex(SHA256_HEX_PATTERN);
const versionLabelSchema = z.string().min(1).max(64).regex(SBOM_VERSION_LABEL_PATTERN);

function intRange(min: number, max: number) {
  return z.number().int().min(min).max(max);
}

export const parserLimitsSchema = z.strictObject({
  maxBytes: intRange(SBOM_UPLOAD_MAX_BYTES_MIN, SBOM_UPLOAD_MAX_BYTES_MAX),
  jsonMaxDepth: intRange(SBOM_JSON_MAX_DEPTH_MIN, SBOM_JSON_MAX_DEPTH_MAX),
  jsonMaxNodes: intRange(SBOM_JSON_MAX_NODES_MIN, SBOM_JSON_MAX_NODES_MAX),
  jsonMaxStringBytes: intRange(SBOM_JSON_MAX_STRING_BYTES_MIN, SBOM_JSON_MAX_STRING_BYTES_MAX),
  maxComponents: intRange(SBOM_MAX_COMPONENTS_MIN, SBOM_MAX_COMPONENTS_MAX),
  maxDependencyEdges: intRange(SBOM_MAX_DEPENDENCY_EDGES_MIN, SBOM_MAX_DEPENDENCY_EDGES_MAX),
  maxBomRefBytes: intRange(SBOM_MAX_BOM_REF_BYTES_MIN, SBOM_MAX_BOM_REF_BYTES_MAX),
  maxPurlBytes: intRange(SBOM_MAX_PURL_BYTES_MIN, SBOM_MAX_PURL_BYTES_MAX),
  maxComponentNameChars: intRange(
    SBOM_MAX_COMPONENT_NAME_CHARS_MIN,
    SBOM_MAX_COMPONENT_NAME_CHARS_MAX,
  ),
  maxVersionChars: intRange(SBOM_MAX_VERSION_CHARS_MIN, SBOM_MAX_VERSION_CHARS_MAX),
  maxMetadataTools: intRange(SBOM_MAX_METADATA_TOOLS_MIN, SBOM_MAX_METADATA_TOOLS_MAX),
  maxExternalRefsPerComponent: intRange(
    SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MIN,
    SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MAX,
  ),
  maxPropertiesPerComponent: intRange(
    SBOM_MAX_PROPERTIES_PER_COMPONENT_MIN,
    SBOM_MAX_PROPERTIES_PER_COMPONENT_MAX,
  ),
});

export const parserWorkerRequestSchema = z.strictObject({
  requestId: z.uuid(),
  bytes: z.instanceof(ArrayBuffer),
  expectedSha256: sha256Schema,
  byteLength: z.number().int().positive(),
  limits: parserLimitsSchema,
  parserVersion: versionLabelSchema,
  normalizationVersion: versionLabelSchema,
});

const componentVersionSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('known'),
    value: z.string().min(1),
  }),
  z.strictObject({
    kind: z.literal('unknown'),
  }),
]);

const normalizedComponentSchema = z.strictObject({
  bomRef: z.string().min(1).nullable(),
  name: z.string().min(1),
  namespace: z.string().min(1).nullable(),
  ecosystem: z.string().min(1).nullable(),
  identityState: z.enum(componentIdentityStates),
  versionlessPurl: z.string().min(1).nullable(),
  versionedPurl: z.string().min(1).nullable(),
  version: componentVersionSchema,
  isDirect: z.boolean().nullable(),
  identityKey: z.string().min(1),
});

const normalizedEdgeSchema = z.strictObject({
  fromBomRef: z.string().min(1),
  toBomRef: z.string().min(1),
  relationshipType: z.enum(dependencyRelationshipTypes),
});

const warningSummarySchema = z.strictObject({
  code: z.enum(parseWarningCodes),
  count: z.number().int().positive(),
});

export const parserWorkerSuccessSchema = z.strictObject({
  ok: z.literal(true),
  specificationVersion: z.enum(sbomSpecificationVersions),
  graphCompleteness: z.enum(graphCompletenessValues),
  components: z.array(normalizedComponentSchema),
  edges: z.array(normalizedEdgeSchema),
  warnings: z.array(warningSummarySchema),
  stats: z.strictObject({
    componentCount: z.number().int().nonnegative(),
    dependencyEdgeCount: z.number().int().nonnegative(),
    warningCount: z.number().int().nonnegative(),
  }),
  capturedAt: utcTimestampSchema.nullable(),
  parserVersion: versionLabelSchema,
  normalizationVersion: versionLabelSchema,
});

export const parserWorkerFailureSchema = z.strictObject({
  ok: z.literal(false),
  disposition: z.enum(['rejected', 'quarantined']),
  code: z.enum(safeFailureCodes),
});

export type ParserWorkerRequest = z.infer<typeof parserWorkerRequestSchema>;
export type ParserWorkerSuccess = z.infer<typeof parserWorkerSuccessSchema>;
export type ParserWorkerFailure = z.infer<typeof parserWorkerFailureSchema>;

export type ParserThreadMessage = ParserWorkerSuccess | ParserWorkerFailure;

function sha256Hex(bytes: ArrayBuffer): string {
  return createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}

function serializedSize(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

export function validateParserWorkerRequest(value: unknown): Result<ParserWorkerRequest> {
  const parsed = parserWorkerRequestSchema.safeParse(value);
  if (!parsed.success) {
    return err({ code: 'validation', message: 'Parser worker request is not valid.' });
  }

  const request = parsed.data;
  if (request.byteLength !== request.bytes.byteLength) {
    return err({
      code: 'validation',
      message: 'Parser worker byte length must match the transferable buffer.',
    });
  }
  if (request.byteLength > request.limits.maxBytes) {
    return err({
      code: 'unprocessable_evidence',
      message: 'Parser worker buffer exceeds the typed byte limit.',
    });
  }
  if (sha256Hex(request.bytes) !== request.expectedSha256) {
    return err({
      code: 'unprocessable_evidence',
      message: 'Parser worker buffer does not match the expected SHA-256.',
    });
  }

  return ok(request);
}

export function validateParserWorkerSuccess(
  value: unknown,
  limits: SbomParserLimits,
  maxSerializedBytes: number = SBOM_PARSER_RESULT_MAX_SERIALIZED_BYTES,
): Result<ParserWorkerSuccess> {
  const parsed = parserWorkerSuccessSchema.safeParse(value);
  if (!parsed.success) {
    return err({ code: 'validation', message: 'Parser worker success is not valid.' });
  }

  const success = parsed.data;
  if (serializedSize(success) > maxSerializedBytes) {
    return err({
      code: 'unprocessable_evidence',
      message: 'Parser worker success exceeds the serialized size ceiling.',
    });
  }

  if (success.components.length > limits.maxComponents) {
    return err({
      code: 'unprocessable_evidence',
      message: 'Parser worker success exceeds the component limit.',
    });
  }
  if (success.edges.length > limits.maxDependencyEdges) {
    return err({
      code: 'unprocessable_evidence',
      message: 'Parser worker success exceeds the dependency edge limit.',
    });
  }
  if (success.warnings.length > parseWarningCodes.length) {
    return err({
      code: 'unprocessable_evidence',
      message: 'Parser worker success exceeds the warning summary bound.',
    });
  }

  if (
    success.stats.componentCount !== success.components.length ||
    success.stats.dependencyEdgeCount !== success.edges.length
  ) {
    return err({
      code: 'validation',
      message: 'Parser worker stats must match component and edge array lengths.',
    });
  }

  const graph = parserSuccessToNormalizedGraph(success);
  if (!graph.ok) {
    return graph;
  }

  if (success.components.some((component) => component.name.length > limits.maxComponentNameChars)) {
    return err({
      code: 'unprocessable_evidence',
      message: 'Parser worker component name exceeds the typed limit.',
    });
  }
  for (const component of success.components) {
    if (
      component.bomRef !== null &&
      Buffer.byteLength(component.bomRef, 'utf8') > limits.maxBomRefBytes
    ) {
      return err({
        code: 'unprocessable_evidence',
        message: 'Parser worker bom-ref exceeds the typed limit.',
      });
    }
    if (
      component.versionlessPurl !== null &&
      Buffer.byteLength(component.versionlessPurl, 'utf8') > limits.maxPurlBytes
    ) {
      return err({
        code: 'unprocessable_evidence',
        message: 'Parser worker versionless PURL exceeds the typed limit.',
      });
    }
    if (
      component.versionedPurl !== null &&
      Buffer.byteLength(component.versionedPurl, 'utf8') > limits.maxPurlBytes
    ) {
      return err({
        code: 'unprocessable_evidence',
        message: 'Parser worker versioned PURL exceeds the typed limit.',
      });
    }
    if (
      component.version.kind === 'known' &&
      component.version.value.length > limits.maxVersionChars
    ) {
      return err({
        code: 'unprocessable_evidence',
        message: 'Parser worker version exceeds the typed limit.',
      });
    }
  }

  const validated = validateNormalizedComponentGraph(graph.value);
  if (!validated.ok) {
    return validated;
  }

  return ok(success);
}

export function parserSuccessToNormalizedGraph(
  success: ParserWorkerSuccess,
): Result<NormalizedComponentGraph> {
  const components: NormalizedComponent[] = [];
  for (const component of success.components) {
    const version = parseComponentVersion(component.version);
    if (!version.ok) {
      return version;
    }
    components.push({ ...component, version: version.value });
  }

  return ok({
    specificationVersion: success.specificationVersion,
    graphCompleteness: success.graphCompleteness,
    components,
    edges: success.edges,
    warnings: success.warnings,
    componentCount: success.stats.componentCount,
    dependencyEdgeCount: success.stats.dependencyEdgeCount,
    warningCount: success.stats.warningCount,
    capturedAt: success.capturedAt === null ? null : new Date(success.capturedAt),
    parserVersion: success.parserVersion,
    normalizationVersion: success.normalizationVersion,
  });
}

export function validateParserWorkerFailure(value: unknown): Result<ParserWorkerFailure> {
  const parsed = parserWorkerFailureSchema.safeParse(value);
  if (!parsed.success) {
    return err({ code: 'validation', message: 'Parser worker failure is not valid.' });
  }

  const failure = parsed.data;
  if (!isParserThreadFailureCode(failure.code)) {
    return err({
      code: 'validation',
      message: 'Parser worker failure codes must be rejected or quarantined outcomes.',
    });
  }

  const disposition = parserThreadDisposition(failure.code);
  if (disposition === undefined || disposition !== failure.disposition) {
    return err({
      code: 'validation',
      message: 'Parser worker failure disposition must match the safe-code catalog.',
    });
  }

  return ok(failure);
}

export function hashParserWorkerBytes(bytes: ArrayBuffer): string {
  return sha256Hex(bytes);
}
