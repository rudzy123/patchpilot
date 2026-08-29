/**
 * Offline CycloneDX JSON schema compilation and parser-thread DTOs.
 * Complete parsing, worker-thread isolation, semantic limits, and graph
 * persistence are deferred.
 */
export { packageBoundary } from './boundary.js';
export { createOfflineAjv } from './offline-ajv.js';
export {
  hashParserWorkerBytes,
  parserLimitsSchema,
  parserWorkerFailureSchema,
  parserWorkerRequestSchema,
  parserWorkerSuccessSchema,
  validateParserWorkerFailure,
  validateParserWorkerRequest,
  validateParserWorkerSuccess,
  type ParserThreadMessage,
  type ParserWorkerFailure,
  type ParserWorkerRequest,
  type ParserWorkerSuccess,
} from './parser-thread.js';
export { parsePackageUrl } from './purl.js';
export {
  ALLOWLISTED_CYCLONEDX_SPEC_VERSIONS,
  compileAllowlistedCycloneDxSchemas,
  readVendoredSchemaFile,
  selectAllowlistedSpecVersion,
  validateCycloneDxDocument,
  type AllowlistedCycloneDxSpecVersion,
  type CycloneDxSchemaValidation,
} from './schema-registry.js';
export { parseUntrustedJson } from './untrusted-json.js';
export { VENDOR_CYCLONEDX_JSON_SCHEMA_DIRECTORY } from './vendor-directory.js';
