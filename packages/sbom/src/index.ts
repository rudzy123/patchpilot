/**
 * Offline CycloneDX JSON schema compilation and worker-thread parser.
 * Graph persistence and ingest job processors remain deferred.
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
export { defaultSbomParserLimits } from './parser-limits.js';
export { handleParserWorkerMessage, parseSbomParserRequest } from './parse-document.js';
export {
  parserWorkerModuleUrl,
  runParserInWorkerThread,
  type RunParserThreadOptions,
} from './run-parser-thread.js';
export { inspectJsonStructure } from './json-structure.js';
export { normalizePackageUrl, parsePackageUrl, versionedPackageUrl } from './purl.js';
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
