import { SBOM_PARSER_RESULT_MAX_SERIALIZED_BYTES } from '@patchpilot/domain';

import { inspectJsonStructure, isPrototypePollutionParseError } from './json-structure.js';
import { normalizeCycloneDxDocument, parserFailure } from './normalize-cyclonedx.js';
import {
  validateParserWorkerRequest,
  validateParserWorkerSuccess,
  type ParserThreadMessage,
  type ParserWorkerRequest,
} from './parser-thread.js';
import { validateCycloneDxDocument } from './schema-registry.js';
import { parseUntrustedJson } from './untrusted-json.js';

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function requestFailure(request: ParserWorkerRequest): ParserThreadMessage | undefined {
  if (request.byteLength !== request.bytes.byteLength) {
    return parserFailure('hash_mismatch');
  }
  if (request.byteLength > request.limits.maxBytes) {
    return parserFailure('payload_too_large');
  }
  return undefined;
}

function notCycloneDx(document: unknown): boolean {
  if (typeof document !== 'object' || document === null || Array.isArray(document)) {
    return true;
  }
  return (document as Record<string, unknown>)['bomFormat'] !== 'CycloneDX';
}

export function parseSbomParserRequest(request: ParserWorkerRequest): ParserThreadMessage {
  const preflight = requestFailure(request);
  if (preflight !== undefined) {
    return preflight;
  }

  let text: string;
  try {
    text = UTF8_DECODER.decode(request.bytes);
  } catch {
    return parserFailure('utf8');
  }

  let document: unknown;
  try {
    document = parseUntrustedJson(text);
  } catch (error) {
    if (isPrototypePollutionParseError(error)) {
      return parserFailure('prototype_pollution');
    }
    return parserFailure('json_syntax');
  }

  const structure = inspectJsonStructure(document, request.limits);
  if (!structure.ok) {
    return parserFailure(structure.code);
  }

  if (notCycloneDx(document)) {
    return parserFailure('not_cyclonedx');
  }

  const schema = validateCycloneDxDocument(document);
  if (!schema.ok) {
    return parserFailure(schema.reason);
  }

  const normalized = normalizeCycloneDxDocument(
    document,
    request.limits,
    request.parserVersion,
    request.normalizationVersion,
    schema.specVersion,
  );
  if (!normalized.ok) {
    return normalized;
  }

  const bounded = validateParserWorkerSuccess(
    normalized,
    request.limits,
    SBOM_PARSER_RESULT_MAX_SERIALIZED_BYTES,
  );
  if (!bounded.ok) {
    if (bounded.error.code === 'unprocessable_evidence') {
      return parserFailure('normalized_output_too_large');
    }
    return parserFailure('schema_invalid');
  }

  return bounded.value;
}

export function handleParserWorkerMessage(message: unknown): ParserThreadMessage {
  const request = validateParserWorkerRequest(message);
  if (!request.ok) {
    if (request.error.code === 'unprocessable_evidence') {
      if (request.error.message.includes('SHA-256')) {
        return parserFailure('hash_mismatch');
      }
      return parserFailure('payload_too_large');
    }
    return parserFailure('parser_crash');
  }

  return parseSbomParserRequest(request.value);
}
