import { randomUUID } from 'node:crypto';

import {
  validateNormalizedComponentGraph,
  type SbomDocumentParserPort,
  type SbomDocumentParseResult,
} from '@patchpilot/domain';

import {
  parserSuccessToNormalizedGraph,
  type ParserThreadMessage,
  type ParserWorkerRequest,
} from './parser-thread.js';
import { runParserInWorkerThread, type RunParserThreadOptions } from './run-parser-thread.js';

export type WorkerThreadSbomParserOptions = {
  timeoutMs: number;
  workerModuleUrl?: URL;
  createRequestId?: () => string;
};

export function parserThreadMessageToParseResult(
  message: ParserThreadMessage,
): SbomDocumentParseResult {
  if (!message.ok) {
    return { ok: false, code: message.code };
  }
  const graph = parserSuccessToNormalizedGraph(message);
  if (!graph.ok) {
    return { ok: false, code: 'parser_crash' };
  }
  const validated = validateNormalizedComponentGraph(graph.value);
  if (!validated.ok) {
    return { ok: false, code: 'parser_crash' };
  }
  return { ok: true, graph: validated.value };
}

export function createWorkerThreadSbomParser(
  options: WorkerThreadSbomParserOptions,
): SbomDocumentParserPort {
  const createRequestId = options.createRequestId ?? randomUUID;
  const threadOptions: RunParserThreadOptions = {
    timeoutMs: options.timeoutMs,
    ...(options.workerModuleUrl === undefined ? {} : { workerModuleUrl: options.workerModuleUrl }),
  };

  return {
    async parse(input) {
      const request: ParserWorkerRequest = {
        requestId: createRequestId(),
        bytes: input.bytes.slice(0),
        expectedSha256: input.expectedSha256,
        byteLength: input.byteLength,
        limits: input.limits,
        parserVersion: input.parserVersion,
        normalizationVersion: input.normalizationVersion,
      };
      const message = await runParserInWorkerThread(request, threadOptions);
      return parserThreadMessageToParseResult(message);
    },
  };
}
