import { existsSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';

import type { ParserThreadMessage, ParserWorkerRequest } from './parser-thread.js';
import { parserFailure } from './normalize-cyclonedx.js';
import { validateParserWorkerFailure, validateParserWorkerSuccess } from './parser-thread.js';

export type RunParserThreadOptions = {
  timeoutMs: number;
  workerModuleUrl?: URL;
};

export function resolveSiblingModuleUrl(metaUrl: string, baseName: string): URL {
  const directory = dirname(fileURLToPath(metaUrl));
  const tsCandidate = join(directory, `${baseName}.ts`);
  const jsCandidate = join(directory, `${baseName}.js`);
  if (metaUrl.endsWith('.ts') && existsSync(tsCandidate)) {
    return pathToFileURL(tsCandidate);
  }
  if (existsSync(jsCandidate)) {
    return pathToFileURL(jsCandidate);
  }
  if (existsSync(tsCandidate)) {
    return pathToFileURL(tsCandidate);
  }
  throw new Error(`Parser worker module ${baseName} was not found.`);
}

export function parserWorkerModuleUrl(): URL {
  const here = dirname(fileURLToPath(import.meta.url));
  const distDirectory = here.endsWith(`${sep}dist`) ? here : join(here, '..', 'dist');
  const distWorker = join(distDirectory, 'parser-worker-thread.js');
  if (!existsSync(distWorker)) {
    throw new Error('Parser worker thread is not built. Build @patchpilot/sbom first.');
  }
  return pathToFileURL(distWorker);
}

function asParserThreadMessage(
  value: unknown,
  limits: ParserWorkerRequest['limits'],
): ParserThreadMessage {
  if (typeof value === 'object' && value !== null && 'ok' in value && value.ok === true) {
    const success = validateParserWorkerSuccess(value, limits);
    if (success.ok) {
      return success.value;
    }
    return parserFailure('parser_crash');
  }

  const failure = validateParserWorkerFailure(value);
  if (failure.ok) {
    return failure.value;
  }
  return parserFailure('parser_crash');
}

/**
 * Run the CycloneDX parser in a worker thread. The wall-clock budget is enforced
 * by worker.terminate(), which preempts CPU-bound JSON.parse/Ajv work that a
 * timeout promise cannot cancel on the same isolate.
 */
export async function runParserInWorkerThread(
  request: ParserWorkerRequest,
  options: RunParserThreadOptions,
): Promise<ParserThreadMessage> {
  const worker = new Worker(options.workerModuleUrl ?? parserWorkerModuleUrl());

  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;

    const settle = (message: ParserThreadMessage): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve(message);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      void worker.terminate().then(() => {
        settle(parserFailure('parser_timeout'));
      });
    }, options.timeoutMs);

    worker.on('message', (value: unknown) => {
      settle(asParserThreadMessage(value, request.limits));
    });
    worker.on('error', () => {
      if (timedOut) {
        settle(parserFailure('parser_timeout'));
        return;
      }
      settle(parserFailure('parser_crash'));
    });
    worker.on('exit', (code) => {
      if (settled) {
        return;
      }
      if (timedOut) {
        settle(parserFailure('parser_timeout'));
        return;
      }
      if (code !== 0) {
        settle(parserFailure('parser_crash'));
      }
    });

    worker.postMessage(request, [request.bytes]);
  });
}
