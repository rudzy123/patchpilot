import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { describe, expect, it, vi } from 'vitest';

import { defaultSbomParserLimits } from './parser-limits.js';
import {
  parserWorkerModuleUrl,
  resolveSiblingModuleUrl,
  runParserInWorkerThread,
} from './run-parser-thread.js';

const REQUEST_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

function bufferWithHash(text: string): { bytes: ArrayBuffer; sha256: string; byteLength: number } {
  const view = Uint8Array.from(Buffer.from(text, 'utf8'));
  const bytes = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  const sha256 = createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  return { bytes, sha256, byteLength: bytes.byteLength };
}

function requestFromText(text: string) {
  const payload = bufferWithHash(text);
  return {
    requestId: REQUEST_ID,
    bytes: payload.bytes,
    expectedSha256: payload.sha256,
    byteLength: payload.byteLength,
    limits: defaultSbomParserLimits(),
    parserVersion: '0.1.0',
    normalizationVersion: '1',
  };
}

describe('runParserInWorkerThread', () => {
  it('enforces the parser budget with worker.terminate, not Promise.race around parse', async () => {
    const hostSource = readFileSync(join(packageRoot, 'src', 'run-parser-thread.ts'), 'utf8');
    const parseSource = readFileSync(join(packageRoot, 'src', 'parse-document.ts'), 'utf8');
    expect(hostSource).toContain('worker.terminate(');
    expect(hostSource).not.toMatch(/Promise\.race\(/);
    expect(parseSource).not.toMatch(/Promise\.race\(/);
    expect(parseSource).not.toContain('worker_threads');

    const terminate = vi.spyOn(Worker.prototype, 'terminate');
    const result = await runParserInWorkerThread(requestFromText('{"bomFormat":"CycloneDX"}'), {
      timeoutMs: 150,
      workerModuleUrl: resolveSiblingModuleUrl(import.meta.url, 'hang-worker-thread'),
    });

    expect(terminate).toHaveBeenCalled();
    expect(result).toEqual({
      ok: false,
      disposition: 'quarantined',
      code: 'parser_timeout',
    });
    terminate.mockRestore();
  });

  it('parses a valid CycloneDX document in the worker thread', async () => {
    const fixture = readFileSync(join(packageRoot, 'src', 'fixtures', 'valid-1.6.json'), 'utf8');
    const result = await runParserInWorkerThread(requestFromText(fixture), {
      timeoutMs: 15_000,
      workerModuleUrl: parserWorkerModuleUrl(),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.specificationVersion).toBe('1.6');
      expect(result.graphCompleteness).toBe('no_dependencies');
    }
  });

  it('treats a worker exit without a message as parser_crash', async () => {
    const result = await runParserInWorkerThread(requestFromText('{"bomFormat":"CycloneDX"}'), {
      timeoutMs: 15_000,
      workerModuleUrl: resolveSiblingModuleUrl(
        import.meta.url,
        'exit-without-message-worker-thread',
      ),
    });

    expect(result).toEqual({
      ok: false,
      disposition: 'quarantined',
      code: 'parser_crash',
    });
  });
});
