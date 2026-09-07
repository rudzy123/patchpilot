/**
 * Local scripted HTTPS/DNS doubles for Session 12 Batch 1 listing tests.
 * Never contacts storage.googleapis.com or any external provider.
 */

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { inspect } from 'node:util';

import { expect } from 'vitest';

import {
  OSV_LISTING_PAGE_SIZE_POLICY,
  OSV_TRANSPORT_POLICY_VERSION,
  createOsvListingContinuationToken,
  createOsvListingRequest,
  type OsvListingRequest,
} from '@patchpilot/vulnerability-intelligence';

import {
  createOsvGcsListingHttpsAdapterForTests,
  type OsvGcsListingDnsLookup,
  type OsvGcsListingHttpsRequest,
  type OsvGcsListingLogger,
  type OsvGcsListingParsePage,
} from './osv-gcs-listing-https-adapter.js';

export const PUBLIC_V4 = '1.1.1.1';
export const SECRET_TOKEN = 'SECRET_PAGE_TOKEN_MARKER_9f3a/with space%2F';

export type ScriptedListingResponse = {
  statusCode?: number;
  headers?: Record<string, string | string[] | undefined>;
  body?: Buffer | Readable | Buffer[];
  delayMs?: number;
  omitResponse?: boolean;
  omitSecureConnect?: boolean;
  omitSocket?: boolean;
  remoteAddress?: string;
  omitRemoteAddress?: boolean;
  remoteFamily?: string;
  closeEarly?: boolean;
  neverEnd?: boolean;
  emitRequestError?: NodeJS.ErrnoException;
  emitSocketError?: Error;
  emitResponseError?: Error;
  abortResponse?: boolean;
  closeAfterData?: boolean;
  duplicateEnd?: boolean;
  dataAfterEnd?: Buffer;
  objectModeChunk?: unknown;
};

export function listingJson(overrides: Record<string, unknown> = {}): Buffer {
  const page = {
    kind: 'storage#objects',
    items: [
      {
        name: 'npm/GHSA-abcd-1234-wxyz.json',
        generation: '1234567890',
        metageneration: '1',
        size: '2048',
        etag: 'CPjhgpqR0/kCEAE=',
        md5Hash: '1B2M2Y8AsgTpgAmY7PhCfg==',
        contentType: 'application/json',
        updated: '2024-01-02T03:04:05.678Z',
      },
    ],
    ...overrides,
  };
  return Buffer.from(JSON.stringify(page), 'utf8');
}

export const MINIMAL_PAGE = listingJson();

export function jsonHeaders(
  body: Buffer,
  extra: Record<string, string | string[] | undefined> = {},
): Record<string, string | string[] | undefined> {
  return {
    'content-type': 'application/json',
    'content-length': String(body.byteLength),
    ...extra,
  };
}

export function listingInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    providerPrefix: 'npm/',
    pageSizePolicy: OSV_LISTING_PAGE_SIZE_POLICY,
    transportPolicyVersion: OSV_TRANSPORT_POLICY_VERSION,
    ...overrides,
  };
}

export function validListingRequest(overrides: Record<string, unknown> = {}): OsvListingRequest {
  const created = createOsvListingRequest(listingInput(overrides));
  if (!created.ok) {
    throw new Error(created.code);
  }
  return created.value;
}

export function continuationRequest(raw: string = SECRET_TOKEN): OsvListingRequest {
  const token = createOsvListingContinuationToken(raw);
  if (!token.ok) {
    throw new Error(token.code);
  }
  return validListingRequest({ continuationToken: token.value });
}

export function createListingTestContext(): {
  recordedOptions: unknown[];
  lookupHosts: string[];
  lookupCalls: number;
  remainingResponses: ScriptedListingResponse[];
  lastDestroyed: { request: boolean; response: boolean };
  setLookup: (impl: OsvGcsListingDnsLookup) => void;
  setResponses: (scripts: readonly ScriptedListingResponse[]) => void;
  lookup: OsvGcsListingDnsLookup;
  request: OsvGcsListingHttpsRequest;
  adapter: (extras?: {
    logger?: OsvGcsListingLogger;
    parseListingPage?: OsvGcsListingParsePage;
  }) => ReturnType<typeof createOsvGcsListingHttpsAdapterForTests>;
  reset: () => void;
} {
  const recordedOptions: unknown[] = [];
  const lookupHosts: string[] = [];
  const remainingResponses: ScriptedListingResponse[] = [];
  const lastDestroyed = { request: false, response: false };
  let lookupCalls = 0;
  let lookupImpl: OsvGcsListingDnsLookup = (_hostname, _options, callback) => {
    callback(null, [{ address: PUBLIC_V4, family: 4 }]);
  };

  const lookup: OsvGcsListingDnsLookup = (hostname, options, callback) => {
    lookupHosts.push(hostname);
    lookupCalls += 1;
    lookupImpl(hostname, options, callback);
  };

  const request: OsvGcsListingHttpsRequest = (options, callback) => {
    recordedOptions.push(options);
    const req = new EventEmitter() as ReturnType<OsvGcsListingHttpsRequest>;
    let destroyed = false;
    (req as { destroy: () => void }).destroy = () => {
      destroyed = true;
      lastDestroyed.request = true;
    };
    (req as { end: () => void }).end = () => {
      const script = remainingResponses.shift() ?? {
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
      };

      const emitSocket = (): EventEmitter | undefined => {
        if (destroyed || script.omitSocket === true) {
          return undefined;
        }
        const socket = new EventEmitter();
        Object.defineProperty(socket, 'remoteAddress', {
          value:
            script.omitRemoteAddress === true ? undefined : (script.remoteAddress ?? PUBLIC_V4),
        });
        Object.defineProperty(socket, 'remoteFamily', {
          value: script.remoteFamily ?? 'IPv4',
        });
        req.emit('socket', socket);
        if (script.emitSocketError !== undefined) {
          socket.emit('error', script.emitSocketError);
        }
        if (script.omitSecureConnect !== true) {
          socket.emit('secureConnect');
        }
        return socket;
      };

      const emitResponse = (): void => {
        if (destroyed || callback === undefined || script.omitResponse === true) {
          return;
        }
        const payload = script.body ?? MINIMAL_PAGE;
        let response: Readable;
        if (script.objectModeChunk !== undefined) {
          const value = script.objectModeChunk;
          response = new Readable({
            objectMode: true,
            read() {
              this.push(value);
              this.push(null);
            },
          });
        } else if (payload instanceof Readable) {
          response = payload;
        } else if (Array.isArray(payload)) {
          response = new Readable({
            read() {
              const next = payload.shift();
              if (next === undefined) {
                if (script.neverEnd === true) {
                  return;
                }
                this.push(null);
                return;
              }
              this.push(next);
            },
          });
        } else {
          response = Readable.from([payload], { objectMode: false });
        }
        if (script.neverEnd === true && !Array.isArray(payload) && !(payload instanceof Readable)) {
          const bytes = payload;
          let pushed = false;
          response = new Readable({
            read() {
              if (pushed) {
                return;
              }
              pushed = true;
              this.push(bytes);
            },
          });
        }
        Object.assign(response, {
          statusCode: script.statusCode ?? 200,
          headers: script.headers ?? jsonHeaders(MINIMAL_PAGE),
        });
        const originalDestroy = response.destroy.bind(response);
        response.destroy = ((error?: Error) => {
          lastDestroyed.response = true;
          return originalDestroy(error);
        }) as typeof response.destroy;
        if (script.closeEarly === true) {
          callback(response as never);
          response.destroy();
          return;
        }
        if (script.duplicateEnd === true || script.dataAfterEnd !== undefined) {
          response.once('end', () => {
            if (script.duplicateEnd === true) {
              queueMicrotask(() => {
                response.emit('end');
              });
            }
            if (script.dataAfterEnd !== undefined) {
              queueMicrotask(() => {
                response.emit('data', script.dataAfterEnd);
              });
            }
          });
        }
        callback(response as never);
        if (script.emitResponseError !== undefined) {
          response.emit('error', script.emitResponseError);
        }
        if (script.abortResponse === true) {
          response.emit('aborted');
        }
        if (script.closeAfterData === true) {
          queueMicrotask(() => {
            response.emit('close');
          });
        }
      };

      const emit = (): void => {
        emitSocket();
        if (script.emitRequestError !== undefined) {
          req.emit('error', script.emitRequestError);
          return;
        }
        emitResponse();
      };

      if (script.delayMs !== undefined && script.delayMs > 0) {
        setTimeout(emit, script.delayMs);
        return;
      }
      queueMicrotask(emit);
    };
    return req;
  };

  return {
    recordedOptions,
    lookupHosts,
    get lookupCalls() {
      return lookupCalls;
    },
    remainingResponses,
    lastDestroyed,
    setLookup: (impl) => {
      lookupImpl = impl;
    },
    setResponses: (scripts) => {
      remainingResponses.length = 0;
      remainingResponses.push(...scripts);
    },
    lookup,
    request,
    adapter: (extras = {}) =>
      createOsvGcsListingHttpsAdapterForTests({
        lookup,
        request,
        ...extras,
      }),
    reset: () => {
      recordedOptions.length = 0;
      lookupHosts.length = 0;
      lookupCalls = 0;
      remainingResponses.length = 0;
      lastDestroyed.request = false;
      lastDestroyed.response = false;
      lookupImpl = (_hostname, _options, callback) => {
        callback(null, [{ address: PUBLIC_V4, family: 4 }]);
      };
    },
  };
}

export function assertConfidential(
  value: unknown,
  secrets: readonly string[] = [SECRET_TOKEN],
): void {
  const text = `${JSON.stringify(value)}\n${inspect(value)}\n${String(value)}`;
  for (const secret of secrets) {
    expect(text).not.toContain(secret);
  }
  expect(text).not.toContain('https://storage.googleapis.com');
  expect(text).not.toContain('pageToken=');
  expect(text).not.toContain('Location');
  expect(text).not.toContain('organizationId');
  expect(text).not.toContain('tenantId');
  expect(text).not.toContain('findingId');
  expect(text).not.toContain('stack');
}
