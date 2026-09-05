/**
 * Session 11 Batch 6A generation-bound OSV provider-object HTTPS retrieval
 * adapter. One attempt. No retries. No redirects. No storage. No parser.
 *
 * Reuses the committed CISA KEV `node:https.request` capability: pinned
 * public-address lookup, post-connect verification, identity encoding,
 * redirect non-follow, and no proxy. Timeouts are the exact Batch 6A-P
 * phase constants. Callers cannot override host, scheme, path, headers,
 * TLS, redirects, or retry behavior.
 *
 * Tests inject lookup and request privately. Production compiles
 * storage.googleapis.com only. Importing this module does not contact GCS.
 */

import { createHash } from 'node:crypto';
import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import https from 'node:https';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';

import {
  OSV_GCS_OBJECTS_GET_MEDIA_HOST,
  OSV_GENERATION_BOUND_RETRIEVAL_POLICY_IDENTIFIER,
  OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES,
  OSV_REQUEST_HEADERS_POLICY,
  OSV_TIMEOUT_POLICY_V1,
  authorizeOsvGenerationBoundRetrieval,
  createOsvGenerationBoundRetrievalFailure,
  createOsvGenerationBoundValidatedRetrieval,
  isOsvGenerationBoundAuthorizedRetrievalAttempt,
  readOsvAuthorizedProviderObjectKey,
  readOsvGcsObjectsGetMediaRequestTarget,
  type OsvGenerationBoundRetrievalFailure,
  type OsvGenerationBoundRetrievalFailureKind,
  type OsvGenerationBoundRetrievalOutcome,
  type OsvGenerationBoundRetrievalPort,
} from '@patchpilot/vulnerability-intelligence';

import {
  pinnedAddressMatchesSocket,
  selectPinnedPublicAddress,
  type IntelligenceResolvedAddress,
} from './intelligence-address-policy.js';
import {
  isIdentityContentEncoding,
  parseApprovedJsonMediaType,
  parseDeclaredContentLength,
} from './intelligence-http-media-type.js';

const USER_AGENT = 'PatchPilot-intelligence/0.1';
const MAX_HEADER_SIZE = 8192;
const TLS_MIN_VERSION = 'TLSv1.2' as const;
const POSITIVE_DECIMAL_GENERATION = /^[1-9][0-9]{0,19}$/;

export type OsvRetrievalDnsLookup = (
  hostname: string,
  options: { all: true; verbatim: true },
  callback: (
    error: NodeJS.ErrnoException | null,
    addresses: Array<{ address: string; family: number }>,
  ) => void,
) => void;

export type OsvRetrievalHttpsRequest = (
  options: RequestOptions,
  callback?: (response: IncomingMessage) => void,
) => ReturnType<typeof https.request>;

export type OsvRetrievalLogger = {
  info: (bindings: Record<string, unknown>, message: string) => void;
  warn: (bindings: Record<string, unknown>, message: string) => void;
};

export type OsvGenerationBoundRetrievalHttpsDependencies = {
  lookup?: OsvRetrievalDnsLookup;
  request?: OsvRetrievalHttpsRequest;
  logger?: OsvRetrievalLogger;
};

const silentLogger: OsvRetrievalLogger = {
  info: () => undefined,
  warn: () => undefined,
};

function failure(kind: OsvGenerationBoundRetrievalFailureKind): OsvGenerationBoundRetrievalOutcome {
  return { ok: false, failure: createOsvGenerationBoundRetrievalFailure(kind) };
}

function headerAsString(value: string | string[] | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (Array.isArray(value)) {
    if (value.length !== 1) {
      return undefined;
    }
    return value[0];
  }
  return value;
}

function mapHttpStatus(status: number | undefined): OsvGenerationBoundRetrievalFailureKind | 'ok' {
  if (status === 200) {
    return 'ok';
  }
  if (status === 401) {
    return 'authentication_required';
  }
  if (status === 403) {
    return 'authorization_rejected';
  }
  if (status === 404) {
    return 'object_not_found';
  }
  if (status === 412) {
    return 'generation_not_found';
  }
  if (status === 408) {
    return 'http_408';
  }
  if (status === 429) {
    return 'http_429';
  }
  if (status === 500) {
    return 'http_500';
  }
  if (status === 502) {
    return 'http_502';
  }
  if (status === 503) {
    return 'service_unavailable';
  }
  if (status === 504) {
    return 'http_504';
  }
  if (status !== undefined && status >= 300 && status < 400) {
    return 'redirect_rejected';
  }
  return 'unexpected_http_status';
}

function readResponseGeneration(
  headers: IncomingMessage['headers'],
): { kind: 'missing' } | { kind: 'invalid' } | { kind: 'value'; generation: string } {
  const raw = headerAsString(headers['x-goog-generation']);
  if (raw === undefined || raw.trim().length === 0) {
    return { kind: 'missing' };
  }
  const trimmed = raw.trim();
  if (!POSITIVE_DECIMAL_GENERATION.test(trimmed)) {
    return { kind: 'invalid' };
  }
  return { kind: 'value', generation: trimmed };
}

function durationBucket(durationMs: number): string {
  if (durationMs < 100) {
    return '0_99';
  }
  if (durationMs < 1000) {
    return '100_999';
  }
  if (durationMs < 5000) {
    return '1000_4999';
  }
  if (durationMs < 30000) {
    return '5000_29999';
  }
  return '30000_plus';
}

function sizeBucket(bytes: number): string {
  if (bytes < 1024) {
    return '0_1023';
  }
  if (bytes < 65536) {
    return '1024_65535';
  }
  return '65536_1048576';
}

function safeEventBindings(input: {
  readonly operation: string;
  readonly phase: string;
  readonly retryability?: OsvGenerationBoundRetrievalFailure['retryability'];
  readonly statusClass?: string;
  readonly durationMs: number;
  readonly sizeBytes?: number;
  readonly providerObjectKeyDigest?: string;
  readonly publicCode?: string;
}): Record<string, unknown> {
  return {
    operation: input.operation,
    phase: input.phase,
    policyIdentifier: OSV_GENERATION_BOUND_RETRIEVAL_POLICY_IDENTIFIER,
    durationBucket: durationBucket(input.durationMs),
    ...(input.retryability === undefined ? {} : { retryability: input.retryability }),
    ...(input.statusClass === undefined ? {} : { statusClass: input.statusClass }),
    ...(input.sizeBytes === undefined ? {} : { sizeBucket: sizeBucket(input.sizeBytes) }),
    ...(input.providerObjectKeyDigest === undefined
      ? {}
      : { providerObjectKeyDigest: input.providerObjectKeyDigest }),
    ...(input.publicCode === undefined ? {} : { publicCode: input.publicCode }),
  };
}

function emitSafe(
  logger: OsvRetrievalLogger,
  level: 'info' | 'warn',
  bindings: Record<string, unknown>,
  message: string,
): void {
  try {
    logger[level](bindings, message);
  } catch {
    return;
  }
}

function completePinnedLookup(
  pinned: IntelligenceResolvedAddress,
  lookupOptions: LookupOptions | number | undefined,
  callback: (
    error: NodeJS.ErrnoException | null,
    address: string | LookupAddress[],
    family?: number,
  ) => void,
): void {
  const all =
    typeof lookupOptions === 'object' && lookupOptions !== null && lookupOptions.all === true;
  if (all) {
    callback(null, [{ address: pinned.address, family: pinned.family }]);
    return;
  }
  callback(null, pinned.address, pinned.family);
}

function createDirectHttpsAgent(): https.Agent {
  return new https.Agent({
    keepAlive: false,
    maxSockets: 1,
    proxyEnv: {},
    autoSelectFamily: false,
  });
}

function dnsErrorKind(
  _error: NodeJS.ErrnoException | null,
): OsvGenerationBoundRetrievalFailureKind {
  return 'temporary_dns_failure';
}

function remainingBudgetMs(startedAt: number, budgetMs: number): number {
  return Math.max(1, budgetMs - (Date.now() - startedAt));
}

function lookupPinned(
  lookup: OsvRetrievalDnsLookup,
  timeoutMs: number,
  signal: AbortSignal | undefined,
): Promise<OsvGenerationBoundRetrievalOutcome | IntelligenceResolvedAddress> {
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = (): void => {
      finish(failure('cancelled'));
    };
    const finish = (
      result: OsvGenerationBoundRetrievalOutcome | IntelligenceResolvedAddress,
    ): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      signal?.removeEventListener('abort', onAbort);
      resolve(result);
    };

    if (signal?.aborted === true) {
      finish(failure('cancelled'));
      return;
    }

    timer = setTimeout(() => {
      finish(failure('connection_timeout'));
    }, timeoutMs);

    signal?.addEventListener('abort', onAbort, { once: true });

    lookup(OSV_GCS_OBJECTS_GET_MEDIA_HOST, { all: true, verbatim: true }, (error, addresses) => {
      if (settled) {
        return;
      }
      if (error !== null) {
        finish(failure(dnsErrorKind(error)));
        return;
      }
      const resolved = addresses.flatMap((entry) => {
        if (entry.family === 4 || entry.family === 6) {
          return [{ address: entry.address, family: entry.family as 4 | 6 }];
        }
        return [];
      });
      const pinned = selectPinnedPublicAddress(resolved);
      if (pinned === undefined) {
        finish(failure('invalid_request'));
        return;
      }
      finish(pinned);
    });
  });
}

function consumeValidatedBody(input: {
  readonly request: ClientRequest;
  readonly response: IncomingMessage;
  readonly declaredSizeBytes: number;
  readonly maxBytes: number;
  readonly inactivityTimeoutMs: number;
  readonly remainingTotalMs: number;
  readonly callerAborted: () => boolean;
}): Promise<
  | {
      readonly ok: true;
      readonly bytes: Uint8Array;
      readonly sha256: string;
      readonly received: number;
    }
  | { readonly ok: false; readonly kind: OsvGenerationBoundRetrievalFailureKind }
> {
  return new Promise((resolve) => {
    let settled = false;
    let received = 0;
    let overflowed = false;
    const hasher = createHash('sha256');
    const buffer = new Uint8Array(input.declaredSizeBytes);
    let inactivityTimer: ReturnType<typeof setTimeout> | undefined;

    const finish = (
      result:
        | {
            readonly ok: true;
            readonly bytes: Uint8Array;
            readonly sha256: string;
            readonly received: number;
          }
        | { readonly ok: false; readonly kind: OsvGenerationBoundRetrievalFailureKind },
    ): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (inactivityTimer !== undefined) {
        clearTimeout(inactivityTimer);
      }
      clearTimeout(totalTimer);
      input.response.removeAllListeners();
      input.response.destroy();
      input.request.destroy();
      resolve(result);
    };

    const armInactivity = (): void => {
      if (inactivityTimer !== undefined) {
        clearTimeout(inactivityTimer);
      }
      inactivityTimer = setTimeout(() => {
        finish({ ok: false, kind: 'response_body_timeout' });
      }, input.inactivityTimeoutMs);
    };

    const totalTimer = setTimeout(
      () => {
        finish({
          ok: false,
          kind: input.callerAborted() ? 'cancelled' : 'total_deadline_exceeded',
        });
      },
      Math.max(1, input.remainingTotalMs),
    );

    const onData = (chunk: Buffer | Uint8Array): void => {
      if (settled) {
        return;
      }
      if (input.callerAborted()) {
        finish({ ok: false, kind: 'cancelled' });
        return;
      }
      const bytes = chunk instanceof Uint8Array ? chunk : Buffer.from(chunk);
      if (bytes.byteLength === 0) {
        armInactivity();
        return;
      }
      if (received > input.maxBytes - bytes.byteLength) {
        overflowed = true;
        finish({ ok: false, kind: 'response_too_large' });
        return;
      }
      if (received + bytes.byteLength > input.declaredSizeBytes) {
        finish({
          ok: false,
          kind:
            received + bytes.byteLength > input.maxBytes
              ? 'response_too_large'
              : 'declared_size_mismatch',
        });
        return;
      }
      hasher.update(bytes);
      buffer.set(bytes, received);
      received += bytes.byteLength;
      armInactivity();
    };

    input.response.on('data', onData);
    input.response.once('end', () => {
      if (settled) {
        return;
      }
      if (overflowed) {
        finish({ ok: false, kind: 'response_too_large' });
        return;
      }
      if (input.callerAborted()) {
        finish({ ok: false, kind: 'cancelled' });
        return;
      }
      if (received === 0 || received !== input.declaredSizeBytes) {
        finish({ ok: false, kind: 'declared_size_mismatch' });
        return;
      }
      let digest: string;
      try {
        digest = hasher.digest('hex');
      } catch {
        finish({ ok: false, kind: 'content_hash_failure' });
        return;
      }
      finish({ ok: true, bytes: buffer, sha256: digest, received });
    });
    input.response.once('error', () => {
      finish({
        ok: false,
        kind: input.callerAborted() ? 'cancelled' : 'partial_body',
      });
    });
    input.response.once('aborted', () => {
      finish({
        ok: false,
        kind: input.callerAborted() ? 'cancelled' : 'partial_body',
      });
    });
    input.response.once('close', () => {
      if (settled) {
        return;
      }
      finish({
        ok: false,
        kind: input.callerAborted() ? 'cancelled' : 'partial_body',
      });
    });

    armInactivity();
  });
}

export function createOsvGenerationBoundRetrievalHttpsAdapter(
  dependencies: OsvGenerationBoundRetrievalHttpsDependencies = {},
): OsvGenerationBoundRetrievalPort {
  const lookup =
    dependencies.lookup ??
    ((hostname, options, callback) => {
      dnsLookup(hostname, options, callback);
    });
  const requestFn = dependencies.request ?? https.request;
  const logger = dependencies.logger ?? silentLogger;

  return {
    async retrieveGenerationBoundObject(input) {
      const started = Date.now();
      const authorized = authorizeOsvGenerationBoundRetrieval(input);
      if (!authorized.ok) {
        emitSafe(
          logger,
          'warn',
          safeEventBindings({
            operation: 'osv_generation_bound_retrieve',
            phase: authorized.failure.phase,
            retryability: authorized.failure.retryability,
            durationMs: Date.now() - started,
            publicCode: authorized.failure.publicCode,
          }),
          'osv retrieval preflight failed',
        );
        return authorized;
      }
      const attempt = authorized.value;
      if (!isOsvGenerationBoundAuthorizedRetrievalAttempt(attempt)) {
        return failure('invalid_request');
      }
      if (attempt.signal?.aborted === true) {
        return failure('cancelled');
      }

      const target = readOsvGcsObjectsGetMediaRequestTarget(attempt.compiledRequest);
      if (!target.ok) {
        return target;
      }
      const providerKey = readOsvAuthorizedProviderObjectKey(attempt);
      if (!providerKey.ok) {
        return providerKey;
      }

      const dns = await lookupPinned(
        lookup,
        remainingBudgetMs(started, OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs),
        attempt.signal,
      );
      if ('ok' in dns) {
        return dns;
      }
      const pinned = dns;

      return await new Promise<OsvGenerationBoundRetrievalOutcome>((resolve) => {
        let settled = false;
        let ignoreRequestErrors = false;
        let pinVerified = false;
        let headersReceived = false;
        let connectTimer: ReturnType<typeof setTimeout> | undefined;
        let headerTimer: ReturnType<typeof setTimeout> | undefined;
        let totalTimer: ReturnType<typeof setTimeout> | undefined;
        let req: ReturnType<typeof https.request> | undefined;
        let abortHandler: (() => void) | undefined;
        const agent = createDirectHttpsAgent();

        const clearTimers = (): void => {
          if (connectTimer !== undefined) {
            clearTimeout(connectTimer);
            connectTimer = undefined;
          }
          if (headerTimer !== undefined) {
            clearTimeout(headerTimer);
            headerTimer = undefined;
          }
          if (totalTimer !== undefined) {
            clearTimeout(totalTimer);
            totalTimer = undefined;
          }
        };

        const destroyRequest = (): void => {
          ignoreRequestErrors = true;
          req?.destroy();
          agent.destroy();
        };

        const finish = (result: OsvGenerationBoundRetrievalOutcome): void => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimers();
          if (abortHandler !== undefined && attempt.signal !== undefined) {
            attempt.signal.removeEventListener('abort', abortHandler);
            abortHandler = undefined;
          }
          destroyRequest();
          if (result.ok) {
            emitSafe(
              logger,
              'info',
              safeEventBindings({
                operation: 'osv_generation_bound_retrieve',
                phase: 'response_validation',
                durationMs: Date.now() - started,
                sizeBytes: result.value.receivedSizeBytes,
                providerObjectKeyDigest: attempt.providerObjectKeyDigest,
              }),
              'osv retrieval ok',
            );
          } else {
            emitSafe(
              logger,
              'warn',
              safeEventBindings({
                operation: 'osv_generation_bound_retrieve',
                phase: result.failure.phase,
                retryability: result.failure.retryability,
                durationMs: Date.now() - started,
                providerObjectKeyDigest: attempt.providerObjectKeyDigest,
                publicCode: result.failure.publicCode,
              }),
              'osv retrieval failed',
            );
          }
          resolve(result);
        };

        const abortKind = (): OsvGenerationBoundRetrievalFailureKind => {
          if (attempt.signal?.aborted === true) {
            return 'cancelled';
          }
          if (!pinVerified) {
            return 'connection_timeout';
          }
          if (!headersReceived) {
            return 'response_header_timeout';
          }
          return 'total_deadline_exceeded';
        };

        if (attempt.signal?.aborted === true) {
          finish(failure('cancelled'));
          return;
        }

        connectTimer = setTimeout(
          () => {
            finish(failure(attempt.signal?.aborted === true ? 'cancelled' : 'connection_timeout'));
          },
          remainingBudgetMs(started, OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs),
        );

        totalTimer = setTimeout(
          () => {
            finish(failure(abortKind()));
          },
          remainingBudgetMs(started, OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs),
        );

        const compiledHeaders = OSV_REQUEST_HEADERS_POLICY.compiledHeaders;
        const options: RequestOptions = {
          method: target.value.method,
          hostname: target.value.hostname,
          port: target.value.port,
          path: target.value.pathWithQuery,
          servername: OSV_GCS_OBJECTS_GET_MEDIA_HOST,
          agent,
          rejectUnauthorized: true,
          minVersion: TLS_MIN_VERSION,
          maxHeaderSize: MAX_HEADER_SIZE,
          lookup: (_hostname, lookupOptions, callback) => {
            completePinnedLookup(pinned, lookupOptions, callback);
          },
          headers: {
            Host: OSV_GCS_OBJECTS_GET_MEDIA_HOST,
            Accept: compiledHeaders.Accept,
            'Accept-Encoding': compiledHeaders['Accept-Encoding'],
            'Cache-Control': compiledHeaders['Cache-Control'],
            'User-Agent': USER_AGENT,
            Connection: 'close',
          },
        };

        try {
          req = requestFn(options, (response) => {
            if (settled) {
              response.destroy();
              return;
            }
            if (!pinVerified) {
              response.destroy();
              finish(failure('invalid_request'));
              return;
            }
            headersReceived = true;
            if (connectTimer !== undefined) {
              clearTimeout(connectTimer);
              connectTimer = undefined;
            }
            if (headerTimer !== undefined) {
              clearTimeout(headerTimer);
              headerTimer = undefined;
            }

            const status = response.statusCode;
            const classified = mapHttpStatus(status);
            if (classified !== 'ok') {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure(classified));
              return;
            }

            if (headerAsString(response.headers.location) !== undefined) {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('malformed_response_metadata'));
              return;
            }

            const mediaType = parseApprovedJsonMediaType(response.headers['content-type']);
            if (mediaType === undefined) {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('invalid_content_type'));
              return;
            }

            if (!isIdentityContentEncoding(response.headers['content-encoding'])) {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('invalid_content_encoding'));
              return;
            }

            const declaredLength = parseDeclaredContentLength(response.headers['content-length']);
            if (declaredLength.kind === 'invalid') {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('malformed_content_length'));
              return;
            }
            if (
              declaredLength.kind === 'value' &&
              declaredLength.bytes > OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES
            ) {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('content_length_exceeds_policy'));
              return;
            }
            if (
              declaredLength.kind === 'value' &&
              declaredLength.bytes !== attempt.declaredSizeBytes
            ) {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('declared_size_mismatch'));
              return;
            }

            const generationHeader = readResponseGeneration(response.headers);
            if (generationHeader.kind === 'missing') {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('provider_generation_missing'));
              return;
            }
            if (generationHeader.kind === 'invalid') {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('malformed_response_metadata'));
              return;
            }
            if (generationHeader.generation !== attempt.generation) {
              ignoreRequestErrors = true;
              response.destroy();
              finish(failure('provider_generation_mismatch'));
              return;
            }

            const currentReq = req;
            if (currentReq === undefined) {
              response.destroy();
              finish(failure('invalid_request'));
              return;
            }

            const remainingTotal = Math.max(
              1,
              OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs - (Date.now() - started),
            );
            if (totalTimer !== undefined) {
              clearTimeout(totalTimer);
              totalTimer = undefined;
            }

            void consumeValidatedBody({
              request: currentReq,
              response,
              declaredSizeBytes: attempt.declaredSizeBytes,
              maxBytes: OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES,
              inactivityTimeoutMs: OSV_TIMEOUT_POLICY_V1.bodyInactivityTimeoutMs,
              remainingTotalMs: remainingTotal,
              callerAborted: () => attempt.signal?.aborted === true,
            }).then((body) => {
              if (settled) {
                return;
              }
              if (!body.ok) {
                finish(failure(body.kind));
                return;
              }
              if (attempt.signal?.aborted === true) {
                finish(failure('cancelled'));
                return;
              }
              finish(
                createOsvGenerationBoundValidatedRetrieval({
                  sourceIdentifier: attempt.sourceIdentifier,
                  providerObjectKeyDigest: attempt.providerObjectKeyDigest,
                  providerObjectKey: providerKey.value,
                  generation: attempt.generation,
                  declaredSizeBytes: attempt.declaredSizeBytes,
                  receivedSizeBytes: body.received,
                  sha256: body.sha256,
                  bytes: body.bytes,
                }),
              );
            });
          });
        } catch {
          finish(failure('invalid_request'));
          return;
        }

        req.on('socket', (socket) => {
          socket.on('error', () => {
            if (ignoreRequestErrors || settled) {
              return;
            }
            finish(
              failure(
                attempt.signal?.aborted === true
                  ? 'cancelled'
                  : headersReceived
                    ? 'partial_body'
                    : 'connection_reset',
              ),
            );
          });
          socket.once('secureConnect', () => {
            if (!pinnedAddressMatchesSocket(pinned, socket.remoteAddress, socket.remoteFamily)) {
              finish(failure('invalid_request'));
              return;
            }
            pinVerified = true;
            if (connectTimer !== undefined) {
              clearTimeout(connectTimer);
              connectTimer = undefined;
            }
            if (headerTimer === undefined && !headersReceived && !settled) {
              headerTimer = setTimeout(() => {
                finish(
                  failure(
                    attempt.signal?.aborted === true ? 'cancelled' : 'response_header_timeout',
                  ),
                );
              }, OSV_TIMEOUT_POLICY_V1.responseHeaderTimeoutMs);
            }
          });
        });

        req.on('error', (error: NodeJS.ErrnoException) => {
          if (ignoreRequestErrors || settled) {
            return;
          }
          if (attempt.signal?.aborted === true) {
            finish(failure('cancelled'));
            return;
          }
          const code = error.code;
          if (code === 'ECONNRESET' || code === 'EPIPE') {
            finish(failure(headersReceived ? 'partial_body' : 'connection_reset'));
            return;
          }
          if (code === 'ETIMEDOUT' || code === 'ECONNREFUSED') {
            finish(failure('connection_timeout'));
            return;
          }
          finish(failure(headersReceived ? 'partial_body' : 'connection_reset'));
        });

        if (attempt.signal !== undefined) {
          abortHandler = (): void => {
            finish(failure('cancelled'));
          };
          attempt.signal.addEventListener('abort', abortHandler, { once: true });
        }

        req.end();
      });
    },
  };
}

export function createOsvGenerationBoundRetrievalHttpsClient(): OsvGenerationBoundRetrievalPort {
  return createOsvGenerationBoundRetrievalHttpsAdapter();
}
