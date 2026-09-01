import { createHash } from 'node:crypto';
import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import https from 'node:https';
import type { IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';

import { INTELLIGENCE_KEV_HOSTNAME, INTELLIGENCE_KEV_PATH } from '@patchpilot/config';
import {
  classifyIntelligenceSafeFailure,
  createSystemClock,
  type Clock,
  type IntelligenceProviderHttpFailure,
  type IntelligenceProviderHttpPort,
  type IntelligenceProviderHttpRequest,
  type IntelligenceProviderHttpResult,
  type IntelligenceSafeFailureCode,
} from '@patchpilot/domain';

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
import {
  clampRetryAfterMs,
  defaultIntelligenceRetryDelay,
  defaultIntelligenceRetryJitter,
  isIntelligenceHttpRetryable,
  resolveIntelligenceRetryDelayMs,
  type IntelligenceRetryDelay,
  type IntelligenceRetryJitter,
} from './intelligence-http-retry.js';
import { createIntelligenceHttpStream } from './intelligence-http-stream.js';

const USER_AGENT = 'PatchPilot-intelligence/0.1';
const MAX_HEADER_SIZE = 8192;
const TLS_MIN_VERSION = 'TLSv1.2' as const;

const TRANSIENT_DNS_CODES = new Set(['EAI_AGAIN', 'ETIMEDOUT', 'ECONNREFUSED', 'ESERVFAIL']);

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

export type IntelligenceDnsLookup = (
  hostname: string,
  options: { all: true; verbatim: true },
  callback: (
    error: NodeJS.ErrnoException | null,
    addresses: Array<{ address: string; family: number }>,
  ) => void,
) => void;

export type IntelligenceHttpsRequest = (
  options: RequestOptions,
  callback?: (response: IncomingMessage) => void,
) => ReturnType<typeof https.request>;

export type IntelligenceHttpLogger = {
  info: (bindings: Record<string, unknown>, message: string) => void;
  warn: (bindings: Record<string, unknown>, message: string) => void;
};

export type CisaKevHttpsTransportConfig = {
  connectTimeoutMs: number;
  totalTimeoutMs: number;
  maxBytes: number;
};

export type CisaKevHttpsTransportDependencies = {
  lookup?: IntelligenceDnsLookup;
  request?: IntelligenceHttpsRequest;
  clock?: Clock;
  delay?: IntelligenceRetryDelay;
  jitter?: IntelligenceRetryJitter;
  logger?: IntelligenceHttpLogger;
};

const silentLogger: IntelligenceHttpLogger = {
  info: () => undefined,
  warn: () => undefined,
};

function failure(
  code: IntelligenceSafeFailureCode,
  retryAfterMs?: number,
): IntelligenceProviderHttpFailure {
  const classified = classifyIntelligenceSafeFailure(code);
  return {
    kind: 'failure',
    category: classified.category,
    code,
    ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
  };
}

function headerAsString(value: string | string[] | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  return Array.isArray(value) ? value[0] : value;
}

function hashEtag(header: string | string[] | undefined): string | null {
  const raw = headerAsString(header);
  if (raw === undefined || raw.length === 0) {
    return null;
  }

  return createHash('sha256').update(raw).digest('hex');
}

function parseLastModified(header: string | string[] | undefined): Date | null {
  const raw = headerAsString(header);
  if (raw === undefined || raw.length === 0) {
    return null;
  }

  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) {
    return null;
  }

  return new Date(parsed);
}

function classifyHttpStatus(status: number | undefined): IntelligenceSafeFailureCode | 'ok' {
  if (status === 200) {
    return 'ok';
  }

  if (status === 304) {
    return 'provider_client_error';
  }

  if (status !== undefined && status >= 300 && status < 400) {
    return 'redirect_rejected';
  }

  if (status === 408) {
    return 'response_timeout';
  }

  if (status === 429) {
    return 'rate_limited';
  }

  if (status !== undefined && status >= 500 && status <= 599) {
    return 'provider_server_error';
  }

  return 'provider_client_error';
}

function dnsErrorCode(error: NodeJS.ErrnoException | null): IntelligenceSafeFailureCode {
  const code = error?.code;
  if (code !== undefined && TRANSIENT_DNS_CODES.has(code)) {
    return 'connection_timeout';
  }

  return 'dns_rejected';
}

function lookupAll(
  lookup: IntelligenceDnsLookup,
  timeoutMs: number,
  signal: AbortSignal,
  callerAborted: () => boolean,
): Promise<IntelligenceProviderHttpFailure | IntelligenceResolvedAddress> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (
      result: IntelligenceProviderHttpFailure | IntelligenceResolvedAddress,
    ): void => {
      if (settled) {
        return;
      }

      settled = true;
      resolve(result);
    };

    const onAbort = (): void => {
      finish(failure(callerAborted() ? 'request_cancelled' : 'connection_timeout'));
    };

    if (signal.aborted) {
      onAbort();
      return;
    }

    const timer = setTimeout(() => {
      finish(failure('connection_timeout'));
    }, timeoutMs);

    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        onAbort();
      },
      { once: true },
    );

    lookup(INTELLIGENCE_KEV_HOSTNAME, { all: true, verbatim: true }, (error, addresses) => {
      clearTimeout(timer);
      if (settled) {
        return;
      }

      if (error !== null) {
        finish(failure(dnsErrorCode(error)));
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
        finish(failure('dns_rejected'));
        return;
      }

      finish(pinned);
    });
  });
}

function safeBindings(
  operation: string,
  started: number,
  attempt: number,
  correlationId: string,
  code?: IntelligenceSafeFailureCode,
): Record<string, unknown> {
  return {
    operation,
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    durationMs: Math.max(0, Date.now() - started),
    attempt,
    correlationId,
    ...(code === undefined ? {} : { code }),
  };
}

export function createCisaKevHttpsTransport(
  config: CisaKevHttpsTransportConfig,
  dependencies: CisaKevHttpsTransportDependencies = {},
): IntelligenceProviderHttpPort {
  const lookup =
    dependencies.lookup ??
    ((hostname, options, callback) => {
      dnsLookup(hostname, options, callback);
    });
  const requestFn = dependencies.request ?? https.request;
  const clock = dependencies.clock ?? createSystemClock();
  const delayFn = dependencies.delay ?? defaultIntelligenceRetryDelay;
  const jitter = dependencies.jitter ?? defaultIntelligenceRetryJitter;
  const logger = dependencies.logger ?? silentLogger;

  const fetchOnce = async (
    input: IntelligenceProviderHttpRequest,
    attempt: number,
  ): Promise<IntelligenceProviderHttpResult> => {
    const started = Date.now();
    const connectTimeoutMs = Math.min(config.connectTimeoutMs, input.connectTimeoutMs);
    const totalTimeoutMs = Math.min(config.totalTimeoutMs, input.totalTimeoutMs);
    const maxBytes = Math.min(config.maxBytes, input.maxBytes);
    const caller = input.signal;
    if (caller?.aborted === true) {
      return failure('request_cancelled');
    }

    const attemptTimeout = AbortSignal.timeout(totalTimeoutMs);
    const connectTimeout = AbortSignal.timeout(connectTimeoutMs);
    const combined =
      caller === undefined
        ? AbortSignal.any([attemptTimeout, connectTimeout])
        : AbortSignal.any([caller, attemptTimeout, connectTimeout]);

    const dns = await lookupAll(lookup, connectTimeoutMs, combined, () => caller?.aborted === true);
    if ('kind' in dns) {
      logger.warn(
        safeBindings('dns_lookup', started, attempt, input.correlationId, dns.code),
        'kev http failed',
      );
      return dns;
    }

    const pinned = dns;
    return new Promise<IntelligenceProviderHttpResult>((resolve) => {
      let settled = false;
      let ignoreRequestErrors = false;
      let pinVerified = false;
      let firstByteTimer: ReturnType<typeof setTimeout> | undefined;
      let connectTimer: ReturnType<typeof setTimeout> | undefined;
      let totalTimer: ReturnType<typeof setTimeout> | undefined;
      let req: ReturnType<typeof https.request> | undefined;
      const agent = createDirectHttpsAgent();

      const destroyRequest = (): void => {
        ignoreRequestErrors = true;
        req?.destroy();
        agent.destroy();
      };

      const finish = (result: IntelligenceProviderHttpResult): void => {
        if (settled) {
          return;
        }

        settled = true;
        ignoreRequestErrors = true;
        if (connectTimer !== undefined) {
          clearTimeout(connectTimer);
        }

        if (firstByteTimer !== undefined) {
          clearTimeout(firstByteTimer);
        }

        if (result.kind === 'failure') {
          if (totalTimer !== undefined) {
            clearTimeout(totalTimer);
          }

          destroyRequest();
          logger.warn(
            safeBindings('fetch_catalog', started, attempt, input.correlationId, result.code),
            'kev http failed',
          );
        } else {
          logger.info(
            safeBindings('fetch_catalog', started, attempt, input.correlationId),
            'kev http ok',
          );
        }

        resolve(result);
      };

      const abortCode = (): IntelligenceSafeFailureCode => {
        if (caller?.aborted === true) {
          return 'request_cancelled';
        }

        if (connectTimeout.aborted && !attemptTimeout.aborted) {
          return 'connection_timeout';
        }

        return 'response_timeout';
      };

      connectTimer = setTimeout(() => {
        finish(failure(caller?.aborted === true ? 'request_cancelled' : 'connection_timeout'));
      }, connectTimeoutMs);

      totalTimer = setTimeout(() => {
        finish(failure(abortCode()));
      }, totalTimeoutMs);

      const options: RequestOptions = {
        method: 'GET',
        hostname: INTELLIGENCE_KEV_HOSTNAME,
        port: 443,
        path: INTELLIGENCE_KEV_PATH,
        servername: INTELLIGENCE_KEV_HOSTNAME,
        agent,
        rejectUnauthorized: true,
        minVersion: TLS_MIN_VERSION,
        maxHeaderSize: MAX_HEADER_SIZE,
        lookup: (_hostname, lookupOptions, callback) => {
          completePinnedLookup(pinned, lookupOptions, callback);
        },
        headers: {
          Host: INTELLIGENCE_KEV_HOSTNAME,
          Accept: 'application/json',
          'Accept-Encoding': 'identity',
          'User-Agent': USER_AGENT,
          Connection: 'close',
        },
      };

      try {
        req = requestFn(options, (response) => {
          if (!pinVerified) {
            ignoreRequestErrors = true;
            response.destroy();
            finish(failure('dns_rejected'));
            return;
          }

          if (connectTimer !== undefined) {
            clearTimeout(connectTimer);
            connectTimer = undefined;
          }

          if (firstByteTimer !== undefined) {
            clearTimeout(firstByteTimer);
            firstByteTimer = undefined;
          }

          const status = response.statusCode;
          const classified = classifyHttpStatus(status);
          if (classified !== 'ok') {
            const retryAfterHeader = response.headers['retry-after'];
            ignoreRequestErrors = true;
            response.destroy();
            if (classified === 'rate_limited') {
              const wait = resolveIntelligenceRetryDelayMs({
                ...(retryAfterHeader === undefined ? {} : { retryAfterHeader }),
                attempt,
                floorMs: input.retryPolicy.backoffFloorMs,
                ceilingMs: input.retryPolicy.backoffCeilingMs,
                now: clock.now(),
                jitter,
              });
              finish(
                failure(classified, clampRetryAfterMs(wait, input.retryPolicy.backoffCeilingMs)),
              );
              return;
            }

            finish(failure(classified));
            return;
          }

          const mediaType = parseApprovedJsonMediaType(response.headers['content-type']);
          if (mediaType === undefined) {
            ignoreRequestErrors = true;
            response.destroy();
            finish(failure('content_type_invalid'));
            return;
          }

          if (!isIdentityContentEncoding(response.headers['content-encoding'])) {
            ignoreRequestErrors = true;
            response.destroy();
            finish(failure('content_type_invalid'));
            return;
          }

          const declared = parseDeclaredContentLength(response.headers['content-length']);
          if (declared.kind === 'invalid') {
            ignoreRequestErrors = true;
            response.destroy();
            finish(failure('processing_failed'));
            return;
          }

          if (declared.kind === 'value' && declared.bytes === 0) {
            ignoreRequestErrors = true;
            response.destroy();
            finish(failure('response_empty'));
            return;
          }

          if (declared.kind === 'value' && declared.bytes > maxBytes) {
            ignoreRequestErrors = true;
            response.destroy();
            finish(failure('response_too_large'));
            return;
          }

          const currentReq = req;
          if (currentReq === undefined) {
            response.destroy();
            finish(failure('processing_failed'));
            return;
          }

          const stream = createIntelligenceHttpStream({
            request: currentReq,
            response,
            maxBytes,
            declaredByteLength: declared.kind === 'value' ? declared.bytes : null,
            callerAborted: () => caller?.aborted === true,
          });

          if (totalTimer !== undefined) {
            clearTimeout(totalTimer);
            totalTimer = undefined;
          }

          const remaining = Math.max(1, totalTimeoutMs - (Date.now() - started));
          totalTimer = setTimeout(() => {
            void stream.timeout();
          }, remaining);

          void stream.completion
            .finally(() => {
              if (totalTimer !== undefined) {
                clearTimeout(totalTimer);
              }
              agent.destroy();
            })
            .catch(() => undefined);

          finish({
            kind: 'response',
            status: 200,
            declaredContentType: mediaType,
            declaredByteLength: declared.kind === 'value' ? declared.bytes : null,
            etagHash: hashEtag(response.headers.etag),
            lastModified: parseLastModified(response.headers['last-modified']),
            body: stream.body,
            completion: stream.completion,
            cancel: stream.cancel,
          });
        });
      } catch {
        finish(failure('processing_failed'));
        return;
      }

      firstByteTimer = setTimeout(() => {
        finish(failure(caller?.aborted === true ? 'request_cancelled' : 'response_timeout'));
      }, connectTimeoutMs);

      req.on('socket', (socket) => {
        socket.on('error', () => {
          if (ignoreRequestErrors || settled) {
            return;
          }

          finish(failure(caller?.aborted === true ? 'request_cancelled' : 'connection_timeout'));
        });
        socket.once('secureConnect', () => {
          if (!pinnedAddressMatchesSocket(pinned, socket.remoteAddress, socket.remoteFamily)) {
            finish(failure('dns_rejected'));
            return;
          }

          pinVerified = true;
          if (connectTimer !== undefined) {
            clearTimeout(connectTimer);
            connectTimer = undefined;
          }
        });
      });

      req.on('error', (error: NodeJS.ErrnoException) => {
        if (ignoreRequestErrors || settled) {
          return;
        }
        const code = error.code;
        if (caller?.aborted === true) {
          finish(failure('request_cancelled'));
          return;
        }

        if (code === 'ETIMEDOUT') {
          finish(failure('connection_timeout'));
          return;
        }

        if (code === 'ECONNRESET' || code === 'EPIPE' || code === 'ECONNREFUSED') {
          finish(failure('connection_timeout'));
          return;
        }

        finish(failure('connection_timeout'));
      });

      if (caller !== undefined) {
        caller.addEventListener(
          'abort',
          () => {
            finish(failure('request_cancelled'));
          },
          { once: true },
        );
      }

      req.end();
    });
  };

  return {
    async fetchCatalog(request) {
      if (request.provider !== 'cisa_kev' || request.sourceIdentifier !== 'cisa_kev_json_catalog') {
        return failure('invalid_provider_source');
      }

      const maxRetries = Math.max(0, request.retryPolicy.maxRetries);
      let last: IntelligenceProviderHttpResult = failure('processing_failed');
      for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
        if (request.signal?.aborted === true) {
          return failure('request_cancelled');
        }

        last = await fetchOnce(request, attempt);
        if (
          last.kind !== 'failure' ||
          !isIntelligenceHttpRetryable(last.code) ||
          attempt === maxRetries
        ) {
          return last;
        }

        const waitMs =
          last.retryAfterMs ??
          resolveIntelligenceRetryDelayMs({
            attempt,
            floorMs: request.retryPolicy.backoffFloorMs,
            ceilingMs: request.retryPolicy.backoffCeilingMs,
            now: clock.now(),
            jitter,
          });
        try {
          await delayFn(waitMs, request.signal);
        } catch {
          return failure('request_cancelled');
        }
      }

      return last;
    },
  };
}

export function createCisaKevHttpsClient(
  config: CisaKevHttpsTransportConfig,
  logger?: IntelligenceHttpLogger,
): IntelligenceProviderHttpPort {
  return createCisaKevHttpsTransport(config, logger === undefined ? {} : { logger });
}
