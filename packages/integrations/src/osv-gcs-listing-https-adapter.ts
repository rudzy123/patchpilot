/**
 * Session 12 Batch 1 / ADR 0028 R2 GCS JSON Objects listing-page HTTPS adapter.
 * Session 12 Batch 2 adversarially hardens single-page transport: Location and
 * Transfer-Encoding fail closed, DNS answers are copied before pin selection,
 * non-byte body chunks are rejected, and socket listeners are one-shot with
 * cleanup. Exactly one HTTPS request per invocation. No pagination, retry,
 * redirect follow, body retrieval, persistence, storage, parser-worker,
 * activation, matching, or Finding path.
 *
 * Request grammar comes from the committed Batch 3C builder. Response pages
 * are handed to the committed Batch 3C parser. Transport failures use the
 * committed Batch 3B `OsvTransportFailure` catalog. Timeout phases reuse
 * `OSV_TIMEOUT_POLICY_V1` because listing-specific milliseconds were not
 * committed and that policy is the approved GCS HTTPS one-attempt, 1 MiB,
 * no-retry, four-phase bound for the same host and identity encoding.
 *
 * Production composition must not construct this adapter. Importing this
 * module does not contact storage.googleapis.com.
 */

import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import https from 'node:https';
import type { ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';

import {
  OSV_GCS_JSON_OBJECTS_LIST_HOST,
  OSV_GCS_JSON_OBJECTS_LIST_METHOD,
  OSV_GCS_LISTING_PAGE_MAX_BYTES,
  OSV_GCS_LISTING_PROTOCOL_VERSION,
  OSV_TIMEOUT_POLICY_V1,
  OSV_TRANSPORT_POLICY_VERSION,
  createOsvGcsListingRequest,
  createOsvListingRequest,
  createOsvTransportFailure,
  isOsvListingRequest,
  osvGcsListingRequestHref,
  parseOsvGcsListingPage,
  readOsvListingContinuationTokenForTransport,
  type OsvListingPage,
  type OsvListingRequest,
  type OsvTransportFailure,
  type OsvTransportFailureKind,
  type OsvTransportPort,
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
const HTTPS_PORT = 443 as const;

/**
 * ADR 0028 listing-page request-construction ceiling for continuation-token
 * UTF-8 bytes. This is not pagination or a change to
 * Batch 3B token constructors.
 */
const LISTING_CONTINUATION_TOKEN_MAX_UTF8_BYTES = 8192 as const;

export type OsvGcsListingHttpsOutcome =
  | { readonly ok: true; readonly page: OsvListingPage }
  | { readonly ok: false; readonly failure: OsvTransportFailure };

type ListingFailure = Extract<OsvGcsListingHttpsOutcome, { readonly ok: false }>;

export type OsvGcsListingDnsLookup = (
  hostname: string,
  options: { all: true; verbatim: true },
  callback: (
    error: NodeJS.ErrnoException | null,
    addresses: Array<{ address: string; family: number }>,
  ) => void,
) => void;

export type OsvGcsListingHttpsRequest = (
  options: RequestOptions,
  callback?: (response: IncomingMessage) => void,
) => ReturnType<typeof https.request>;

export type OsvGcsListingLogger = {
  info: (bindings: Record<string, unknown>, message: string) => void;
  warn: (bindings: Record<string, unknown>, message: string) => void;
};

export type OsvGcsListingParsePage = typeof parseOsvGcsListingPage;

export type OsvGcsListingHttpsTestDependencies = {
  lookup?: OsvGcsListingDnsLookup;
  request?: OsvGcsListingHttpsRequest;
  logger?: OsvGcsListingLogger;
  parseListingPage?: OsvGcsListingParsePage;
};

const silentLogger: OsvGcsListingLogger = {
  info: () => undefined,
  warn: () => undefined,
};

function failure(kind: OsvTransportFailureKind): ListingFailure {
  const created = createOsvTransportFailure({ kind });
  if (!created.ok) {
    const fallback = createOsvTransportFailure({ kind: 'malformed_response' });
    if (!fallback.ok) {
      throw new Error('transport failure catalog is inconsistent');
    }
    return { ok: false, failure: fallback.value };
  }
  return { ok: false, failure: created.value };
}

function responseLocationIsPresent(value: string | string[] | undefined): boolean {
  return value !== undefined;
}

function classifyListingTransferFraming(
  headers: IncomingMessage['headers'],
): OsvTransportFailureKind | 'ok' {
  const transfer = headers['transfer-encoding'];
  if (transfer === undefined) {
    return 'ok';
  }
  const values = Array.isArray(transfer) ? transfer : [transfer];
  if (values.length !== 1) {
    return 'malformed_response';
  }
  const raw = values[0];
  if (raw === undefined) {
    return 'malformed_response';
  }
  const normalized = raw.trim().toLowerCase();
  if (
    normalized.includes('gzip') ||
    normalized.includes('br') ||
    normalized.includes('deflate') ||
    normalized.includes('compress')
  ) {
    return 'invalid_content_encoding';
  }
  if (normalized !== 'chunked') {
    return 'malformed_response';
  }
  if (headers['content-length'] !== undefined) {
    return 'malformed_response';
  }
  return 'ok';
}

function mapHttpStatus(status: number | undefined): OsvTransportFailureKind | 'ok' {
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
    return 'http_503';
  }
  if (status === 504) {
    return 'http_504';
  }
  if (status !== undefined && status >= 300 && status < 400) {
    return 'redirect_rejected';
  }
  return 'malformed_response';
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

function observationBucket(count: number): string {
  if (count === 0) {
    return '0';
  }
  if (count <= 10) {
    return '1_10';
  }
  if (count <= 100) {
    return '11_100';
  }
  if (count <= 1000) {
    return '101_1000';
  }
  return '1000_plus';
}

function safeEventBindings(input: {
  readonly phase: string;
  readonly providerPrefix?: string;
  readonly retryability?: OsvTransportFailure['retryability'];
  readonly statusClass?: string;
  readonly durationMs: number;
  readonly sizeBytes?: number;
  readonly observationCount?: number;
  readonly publicCode?: string;
}): Record<string, unknown> {
  return {
    operation: 'osv_gcs_listing_list_page',
    phase: input.phase,
    policyIdentifier: OSV_TRANSPORT_POLICY_VERSION,
    listingProtocolVersion: OSV_GCS_LISTING_PROTOCOL_VERSION,
    durationBucket: durationBucket(input.durationMs),
    ...(input.providerPrefix === undefined ? {} : { providerPrefix: input.providerPrefix }),
    ...(input.retryability === undefined ? {} : { retryability: input.retryability }),
    ...(input.statusClass === undefined ? {} : { statusClass: input.statusClass }),
    ...(input.sizeBytes === undefined ? {} : { sizeBucket: sizeBucket(input.sizeBytes) }),
    ...(input.observationCount === undefined
      ? {}
      : { observationCountBucket: observationBucket(input.observationCount) }),
    ...(input.publicCode === undefined ? {} : { publicCode: input.publicCode }),
  };
}

function emitSafe(
  logger: OsvGcsListingLogger,
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

function remainingBudgetMs(startedAt: number, budgetMs: number): number {
  return Math.max(1, budgetMs - (Date.now() - startedAt));
}

function decodeFatalUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function resolveListingRequest(input: unknown): ListingFailure | OsvListingRequest {
  if (isOsvListingRequest(input)) {
    return input;
  }
  const created = createOsvListingRequest(input);
  if (!created.ok) {
    if (
      created.code === 'empty_continuation_token' ||
      created.code === 'invalid_continuation_token'
    ) {
      return failure('invalid_page_token');
    }
    return failure('policy_violation');
  }
  return created.value;
}

function enforceContinuationTokenBound(request: OsvListingRequest): ListingFailure | undefined {
  if (request.continuationToken === undefined) {
    return undefined;
  }
  const raw = readOsvListingContinuationTokenForTransport(request.continuationToken);
  if (!raw.ok) {
    return failure('invalid_page_token');
  }
  if (Buffer.byteLength(raw.value, 'utf8') > LISTING_CONTINUATION_TOKEN_MAX_UTF8_BYTES) {
    return failure('invalid_page_token');
  }
  return undefined;
}

function lookupPinned(
  lookup: OsvGcsListingDnsLookup,
  timeoutMs: number,
  signal: AbortSignal | undefined,
): Promise<OsvGcsListingHttpsOutcome | IntelligenceResolvedAddress> {
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = (): void => {
      finish(failure('cancelled'));
    };
    const finish = (result: OsvGcsListingHttpsOutcome | IntelligenceResolvedAddress): void => {
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
      finish(failure(signal?.aborted === true ? 'cancelled' : 'timeout'));
    }, timeoutMs);

    signal?.addEventListener('abort', onAbort, { once: true });

    lookup(OSV_GCS_JSON_OBJECTS_LIST_HOST, { all: true, verbatim: true }, (error, addresses) => {
      if (settled) {
        return;
      }
      if (error !== null) {
        finish(failure('temporary_dns_failure'));
        return;
      }
      const snapshot = addresses.map((entry) => ({
        address: entry.address,
        family: entry.family,
      }));
      const resolved = snapshot.flatMap((entry) => {
        if (typeof entry.address !== 'string') {
          return [];
        }
        if (entry.family === 4 || entry.family === 6) {
          return [{ address: entry.address, family: entry.family as 4 | 6 }];
        }
        return [];
      });
      const pinned = selectPinnedPublicAddress(resolved);
      if (pinned === undefined) {
        finish(failure('policy_violation'));
        return;
      }
      finish(pinned);
    });
  });
}

function consumeListingBody(input: {
  readonly request: ClientRequest;
  readonly response: IncomingMessage;
  readonly declaredBytes: number | undefined;
  readonly maxBytes: number;
  readonly inactivityTimeoutMs: number;
  readonly remainingTotalMs: number;
  readonly callerAborted: () => boolean;
}): Promise<
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly kind: OsvTransportFailureKind }
> {
  return new Promise((resolve) => {
    let settled = false;
    let received = 0;
    const capacity = input.declaredBytes ?? input.maxBytes;
    const buffer = new Uint8Array(capacity);
    let inactivityTimer: ReturnType<typeof setTimeout> | undefined;

    const finish = (
      result:
        | { readonly ok: true; readonly bytes: Uint8Array }
        | { readonly ok: false; readonly kind: OsvTransportFailureKind },
    ): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (inactivityTimer !== undefined) {
        clearTimeout(inactivityTimer);
        inactivityTimer = undefined;
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
        finish({
          ok: false,
          kind: input.callerAborted() ? 'cancelled' : 'timeout',
        });
      }, input.inactivityTimeoutMs);
    };

    const totalTimer = setTimeout(
      () => {
        finish({
          ok: false,
          kind: input.callerAborted() ? 'cancelled' : 'timeout',
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
      if (!(chunk instanceof Uint8Array)) {
        finish({ ok: false, kind: 'malformed_response' });
        return;
      }
      if (chunk.byteLength === 0) {
        armInactivity();
        return;
      }
      if (received > input.maxBytes - chunk.byteLength) {
        finish({ ok: false, kind: 'response_too_large' });
        return;
      }
      if (input.declaredBytes !== undefined && received + chunk.byteLength > input.declaredBytes) {
        finish({
          ok: false,
          kind:
            received + chunk.byteLength > input.maxBytes
              ? 'response_too_large'
              : 'malformed_response',
        });
        return;
      }
      buffer.set(chunk, received);
      received += chunk.byteLength;
      armInactivity();
    };

    input.response.on('data', onData);
    input.response.once('end', () => {
      if (settled) {
        return;
      }
      if (input.callerAborted()) {
        finish({ ok: false, kind: 'cancelled' });
        return;
      }
      if (received === 0) {
        finish({ ok: false, kind: 'malformed_response' });
        return;
      }
      if (input.declaredBytes !== undefined && received !== input.declaredBytes) {
        finish({ ok: false, kind: 'malformed_response' });
        return;
      }
      finish({ ok: true, bytes: buffer.slice(0, received) });
    });
    input.response.once('error', () => {
      finish({
        ok: false,
        kind: input.callerAborted() ? 'cancelled' : 'malformed_response',
      });
    });
    input.response.once('aborted', () => {
      finish({
        ok: false,
        kind: input.callerAborted() ? 'cancelled' : 'malformed_response',
      });
    });
    input.response.once('close', () => {
      if (settled) {
        return;
      }
      finish({
        ok: false,
        kind: input.callerAborted() ? 'cancelled' : 'malformed_response',
      });
    });

    armInactivity();
  });
}

function compiledRequestInput(request: OsvListingRequest): Record<string, unknown> {
  const input: Record<string, unknown> = {
    providerPrefix: request.providerPrefix,
    transportPolicyVersion: request.transportPolicyVersion,
  };
  if (request.continuationToken !== undefined) {
    input['continuationToken'] = request.continuationToken;
  }
  return input;
}

/**
 * Test-only factory. Production callers must use `createOsvGcsListingHttpsAdapter`.
 * Do not export this from the package index.
 */
export function createOsvGcsListingHttpsAdapterForTests(
  dependencies: OsvGcsListingHttpsTestDependencies = {},
): OsvTransportPort {
  const lookup =
    dependencies.lookup ??
    ((hostname, options, callback) => {
      dnsLookup(hostname, options, callback);
    });
  const requestFn = dependencies.request ?? https.request;
  const logger = dependencies.logger ?? silentLogger;
  const parsePage = dependencies.parseListingPage ?? parseOsvGcsListingPage;

  return {
    async listPage(input) {
      const started = Date.now();
      try {
        return await executeListPage({
          input,
          started,
          lookup,
          requestFn,
          logger,
          parsePage,
        });
      } catch {
        return failure('malformed_response');
      }
    },
  };
}

async function executeListPage(args: {
  readonly input: unknown;
  readonly started: number;
  readonly lookup: OsvGcsListingDnsLookup;
  readonly requestFn: OsvGcsListingHttpsRequest;
  readonly logger: OsvGcsListingLogger;
  readonly parsePage: OsvGcsListingParsePage;
}): Promise<OsvGcsListingHttpsOutcome> {
  const resolved = resolveListingRequest(args.input);
  if ('ok' in resolved) {
    emitSafe(
      args.logger,
      'warn',
      safeEventBindings({
        phase: 'input_received',
        retryability: resolved.failure.retryability,
        durationMs: Date.now() - args.started,
        publicCode: resolved.failure.publicCode,
      }),
      'osv listing preflight failed',
    );
    return resolved;
  }
  const listingRequest = resolved;
  const tokenBound = enforceContinuationTokenBound(listingRequest);
  if (tokenBound !== undefined) {
    emitSafe(
      args.logger,
      'warn',
      safeEventBindings({
        phase: 'request_validated',
        providerPrefix: listingRequest.providerPrefix,
        retryability: tokenBound.failure.retryability,
        durationMs: Date.now() - args.started,
        publicCode: tokenBound.failure.publicCode,
      }),
      'osv listing preflight failed',
    );
    return tokenBound;
  }
  if (listingRequest.signal?.aborted === true) {
    return failure('cancelled');
  }

  const compiled = createOsvGcsListingRequest(compiledRequestInput(listingRequest));
  if (!compiled.ok) {
    return { ok: false, failure: compiled.failure };
  }
  const href = osvGcsListingRequestHref(compiled.value);
  if (!href.ok) {
    return { ok: false, failure: href.failure };
  }
  let pathWithQuery: string;
  try {
    const url = new URL(href.value);
    if (
      url.protocol !== 'https:' ||
      url.hostname !== OSV_GCS_JSON_OBJECTS_LIST_HOST ||
      (url.port !== '' && url.port !== String(HTTPS_PORT))
    ) {
      return failure('policy_violation');
    }
    pathWithQuery = `${url.pathname}${url.search}`;
  } catch {
    return failure('policy_violation');
  }

  const dns = await lookupPinned(
    args.lookup,
    remainingBudgetMs(args.started, OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs),
    listingRequest.signal,
  );
  if ('ok' in dns) {
    return dns;
  }
  const pinned = dns;

  return await new Promise<OsvGcsListingHttpsOutcome>((resolve) => {
    let settled = false;
    let ignoreRequestErrors = false;
    let pinVerified = false;
    let headersReceived = false;
    let connectTimer: ReturnType<typeof setTimeout> | undefined;
    let headerTimer: ReturnType<typeof setTimeout> | undefined;
    let totalTimer: ReturnType<typeof setTimeout> | undefined;
    let req: ReturnType<typeof https.request> | undefined;
    let attachedSocket: { removeAllListeners: () => void } | undefined;
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
      if (attachedSocket !== undefined) {
        attachedSocket.removeAllListeners();
        attachedSocket = undefined;
      }
      req?.destroy();
      agent.destroy();
    };

    const finish = (result: OsvGcsListingHttpsOutcome): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimers();
      if (abortHandler !== undefined && listingRequest.signal !== undefined) {
        listingRequest.signal.removeEventListener('abort', abortHandler);
        abortHandler = undefined;
      }
      destroyRequest();
      if (result.ok) {
        emitSafe(
          args.logger,
          'info',
          safeEventBindings({
            phase: 'succeeded',
            providerPrefix: listingRequest.providerPrefix,
            durationMs: Date.now() - args.started,
            observationCount: result.page.itemCount,
          }),
          'osv listing ok',
        );
      } else {
        emitSafe(
          args.logger,
          'warn',
          safeEventBindings({
            phase: result.failure.kind,
            providerPrefix: listingRequest.providerPrefix,
            retryability: result.failure.retryability,
            durationMs: Date.now() - args.started,
            publicCode: result.failure.publicCode,
          }),
          'osv listing failed',
        );
      }
      resolve(result);
    };

    if (listingRequest.signal?.aborted === true) {
      finish(failure('cancelled'));
      return;
    }

    connectTimer = setTimeout(
      () => {
        finish(failure(listingRequest.signal?.aborted === true ? 'cancelled' : 'timeout'));
      },
      remainingBudgetMs(args.started, OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs),
    );

    totalTimer = setTimeout(
      () => {
        finish(failure(listingRequest.signal?.aborted === true ? 'cancelled' : 'timeout'));
      },
      remainingBudgetMs(args.started, OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs),
    );

    const compiledHeaders = compiled.value.headers;
    const headerRecord: Record<string, string> = {
      Host: OSV_GCS_JSON_OBJECTS_LIST_HOST,
      'User-Agent': USER_AGENT,
      Connection: 'close',
    };
    for (const header of compiledHeaders) {
      headerRecord[header.name] = header.value;
    }

    const options: RequestOptions = {
      method: OSV_GCS_JSON_OBJECTS_LIST_METHOD,
      hostname: OSV_GCS_JSON_OBJECTS_LIST_HOST,
      port: HTTPS_PORT,
      path: pathWithQuery,
      servername: OSV_GCS_JSON_OBJECTS_LIST_HOST,
      agent,
      rejectUnauthorized: true,
      minVersion: TLS_MIN_VERSION,
      maxHeaderSize: MAX_HEADER_SIZE,
      lookup: (_hostname, lookupOptions, callback) => {
        completePinnedLookup(pinned, lookupOptions, callback);
      },
      headers: headerRecord,
    };

    try {
      req = args.requestFn(options, (response) => {
        if (settled) {
          response.destroy();
          return;
        }
        if (!pinVerified) {
          response.destroy();
          finish(failure('policy_violation'));
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

        if (responseLocationIsPresent(response.headers.location)) {
          ignoreRequestErrors = true;
          response.destroy();
          finish(failure('malformed_response'));
          return;
        }

        const framing = classifyListingTransferFraming(response.headers);
        if (framing !== 'ok') {
          ignoreRequestErrors = true;
          response.destroy();
          finish(failure(framing));
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
          finish(failure('malformed_response'));
          return;
        }
        if (
          declaredLength.kind === 'value' &&
          declaredLength.bytes > OSV_GCS_LISTING_PAGE_MAX_BYTES
        ) {
          ignoreRequestErrors = true;
          response.destroy();
          finish(failure('response_too_large'));
          return;
        }
        if (declaredLength.kind === 'value' && declaredLength.bytes === 0) {
          ignoreRequestErrors = true;
          response.destroy();
          finish(failure('malformed_response'));
          return;
        }

        const currentReq = req;
        if (currentReq === undefined) {
          response.destroy();
          finish(failure('policy_violation'));
          return;
        }

        const remainingTotal = Math.max(
          1,
          OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs - (Date.now() - args.started),
        );
        if (totalTimer !== undefined) {
          clearTimeout(totalTimer);
          totalTimer = undefined;
        }

        void consumeListingBody({
          request: currentReq,
          response,
          declaredBytes: declaredLength.kind === 'value' ? declaredLength.bytes : undefined,
          maxBytes: OSV_GCS_LISTING_PAGE_MAX_BYTES,
          inactivityTimeoutMs: OSV_TIMEOUT_POLICY_V1.bodyInactivityTimeoutMs,
          remainingTotalMs: remainingTotal,
          callerAborted: () => listingRequest.signal?.aborted === true,
        }).then((body) => {
          if (settled) {
            return;
          }
          if (!body.ok) {
            finish(failure(body.kind));
            return;
          }
          if (listingRequest.signal?.aborted === true) {
            finish(failure('cancelled'));
            return;
          }
          if (!decodeFatalUtf8(body.bytes)) {
            finish(failure('malformed_response'));
            return;
          }
          const parsed = args.parsePage({
            bytes: body.bytes,
            providerPrefix: listingRequest.providerPrefix,
            transportPolicyVersion: listingRequest.transportPolicyVersion,
          });
          if (!parsed.ok) {
            finish({ ok: false, failure: parsed.failure });
            return;
          }
          finish({ ok: true, page: parsed.value.page });
        });
      });
    } catch {
      finish(failure('malformed_response'));
      return;
    }

    req.once('socket', (socket) => {
      if (settled) {
        return;
      }
      attachedSocket = socket;
      socket.once('error', () => {
        if (ignoreRequestErrors || settled) {
          return;
        }
        finish(
          failure(
            listingRequest.signal?.aborted === true
              ? 'cancelled'
              : headersReceived
                ? 'malformed_response'
                : 'connection_reset',
          ),
        );
      });
      socket.once('secureConnect', () => {
        if (settled) {
          return;
        }
        if (!pinnedAddressMatchesSocket(pinned, socket.remoteAddress, socket.remoteFamily)) {
          finish(failure('policy_violation'));
          return;
        }
        pinVerified = true;
        if (connectTimer !== undefined) {
          clearTimeout(connectTimer);
          connectTimer = undefined;
        }
        if (headerTimer === undefined && !headersReceived && !settled) {
          headerTimer = setTimeout(() => {
            finish(failure(listingRequest.signal?.aborted === true ? 'cancelled' : 'timeout'));
          }, OSV_TIMEOUT_POLICY_V1.responseHeaderTimeoutMs);
        }
      });
    });

    req.on('error', (error: NodeJS.ErrnoException) => {
      if (ignoreRequestErrors || settled) {
        return;
      }
      if (listingRequest.signal?.aborted === true) {
        finish(failure('cancelled'));
        return;
      }
      const code = error.code;
      if (code === 'ECONNRESET' || code === 'EPIPE') {
        finish(failure(headersReceived ? 'malformed_response' : 'connection_reset'));
        return;
      }
      if (code === 'ETIMEDOUT' || code === 'ECONNREFUSED') {
        finish(failure('timeout'));
        return;
      }
      finish(failure(headersReceived ? 'malformed_response' : 'connection_reset'));
    });

    if (listingRequest.signal !== undefined) {
      abortHandler = (): void => {
        finish(failure('cancelled'));
      };
      listingRequest.signal.addEventListener('abort', abortHandler, { once: true });
    }

    req.end();
  });
}

/**
 * Production factory. Callers cannot inject endpoint, socket, TLS, redirect,
 * timeout, header, parser, or credential overrides.
 */
export function createOsvGcsListingHttpsAdapter(): OsvTransportPort {
  return createOsvGcsListingHttpsAdapterForTests();
}
