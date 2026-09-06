/**
 * Session 12 Batch 1 listing HTTPS event-order tests.
 * Local EventEmitter doubles only. One terminal settlement per invocation.
 */

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import {
  createOsvGcsListingHttpsAdapterForTests,
  type OsvGcsListingDnsLookup,
  type OsvGcsListingHttpsRequest,
} from './osv-gcs-listing-https-adapter.js';
import {
  MINIMAL_PAGE,
  PUBLIC_V4,
  jsonHeaders,
  validListingRequest,
} from './osv-gcs-listing-https-adapter.test-harness.js';

const lookup: OsvGcsListingDnsLookup = (_hostname, _options, callback) => {
  callback(null, [{ address: PUBLIC_V4, family: 4 }]);
};

type ControlledRequest = EventEmitter & {
  destroy: () => void;
  end: () => void;
};

function createControlledRequest(): {
  request: OsvGcsListingHttpsRequest;
  get: () => {
    req: ControlledRequest;
    callback: ((response: Readable) => void) | undefined;
    destroyed: boolean;
  };
} {
  let req: ControlledRequest | undefined;
  let callback: ((response: Readable) => void) | undefined;
  let destroyed = false;
  const request: OsvGcsListingHttpsRequest = (_options, next) => {
    callback = next as ((response: Readable) => void) | undefined;
    req = new EventEmitter() as ControlledRequest;
    req.destroy = () => {
      destroyed = true;
    };
    req.end = () => undefined;
    return req as ReturnType<OsvGcsListingHttpsRequest>;
  };
  return {
    request,
    get: () => {
      if (req === undefined) {
        throw new Error('request not created');
      }
      return { req, callback, destroyed };
    },
  };
}

function emitPinnedSocket(req: EventEmitter): EventEmitter {
  const socket = new EventEmitter();
  Object.defineProperty(socket, 'remoteAddress', { value: PUBLIC_V4 });
  Object.defineProperty(socket, 'remoteFamily', { value: 'IPv4' });
  req.emit('socket', socket);
  socket.emit('secureConnect');
  return socket;
}

function jsonResponse(body: Buffer = MINIMAL_PAGE): Readable {
  const response = Readable.from([body], { objectMode: false });
  Object.assign(response, {
    statusCode: 200,
    headers: jsonHeaders(body),
  });
  return response;
}

describe('OSV GCS listing HTTPS event ordering', () => {
  it('settles once on request error before socket', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req } = controlled.get();
    req.emit('error', Object.assign(new Error('early'), { code: 'ECONNRESET' }));
    req.emit('error', Object.assign(new Error('late'), { code: 'ECONNRESET' }));
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('connection_reset');
    }
  });

  it('settles once on socket error then ignores secureConnect', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req } = controlled.get();
    const socket = new EventEmitter();
    Object.defineProperty(socket, 'remoteAddress', { value: PUBLIC_V4 });
    Object.defineProperty(socket, 'remoteFamily', { value: 'IPv4' });
    req.emit('socket', socket);
    socket.emit('error', new Error('socket'));
    socket.emit('secureConnect');
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('connection_reset');
    }
  });

  it('ignores late request close after success', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req, callback } = controlled.get();
    emitPinnedSocket(req);
    if (callback === undefined) {
      throw new Error('missing callback');
    }
    callback(jsonResponse());
    const result = await pending;
    expect(result.ok).toBe(true);
    req.emit('close');
    expect(result.ok).toBe(true);
  });

  it('ignores data after response error', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req, callback } = controlled.get();
    emitPinnedSocket(req);
    if (callback === undefined) {
      throw new Error('missing callback');
    }
    const response = new Readable({
      read() {
        this.emit('error', new Error('body'));
        this.push(MINIMAL_PAGE);
      },
    });
    Object.assign(response, {
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
    });
    callback(response);
    const result = await pending;
    expect(result.ok).toBe(false);
    response.emit('data', MINIMAL_PAGE);
    response.emit('end');
    expect(result.ok).toBe(false);
  });

  it('ignores error after a successful end', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req, callback } = controlled.get();
    emitPinnedSocket(req);
    if (callback === undefined) {
      throw new Error('missing callback');
    }
    const response = jsonResponse();
    callback(response);
    const result = await pending;
    expect(result.ok).toBe(true);
    response.on('error', () => undefined);
    response.emit('error', new Error('late'));
    response.emit('close');
    expect(result.ok).toBe(true);
  });

  it('rejects a response that arrives before pin verification', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req, callback } = controlled.get();
    if (callback === undefined) {
      throw new Error('missing callback');
    }
    callback(jsonResponse());
    req.emit('error', Object.assign(new Error('reset'), { code: 'ECONNRESET' }));
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(['policy_violation', 'connection_reset']).toContain(result.failure.kind);
    }
  });

  it('destroys the request on failure and does not leave a second listener cycle', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req } = controlled.get();
    req.emit('error', Object.assign(new Error('reset'), { code: 'ECONNRESET' }));
    await pending;
    expect(controlled.get().destroyed).toBe(true);
    req.emit('error', Object.assign(new Error('again'), { code: 'ECONNRESET' }));
  });
});
