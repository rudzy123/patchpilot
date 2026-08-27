import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { context, trace } from '@opentelemetry/api';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { startTelemetry } from './index.js';

const packageJsonPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');

const decoyEnvKeys = [
  'OTEL_SDK_DISABLED',
  'OTEL_TRACES_EXPORTER',
  'OTEL_EXPORTER_OTLP_ENDPOINT',
  'OTEL_EXPORTER_OTLP_PROTOCOL',
  'OTEL_RESOURCE_ATTRIBUTES',
  'OTEL_SERVICE_NAME',
  'OTEL_TRACES_SAMPLER',
  'OTEL_PROPAGATORS',
  'OTEL_METRICS_EXPORTER',
  'OTEL_LOGS_EXPORTER',
] as const;

describe('telemetry lifecycle', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    restoreDecoyEnv();
    trace.disable();
    context.disable();
  });

  it('starts as a no-op when disabled', async () => {
    const handle = await startTelemetry({
      serviceName: 'test',
      enabled: false,
    });
    await expect(handle.shutdown()).resolves.toBeUndefined();
  });

  it('shuts down disabled telemetry idempotently', async () => {
    const handle = await startTelemetry({
      serviceName: 'test',
      enabled: false,
    });
    await expect(Promise.all([handle.shutdown(), handle.shutdown()])).resolves.toEqual([
      undefined,
      undefined,
    ]);
    await expect(handle.shutdown()).resolves.toBeUndefined();
  });

  it('does not contact a collector when telemetry is disabled', async () => {
    const sink = await startLoopbackTraceSink();
    try {
      const handle = await startTelemetry({
        serviceName: 'test',
        enabled: false,
        tracesEndpoint: sink.url,
      });
      await handle.shutdown();
      expect(sink.requestCount()).toBe(0);
    } finally {
      await sink.close();
    }
  });

  it('starts enabled telemetry without an endpoint and makes no outbound request', async () => {
    const sink = await startLoopbackTraceSink();
    try {
      const handle = await startTelemetry({
        serviceName: 'test',
        enabled: true,
      });
      await emitSampleSpan();
      await handle.shutdown();
      expect(sink.requestCount()).toBe(0);
    } finally {
      await sink.close();
    }
  });

  it('ignores decoy OTEL endpoint environment variables when no tracesEndpoint is configured', async () => {
    const sink = await startLoopbackTraceSink();
    try {
      applyDecoyEnv({
        OTEL_EXPORTER_OTLP_ENDPOINT: sink.url,
        OTEL_EXPORTER_OTLP_PROTOCOL: 'http/protobuf',
        OTEL_TRACES_EXPORTER: 'otlp',
        OTEL_SERVICE_NAME: 'decoy-service',
        OTEL_TRACES_SAMPLER: 'always_off',
      });
      const handle = await startTelemetry({
        serviceName: 'test',
        enabled: true,
      });
      await emitSampleSpan();
      await handle.shutdown();
      expect(sink.requestCount()).toBe(0);
    } finally {
      await sink.close();
    }
  });

  it('exports OTLP HTTP JSON to a configured local endpoint', async () => {
    const sink = await startLoopbackTraceSink();
    try {
      const pendingRequest = sink.waitForRequest();
      const handle = await startTelemetry({
        serviceName: 'observability-export-test',
        enabled: true,
        tracesEndpoint: sink.url,
      });
      await emitSampleSpan();
      await handle.shutdown();
      const request = await pendingRequest;
      expect(request.contentType).toMatch(/application\/json/i);
      expect(() => JSON.parse(request.body) as unknown).not.toThrow();
      expect(JSON.parse(request.body)).toEqual(expect.any(Object));
    } finally {
      await sink.close();
    }
  });

  it('flushes and closes on shutdown, including concurrent and repeated calls', async () => {
    const sink = await startLoopbackTraceSink();
    try {
      const pendingRequest = sink.waitForRequest();
      const handle = await startTelemetry({
        serviceName: 'observability-shutdown-test',
        enabled: true,
        tracesEndpoint: sink.url,
      });
      await emitSampleSpan();
      await expect(Promise.all([handle.shutdown(), handle.shutdown()])).resolves.toEqual([
        undefined,
        undefined,
      ]);
      await expect(handle.shutdown()).resolves.toBeUndefined();
      await pendingRequest;
    } finally {
      await sink.close();
    }
  });

  it('surfaces initialization failure from the trace provider', async () => {
    const sdkTraceNode = await import('@opentelemetry/sdk-trace-node');
    vi.spyOn(sdkTraceNode, 'NodeTracerProvider').mockImplementation(() => {
      throw new Error('provider construction failed');
    });

    await expect(
      startTelemetry({
        serviceName: 'test',
        enabled: true,
      }),
    ).rejects.toThrow('provider construction failed');
  });

  it('does not declare a direct dependency on @opentelemetry/sdk-node', () => {
    const manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as {
      dependencies?: Record<string, string>;
    };
    expect(manifest.dependencies).not.toHaveProperty('@opentelemetry/sdk-node');
  });
});

const decoyEnvBackup = new Map<string, string | undefined>();

function applyDecoyEnv(values: Partial<Record<(typeof decoyEnvKeys)[number], string>>): void {
  // Tests may mutate process.env to prove production telemetry ignores decoy OTEL_*
  // variables. packages/observability runtime code still must not read process.env.
  for (const key of decoyEnvKeys) {
    if (!decoyEnvBackup.has(key)) {
      decoyEnvBackup.set(key, process.env[key]);
    }
  }

  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) {
      continue;
    }
    process.env[key] = value;
  }
}

function restoreDecoyEnv(): void {
  for (const [key, value] of decoyEnvBackup) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  decoyEnvBackup.clear();
}

async function emitSampleSpan(): Promise<void> {
  const span = trace.getTracer('patchpilot-observability-test').startSpan('unit-test-span');
  span.end();
}

type CapturedRequest = {
  contentType: string;
  body: string;
};

type LoopbackTraceSink = {
  url: string;
  requestCount: () => number;
  waitForRequest: () => Promise<CapturedRequest>;
  close: () => Promise<void>;
};

async function startLoopbackTraceSink(): Promise<LoopbackTraceSink> {
  let requestCount = 0;
  let pending:
    | {
        resolve: (request: CapturedRequest) => void;
        reject: (error: Error) => void;
      }
    | undefined;
  let captured: CapturedRequest | undefined;

  const server: Server = createServer((request: IncomingMessage, response: ServerResponse) => {
    requestCount += 1;
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer | string) => {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    });
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const contentType = request.headers['content-type'] ?? '';
      captured = { contentType, body };
      response.statusCode = 200;
      response.end('{}');
      pending?.resolve(captured);
      pending = undefined;
    });
    request.on('error', (error: Error) => {
      pending?.reject(error);
      pending = undefined;
    });
  });

  server.listen(0, '127.0.0.1');
  await onceListening(server);

  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('Loopback trace sink did not bind to a TCP port.');
  }

  return {
    url: `http://127.0.0.1:${address.port}/v1/traces`,
    requestCount: () => requestCount,
    waitForRequest: () => {
      if (captured) {
        return Promise.resolve(captured);
      }

      return new Promise<CapturedRequest>((resolve, reject) => {
        pending = { resolve, reject };
      });
    },
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      }),
  };
}

async function onceListening(server: Server): Promise<void> {
  if (server.listening) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
  });
}
