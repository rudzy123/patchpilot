import { context, trace } from '@opentelemetry/api';

export type TelemetryOptions = {
  serviceName: string;
  enabled: boolean;
  tracesEndpoint?: string;
};

export type TelemetryHandle = {
  shutdown: () => Promise<void>;
};

const FORCE_FLUSH_TIMEOUT_MS = 5_000;
const EXPORT_TIMEOUT_MS = 5_000;

/**
 * Starts OpenTelemetry traces if enabled. Local startup and tests do not require
 * a collector. Metrics, logs exporters, and automatic instrumentation are not
 * initialized.
 *
 * Future HTTP, job, feed, and policy metrics belong in this package as named
 * instruments created after the SDK starts — not in domain code.
 */
export async function startTelemetry(options: TelemetryOptions): Promise<TelemetryHandle> {
  if (!options.enabled) {
    return createNoopHandle();
  }

  const tracesEndpoint = readTracesEndpoint(options);
  const [
    { NodeTracerProvider },
    { AlwaysOnSampler, BatchSpanProcessor, NoopSpanProcessor },
    { resourceFromAttributes },
    { ATTR_SERVICE_NAME },
  ] = await Promise.all([
    import('@opentelemetry/sdk-trace-node'),
    import('@opentelemetry/sdk-trace'),
    import('@opentelemetry/resources'),
    import('@opentelemetry/semantic-conventions'),
  ]);

  const spanProcessors =
    tracesEndpoint === undefined
      ? [new NoopSpanProcessor()]
      : [
          new BatchSpanProcessor({
            exporter: await createTraceExporter(tracesEndpoint),
            exportTimeoutMillis: EXPORT_TIMEOUT_MS,
            scheduledDelayMillis: FORCE_FLUSH_TIMEOUT_MS,
            maxExportBatchSize: 512,
            maxQueueSize: 2048,
          }),
        ];

  const provider = new NodeTracerProvider({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: options.serviceName,
    }),
    sampler: new AlwaysOnSampler(),
    spanProcessors,
    forceFlushTimeoutMillis: FORCE_FLUSH_TIMEOUT_MS,
  });

  try {
    // Null skips W3C Trace Context and Baggage. Undefined would install both.
    provider.register({ propagator: null });
  } catch (error) {
    await shutdownProvider(provider);
    throw error;
  }

  return createProviderHandle(provider);
}

function readTracesEndpoint(options: TelemetryOptions): string | undefined {
  if (options.tracesEndpoint === undefined || options.tracesEndpoint.length === 0) {
    return undefined;
  }

  return options.tracesEndpoint;
}

async function createTraceExporter(url: string) {
  const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-http');
  return new OTLPTraceExporter({
    url,
    timeoutMillis: EXPORT_TIMEOUT_MS,
    headers: {},
  });
}

function createNoopHandle(): TelemetryHandle {
  return createIdempotentHandle(async () => undefined);
}

function createProviderHandle(provider: { shutdown: () => Promise<void> }): TelemetryHandle {
  return createIdempotentHandle(async () => {
    await shutdownProvider(provider);
  });
}

function createIdempotentHandle(shutdownOnce: () => Promise<void>): TelemetryHandle {
  let shutdownResult: Promise<void> | undefined;

  return {
    shutdown(): Promise<void> {
      shutdownResult ??= shutdownOnce();
      return shutdownResult;
    },
  };
}

async function shutdownProvider(provider: { shutdown: () => Promise<void> }): Promise<void> {
  try {
    await provider.shutdown();
  } catch {
    // Export or flush failure must not block process shutdown (fail-open).
  } finally {
    // OpenTelemetry API registers a global provider once. Release it so a later
    // startTelemetry call can register, and so tests do not share a dead provider.
    trace.disable();
    context.disable();
  }
}
