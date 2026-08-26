export type TelemetryOptions = {
  serviceName: string;
  enabled: boolean;
  tracesEndpoint?: string;
};

export type TelemetryHandle = {
  shutdown: () => Promise<void>;
};

/**
 * Starts OpenTelemetry if enabled. Local startup and tests do not require a collector.
 *
 * Future HTTP, job, feed, and policy metrics belong in this package as named
 * instruments created after the SDK starts — not in domain code.
 */
export async function startTelemetry(options: TelemetryOptions): Promise<TelemetryHandle> {
  if (!options.enabled) {
    return {
      async shutdown(): Promise<void> {
        return;
      },
    };
  }

  const [{ NodeSDK }, { OTLPTraceExporter }] = await Promise.all([
    import('@opentelemetry/sdk-node'),
    import('@opentelemetry/exporter-trace-otlp-http'),
  ]);

  const exporterOptions =
    options.tracesEndpoint === undefined ? {} : { url: options.tracesEndpoint };

  const sdk = new NodeSDK({
    serviceName: options.serviceName,
    traceExporter: new OTLPTraceExporter(exporterOptions),
  });

  sdk.start();

  return {
    async shutdown(): Promise<void> {
      await sdk.shutdown();
    },
  };
}
