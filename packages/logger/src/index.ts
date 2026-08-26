import { pino, type Logger, type LoggerOptions } from 'pino';
import type { Writable } from 'node:stream';

export type { Logger };

export type LoggerFactoryOptions = {
  service: string;
  level: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
  pretty: boolean;
  destination?: Writable;
};

const redactPaths = [
  'authorization',
  'cookie',
  'set-cookie',
  'proxy-authorization',
  'www-authenticate',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'apiKey',
  'api_key',
  'githubToken',
  'github_token',
  'secretAccessKey',
  'secret_access_key',
  'secretKey',
  'secret_key',
  'signedUrl',
  'signed_url',
  'password',
  'passwd',
  'credentials',
  'databaseUrl',
  'DATABASE_URL',
  'redisUrl',
  'REDIS_URL',
  'headers.authorization',
  'headers.cookie',
  'headers["proxy-authorization"]',
  'headers["www-authenticate"]',
  'headers["set-cookie"]',
  'headers["set-cookie"][*]',
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["proxy-authorization"]',
  'req.headers["www-authenticate"]',
  'req.headers["set-cookie"]',
  'res.headers["set-cookie"]',
  '*.authorization',
  '*.cookie',
  '*.accessToken',
  '*.access_token',
  '*.refreshToken',
  '*.refresh_token',
  '*.apiKey',
  '*.api_key',
  '*.githubToken',
  '*.github_token',
  '*.secretAccessKey',
  '*.secret_access_key',
  '*.secretKey',
  '*.secret_key',
  '*.signedUrl',
  '*.signed_url',
  '*.password',
  '*.passwd',
  '*.credentials',
  '*.databaseUrl',
  '*.DATABASE_URL',
  '*.redisUrl',
  '*.REDIS_URL',
  'env',
  'process.env',
] as const;

export function createLogger(options: LoggerFactoryOptions): Logger {
  const loggerOptions: LoggerOptions = {
    name: options.service,
    level: options.level,
    redact: {
      paths: [...redactPaths],
      censor: '[Redacted]',
    },
    serializers: {
      req(request: unknown) {
        return serializeRequest(request);
      },
    },
    base: {
      service: options.service,
    },
  };

  if (options.pretty) {
    return pino(
      {
        ...loggerOptions,
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname',
          },
        },
      },
      options.destination,
    );
  }

  return pino(loggerOptions, options.destination);
}

export function createChildLogger(
  logger: Logger,
  bindings: { requestId?: string; correlationId?: string; jobId?: string },
): Logger {
  return logger.child(bindings);
}

function serializeRequest(request: unknown): Record<string, unknown> {
  if (typeof request !== 'object' || request === null) {
    return { type: 'request' };
  }

  const record = request as Record<string, unknown>;
  const headers = sanitizeHeaders(record['headers']);

  const rawUrl = record['url'];
  const url = typeof rawUrl === 'string' ? rawUrl.split('?')[0] : rawUrl;

  return {
    method: record['method'],
    url,
    headers,
  };
}

function sanitizeHeaders(headers: unknown): Record<string, unknown> {
  if (typeof headers !== 'object' || headers === null) {
    return {};
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
    const lower = key.toLowerCase();
    if (
      lower === 'authorization' ||
      lower === 'proxy-authorization' ||
      lower === 'www-authenticate' ||
      lower === 'cookie' ||
      lower === 'set-cookie' ||
      lower.includes('token') ||
      lower.includes('api-key') ||
      lower.includes('apikey') ||
      lower.includes('secret') ||
      lower.includes('signature')
    ) {
      sanitized[key] = '[Redacted]';
      continue;
    }

    sanitized[key] = value;
  }

  return sanitized;
}

export { redactPaths };
