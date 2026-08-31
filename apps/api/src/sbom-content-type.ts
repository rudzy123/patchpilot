import { SBOM_APPROVED_CONTENT_TYPES, type SbomApprovedContentType } from '@patchpilot/domain';

export type SbomContentTypeParseResult =
  | { ok: true; contentType: SbomApprovedContentType }
  | { ok: false; reason: 'media_type' | 'charset' | 'parameter' };

const UTF8_CHARSETS = new Set(['utf-8', 'utf8']);

export function parseApprovedSbomContentType(
  header: string | undefined,
): SbomContentTypeParseResult {
  if (header === undefined) {
    return { ok: false, reason: 'media_type' };
  }

  const parts = header
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  const mediaType = parts[0]?.toLowerCase();
  if (
    mediaType === undefined ||
    !(SBOM_APPROVED_CONTENT_TYPES as readonly string[]).includes(mediaType)
  ) {
    return { ok: false, reason: 'media_type' };
  }

  for (const parameter of parts.slice(1)) {
    const separator = parameter.indexOf('=');
    if (separator <= 0) {
      return { ok: false, reason: 'parameter' };
    }

    const name = parameter.slice(0, separator).trim().toLowerCase();
    let value = parameter.slice(separator + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      value = value.slice(1, -1);
    }

    if (name !== 'charset') {
      return { ok: false, reason: 'parameter' };
    }
    if (!UTF8_CHARSETS.has(value.toLowerCase())) {
      return { ok: false, reason: 'charset' };
    }
  }

  return { ok: true, contentType: mediaType as SbomApprovedContentType };
}

const VISIBLE_ASCII = /^[\x21-\x7E]+$/;

export function parseIdempotencyKeyHeader(
  header: string | undefined,
  minLength: number,
  maxLength: number,
): { ok: true; value: string } | { ok: false } {
  if (header === undefined || header.length < minLength || header.length > maxLength) {
    return { ok: false };
  }
  if (!VISIBLE_ASCII.test(header)) {
    return { ok: false };
  }
  return { ok: true, value: header };
}

export function parseDeclaredByteLength(
  header: string | undefined,
  maxBytes: number,
): { ok: true; value?: number } | { ok: false; tooLarge: boolean } {
  if (header === undefined) {
    return { ok: true };
  }
  if (!/^[0-9]+$/.test(header)) {
    return { ok: false, tooLarge: false };
  }

  const value = Number(header);
  if (!Number.isSafeInteger(value) || value < 1) {
    return { ok: false, tooLarge: false };
  }
  if (value > maxBytes) {
    return { ok: false, tooLarge: true };
  }
  return { ok: true, value };
}

export async function* bytesFromRequestBody(body: unknown): AsyncIterable<Uint8Array> {
  if (isAsyncIterable(body)) {
    for await (const chunk of body) {
      yield toUint8Array(chunk);
    }
    return;
  }

  if (typeof body === 'string') {
    yield Buffer.from(body);
    return;
  }

  if (body instanceof Uint8Array) {
    yield body;
  }
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    Symbol.asyncIterator in value &&
    typeof (value as AsyncIterable<unknown>)[Symbol.asyncIterator] === 'function'
  );
}

function toUint8Array(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  if (typeof chunk === 'string') {
    return Buffer.from(chunk);
  }
  return Buffer.from(String(chunk));
}
