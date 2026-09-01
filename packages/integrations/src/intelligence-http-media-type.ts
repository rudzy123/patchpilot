import {
  INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS,
  type IntelligenceSafeContentTypeLabel,
} from '@patchpilot/domain';

function headerValue(header: string | string[] | undefined): string | undefined {
  if (header === undefined) {
    return undefined;
  }

  if (Array.isArray(header)) {
    if (header.length === 0) {
      return undefined;
    }

    if (header.length > 1) {
      return undefined;
    }

    return header[0];
  }

  return header;
}

function unquote(value: string): string {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }

  return value;
}

export function parseApprovedJsonMediaType(
  header: string | string[] | undefined,
): IntelligenceSafeContentTypeLabel | undefined {
  const raw = headerValue(header);
  if (raw === undefined) {
    return undefined;
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.includes(',')) {
    return undefined;
  }

  const [typeToken, ...parameterTokens] = trimmed.split(';');
  if (typeToken === undefined) {
    return undefined;
  }

  const mediaType = typeToken.trim().toLowerCase();
  if (mediaType !== 'application/json') {
    return undefined;
  }

  let charset: string | undefined;
  for (const token of parameterTokens) {
    const separator = token.indexOf('=');
    if (separator <= 0) {
      return undefined;
    }

    const name = token.slice(0, separator).trim().toLowerCase();
    const value = unquote(token.slice(separator + 1).trim()).toLowerCase();
    if (name.length === 0 || value.length === 0) {
      return undefined;
    }

    if (name !== 'charset') {
      return undefined;
    }

    if (charset !== undefined) {
      return undefined;
    }

    charset = value;
  }

  if (charset === undefined) {
    return INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS[0];
  }

  if (charset !== 'utf-8') {
    return undefined;
  }

  return INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS[1];
}

export function isIdentityContentEncoding(header: string | string[] | undefined): boolean {
  if (header === undefined) {
    return true;
  }

  const values = Array.isArray(header) ? header : [header];
  if (values.length === 0) {
    return true;
  }

  if (values.length > 1) {
    return false;
  }

  const value = values[0]?.trim().toLowerCase();
  return value === undefined || value.length === 0 || value === 'identity';
}

export function parseDeclaredContentLength(
  header: string | string[] | undefined,
): { kind: 'absent' } | { kind: 'invalid' } | { kind: 'value'; bytes: number } {
  if (header === undefined) {
    return { kind: 'absent' };
  }

  const values = Array.isArray(header) ? header : [header];
  if (values.length === 0) {
    return { kind: 'absent' };
  }

  const unique = new Set(values.map((value) => value.trim()));
  if (unique.size !== 1) {
    return { kind: 'invalid' };
  }

  const [raw] = unique;
  if (raw === undefined || raw.length === 0 || !/^[0-9]+$/.test(raw)) {
    return { kind: 'invalid' };
  }

  const bytes = Number(raw);
  if (!Number.isSafeInteger(bytes) || bytes < 0) {
    return { kind: 'invalid' };
  }

  return { kind: 'value', bytes };
}
