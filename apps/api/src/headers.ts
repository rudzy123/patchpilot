export function readSingleHeader(value: string | string[] | undefined): string | undefined {
  if (typeof value === 'string') {
    return value;
  }

  if (Array.isArray(value) && typeof value[0] === 'string') {
    return value[0];
  }

  return undefined;
}

export function isJsonContentType(value: string | string[] | undefined): boolean {
  const header = readSingleHeader(value);
  if (header === undefined) {
    return false;
  }

  const mediaType = header.split(';', 1)[0]?.trim().toLowerCase();
  return mediaType === 'application/json';
}
