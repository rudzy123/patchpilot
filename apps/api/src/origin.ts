export function exactOriginAllowed(
  origin: string | undefined,
  allowedOrigins: readonly string[],
): boolean {
  if (origin === undefined || origin.length === 0) {
    return false;
  }

  return allowedOrigins.includes(origin);
}
