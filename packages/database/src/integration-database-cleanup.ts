export function redactConnectionSecrets(message: string): string {
  return message
    .replace(/postgresql:\/\/[^\s'"]+/gi, 'postgresql://<redacted>')
    .replace(/postgres:\/\/[^\s'"]+/gi, 'postgres://<redacted>');
}

export function formatCleanupFailure(error: unknown): string {
  const detail = error instanceof Error ? error.message : 'unknown cleanup failure';
  return `integration database cleanup failed: ${redactConnectionSecrets(detail)}`;
}

export async function withCleanupOnFailure<T>(
  operation: () => Promise<T>,
  cleanup: () => Promise<void>,
): Promise<T> {
  try {
    return await operation();
  } catch (operationError) {
    try {
      await cleanup();
    } catch (cleanupError) {
      process.stderr.write(`${formatCleanupFailure(cleanupError)}\n`);
    }

    throw operationError;
  }
}
