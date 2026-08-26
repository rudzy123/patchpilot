export function readOptional(
  env: Readonly<Record<string, string | undefined>>,
  key: string,
): string | undefined {
  const value = env[key];
  if (value === undefined) {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function readRequired(
  env: Readonly<Record<string, string | undefined>>,
  key: string,
): string {
  const value = readOptional(env, key);
  if (value === undefined) {
    throw new Error(
      `Missing required environment variable ${key}. See docs/development/environment-variables.md for the expected foundation variables.`,
    );
  }

  return value;
}

export function parseInteger(raw: string, key: string): number {
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || String(value) !== raw) {
    throw new Error(`${key} must be an integer. Received: (redacted)`);
  }

  return value;
}

export function parseBoolean(raw: string, key: string): boolean {
  if (raw === 'true') {
    return true;
  }

  if (raw === 'false') {
    return false;
  }

  throw new Error(`${key} must be "true" or "false".`);
}
