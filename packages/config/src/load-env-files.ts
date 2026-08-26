import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';

const repoMarker = 'pnpm-workspace.yaml';

export function shouldLoadDevelopmentEnvFiles(
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  return (
    env['NODE_ENV'] !== 'production' && env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] !== 'production'
  );
}

export function applyEnvFileContents(
  contents: string,
  env: Readonly<Record<string, string | undefined>>,
): Record<string, string | undefined> {
  const parsed = parseEnv(contents);
  const next: Record<string, string | undefined> = { ...env };

  for (const [key, value] of Object.entries(parsed)) {
    if (next[key] === undefined && value !== undefined && value.length > 0) {
      next[key] = value;
    }
  }

  return next;
}

export function findRepoRootDirectory(startDirectory: string): string | undefined {
  let current = path.resolve(startDirectory);

  for (let depth = 0; depth < 8; depth += 1) {
    if (existsSync(path.join(current, repoMarker))) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }

    current = parent;
  }

  return undefined;
}

export function findDevelopmentEnvFile(startDirectory: string): string | undefined {
  const repoRoot = findRepoRootDirectory(startDirectory);
  if (repoRoot === undefined) {
    return undefined;
  }

  const envFile = path.join(repoRoot, '.env');
  return existsSync(envFile) ? envFile : undefined;
}

export function hydrateProcessEnvFromDevelopmentFiles(
  env: NodeJS.ProcessEnv,
  options?: { startDirectory?: string; moduleUrl?: string },
): void {
  if (!shouldLoadDevelopmentEnvFiles(env)) {
    return;
  }

  const searchStarts = [
    options?.startDirectory,
    options?.moduleUrl === undefined ? undefined : path.dirname(fileURLToPath(options.moduleUrl)),
    process.cwd(),
  ].filter((directory): directory is string => directory !== undefined);

  for (const startDirectory of searchStarts) {
    const envFile = findDevelopmentEnvFile(startDirectory);
    if (envFile === undefined) {
      continue;
    }

    const hydrated = applyEnvFileContents(readFileSync(envFile, 'utf8'), env);
    for (const [key, value] of Object.entries(hydrated)) {
      if (env[key] === undefined && value !== undefined) {
        env[key] = value;
      }
    }

    return;
  }
}
