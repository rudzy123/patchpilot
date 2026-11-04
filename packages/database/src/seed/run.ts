import { loadServerConfig } from '@patchpilot/config';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  canonicalJson as canonicalizePriorityPolicy,
} from '@patchpilot/policy-engine';

import { seedDevelopmentData } from './development.js';

/**
 * Development seed entrypoint. This is the only production seed entrypoint
 * that imports `@patchpilot/policy-engine`. The database barrel does not.
 * Production `pnpm db:seed` remains refused: the command script rejects a
 * production deployment environment and `NODE_ENV=production` before this
 * module starts, and `seedDevelopmentData` applies the same refusal to the
 * env it receives before any write.
 */
function canonicalJson(value: unknown): string {
  const result = canonicalizePriorityPolicy(value);
  if (!result.ok) {
    throw new Error(
      `Builtin priority policy definition could not be canonicalized (${result.error.code}).`,
    );
  }
  return result.value;
}

const config = loadServerConfig();

await seedDevelopmentData({
  env: {
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: config.deploymentEnvironment,
  },
  databaseUrl: config.databaseUrl,
  builtinPriorityDefinition: BUILTIN_PRIORITY_POLICY_DEFINITION,
  canonicalJson,
});
