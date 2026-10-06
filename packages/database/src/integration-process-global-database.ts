import { reapIntegrationDatabases } from './integration-process-global.js';

export async function setup(): Promise<void> {
  await reapIntegrationDatabases();
}
