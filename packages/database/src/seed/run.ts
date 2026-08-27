import { loadServerConfig } from '@patchpilot/config';

import { seedDevelopmentData } from './development.js';

const config = loadServerConfig();

await seedDevelopmentData({
  env: {
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: config.deploymentEnvironment,
  },
  databaseUrl: config.databaseUrl,
});
