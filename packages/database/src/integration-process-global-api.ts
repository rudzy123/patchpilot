import { createIntegrationProcessHooks } from './integration-process-global.js';

const hooks = createIntegrationProcessHooks('api');

export const setup = hooks.setup;
export const teardown = hooks.teardown;
