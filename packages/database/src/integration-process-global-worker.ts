import { createIntegrationProcessHooks } from './integration-process-global.js';

const hooks = createIntegrationProcessHooks('worker');

export const setup = hooks.setup;
export const teardown = hooks.teardown;
