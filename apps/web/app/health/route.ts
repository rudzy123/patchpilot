import { healthLiveResponseSchema } from '@patchpilot/contracts';

export function GET(): Response {
  const payload = healthLiveResponseSchema.parse({
    status: 'live',
    service: 'web',
    timestamp: new Date().toISOString(),
    version: '0.0.0',
  });

  return Response.json(payload);
}
