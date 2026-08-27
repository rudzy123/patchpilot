import { z } from 'zod';

export {
  errorCodeSchema,
  errorEnvelopeSchema,
  type ErrorCode,
  type ErrorEnvelope,
} from './errors.js';
export {
  loginRequestSchema,
  membershipRoleSchema,
  organizationsResponseSchema,
  publicAuthOrganizationSchema,
  publicAuthUserSchema,
  selectOrganizationRequestSchema,
  sessionResponseSchema,
  type LoginRequest,
  type OrganizationsResponse,
  type PublicAuthOrganization,
  type PublicAuthUser,
  type SelectOrganizationRequest,
  type SessionResponse,
} from './auth.js';

export const healthServiceSchema = z.enum(['api', 'web', 'worker']);

export const healthLiveResponseSchema = z.object({
  status: z.literal('live'),
  service: healthServiceSchema,
  timestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
    message: 'timestamp must be UTC ISO 8601',
  }),
  version: z.string().min(1).optional(),
});

export const healthCheckSchema = z.object({
  name: z.string().min(1),
  status: z.enum(['up', 'down']),
});

export const healthReadyResponseSchema = z.object({
  status: z.enum(['ready', 'not_ready']),
  service: healthServiceSchema,
  timestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
    message: 'timestamp must be UTC ISO 8601',
  }),
  version: z.string().min(1).optional(),
  checks: z.array(healthCheckSchema),
});

export type HealthLiveResponse = z.infer<typeof healthLiveResponseSchema>;
export type HealthReadyResponse = z.infer<typeof healthReadyResponseSchema>;
export type HealthCheck = z.infer<typeof healthCheckSchema>;
export type HealthService = z.infer<typeof healthServiceSchema>;

export function utcNowIso(): string {
  return new Date().toISOString();
}
