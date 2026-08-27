import { z } from 'zod';

export const membershipRoleSchema = z.enum(['owner', 'admin', 'member', 'viewer']);

export const loginRequestSchema = z.object({
  email: z.string().min(1).max(320),
  password: z.string().min(1).max(256),
});

export const selectOrganizationRequestSchema = z.object({
  organizationId: z.uuid(),
});

export const publicAuthUserSchema = z.object({
  id: z.uuid(),
  displayName: z.string().min(1),
});

export const publicAuthOrganizationSchema = z.object({
  id: z.uuid(),
  slug: z.string().min(1),
  name: z.string().min(1),
  role: membershipRoleSchema,
});

export const sessionResponseSchema = z.object({
  user: publicAuthUserSchema,
  organization: publicAuthOrganizationSchema.nullable(),
  csrfToken: z.string().min(1),
  expiresAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/, {
    message: 'expiresAt must be UTC ISO 8601',
  }),
});

export const organizationsResponseSchema = z.object({
  organizations: z.array(publicAuthOrganizationSchema),
});

export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type SelectOrganizationRequest = z.infer<typeof selectOrganizationRequestSchema>;
export type PublicAuthUser = z.infer<typeof publicAuthUserSchema>;
export type PublicAuthOrganization = z.infer<typeof publicAuthOrganizationSchema>;
export type SessionResponse = z.infer<typeof sessionResponseSchema>;
export type OrganizationsResponse = z.infer<typeof organizationsResponseSchema>;
