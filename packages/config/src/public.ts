import { z } from 'zod';

export const publicConfigSchema = z
  .object({
    appName: z.literal('PatchPilot'),
    deploymentEnvironment: z.enum(['development', 'test', 'production']),
    apiBaseUrl: z.string().url(),
  })
  .superRefine((value, context) => {
    let parsed: URL;
    try {
      parsed = new URL(value.apiBaseUrl);
    } catch {
      context.addIssue({
        code: 'custom',
        path: ['apiBaseUrl'],
        message: 'API base URL must be a valid URL.',
      });
      return;
    }

    if (parsed.username !== '' || parsed.password !== '') {
      context.addIssue({
        code: 'custom',
        path: ['apiBaseUrl'],
        message: 'API base URL must not include credentials.',
      });
    }

    if (parsed.search !== '' || parsed.hash !== '') {
      context.addIssue({
        code: 'custom',
        path: ['apiBaseUrl'],
        message: 'API base URL must not include a query or fragment.',
      });
    }

    if (value.deploymentEnvironment === 'production' && parsed.protocol !== 'https:') {
      context.addIssue({
        code: 'custom',
        path: ['apiBaseUrl'],
        message: 'Production API base URL must use https.',
      });
    }
  });

export type PublicConfig = z.infer<typeof publicConfigSchema>;

export function loadPublicConfigFrom(
  env: Readonly<Record<string, string | undefined>>,
): PublicConfig {
  const deploymentEnvironment = env['NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT']?.trim();
  const apiBaseUrl = env['NEXT_PUBLIC_API_BASE_URL']?.trim();
  const parsed = publicConfigSchema.safeParse({
    appName: 'PatchPilot',
    deploymentEnvironment,
    apiBaseUrl,
  });

  if (!parsed.success) {
    throw new Error(
      `Public configuration is invalid: ${parsed.error.issues.map((issue) => issue.message).join('; ')}`,
    );
  }

  return {
    ...parsed.data,
    apiBaseUrl: stripTrailingSlash(parsed.data.apiBaseUrl),
  };
}

export function loadPublicConfig(): PublicConfig {
  return loadPublicConfigFrom({
    NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: process.env['NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT'],
    NEXT_PUBLIC_API_BASE_URL: process.env['NEXT_PUBLIC_API_BASE_URL'],
  });
}

function stripTrailingSlash(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}
