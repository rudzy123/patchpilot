import { z } from 'zod';

export const publicConfigSchema = z.object({
  appName: z.literal('PatchPilot'),
  deploymentEnvironment: z.enum(['development', 'test', 'production']),
});

export type PublicConfig = z.infer<typeof publicConfigSchema>;

export function loadPublicConfigFrom(
  env: Readonly<Record<string, string | undefined>>,
): PublicConfig {
  const deploymentEnvironment = env['NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT']?.trim();
  const parsed = publicConfigSchema.safeParse({
    appName: 'PatchPilot',
    deploymentEnvironment: deploymentEnvironment ?? 'development',
  });

  if (!parsed.success) {
    throw new Error(
      `Public configuration is invalid: ${parsed.error.issues.map((issue) => issue.message).join('; ')}`,
    );
  }

  return parsed.data;
}

export function loadPublicConfig(): PublicConfig {
  return loadPublicConfigFrom(process.env);
}
