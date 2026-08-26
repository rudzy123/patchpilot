import { PrismaClient } from '@prisma/client';

export type DatabaseReadiness = {
  ok: boolean;
};

let prismaClient: PrismaClient | undefined;

export function getPrismaClient(options?: { databaseUrl?: string }): PrismaClient {
  prismaClient ??= new PrismaClient({
    log: [],
    ...(options?.databaseUrl === undefined
      ? {}
      : {
          datasources: {
            db: {
              url: options.databaseUrl,
            },
          },
        }),
  });
  return prismaClient;
}

export async function disconnectPrisma(): Promise<void> {
  if (prismaClient === undefined) {
    return;
  }

  const client = prismaClient;
  prismaClient = undefined;
  await client.$disconnect();
}

export async function checkDatabaseReady(
  timeoutMs: number,
  options?: { databaseUrl?: string },
): Promise<DatabaseReadiness> {
  const client = getPrismaClient(options);

  try {
    await Promise.race([
      client.$queryRaw`SELECT 1`,
      new Promise<never>((_resolve, reject) => {
        setTimeout(() => {
          reject(new Error('database readiness timed out'));
        }, timeoutMs);
      }),
    ]);
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

export function resetPrismaClientForTests(): void {
  prismaClient = undefined;
}
