import { PrismaClient } from '@prisma/client';

export type DatabaseReadiness = {
  ok: boolean;
};

let prismaClient: PrismaClient | undefined;
let configuredDatabaseUrl: string | undefined;

export function getPrismaClient(options?: { databaseUrl?: string }): PrismaClient {
  const requestedUrl = options?.databaseUrl;

  if (prismaClient !== undefined) {
    if (requestedUrl !== undefined && requestedUrl !== configuredDatabaseUrl) {
      throw new Error('Prisma client is already initialized with a different database URL.');
    }

    return prismaClient;
  }

  configuredDatabaseUrl = requestedUrl;
  prismaClient = new PrismaClient({
    log: [],
    ...(requestedUrl === undefined
      ? {}
      : {
          datasources: {
            db: {
              url: requestedUrl,
            },
          },
        }),
  });
  return prismaClient;
}

export async function disconnectPrisma(): Promise<void> {
  if (prismaClient === undefined) {
    configuredDatabaseUrl = undefined;
    return;
  }

  const client = prismaClient;
  prismaClient = undefined;
  configuredDatabaseUrl = undefined;
  await client.$disconnect();
}

async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error(message));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

export async function checkDatabaseReady(
  timeoutMs: number,
  options?: { databaseUrl?: string },
): Promise<DatabaseReadiness> {
  const client = getPrismaClient(options);

  try {
    await withTimeout(client.$queryRaw`SELECT 1`, timeoutMs, 'database readiness timed out');
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

export function resetPrismaClientForTests(): void {
  prismaClient = undefined;
  configuredDatabaseUrl = undefined;
}
