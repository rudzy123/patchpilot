import { hostname } from 'node:os';

export const BACKGROUND_JOB_WORKER_IDENTIFIER_MAX_LENGTH = 128;

export function createBackgroundJobWorkerIdentifier(
  host: string = hostname(),
  pid: number = process.pid,
): string {
  const value = `${host}:${String(pid)}`;
  if (value.length <= BACKGROUND_JOB_WORKER_IDENTIFIER_MAX_LENGTH) {
    return value;
  }
  return value.slice(0, BACKGROUND_JOB_WORKER_IDENTIFIER_MAX_LENGTH);
}
