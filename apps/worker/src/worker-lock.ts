export const PATCHPILOT_QUEUE_WORKER_CONCURRENCY = 2;

export function patchpilotWorkerLockDurationMs(input: {
  sbomProcessingLeaseMs: number;
  kevJobLeaseMs: number;
}): number {
  return Math.max(input.sbomProcessingLeaseMs, input.kevJobLeaseMs);
}

export function patchpilotWorkerLockRenewTimeMs(input: {
  lockDurationMs: number;
  jobLeaseRenewalIntervalMs: number;
}): number {
  const half = Math.floor(input.lockDurationMs / 2);
  const cap = Math.max(1, half - 1);
  return Math.min(input.jobLeaseRenewalIntervalMs, cap);
}
