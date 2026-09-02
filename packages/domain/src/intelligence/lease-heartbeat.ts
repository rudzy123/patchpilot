import type { Clock } from '../clock.js';
import { err, type Result } from '../result.js';
import type {
  BackgroundJobExecutionPort,
  BackgroundJobLease,
  RenewBackgroundJobLeaseInput,
} from '../sbom/ports.js';

export type IntelligenceLeaseHeartbeatOwnership = {
  jobId: string;
  workerIdentifier: string;
  organizationId: null;
};

export type IntelligenceLeaseHeartbeatScheduler = {
  schedule(intervalMs: number, tick: () => void): { stop(): void };
};

export type IntelligenceLeaseHeartbeat = {
  readonly signal: AbortSignal;
  start(): void;
  stop(): void;
  renewNow(): Promise<Result<BackgroundJobLease>>;
};

export function createIntervalLeaseHeartbeatScheduler(): IntelligenceLeaseHeartbeatScheduler {
  return {
    schedule(intervalMs, tick) {
      const handle = setInterval(tick, intervalMs);
      return {
        stop() {
          clearInterval(handle);
        },
      };
    },
  };
}

export function createIntelligenceLeaseHeartbeat(input: {
  jobs: BackgroundJobExecutionPort;
  ownership: IntelligenceLeaseHeartbeatOwnership;
  clock: Clock;
  leaseMs: number;
  intervalMs: number;
  scheduler?: IntelligenceLeaseHeartbeatScheduler;
  parentSignal?: AbortSignal;
}): IntelligenceLeaseHeartbeat {
  const controller = new AbortController();
  const scheduler = input.scheduler ?? createIntervalLeaseHeartbeatScheduler();
  let handle: { stop(): void } | undefined;
  let stopped = false;
  let renewInFlight: Promise<Result<BackgroundJobLease>> | undefined;

  const abort = (): void => {
    if (!controller.signal.aborted) {
      controller.abort();
    }
  };

  if (input.parentSignal !== undefined) {
    if (input.parentSignal.aborted) {
      abort();
    } else {
      input.parentSignal.addEventListener('abort', abort, { once: true });
    }
  }

  const renewInput = (): RenewBackgroundJobLeaseInput => {
    const now = input.clock.now();
    return {
      organizationId: null,
      jobId: input.ownership.jobId,
      workerIdentifier: input.ownership.workerIdentifier,
      now,
      leaseExpiresAt: new Date(now.getTime() + input.leaseMs),
    };
  };

  const renewNow = async (): Promise<Result<BackgroundJobLease>> => {
    if (stopped || controller.signal.aborted) {
      return err({ code: 'conflict', message: 'Intelligence job lease is no longer owned.' });
    }
    if (renewInFlight !== undefined) {
      return renewInFlight;
    }
    renewInFlight = input.jobs.renewLease(renewInput());
    try {
      const result = await renewInFlight;
      if (!result.ok) {
        abort();
      }
      return result;
    } finally {
      renewInFlight = undefined;
    }
  };

  return {
    get signal() {
      return controller.signal;
    },
    start() {
      if (stopped || handle !== undefined || controller.signal.aborted) {
        return;
      }
      handle = scheduler.schedule(input.intervalMs, () => {
        void renewNow();
      });
    },
    stop() {
      stopped = true;
      handle?.stop();
      handle = undefined;
    },
    renewNow,
  };
}
