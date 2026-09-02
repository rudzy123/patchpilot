import { createHash, type Hash } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { ClientRequest } from 'node:http';

import type {
  IntelligenceByteStream,
  IntelligenceSafeFailureCode,
  IntelligenceStreamCompletion,
} from '@patchpilot/domain';

export class IntelligenceHttpStreamError extends Error {
  public readonly code: IntelligenceSafeFailureCode;

  public constructor(code: IntelligenceSafeFailureCode) {
    super(code);
    this.name = 'IntelligenceHttpStreamError';
    this.code = code;
  }
}

export type IntelligenceHttpStreamHandle = {
  body: IntelligenceByteStream;
  completion: Promise<IntelligenceStreamCompletion>;
  timeout: () => Promise<void>;
  cancel: () => Promise<void>;
};

export type CreateIntelligenceHttpStreamInput = {
  request: ClientRequest;
  response: IncomingMessage;
  maxBytes: number;
  declaredByteLength: number | null;
  callerAborted: () => boolean;
};

function destroyHttp(request: ClientRequest, response: IncomingMessage): void {
  response.destroy();
  request.destroy();
}

export function createIntelligenceHttpStream(
  input: CreateIntelligenceHttpStreamInput,
): IntelligenceHttpStreamHandle {
  const hasher: Hash = createHash('sha256');
  let observed = 0;
  let consumed = false;
  let settled = false;
  let resolveCompletion!: (value: IntelligenceStreamCompletion) => void;
  let rejectCompletion!: (reason: { code: IntelligenceSafeFailureCode }) => void;
  const completion = new Promise<IntelligenceStreamCompletion>((resolve, reject) => {
    resolveCompletion = resolve;
    rejectCompletion = reject;
  });
  void completion.catch(() => undefined);

  const fail = (code: IntelligenceSafeFailureCode): void => {
    if (settled) {
      return;
    }

    settled = true;
    destroyHttp(input.request, input.response);
    rejectCompletion({ code });
  };

  const succeed = (sha256: string): void => {
    if (settled) {
      return;
    }

    settled = true;
    resolveCompletion({ observedByteLength: observed, sha256 });
  };

  input.response.once('aborted', () => {
    fail(input.callerAborted() ? 'request_cancelled' : 'response_timeout');
  });
  input.response.once('error', () => {
    fail(input.callerAborted() ? 'request_cancelled' : 'response_timeout');
  });

  const body: IntelligenceByteStream = {
    async *[Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      if (consumed) {
        throw new IntelligenceHttpStreamError('processing_failed');
      }

      consumed = true;
      try {
        for await (const chunk of input.response) {
          const bytes = chunk instanceof Uint8Array ? chunk : Buffer.from(chunk);
          hasher.update(bytes);
          observed += bytes.byteLength;
          if (observed > input.maxBytes) {
            fail('response_too_large');
            throw new IntelligenceHttpStreamError('response_too_large');
          }

          yield bytes;
        }

        if (observed === 0) {
          fail('response_empty');
          throw new IntelligenceHttpStreamError('response_empty');
        }

        if (input.declaredByteLength !== null && observed !== input.declaredByteLength) {
          fail('hash_mismatch');
          throw new IntelligenceHttpStreamError('hash_mismatch');
        }

        succeed(hasher.digest('hex'));
      } catch (error) {
        if (error instanceof IntelligenceHttpStreamError) {
          fail(error.code);
          throw error;
        }

        const code = input.callerAborted() ? 'request_cancelled' : 'response_timeout';
        fail(code);
        throw new IntelligenceHttpStreamError(code);
      }
    },
  };

  return {
    body,
    completion,
    timeout: async () => {
      fail(input.callerAborted() ? 'request_cancelled' : 'response_timeout');
    },
    cancel: async () => {
      fail('request_cancelled');
    },
  };
}
