import { createHash, type Hash } from 'node:crypto';
import { Readable, Transform, type TransformCallback } from 'node:stream';

import type { StorageFailureCategory } from '@patchpilot/domain';

import { ObjectStorageStreamError } from './s3-errors.js';

export const SNIFF_PREFIX_MAX_BYTES = 512;

const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const JSON_WHITESPACE = new Set([0x09, 0x0a, 0x0d, 0x20]);

const PDF_MAGIC = Buffer.from('%PDF');
const ZIP_LOCAL = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const ZIP_EMPTY = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const ZIP_SPANNED = Buffer.from([0x50, 0x4b, 0x07, 0x08]);
const GZIP_MAGIC = Buffer.from([0x1f, 0x8b]);
const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
const MZ_MAGIC = Buffer.from([0x4d, 0x5a]);
const USTAR_OFFSET = 257;
const USTAR_MAGIC = Buffer.from('ustar');

export type SniffDecision = { kind: 'accept' } | { kind: 'reject' } | { kind: 'need_more' };

function startsWith(buffer: Uint8Array, magic: Uint8Array): boolean {
  if (buffer.byteLength < magic.byteLength) {
    return false;
  }

  for (let index = 0; index < magic.byteLength; index += 1) {
    if (buffer[index] !== magic[index]) {
      return false;
    }
  }

  return true;
}

function stripBom(prefix: Uint8Array): Uint8Array {
  if (prefix.byteLength >= 3 && startsWith(prefix, UTF8_BOM)) {
    return prefix.subarray(3);
  }

  return prefix;
}

function hasBlockedSignature(stripped: Uint8Array): boolean {
  if (
    startsWith(stripped, PDF_MAGIC) ||
    startsWith(stripped, ZIP_LOCAL) ||
    startsWith(stripped, ZIP_EMPTY) ||
    startsWith(stripped, ZIP_SPANNED) ||
    startsWith(stripped, GZIP_MAGIC) ||
    startsWith(stripped, ELF_MAGIC) ||
    startsWith(stripped, MZ_MAGIC)
  ) {
    return true;
  }

  if (stripped.byteLength >= USTAR_OFFSET + USTAR_MAGIC.byteLength) {
    const marker = stripped.subarray(USTAR_OFFSET, USTAR_OFFSET + USTAR_MAGIC.byteLength);
    if (startsWith(marker, USTAR_MAGIC)) {
      return true;
    }
  }

  return false;
}

function firstMeaningfulIndex(stripped: Uint8Array): number | undefined {
  for (let index = 0; index < stripped.byteLength; index += 1) {
    const value = stripped[index];
    if (value !== undefined && !JSON_WHITESPACE.has(value)) {
      return index;
    }
  }

  return undefined;
}

export function sniffSbomPrefix(prefix: Uint8Array, endOfStream: boolean): SniffDecision {
  const stripped = stripBom(prefix);

  if (hasBlockedSignature(stripped)) {
    return { kind: 'reject' };
  }

  const meaningful = firstMeaningfulIndex(stripped);
  if (meaningful !== undefined) {
    const byte = stripped[meaningful];
    if (byte === 0x7b) {
      return { kind: 'accept' };
    }

    return { kind: 'reject' };
  }

  if (endOfStream || prefix.byteLength >= SNIFF_PREFIX_MAX_BYTES) {
    return { kind: 'reject' };
  }

  return { kind: 'need_more' };
}

export function readableFromByteStream(
  body: AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
): Readable {
  if (body instanceof Readable && body.readableObjectMode === false) {
    attachAbort(body, signal);
    return body;
  }

  const iterator = body[Symbol.asyncIterator]();
  const readable = new Readable({
    objectMode: false,
    async read() {
      try {
        const next = await iterator.next();
        if (next.done) {
          this.push(null);
          return;
        }

        const chunk = next.value;
        this.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      } catch (error) {
        this.destroy(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
      }
    },
    destroy(error, callback) {
      void iterator.return?.();
      callback(error);
    },
  });
  attachAbort(readable, signal);
  return readable;
}

function attachAbort(stream: Readable, signal?: AbortSignal): void {
  if (signal === undefined) {
    return;
  }

  const onAbort = (): void => {
    stream.destroy(new ObjectStorageStreamError('aborted'));
  };

  if (signal.aborted) {
    onAbort();
    return;
  }

  signal.addEventListener('abort', onAbort, { once: true });
  stream.once('close', () => {
    signal.removeEventListener('abort', onAbort);
  });
}

export function destroyStream(stream: unknown): void {
  if (stream === null || typeof stream !== 'object' || !('destroy' in stream)) {
    return;
  }

  const destroy = (stream as { destroy?: (error?: Error) => void }).destroy;
  if (typeof destroy === 'function') {
    destroy.call(stream);
  }
}

type PutInspectOptions = {
  maxBytes: number;
};

export class PutInspectTransform extends Transform {
  private readonly hasher: Hash = createHash('sha256');
  private readonly maxBytes: number;
  private observed = 0;
  private readonly sniff = Buffer.alloc(SNIFF_PREFIX_MAX_BYTES);
  private sniffLength = 0;
  private sniffDecided = false;
  private digestHex: string | undefined;

  public constructor(options: PutInspectOptions) {
    super({ objectMode: false });
    this.maxBytes = options.maxBytes;
  }

  public observedByteLength(): number {
    return this.observed;
  }

  public sha256Hex(): string {
    if (this.digestHex === undefined) {
      throw new ObjectStorageStreamError('internal');
    }

    return this.digestHex;
  }

  public override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      this.consume(chunk, false);
      callback();
    } catch (error) {
      callback(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    }
  }

  public override _flush(callback: TransformCallback): void {
    try {
      if (!this.sniffDecided) {
        const decision = sniffSbomPrefix(this.heldPrefix(), true);
        if (decision.kind !== 'accept') {
          callback(new ObjectStorageStreamError('invalid_content'));
          return;
        }

        this.pushHeldPrefix();
        this.sniffDecided = true;
      }

      this.digestHex = this.hasher.digest('hex');
      callback();
    } catch (error) {
      callback(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    }
  }

  private consume(chunk: Buffer, endOfStream: boolean): void {
    this.hasher.update(chunk);
    this.observed += chunk.byteLength;
    if (this.observed > this.maxBytes) {
      throw new ObjectStorageStreamError('size_limit');
    }

    if (this.sniffDecided) {
      this.push(chunk);
      return;
    }

    const remaining = SNIFF_PREFIX_MAX_BYTES - this.sniffLength;
    if (remaining > 0) {
      const take = Math.min(remaining, chunk.byteLength);
      chunk.copy(this.sniff, this.sniffLength, 0, take);
      this.sniffLength += take;
    }

    const decision = sniffSbomPrefix(this.heldPrefix(), endOfStream);
    if (decision.kind === 'reject') {
      throw new ObjectStorageStreamError('invalid_content');
    }

    if (decision.kind === 'accept') {
      this.pushHeldPrefix();
      if (chunk.byteLength > remaining && remaining >= 0) {
        const rest = chunk.subarray(Math.max(remaining, 0));
        if (rest.byteLength > 0) {
          this.push(rest);
        }
      }

      this.sniffDecided = true;
      this.sniffLength = 0;
    }
  }

  private heldPrefix(): Uint8Array {
    return this.sniff.subarray(0, this.sniffLength);
  }

  private pushHeldPrefix(): void {
    if (this.sniffLength > 0) {
      this.push(Buffer.from(this.sniff.subarray(0, this.sniffLength)));
    }
  }
}

export function createPutInspectTransform(options: PutInspectOptions): PutInspectTransform {
  return new PutInspectTransform(options);
}

type GetCountOptions = {
  maxBytes: number;
  expectedByteLength?: number;
  expectedSha256?: string;
};

export class GetCountTransform extends Transform {
  private readonly hasher: Hash | undefined;
  private readonly maxBytes: number;
  private readonly expectedByteLength: number | undefined;
  private readonly expectedSha256: string | undefined;
  private observed = 0;
  private digestHex: string | undefined;

  public constructor(options: GetCountOptions) {
    super({ objectMode: false });
    this.maxBytes = options.maxBytes;
    this.expectedByteLength = options.expectedByteLength;
    this.expectedSha256 = options.expectedSha256;
    this.hasher = options.expectedSha256 === undefined ? undefined : createHash('sha256');
  }

  public observedByteLength(): number {
    return this.observed;
  }

  public sha256Hex(): string | undefined {
    return this.digestHex;
  }

  public override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      this.hasher?.update(chunk);
      this.observed += chunk.byteLength;
      if (this.observed > this.maxBytes) {
        throw new ObjectStorageStreamError('size_limit');
      }

      this.push(chunk);
      callback();
    } catch (error) {
      callback(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    }
  }

  public override _flush(callback: TransformCallback): void {
    try {
      if (this.expectedByteLength !== undefined && this.observed !== this.expectedByteLength) {
        throw new ObjectStorageStreamError('invalid_content');
      }

      if (this.hasher !== undefined) {
        this.digestHex = this.hasher.digest('hex');
        if (this.expectedSha256 !== undefined && this.digestHex !== this.expectedSha256) {
          throw new ObjectStorageStreamError('invalid_content');
        }
      }

      callback();
    } catch (error) {
      callback(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    }
  }
}

export function createGetCountTransform(options: GetCountOptions): GetCountTransform {
  return new GetCountTransform(options);
}

type HashCountOptions = {
  maxBytes: number;
  expectedByteLength?: number;
  expectedSha256?: string;
};

export class HashCountTransform extends Transform {
  private readonly hasher: Hash = createHash('sha256');
  private readonly maxBytes: number;
  private readonly expectedByteLength: number | undefined;
  private readonly expectedSha256: string | undefined;
  private observed = 0;
  private digestHex: string | undefined;

  public constructor(options: HashCountOptions) {
    super({ objectMode: false });
    this.maxBytes = options.maxBytes;
    this.expectedByteLength = options.expectedByteLength;
    this.expectedSha256 = options.expectedSha256;
  }

  public observedByteLength(): number {
    return this.observed;
  }

  public sha256Hex(): string {
    if (this.digestHex === undefined) {
      throw new ObjectStorageStreamError('internal');
    }

    return this.digestHex;
  }

  public override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    callback: TransformCallback,
  ): void {
    try {
      this.hasher.update(chunk);
      this.observed += chunk.byteLength;
      if (this.observed > this.maxBytes) {
        throw new ObjectStorageStreamError('size_limit');
      }

      this.push(chunk);
      callback();
    } catch (error) {
      callback(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    }
  }

  public override _flush(callback: TransformCallback): void {
    try {
      if (this.observed < 1) {
        throw new ObjectStorageStreamError('invalid_content');
      }

      if (this.expectedByteLength !== undefined && this.observed !== this.expectedByteLength) {
        throw new ObjectStorageStreamError('invalid_content');
      }

      this.digestHex = this.hasher.digest('hex');
      if (this.expectedSha256 !== undefined && this.digestHex !== this.expectedSha256) {
        throw new ObjectStorageStreamError('invalid_content');
      }

      callback();
    } catch (error) {
      callback(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    }
  }
}

export function createHashCountTransform(options: HashCountOptions): HashCountTransform {
  return new HashCountTransform(options);
}

export function asNodeReadable(body: unknown): Readable {
  if (body instanceof Readable) {
    return body;
  }

  if (body !== null && typeof body === 'object' && Symbol.asyncIterator in body) {
    return readableFromByteStream(body as AsyncIterable<Uint8Array>);
  }

  throw new ObjectStorageStreamError('internal');
}

export type AbortBundle = {
  signal: AbortSignal;
  callerAborted: () => boolean;
  timedOut: () => boolean;
};

export function combineAbortSignals(
  caller: AbortSignal | undefined,
  timeoutMs: number,
): AbortBundle {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = caller === undefined ? timeout : AbortSignal.any([caller, timeout]);
  return {
    signal,
    callerAborted: () => caller?.aborted === true,
    timedOut: () => timeout.aborted && caller?.aborted !== true,
  };
}

export function failureFromStream(error: unknown): StorageFailureCategory {
  if (error instanceof ObjectStorageStreamError) {
    return error.category;
  }

  return 'internal';
}
