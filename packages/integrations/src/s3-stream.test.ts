import { createHash } from 'node:crypto';
import { Readable, Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import { describe, expect, it } from 'vitest';

import {
  createGetCountTransform,
  createPutInspectTransform,
  readableFromByteStream,
  sniffSbomPrefix,
  SNIFF_PREFIX_MAX_BYTES,
} from './s3-stream.js';
import { ObjectStorageStreamError } from './s3-errors.js';

async function collect(transform: Transform, source: Uint8Array): Promise<Buffer> {
  const chunks: Buffer[] = [];
  const sink = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk as Buffer));
      callback();
    },
  });
  await pipeline(Readable.from([source], { objectMode: false }), transform, sink);
  return Buffer.concat(chunks);
}

describe('sniffSbomPrefix', () => {
  it('accepts JSON objects, including a UTF-8 BOM and leading whitespace', () => {
    expect(sniffSbomPrefix(Buffer.from('{'), true)).toEqual({ kind: 'accept' });
    expect(sniffSbomPrefix(Buffer.from('\uFEFF  \n{'), false)).toEqual({ kind: 'accept' });
    expect(sniffSbomPrefix(Buffer.from('  '), false)).toEqual({ kind: 'need_more' });
  });

  it('rejects empty, whitespace-only, arrays, XML, and blocked signatures', () => {
    expect(sniffSbomPrefix(Buffer.from(''), true).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from('   \n'), true).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from('[]'), false).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from('<bom/>'), false).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from('%PDF-1.4'), false).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from([0x50, 0x4b, 0x03, 0x04]), false).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from([0x1f, 0x8b, 0x08]), false).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from([0x7f, 0x45, 0x4c, 0x46]), false).kind).toBe('reject');
    expect(sniffSbomPrefix(Buffer.from('MZ'), false).kind).toBe('reject');
    const tar = Buffer.alloc(262);
    Buffer.from('ustar').copy(tar, 257);
    expect(sniffSbomPrefix(tar, false).kind).toBe('reject');
  });

  it('rejects a full 512-byte prefix with no meaningful JSON object byte', () => {
    expect(sniffSbomPrefix(Buffer.alloc(SNIFF_PREFIX_MAX_BYTES, 0x20), false).kind).toBe('reject');
  });
});

describe('PutInspectTransform', () => {
  it('counts and hashes original bytes including a UTF-8 BOM', async () => {
    const bomJson = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":1}')]);
    const transform = createPutInspectTransform({ maxBytes: 1024 });
    const collected = await collect(transform, bomJson);
    expect(collected.equals(bomJson)).toBe(true);
    expect(transform.observedByteLength()).toBe(bomJson.byteLength);
    expect(transform.sha256Hex()).toBe(createHash('sha256').update(bomJson).digest('hex'));
  });

  it('rejects over-limit streams during consumption', async () => {
    const transform = createPutInspectTransform({ maxBytes: 4 });
    await expect(collect(transform, Buffer.from('{"abcd"}'))).rejects.toBeInstanceOf(
      ObjectStorageStreamError,
    );
    try {
      await collect(createPutInspectTransform({ maxBytes: 4 }), Buffer.from('{"abcd"}'));
    } catch (error) {
      expect(error).toMatchObject({ category: 'size_limit' });
    }
  });

  it('rejects a blocked prefix without buffering the document', async () => {
    const transform = createPutInspectTransform({ maxBytes: 1024 });
    await expect(collect(transform, Buffer.from('%PDF-1.4 rest'))).rejects.toMatchObject({
      category: 'invalid_content',
    });
  });
});

describe('GetCountTransform', () => {
  it('resolves observed length only after end-of-stream and verifies a hash', async () => {
    const payload = Buffer.from('{"ok":true}');
    const transform = createGetCountTransform({
      maxBytes: 1024,
      expectedByteLength: payload.byteLength,
      expectedSha256: createHash('sha256').update(payload).digest('hex'),
    });
    const collected = await collect(transform, payload);
    expect(collected.equals(payload)).toBe(true);
    expect(transform.observedByteLength()).toBe(payload.byteLength);
    expect(transform.sha256Hex()).toBe(createHash('sha256').update(payload).digest('hex'));
  });

  it('rejects a final hash mismatch', async () => {
    const transform = createGetCountTransform({
      maxBytes: 1024,
      expectedSha256: 'a'.repeat(64),
    });
    await expect(collect(transform, Buffer.from('{}'))).rejects.toMatchObject({
      category: 'invalid_content',
    });
  });
});

describe('readableFromByteStream', () => {
  it('yields original bytes from an async iterable without concatenating the document', async () => {
    async function* chunks(): AsyncGenerator<Uint8Array> {
      yield new Uint8Array([0x7b]);
      yield new Uint8Array([0x7d]);
    }

    const readable = readableFromByteStream(chunks());
    const collected: Buffer[] = [];
    for await (const chunk of readable) {
      collected.push(Buffer.from(chunk as Buffer));
    }

    expect(Buffer.concat(collected).toString('utf8')).toBe('{}');
    expect(readable.readableObjectMode).toBe(false);
  });
});
