import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { readOfflineNpmImportDirectory } from './offline-npm-osv-import-directory.js';

const encoder = new TextEncoder();

function temporaryDirectory(): string {
  return mkdtempSync(path.join(tmpdir(), 'offline-import-path-token-'));
}

describe('offline npm OSV import directory preflight', () => {
  it('reads regular files in code-unit order', async () => {
    const directory = temporaryDirectory();
    try {
      writeFileSync(path.join(directory, 'b.json'), 'B');
      writeFileSync(path.join(directory, 'a.json'), 'A');
      const read = await readOfflineNpmImportDirectory(directory);
      expect(read.ok).toBe(true);
      if (read.ok) {
        expect(read.files.map((file) => file.name)).toEqual(['a.json', 'b.json']);
        expect(new TextDecoder().decode(read.files[0]?.bytes)).toBe('A');
        expect(new TextDecoder().decode(read.files[1]?.bytes)).toBe('B');
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('does not follow a symlink file', async () => {
    const directory = temporaryDirectory();
    try {
      const target = path.join(directory, 'target.json');
      writeFileSync(target, '{"secret":"do-not-follow"}');
      symlinkSync(target, path.join(directory, 'link.json'));
      writeFileSync(path.join(directory, 'b.json'), '{"id":"B"}');
      writeFileSync(path.join(directory, 'a.json'), '{"id":"A"}');
      const read = await readOfflineNpmImportDirectory(directory);
      expect(read.ok).toBe(false);
      if (!read.ok) {
        expect(read.reason).toBe('directory_rejected');
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('admits an empty directory and rejects a subdirectory, a hidden name, and a fifo', async () => {
    const empty = temporaryDirectory();
    const nested = temporaryDirectory();
    const hidden = temporaryDirectory();
    const fifo = temporaryDirectory();
    try {
      await expect(readOfflineNpmImportDirectory(empty)).resolves.toEqual({
        ok: true,
        files: [],
        unreadable: [],
      });
      mkdirSync(path.join(nested, 'npm'));
      const nestedRead = await readOfflineNpmImportDirectory(nested);
      expect(nestedRead).toEqual({ ok: false, reason: 'directory_rejected' });
      writeFileSync(path.join(hidden, '.hidden.json'), '{}');
      const hiddenRead = await readOfflineNpmImportDirectory(hidden);
      expect(hiddenRead).toEqual({ ok: false, reason: 'directory_rejected' });
      execFileSync('mkfifo', [path.join(fifo, 'pipe')]);
      const fifoRead = await readOfflineNpmImportDirectory(fifo);
      expect(fifoRead).toEqual({ ok: false, reason: 'directory_rejected' });
    } finally {
      rmSync(empty, { recursive: true, force: true });
      rmSync(nested, { recursive: true, force: true });
      rmSync(hidden, { recursive: true, force: true });
      rmSync(fifo, { recursive: true, force: true });
    }
  });

  it('rejects a file larger than the parser ceiling and a symlink directory', async () => {
    const oversized = temporaryDirectory();
    const real = temporaryDirectory();
    const parent = temporaryDirectory();
    try {
      writeFileSync(path.join(oversized, 'big.json'), Buffer.alloc(1_048_577, 0x61));
      const oversizedRead = await readOfflineNpmImportDirectory(oversized);
      expect(oversizedRead).toEqual({ ok: false, reason: 'directory_rejected' });
      writeFileSync(path.join(real, 'a.json'), encoder.encode('{}'));
      const link = path.join(parent, 'linked');
      symlinkSync(real, link);
      const linked = await readOfflineNpmImportDirectory(link);
      expect(linked.ok).toBe(false);
    } finally {
      rmSync(oversized, { recursive: true, force: true });
      rmSync(real, { recursive: true, force: true });
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('keeps a readable sibling when one file cannot be read', async () => {
    const directory = temporaryDirectory();
    try {
      writeFileSync(path.join(directory, 'readable.json'), '{"id":"A"}');
      const locked = path.join(directory, 'locked.json');
      writeFileSync(locked, '{"id":"B"}');
      chmodSync(locked, 0);
      const read = await readOfflineNpmImportDirectory(directory);
      expect(read.ok).toBe(true);
      if (!read.ok) {
        return;
      }
      expect(read.unreadable).toEqual(['locked.json']);
      expect(read.files).toHaveLength(1);
      expect(read.files[0]?.name).toBe('readable.json');
      expect(Buffer.from(read.files[0]?.bytes ?? []).toString('utf8')).toBe('{"id":"A"}');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects a URL directory argument before opening it', async () => {
    await expect(readOfflineNpmImportDirectory('https://example.test/npm')).resolves.toEqual({
      ok: false,
      reason: 'directory_rejected',
    });
    await expect(readOfflineNpmImportDirectory('file:///tmp/advisories')).resolves.toEqual({
      ok: false,
      reason: 'directory_rejected',
    });
  });
});
