/**
 * Filesystem preflight for the deployment-local offline npm OSV import.
 * Lists one directory through the opened file descriptor and does not recurse.
 * Symlinks are not followed. This module does not open a network socket.
 */

import { constants } from 'node:fs';
import { open, readdir, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

import {
  OFFLINE_NPM_OSV_IMPORT_MAX_FILE_BYTES,
  OFFLINE_NPM_OSV_IMPORT_MAX_FILES,
  compareOfflineNpmImportNames,
  offlineNpmImportDirectoryArgumentRejection,
  offlineNpmImportEntryNameRejection,
} from '@patchpilot/vulnerability-intelligence';

export type OfflineNpmImportAdmittedFile = {
  readonly name: string;
  readonly bytes: Uint8Array;
};

export type OfflineNpmImportDirectoryRead =
  | { readonly ok: true; readonly files: readonly OfflineNpmImportAdmittedFile[] }
  | { readonly ok: false; readonly reason: 'directory_rejected' | 'unreadable_file' };

const DIRECTORY_FLAGS = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const FILE_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;

export async function readOfflineNpmImportDirectory(
  directory: string,
): Promise<OfflineNpmImportDirectoryRead> {
  if (
    offlineNpmImportDirectoryArgumentRejection(directory) !== null ||
    !Number.isInteger(constants.O_NOFOLLOW) ||
    !Number.isInteger(constants.O_DIRECTORY) ||
    !Number.isInteger(constants.O_NONBLOCK)
  ) {
    return { ok: false, reason: 'directory_rejected' };
  }
  let directoryHandle: FileHandle | undefined;
  try {
    directoryHandle = await open(directory, DIRECTORY_FLAGS);
    const opened = await directoryHandle.stat();
    if (!opened.isDirectory()) {
      return { ok: false, reason: 'directory_rejected' };
    }
    const fd = directoryHandle.fd;
    if (!Number.isInteger(fd) || fd < 0) {
      return { ok: false, reason: 'directory_rejected' };
    }
    const directoryFdPath = `/proc/self/fd/${String(fd)}`;
    const names = await readdir(directoryFdPath, { encoding: 'utf8' });
    if (names.length > OFFLINE_NPM_OSV_IMPORT_MAX_FILES) {
      return { ok: false, reason: 'directory_rejected' };
    }
    for (const name of names) {
      if (offlineNpmImportEntryNameRejection(name) !== null) {
        return { ok: false, reason: 'directory_rejected' };
      }
    }
    const files: OfflineNpmImportAdmittedFile[] = [];
    for (const name of [...names].sort(compareOfflineNpmImportNames)) {
      const read = await readAdmittedFile(directoryFdPath, name);
      if (!read.ok) {
        return read;
      }
      files.push(read.file);
    }
    return { ok: true, files };
  } catch {
    return { ok: false, reason: 'directory_rejected' };
  } finally {
    await directoryHandle?.close().catch(() => undefined);
  }
}

async function readAdmittedFile(
  directoryFdPath: string,
  name: string,
): Promise<
  | { readonly ok: true; readonly file: OfflineNpmImportAdmittedFile }
  | { readonly ok: false; readonly reason: 'directory_rejected' | 'unreadable_file' }
> {
  if (offlineNpmImportEntryNameRejection(name) !== null) {
    return { ok: false, reason: 'directory_rejected' };
  }
  const child = path.join(directoryFdPath, name);
  if (path.basename(child) !== name) {
    return { ok: false, reason: 'directory_rejected' };
  }
  let handle: FileHandle | undefined;
  try {
    handle = await open(child, FILE_FLAGS);
    const stat = await handle.stat();
    if (!stat.isFile()) {
      return { ok: false, reason: 'directory_rejected' };
    }
    if (
      !Number.isSafeInteger(stat.size) ||
      stat.size < 0 ||
      stat.size > OFFLINE_NPM_OSV_IMPORT_MAX_FILE_BYTES
    ) {
      return { ok: false, reason: 'directory_rejected' };
    }
    const bytes = await readExact(handle, stat.size);
    if (bytes === null) {
      return { ok: false, reason: 'unreadable_file' };
    }
    const after = await handle.stat();
    if (!after.isFile() || after.size !== stat.size) {
      return { ok: false, reason: 'unreadable_file' };
    }
    return { ok: true, file: { name, bytes } };
  } catch (error) {
    const code = errorCode(error);
    if (code === 'ELOOP' || code === 'EISDIR' || code === 'ENOTDIR' || code === 'ENXIO') {
      return { ok: false, reason: 'directory_rejected' };
    }
    return { ok: false, reason: 'unreadable_file' };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function readExact(handle: FileHandle, size: number): Promise<Uint8Array | null> {
  const buffer = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const result = await handle.read(buffer, offset, size - offset, offset);
    if (result.bytesRead === 0) {
      return null;
    }
    offset += result.bytesRead;
  }
  return buffer;
}

function errorCode(error: unknown): string | null {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return null;
  }
  const code = error.code;
  return typeof code === 'string' ? code : null;
}
