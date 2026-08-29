#!/usr/bin/env node

/**
 * Maintainer-only CycloneDX JSON schema vendor script.
 *
 * Explicit manual execution is required:
 *   node scripts/vendor-cyclonedx-json-schema.mjs --execute
 *
 * This file is not a package.json lifecycle script, not a Turbo task, and not
 * invoked by CI, install, test, or build.
 */

import { createHash } from 'node:crypto';
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SOURCE_REPOSITORY = 'https://github.com/CycloneDX/specification';
const SOURCE_TAG = '1.6.1';
const PINNED_COMMIT = '8a27bfd1be5be0dcb2c208a34d2f4fa0b6d75bd7';

const SEED_SOURCE_PATHS = Object.freeze([
  'schema/bom-1.4.schema.json',
  'schema/bom-1.5.schema.json',
  'schema/bom-1.6.schema.json',
  'schema/jsf-0.82.schema.json',
  'schema/spdx.schema.json',
]);

const FORBIDDEN_SOURCE_PATH_PATTERN =
  /(?:^|\/)(?:bom-1\.[01237]|.*-strict|.*\.xsd|.*\.proto|ext\/|tools\/|examples?\/)/i;

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const vendorDirectory = path.join(rootDirectory, 'packages/sbom/vendor/cyclonedx-json-schema');

/**
 * @param {string} message
 * @returns {never}
 */
function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/**
 * @returns {void}
 */
function assertManualExecution() {
  if (process.env['npm_lifecycle_event']) {
    fail(
      `Refusing to vendor schemas during npm/pnpm lifecycle '${process.env['npm_lifecycle_event']}'.`,
    );
  }
  if (process.env['CI'] === 'true') {
    fail('Refusing to vendor schemas during CI.');
  }
  if (!process.argv.includes('--execute')) {
    fail('Refusing to run without explicit --execute. This script is maintainer-only.');
  }
}

/**
 * @param {readonly string[]} args
 * @param {string} cwd
 * @returns {string}
 */
function runGit(args, cwd) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    fail(`git ${args.join(' ')} failed: ${result.stderr || result.stdout}`);
  }
  return (result.stdout ?? '').trim();
}

/**
 * @param {unknown} node
 * @param {(key: string, value: unknown) => void} visit
 * @returns {void}
 */
function walkJson(node, visit) {
  if (Array.isArray(node)) {
    for (const item of node) {
      walkJson(item, visit);
    }
    return;
  }
  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      visit(key, value);
      walkJson(value, visit);
    }
  }
}

/**
 * @param {unknown} schema
 * @returns {string[]}
 */
function collectRefs(schema) {
  /** @type {string[]} */
  const refs = [];
  walkJson(schema, (key, value) => {
    if (key === '$ref' && typeof value === 'string') {
      refs.push(value);
    }
  });
  return refs;
}

/**
 * @param {string} fromSourcePath
 * @param {string} ref
 * @returns {string | undefined}
 */
function resolveLocalRef(fromSourcePath, ref) {
  const withoutFragment = ref.split('#')[0] ?? '';
  if (withoutFragment.length === 0) {
    return undefined;
  }
  if (withoutFragment.startsWith('http://') || withoutFragment.startsWith('https://')) {
    if (withoutFragment.startsWith('http://json-schema.org/')) {
      return undefined;
    }
    fail(`Unexpected remote $ref from ${fromSourcePath}: ${ref}`);
  }
  const fromDir = path.posix.dirname(fromSourcePath);
  return path.posix.normalize(`${fromDir}/${withoutFragment}`);
}

/**
 * @param {string} cloneDirectory
 * @returns {string[]}
 */
function discoverRequiredSourcePaths(cloneDirectory) {
  const required = new Set(SEED_SOURCE_PATHS);
  const pending = [...SEED_SOURCE_PATHS];

  while (pending.length > 0) {
    const sourcePath = pending.pop();
    if (sourcePath === undefined) {
      continue;
    }
    if (FORBIDDEN_SOURCE_PATH_PATTERN.test(sourcePath)) {
      fail(`Refusing forbidden schema path ${sourcePath}`);
    }
    if (!sourcePath.endsWith('.schema.json')) {
      fail(`Refusing non-JSON-schema path ${sourcePath}`);
    }
    const absolute = path.join(cloneDirectory, sourcePath);
    const schema = JSON.parse(readFileSync(absolute, 'utf8'));
    for (const ref of collectRefs(schema)) {
      const resolved = resolveLocalRef(sourcePath, ref);
      if (resolved === undefined) {
        continue;
      }
      if (!required.has(resolved)) {
        required.add(resolved);
        pending.push(resolved);
      }
    }
  }

  return [...required].sort();
}

/**
 * @param {string} filePath
 * @returns {string}
 */
function sha256OfFile(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

/**
 * @param {string} commit
 * @returns {string}
 */
function writeNotice(commit) {
  return `CycloneDX JSON Schema (vendored)

This directory contains JSON Schema files copied from:
  ${SOURCE_REPOSITORY}
  tag ${SOURCE_TAG}
  commit ${commit}

CycloneDX Specification is Copyright (c) OWASP Foundation. All Rights Reserved.
The schemas are licensed under the Apache License, Version 2.0. See LICENSE
in this directory for the license text.

JSON Signature Format (jsf-0.82.schema.json) is included because the CycloneDX
BOM schemas reference it. The upstream schema comment records that JSF was
developed by Anders Rundgren as part of the OpenKeyStore project.

PatchPilot does not download these schemas at install, test, build, runtime, or CI.
`;
}

function vendor() {
  assertManualExecution();

  const cloneParent = mkdtempSync(path.join(tmpdir(), 'patchpilot-cyclonedx-'));
  const cloneDirectory = path.join(cloneParent, 'specification');

  try {
    runGit(
      ['clone', '--branch', SOURCE_TAG, '--depth', '1', SOURCE_REPOSITORY, cloneDirectory],
      rootDirectory,
    );

    const head = runGit(['rev-parse', 'HEAD'], cloneDirectory).toLowerCase();
    const tagObject = runGit(['rev-parse', SOURCE_TAG], cloneDirectory).toLowerCase();
    const peeled = runGit(['rev-parse', `${SOURCE_TAG}^{commit}`], cloneDirectory).toLowerCase();
    const tagType = runGit(['cat-file', '-t', SOURCE_TAG], cloneDirectory);

    if (!/^[0-9a-f]{40}$/.test(head) || !/^[0-9a-f]{40}$/.test(peeled)) {
      fail('Resolved commit is not a lowercase 40-character SHA.');
    }
    if (head !== PINNED_COMMIT || peeled !== PINNED_COMMIT) {
      fail(`Resolved commit ${peeled} (HEAD ${head}) does not match pinned ${PINNED_COMMIT}.`);
    }
    if (tagType === 'commit' && tagObject !== peeled) {
      fail(`Lightweight tag ${SOURCE_TAG} does not point at peeled commit ${peeled}.`);
    }
    if (tagType === 'tag' && tagObject === peeled) {
      fail(`Annotated tag ${SOURCE_TAG} did not peel to a distinct commit object.`);
    }

    const requiredSourcePaths = discoverRequiredSourcePaths(cloneDirectory);
    for (const seed of SEED_SOURCE_PATHS) {
      if (!requiredSourcePaths.includes(seed)) {
        fail(`Seed schema ${seed} was dropped during $ref discovery.`);
      }
    }

    rmSync(vendorDirectory, { recursive: true, force: true });
    mkdirSync(vendorDirectory, { recursive: true });

    /** @type {Array<{ localPath: string; sourcePath: string; sha256: string }>} */
    const copied = [];
    for (const sourcePath of requiredSourcePaths) {
      const fileName = path.posix.basename(sourcePath);
      const destination = path.join(vendorDirectory, fileName);
      copyFileSync(path.join(cloneDirectory, sourcePath), destination);
      copied.push({
        localPath: fileName,
        sourcePath,
        sha256: sha256OfFile(destination),
      });
    }

    copyFileSync(path.join(cloneDirectory, 'LICENSE'), path.join(vendorDirectory, 'LICENSE'));
    copied.push({
      localPath: 'LICENSE',
      sourcePath: 'LICENSE',
      sha256: sha256OfFile(path.join(vendorDirectory, 'LICENSE')),
    });

    copied.sort((left, right) => left.localPath.localeCompare(right.localPath));

    writeFileSync(path.join(vendorDirectory, 'NOTICE'), writeNotice(peeled));

    const sums = copied.map((entry) => `${entry.sha256}  ${entry.localPath}`).join('\n') + '\n';
    writeFileSync(path.join(vendorDirectory, 'SHA256SUMS'), sums);

    const retrievedAt = new Date().toISOString();
    const provenance = {
      schemaVersion: '1',
      sourceRepository: SOURCE_REPOSITORY,
      sourceTag: SOURCE_TAG,
      sourceCommit: peeled,
      retrievedAt,
      license: 'Apache-2.0',
      licenseFile: 'LICENSE',
      files: copied,
    };
    writeFileSync(
      path.join(vendorDirectory, 'PROVENANCE.json'),
      `${JSON.stringify(provenance, null, 2)}\n`,
    );

    for (const entry of copied.filter((item) => item.localPath.endsWith('.schema.json'))) {
      const schema = JSON.parse(readFileSync(path.join(vendorDirectory, entry.localPath), 'utf8'));
      for (const ref of collectRefs(schema)) {
        const resolved = resolveLocalRef(entry.sourcePath, ref);
        if (resolved === undefined) {
          continue;
        }
        const localName = path.posix.basename(resolved);
        const present = copied.some((item) => item.localPath === localName);
        if (!present) {
          fail(`Local $ref ${ref} from ${entry.localPath} was not vendored.`);
        }
      }
    }

    const leftover = readdirSync(vendorDirectory).filter((name) => {
      if (name.endsWith('.schema.json')) {
        return !copied.some((item) => item.localPath === name);
      }
      return false;
    });
    if (leftover.length > 0) {
      fail(`Unexpected schema files in vendor directory: ${leftover.join(', ')}`);
    }

    process.stdout.write(
      `Vendored CycloneDX JSON schemas from ${SOURCE_TAG} (${peeled}) into ${vendorDirectory}\n`,
    );
  } finally {
    rmSync(cloneParent, { recursive: true, force: true });
  }
}

vendor();
