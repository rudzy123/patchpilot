#!/usr/bin/env node

/**
 * Maintainer-only CISA KEV JSON Schema vendor script.
 *
 * Explicit manual execution is required:
 *   node scripts/vendor-cisa-kev-schema.mjs --execute
 *
 * This file is not a package.json lifecycle script, not a Turbo task, and not
 * invoked by CI, install, test, build, or runtime. It fetches only the official
 * CISA KEV JSON Schema. It never fetches the production KEV catalog, CSV, HTML,
 * OSV data, license contents, or arbitrary reference URLs.
 */

import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const APPROVED_SOURCE_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json';
const APPROVED_HOSTNAME = 'www.cisa.gov';
const APPROVED_PATH = '/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json';
const APPROVED_SHA256 = '577f4ccc06b7b7c6a109e1a0d6457a26db7fc5219398ff2e287b9a7e14e2d9ef';
const APPROVED_BYTE_LENGTH = 3407;
const APPROVED_INTERNAL_REF = '#/$defs/vulnerability';
const APPROVED_FORMATS = Object.freeze(['date', 'date-time']);
const MAX_RESPONSE_BYTES = 65_536;
const CONNECT_TIMEOUT_MS = 5_000;
const TOTAL_TIMEOUT_MS = 30_000;
const USER_AGENT =
  'PatchPilot-maintainer-vendor-cisa-kev-schema/1 (maintainer-only; official JSON Schema only; does not fetch the KEV catalog)';
const SCHEMA_FILE_NAME = 'known_exploited_vulnerabilities_schema.json';
const LICENSE_URL = 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt';
const SOURCE_ORGANIZATION = 'CISA';
const SOURCE_WEBSITE = 'https://www.cisa.gov';
const AMBIENT_PROXY_VARIABLES = Object.freeze([
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
]);

const CC0_1_0_UNIVERSAL = `Creative Commons Legal Code

CC0 1.0 Universal

    CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
    LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
    ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
    INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
    REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
    PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
    THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
    HEREUNDER.

Statement of Purpose

The laws of most jurisdictions throughout the world automatically confer
exclusive Copyright and Related Rights (defined below) upon the creator
and subsequent owner(s) (each and all, an "owner") of an original work of
authorship and/or a database (each, a "Work").

Certain owners wish to permanently relinquish those rights to a Work for
the purpose of contributing to a commons of creative, cultural and
scientific works ("Commons") that the public can reliably and without fear
of later claims of infringement build upon, modify, incorporate in other
works, reuse and redistribute as freely as possible in any form whatsoever
and for any purposes, including without limitation commercial purposes.
These owners may contribute to the Commons to promote the ideal of a free
culture and the further production of creative, cultural and scientific
works, or to gain reputation or greater distribution for their Work in
part through the use and efforts of others.

For these and/or other purposes and motivations, and without any
expectation of additional consideration or compensation, the person
associating CC0 with a Work (the "Affirmer"), to the extent that he or she
is an owner of Copyright and Related Rights in the Work, voluntarily
elects to apply CC0 to the Work and publicly distribute the Work under its
terms, with knowledge of his or her Copyright and Related Rights in the
Work and the meaning and intended legal effect of CC0 on those rights.

1. Copyright and Related Rights. A Work made available under CC0 may be
protected by copyright and related or neighboring rights ("Copyright and
Related Rights"). Copyright and Related Rights include, but are not
limited to, the following:

  i. the right to reproduce, adapt, distribute, perform, display,
     communicate, and translate a Work;
 ii. moral rights retained by the original author(s) and/or performer(s);
iii. publicity and privacy rights pertaining to a person's image or
     likeness depicted in a Work;
 iv. rights protecting against unfair competition in regards to a Work,
     subject to the limitations in paragraph 4(a), below;
  v. rights protecting the extraction, dissemination, use and reuse of data
     in a Work;
 vi. database rights (such as those arising under Directive 96/9/EC of the
     European Parliament and of the Council of 11 March 1996 on the legal
     protection of databases, and under any national implementation
     thereof, including any amended or successor version of such
     directive); and
vii. other similar, equivalent or corresponding rights throughout the
     world based on applicable law or treaty, and any national
     implementations thereof.

2. Waiver. To the greatest extent permitted by, but not in contravention
of, applicable law, Affirmer hereby overtly, fully, permanently,
irrevocably and unconditionally waives, abandons, and surrenders all of
Affirmer's Copyright and Related Rights and associated claims and causes
of action, whether now known or unknown (including existing as well as
future claims and causes of action), in the Work (i) in all territories
worldwide, (ii) for the maximum duration provided by applicable law or
treaty (including future time extensions), (iii) in any current or future
medium and for any number of copies, and (iv) for any purpose whatsoever,
including without limitation commercial, advertising or promotional
purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each
member of the public at large and to the detriment of Affirmer's heirs and
successors, fully intending that such Waiver shall not be subject to
revocation, rescission, cancellation, termination, or any other legal or
equitable action to disrupt the quiet enjoyment of the Work by the public
as contemplated by Affirmer's express Statement of Purpose.

3. Public License Fallback. Should any part of the Waiver for any reason
be judged legally invalid or ineffective under applicable law, then the
Waiver shall be preserved to the maximum extent permitted taking into
account Affirmer's express Statement of Purpose. In addition, to the
extent the Waiver is so judged Affirmer hereby grants to each affected
person a royalty-free, non transferable, non sublicensable, non exclusive,
irrevocable and unconditional license to exercise Affirmer's Copyright and
Related Rights in the Work (i) in all territories worldwide, (ii) for the
maximum duration provided by applicable law or treaty (including future
time extensions), (iii) in any current or future medium and for any number
of copies, and (iv) for any purpose whatsoever, including without
limitation commercial, advertising or promotional purposes (the
"License"). The License shall be deemed effective as of the date CC0 was
applied by Affirmer to the Work. Should any part of the License for any
reason be judged legally invalid or ineffective under applicable law, such
partial invalidity or ineffectiveness shall not invalidate the remainder
of the License, and in such case Affirmer hereby affirms that he or she
will not (i) exercise any of his or her remaining Copyright and Related
Rights in the Work or (ii) assert any associated claims and causes of
action with respect to the Work, in either case contrary to Affirmer's
express Statement of Purpose.

4. Limitations and Disclaimers.

 a. No trademark or patent rights held by Affirmer are waived, abandoned,
    surrendered, licensed or otherwise affected by this document.
 b. Affirmer offers the Work as-is and makes no representations or
    warranties of any kind concerning the Work, express, implied,
    statutory or otherwise, including without limitation warranties of
    title, merchantability, fitness for a particular purpose, non
    infringement, or the absence of latent or other defects, accuracy, or
    the present or absence of errors, whether or not discoverable, all to
    the greatest extent permissible under applicable law.
 c. Affirmer disclaims responsibility for clearing rights of other persons
    that may apply to the Work or any use thereof, including without
    limitation any person's Copyright and Related Rights in the Work.
    Further, Affirmer disclaims responsibility for obtaining any necessary
    consents, permissions or other rights required for any use of the
    Work.
 d. Affirmer understands and acknowledges that Creative Commons is not a
    party to this document and has no duty or obligation with respect to
    this CC0 or use of the Work.
`;

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const vendorDirectory = path.join(
  rootDirectory,
  'packages/vulnerability-intelligence/vendor/cisa-kev-schema',
);

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
      `Refusing to vendor the CISA KEV schema during npm/pnpm lifecycle '${process.env['npm_lifecycle_event']}'.`,
    );
  }
  if (process.env['CI'] === 'true') {
    fail('Refusing to vendor the CISA KEV schema during CI.');
  }
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0] !== '--execute') {
    fail(
      'Refusing to run without explicit --execute as the only argument. This script is maintainer-only.',
    );
  }
}

/**
 * @returns {void}
 */
function assertNoAmbientProxy() {
  const present = AMBIENT_PROXY_VARIABLES.filter((name) => {
    const value = process.env[name];
    return value !== undefined && value.length > 0;
  });
  if (present.length > 0) {
    fail(
      `Refusing to vendor while ambient proxy variables are set (${present.join(', ')}). Unset them or run without a proxy.`,
    );
  }
}

/**
 * @param {string} urlString
 * @returns {URL}
 */
function parseApprovedUrl(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    fail('Approved source URL is not a valid URL.');
  }
  if (parsed.href !== APPROVED_SOURCE_URL) {
    fail('Refusing changed protocol, host, path, port, credentials, query, or fragment.');
  }
  if (parsed.protocol !== 'https:') {
    fail('Refusing non-HTTPS schema URL.');
  }
  if (parsed.hostname !== APPROVED_HOSTNAME) {
    fail('Refusing schema URL host that is not www.cisa.gov.');
  }
  if (parsed.pathname !== APPROVED_PATH) {
    fail('Refusing schema URL path that is not the official KEV JSON Schema path.');
  }
  if (parsed.port !== '') {
    fail('Refusing schema URL with a non-default port.');
  }
  if (parsed.username !== '' || parsed.password !== '') {
    fail('Refusing schema URL with credentials.');
  }
  if (parsed.search !== '') {
    fail('Refusing schema URL with a query string.');
  }
  if (parsed.hash !== '') {
    fail('Refusing schema URL with a fragment.');
  }
  return parsed;
}

/**
 * @param {string | string[] | undefined} value
 * @param {string} name
 * @returns {string | undefined}
 */
function singleHeader(value, name) {
  if (value === undefined) {
    return undefined;
  }
  if (Array.isArray(value)) {
    if (value.length !== 1 || value[0] === undefined) {
      fail(`Unexpected multi-value ${name} header.`);
    }
    return value[0];
  }
  return value;
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isApprovedJsonContentType(value) {
  const trimmed = value.trim();
  if (/^application\/json$/i.test(trimmed)) {
    return true;
  }
  return /^application\/json\s*;\s*charset\s*=\s*[A-Za-z0-9._-]+$/.test(trimmed);
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
 * @returns {void}
 */
function assertOfficialSchemaShape(schema) {
  if (typeof schema !== 'object' || schema === null || Array.isArray(schema)) {
    fail('Official schema is not a JSON object.');
  }
  const record = /** @type {Record<string, unknown>} */ (schema);
  const draft = record['$schema'];
  if (typeof draft !== 'string' || !draft.includes('draft-07')) {
    fail(
      'Official schema is not JSON Schema draft-07. A changed upstream schema needs explicit review.',
    );
  }

  /** @type {string[]} */
  const refs = [];
  /** @type {string[]} */
  const formats = [];
  walkJson(schema, (key, value) => {
    if (key === '$ref') {
      if (typeof value !== 'string') {
        fail('Official schema has a non-string $ref.');
      }
      refs.push(value);
    }
    if (key === 'format') {
      if (typeof value !== 'string') {
        fail('Official schema has a non-string format keyword.');
      }
      formats.push(value);
    }
  });

  if (refs.length !== 1 || refs[0] !== APPROVED_INTERNAL_REF) {
    fail(
      'Official schema must contain exactly one internal $ref (#/$defs/vulnerability). A changed upstream schema needs explicit review.',
    );
  }
  for (const ref of refs) {
    if (ref.startsWith('http://') || ref.startsWith('https://') || !ref.startsWith('#')) {
      fail(`Official schema contains a remote or non-internal $ref: ${ref}`);
    }
  }

  const uniqueFormats = [...new Set(formats)].sort();
  if (
    uniqueFormats.length !== APPROVED_FORMATS.length ||
    uniqueFormats.some((format, index) => format !== APPROVED_FORMATS[index])
  ) {
    fail(
      'Official schema format inventory is not exactly date and date-time. A changed upstream schema needs explicit review.',
    );
  }

  const defs = record['$defs'];
  if (
    typeof defs !== 'object' ||
    defs === null ||
    Array.isArray(defs) ||
    !('vulnerability' in defs)
  ) {
    fail('Official schema is missing the required $defs.vulnerability target.');
  }

  if (typeof record['url'] !== 'string') {
    fail(
      'Official schema is missing the expected top-level url annotation. Do not edit the schema.',
    );
  }
}

/**
 * @returns {Promise<{ bytes: Buffer; contentType: string; lastModified: string | undefined; etag: string | undefined }>}
 */
function fetchOfficialSchema() {
  const parsed = parseApprovedUrl(APPROVED_SOURCE_URL);
  assertNoAmbientProxy();

  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let received = 0;
    let settled = false;
    /** @type {ReturnType<typeof setTimeout> | undefined} */
    let totalTimer;

    /**
     * @param {Error} error
     * @returns {void}
     */
    const settleError = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      if (totalTimer !== undefined) {
        clearTimeout(totalTimer);
      }
      reject(error);
    };

    const request = https.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: 443,
        path: parsed.pathname,
        method: 'GET',
        timeout: CONNECT_TIMEOUT_MS,
        rejectUnauthorized: true,
        headers: {
          Accept: 'application/json',
          'User-Agent': USER_AGENT,
        },
      },
      (response) => {
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) {
          response.resume();
          settleError(
            new Error(`Refusing HTTP redirect (${status}). Redirect following is disabled.`),
          );
          return;
        }
        if (status !== 200) {
          response.resume();
          settleError(new Error(`Unexpected HTTP status ${status} for the official schema.`));
          return;
        }

        const contentType = singleHeader(response.headers['content-type'], 'Content-Type');
        if (contentType === undefined || !isApprovedJsonContentType(contentType)) {
          response.resume();
          settleError(
            new Error(
              'Official schema Content-Type must be application/json with an optional charset parameter.',
            ),
          );
          return;
        }

        response.on('data', (chunk) => {
          received += chunk.length;
          if (received > MAX_RESPONSE_BYTES) {
            request.destroy();
            settleError(
              new Error(`Response exceeded maximum size of ${MAX_RESPONSE_BYTES} bytes.`),
            );
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (settled) {
            return;
          }
          settled = true;
          if (totalTimer !== undefined) {
            clearTimeout(totalTimer);
          }
          resolve({
            bytes: Buffer.concat(chunks),
            contentType,
            lastModified: singleHeader(response.headers['last-modified'], 'Last-Modified'),
            etag: singleHeader(response.headers['etag'], 'ETag'),
          });
        });
        response.on('error', (error) => {
          settleError(error);
        });
      },
    );

    totalTimer = setTimeout(() => {
      request.destroy();
      settleError(new Error(`Total request time exceeded ${TOTAL_TIMEOUT_MS} ms.`));
    }, TOTAL_TIMEOUT_MS);

    request.on('timeout', () => {
      request.destroy();
      settleError(new Error(`Connection timed out after ${CONNECT_TIMEOUT_MS} ms.`));
    });
    request.on('error', (error) => {
      settleError(error);
    });
    request.end();
  });
}

/**
 * @param {string} filePath
 * @returns {string}
 */
function sha256OfFile(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

/**
 * @param {string} retrievedAt
 * @returns {string}
 */
function writeNotice(retrievedAt) {
  return `CISA Known Exploited Vulnerabilities JSON Schema (vendored)

This directory contains the official CISA KEV JSON Schema copied from:
  ${APPROVED_SOURCE_URL}

Schema role: official JSON Schema for the CISA KEV JSON catalog. This is not
the production KEV catalog body.

Retrieved at (UTC): ${retrievedAt}

The official schema is published under CC0 1.0. See LICENSE in this directory
for the CC0 1.0 Universal legal text. License provenance URL (not fetched by
install, build, test, CI, or runtime):
  ${LICENSE_URL}

This copy does not grant CISA or DHS endorsement. It does not include CISA or
DHS logos or seals, and those marks are not licensed by this vendoring. This
copy does not imply that PatchPilot is a CISA product.

PatchPilot does not download this schema at install, test, build, runtime, or
CI. Re-vendoring is a maintainer-only invocation of
scripts/vendor-cisa-kev-schema.mjs --execute.

The production KEV catalog JSON is not included in this repository.
`;
}

async function vendor() {
  assertManualExecution();
  parseApprovedUrl(APPROVED_SOURCE_URL);

  const stagingParent = mkdtempSync(path.join(tmpdir(), 'patchpilot-cisa-kev-schema-'));
  const stagingDirectory = path.join(stagingParent, 'cisa-kev-schema');

  try {
    mkdirSync(stagingDirectory, { recursive: true });

    const fetched = await fetchOfficialSchema();
    if (fetched.bytes.byteLength !== APPROVED_BYTE_LENGTH) {
      fail(
        `Official schema byte length ${fetched.bytes.byteLength} does not match the approved first-vendor length ${APPROVED_BYTE_LENGTH}. Stop and review; do not accept the new bytes automatically.`,
      );
    }

    const digest = createHash('sha256').update(fetched.bytes).digest('hex');
    if (digest !== APPROVED_SHA256) {
      fail(
        `Official schema SHA-256 ${digest} does not match the approved first-vendor hash ${APPROVED_SHA256}. Stop and review; do not accept the new bytes automatically.`,
      );
    }

    const parsedSchema = JSON.parse(fetched.bytes.toString('utf8'));
    assertOfficialSchemaShape(parsedSchema);

    const schemaPath = path.join(stagingDirectory, SCHEMA_FILE_NAME);
    writeFileSync(schemaPath, fetched.bytes);
    writeFileSync(path.join(stagingDirectory, 'LICENSE'), CC0_1_0_UNIVERSAL);

    const retrievedAt = new Date().toISOString();
    writeFileSync(path.join(stagingDirectory, 'NOTICE'), writeNotice(retrievedAt));

    /** @type {Array<{ localPath: string; sha256: string }>} */
    const checksummed = [
      {
        localPath: 'LICENSE',
        sha256: sha256OfFile(path.join(stagingDirectory, 'LICENSE')),
      },
      {
        localPath: SCHEMA_FILE_NAME,
        sha256: sha256OfFile(schemaPath),
      },
    ].sort((left, right) => left.localPath.localeCompare(right.localPath));

    const schemaEntry = checksummed.find((entry) => entry.localPath === SCHEMA_FILE_NAME);
    if (schemaEntry === undefined || schemaEntry.sha256 !== APPROVED_SHA256) {
      fail('Staged schema checksum does not match the approved first-vendor SHA-256.');
    }

    const sums =
      checksummed.map((entry) => `${entry.sha256}  ${entry.localPath}`).join('\n') + '\n';
    writeFileSync(path.join(stagingDirectory, 'SHA256SUMS'), sums);

    /** @type {Record<string, unknown>} */
    const provenance = {
      schemaVersion: '1',
      sourceOrganization: SOURCE_ORGANIZATION,
      sourceWebsite: SOURCE_WEBSITE,
      sourceUrl: APPROVED_SOURCE_URL,
      retrievedAt,
      responseSha256: digest,
      byteLength: fetched.bytes.byteLength,
      contentType: fetched.contentType,
      license: 'CC0-1.0',
      licenseUrl: LICENSE_URL,
      localPath: SCHEMA_FILE_NAME,
      upstreamDocumentRole:
        'official JSON Schema for the CISA KEV JSON catalog, not the catalog body',
    };
    if (fetched.lastModified !== undefined) {
      provenance['lastModified'] = fetched.lastModified;
    }
    if (fetched.etag !== undefined) {
      provenance['etagSha256'] = createHash('sha256').update(fetched.etag).digest('hex');
    }

    writeFileSync(
      path.join(stagingDirectory, 'PROVENANCE.json'),
      `${JSON.stringify(provenance, null, 2)}\n`,
    );

    rmSync(vendorDirectory, { recursive: true, force: true });
    mkdirSync(vendorDirectory, { recursive: true });
    for (const fileName of [
      SCHEMA_FILE_NAME,
      'LICENSE',
      'NOTICE',
      'SHA256SUMS',
      'PROVENANCE.json',
    ]) {
      copyFileSync(path.join(stagingDirectory, fileName), path.join(vendorDirectory, fileName));
    }

    process.stdout.write(
      `Vendored official CISA KEV JSON Schema (${digest}, ${fetched.bytes.byteLength} bytes) into ${vendorDirectory}\n`,
    );
  } finally {
    rmSync(stagingParent, { recursive: true, force: true });
  }
}

vendor().catch((error) => {
  const message = error instanceof Error ? error.message : 'Unknown vendoring failure.';
  fail(message);
});
