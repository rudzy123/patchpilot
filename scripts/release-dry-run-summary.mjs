#!/usr/bin/env node

import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageJson = JSON.parse(readFileSync(path.join(rootDirectory, 'package.json'), 'utf8'));
const changelogPath = path.join(rootDirectory, 'CHANGELOG.md');

const version = typeof packageJson.version === 'string' ? packageJson.version : 'unknown';
const packageManager =
  typeof packageJson.packageManager === 'string' ? packageJson.packageManager : 'unspecified';
const nodeEngine =
  packageJson.engines && typeof packageJson.engines.node === 'string'
    ? packageJson.engines.node
    : 'unspecified';

const refName = process.env['REF_NAME'] ?? 'local';
const sha = process.env['SHA'] ?? 'unspecified';
const runId = process.env['RUN_ID'] ?? 'local';
const runAttempt = process.env['RUN_ATTEMPT'] ?? '1';

const changelogPresent = existsSync(changelogPath);
const privatePackage = packageJson.private === true;

const lines = [
  'Release dry run summary',
  '',
  `Commit: ${sha}`,
  `Ref: ${refName}`,
  `Root package version: ${version}`,
  `packageManager: ${packageManager}`,
  `engines.node: ${nodeEngine}`,
  `Root package private: ${privatePackage ? 'yes' : 'no'}`,
  `CHANGELOG.md present: ${changelogPresent ? 'yes' : 'no'}`,
  `Expected future SBOM artifact name: patchpilot-sbom-${runId}-${runAttempt}`,
  `Expected Scorecard artifact name: scorecard-${runId}-${runAttempt}`,
  '',
  'This workflow does not publish packages, images, GitHub Releases, or deployments.',
  'This workflow does not log in to a registry or apply production migrations.',
  privatePackage
    ? 'The root package is private; it is not a candidate for npm publish.'
    : 'The root package is not marked private; publishing remains out of scope for this dry run.',
  changelogPresent
    ? 'Changelog file exists. Maintainers still need to confirm release-note completeness before a real tag.'
    : 'No CHANGELOG.md yet. A future release process should add versioned notes before tagging.',
  version === '0.0.0'
    ? 'Version 0.0.0 is development-foundation metadata, not a tagged product release.'
    : `Current version ${version} would be the starting point for a future tagging process.`,
  'Suitable for a future release process only after product MVP work, migrations, and operator artifacts exist.',
  '',
];

const text = lines.join('\n');
process.stdout.write(text);

const summaryPath = process.env['GITHUB_STEP_SUMMARY'];
if (typeof summaryPath === 'string' && summaryPath.length > 0) {
  appendFileSync(
    summaryPath,
    [
      '## Release dry run',
      '',
      ...lines.filter((line) => line !== 'Release dry run summary').map((line) => line),
      '',
    ].join('\n'),
  );
}
