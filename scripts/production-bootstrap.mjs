#!/usr/bin/env node

// Explicit no-write production bootstrap.
//
// Exits 0 only when PATCHPILOT_DEPLOYMENT_ENVIRONMENT is exactly production.
// Arguments are refused. The process creates no files, opens no connections,
// and does not load development data, priority policy, authority grants, or advisories.

/**
 * @param {string} message
 * @returns {never}
 */
function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

if (process.argv.length > 2) {
  fail('Production bootstrap accepts no arguments.');
}

if (process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] !== 'production') {
  fail(
    'Production bootstrap requires PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production and writes nothing.',
  );
}

process.stdout.write('Production bootstrap completed without writing data.\n');
