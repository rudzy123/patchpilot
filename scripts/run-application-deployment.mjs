#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const composeDirectory = path.join(rootDirectory, 'deploy', 'compose');
const composeFile = path.join(composeDirectory, 'compose.yaml');
const exampleEnvFile = path.join(composeDirectory, 'application.env.example');
const filledEnvFile = path.join(composeDirectory, 'application.env');
const bootstrapScript = path.join(rootDirectory, 'scripts', 'production-bootstrap.mjs');

const projectName = 'patchpilot-eval';
const composeProfile = 'application';

const commands = new Set([
  'up',
  'down',
  'status',
  'logs',
  'build',
  'migrate',
  'bootstrap',
  'restart',
  'config',
  'check',
]);

const serviceNames = [
  'postgres',
  'redis',
  'minio',
  'object-storage-init',
  'migrate',
  'bootstrap',
  'api',
  'worker',
  'web',
];

const restartableServices = ['api', 'worker', 'web'];

const passthroughEnv = [
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'LANG',
  'LC_ALL',
  'TMPDIR',
  'DOCKER_HOST',
  'DOCKER_CONTEXT',
  'DOCKER_CERT_PATH',
  'DOCKER_TLS_VERIFY',
  'DOCKER_CONFIG',
  'SSH_AUTH_SOCK',
  'XDG_RUNTIME_DIR',
  'XDG_CONFIG_HOME',
];

const credentialFragments = [
  'patchpilot-dev',
  'not-for-production',
  'minioadmin',
  'changeme',
  'password',
];

const secretKeys = [
  'DATABASE_URL',
  'REDIS_URL',
  'OBJECT_STORAGE_ENDPOINT',
  'OBJECT_STORAGE_ACCESS_KEY',
  'OBJECT_STORAGE_SECRET_KEY',
  'OBJECT_STORAGE_BUCKET',
  'POSTGRES_PASSWORD',
  'MINIO_ROOT_USER',
  'MINIO_ROOT_PASSWORD',
  'PATCHPILOT_REDIS_PASSWORD',
];

const tokenPattern = /^[A-Za-z0-9._~-]{8,128}$/;

/**
 * @param {string} message
 * @returns {never}
 */
function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/**
 * @param {string} filePath
 * @returns {Record<string, string>}
 */
function parseEnvFile(filePath) {
  const text = readFileSync(filePath, 'utf8');
  /** @type {Record<string, string>} */
  const values = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) {
      continue;
    }

    const stripped = line.startsWith('export ') ? line.slice('export '.length).trim() : line;
    const separator = stripped.indexOf('=');
    if (separator <= 0) {
      fail('Application env file has an invalid line.');
    }

    const key = stripped.slice(0, separator).trim();
    let value = stripped.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }

    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      fail('Application env file has an invalid key.');
    }
    if (Object.hasOwn(values, key)) {
      fail(`Application env file repeats ${key}.`);
    }
    values[key] = value;
  }

  return values;
}

/**
 * @param {Record<string, string>} values
 * @param {string} key
 * @returns {string}
 */
function requiredValue(values, key) {
  const value = values[key];
  if (value === undefined || value.trim() === '') {
    fail(`Application env file is missing ${key}.`);
  }
  return value;
}

/**
 * @param {Record<string, string>} values
 * @param {string} key
 * @param {string} expected
 */
function requireExact(values, key, expected) {
  const value = requiredValue(values, key);
  if (value !== expected) {
    fail(`${key} must be ${expected}.`);
  }
}

/**
 * @param {string} value
 * @param {string} key
 */
function rejectCredentialFragments(value, key) {
  const lowered = value.toLowerCase();
  if (credentialFragments.some((fragment) => lowered.includes(fragment))) {
    fail(`${key} contains a development credential fragment.`);
  }
}

/**
 * @param {string} value
 * @param {string} key
 */
function requireToken(value, key) {
  if (!tokenPattern.test(value)) {
    fail(`${key} must be one URL-safe token.`);
  }
  rejectCredentialFragments(value, key);
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isPrivateBucketName(value) {
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value)) {
    return false;
  }
  if (value.includes('..') || value.includes(':') || value.includes('/')) {
    return false;
  }
  return !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value);
}

/**
 * @param {Record<string, string>} values
 */
function assertApplicationEnv(values) {
  if (Object.hasOwn(values, 'PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE')) {
    fail('Do not set PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE.');
  }
  for (const key of Object.keys(values)) {
    if (key.startsWith('INTELLIGENCE_OSV_LISTING_EVIDENCE')) {
      fail('Listing-evidence key material must be omitted.');
    }
  }

  requireExact(values, 'NODE_ENV', 'production');
  requireExact(values, 'PATCHPILOT_DEPLOYMENT_ENVIRONMENT', 'production');
  requireExact(values, 'PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS', 'false');
  requireExact(values, 'LOG_PRETTY', 'false');
  requireExact(values, 'API_HOST', '0.0.0.0');
  requireExact(values, 'API_PORT', '3001');
  requireExact(values, 'WEB_PORT', '3000');
  requireExact(values, 'AUTH_COOKIE_SECURE', 'true');
  requireExact(values, 'AUTH_COOKIE_NAME', '__Host-patchpilot.sid');
  requireExact(values, 'INTELLIGENCE_OSV_ENABLED', 'false');
  requireExact(values, 'OBJECT_STORAGE_USE_SSL', 'false');
  requireExact(values, 'NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT', 'production');
  requireExact(values, 'POSTGRES_USER', 'patchpilot');
  requireExact(values, 'POSTGRES_DB', 'patchpilot');

  const kevEnabled = requiredValue(values, 'INTELLIGENCE_KEV_ENABLED');
  if (kevEnabled !== 'true' && kevEnabled !== 'false') {
    fail('INTELLIGENCE_KEV_ENABLED must be true or false.');
  }

  for (const key of secretKeys) {
    rejectCredentialFragments(requiredValue(values, key), key);
  }

  requireToken(requiredValue(values, 'POSTGRES_PASSWORD'), 'POSTGRES_PASSWORD');
  requireToken(requiredValue(values, 'PATCHPILOT_REDIS_PASSWORD'), 'PATCHPILOT_REDIS_PASSWORD');
  requireToken(requiredValue(values, 'MINIO_ROOT_USER'), 'MINIO_ROOT_USER');
  requireToken(requiredValue(values, 'MINIO_ROOT_PASSWORD'), 'MINIO_ROOT_PASSWORD');
  requireToken(requiredValue(values, 'OBJECT_STORAGE_ACCESS_KEY'), 'OBJECT_STORAGE_ACCESS_KEY');
  requireToken(requiredValue(values, 'OBJECT_STORAGE_SECRET_KEY'), 'OBJECT_STORAGE_SECRET_KEY');

  const bucket = requiredValue(values, 'OBJECT_STORAGE_BUCKET');
  if (!isPrivateBucketName(bucket)) {
    fail('OBJECT_STORAGE_BUCKET must be one private bucket name.');
  }
  rejectCredentialFragments(bucket, 'OBJECT_STORAGE_BUCKET');
  if (requiredValue(values, 'PATCHPILOT_MINIO_DEFAULT_BUCKETS') !== bucket) {
    fail('PATCHPILOT_MINIO_DEFAULT_BUCKETS must equal OBJECT_STORAGE_BUCKET.');
  }
  if (
    requiredValue(values, 'MINIO_ROOT_USER') !== requiredValue(values, 'OBJECT_STORAGE_ACCESS_KEY')
  ) {
    fail('MINIO_ROOT_USER must equal OBJECT_STORAGE_ACCESS_KEY.');
  }
  if (
    requiredValue(values, 'MINIO_ROOT_PASSWORD') !==
    requiredValue(values, 'OBJECT_STORAGE_SECRET_KEY')
  ) {
    fail('MINIO_ROOT_PASSWORD must equal OBJECT_STORAGE_SECRET_KEY.');
  }

  let databaseUrl;
  let redisUrl;
  let objectEndpoint;
  let apiBaseUrl;
  try {
    databaseUrl = new URL(requiredValue(values, 'DATABASE_URL'));
    redisUrl = new URL(requiredValue(values, 'REDIS_URL'));
    objectEndpoint = new URL(requiredValue(values, 'OBJECT_STORAGE_ENDPOINT'));
    apiBaseUrl = new URL(requiredValue(values, 'NEXT_PUBLIC_API_BASE_URL'));
  } catch {
    fail('A service URL in the application env file is invalid.');
  }

  if (
    databaseUrl.protocol !== 'postgresql:' ||
    databaseUrl.username !== 'patchpilot' ||
    decodeURIComponent(databaseUrl.password) !== requiredValue(values, 'POSTGRES_PASSWORD') ||
    databaseUrl.hostname !== 'postgres' ||
    databaseUrl.port !== '5432' ||
    databaseUrl.pathname !== '/patchpilot'
  ) {
    fail('DATABASE_URL must use the postgres service and POSTGRES_PASSWORD.');
  }

  if (
    redisUrl.protocol !== 'redis:' ||
    redisUrl.username !== '' ||
    decodeURIComponent(redisUrl.password) !== requiredValue(values, 'PATCHPILOT_REDIS_PASSWORD') ||
    redisUrl.hostname !== 'redis' ||
    redisUrl.port !== '6379'
  ) {
    fail('REDIS_URL must use the redis service and PATCHPILOT_REDIS_PASSWORD.');
  }

  if (
    objectEndpoint.protocol !== 'http:' ||
    objectEndpoint.username !== '' ||
    objectEndpoint.password !== '' ||
    objectEndpoint.hostname !== 'minio' ||
    objectEndpoint.port !== '9000'
  ) {
    fail('OBJECT_STORAGE_ENDPOINT must be http://minio:9000.');
  }

  if (
    apiBaseUrl.protocol !== 'https:' ||
    apiBaseUrl.username !== '' ||
    apiBaseUrl.password !== '' ||
    apiBaseUrl.search !== '' ||
    apiBaseUrl.hash !== ''
  ) {
    fail('NEXT_PUBLIC_API_BASE_URL must be an https URL without credentials.');
  }

  const origins = requiredValue(values, 'CORS_ALLOWED_ORIGINS')
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
  if (origins.length === 0) {
    fail('CORS_ALLOWED_ORIGINS must list at least one https origin.');
  }
  for (const origin of origins) {
    if (origin === '*' || !origin.startsWith('https://')) {
      fail('CORS_ALLOWED_ORIGINS must be an https allowlist.');
    }
    try {
      const parsed = new URL(origin);
      if (parsed.username !== '' || parsed.password !== '' || parsed.origin !== origin) {
        fail('CORS_ALLOWED_ORIGINS must be exact https origins.');
      }
    } catch {
      fail('CORS_ALLOWED_ORIGINS must be exact https origins.');
    }
  }
}

/**
 * @param {string} command
 * @returns {string}
 */
function resolveEnvFile(command) {
  const override = process.env['PATCHPILOT_APPLICATION_ENV_FILE'];
  if (command === 'check' && override !== undefined && override.trim() !== '') {
    const selected = path.resolve(override);
    if (!existsSync(selected)) {
      fail(`Environment file not found: ${selected}`);
    }
    return selected;
  }

  if (existsSync(filledEnvFile)) {
    return filledEnvFile;
  }

  const exampleAllowed = new Set(['check', 'config', 'build', 'down', 'status', 'logs']);
  if (exampleAllowed.has(command)) {
    return exampleEnvFile;
  }

  fail(
    [
      'Application env file is missing.',
      `Copy ${path.relative(rootDirectory, exampleEnvFile)} to ${path.relative(rootDirectory, filledEnvFile)} and replace the evaluation placeholders before the first start.`,
      'PostgreSQL keeps the password from the first initialization of the evaluation volume.',
    ].join('\n'),
  );
}

/**
 * @param {Record<string, string>} fileValues
 * @returns {NodeJS.ProcessEnv}
 */
function childEnvironment(fileValues) {
  /** @type {NodeJS.ProcessEnv} */
  const env = {};
  for (const key of passthroughEnv) {
    const value = process.env[key];
    if (value !== undefined) {
      env[key] = value;
    }
  }
  for (const [key, value] of Object.entries(fileValues)) {
    if (!passthroughEnv.includes(key)) {
      env[key] = value;
    }
  }
  return env;
}

/**
 * @param {string} envFile
 * @param {string[]} commandArguments
 * @returns {string[]}
 */
function composeArguments(envFile, commandArguments) {
  return [
    'compose',
    '-f',
    composeFile,
    '-p',
    projectName,
    '--profile',
    composeProfile,
    '--env-file',
    envFile,
    ...commandArguments,
  ];
}

/**
 * @param {string[]} extra
 * @param {string[]} allowed
 * @returns {string[]}
 */
function selectedServices(extra, allowed) {
  for (const service of extra) {
    if (service.startsWith('-') || !allowed.includes(service)) {
      fail(`Unsupported service. Expected one of: ${allowed.join(', ')}.`);
    }
  }
  return extra;
}

/**
 * @param {string} command
 * @param {string[]} extra
 * @param {string} envFile
 * @returns {string[]}
 */
function commandArguments(command, extra, envFile) {
  if (extra.length > 0 && command !== 'restart' && command !== 'logs') {
    fail('This command does not accept extra arguments.');
  }

  switch (command) {
    case 'up':
      return composeArguments(envFile, ['up', '-d', '--wait']);
    case 'down':
      return composeArguments(envFile, ['down']);
    case 'status':
      return composeArguments(envFile, ['ps']);
    case 'logs':
      return composeArguments(envFile, [
        'logs',
        '--follow',
        ...selectedServices(extra, serviceNames),
      ]);
    case 'build':
      return composeArguments(envFile, ['build', 'api', 'worker', 'web', 'migrate', 'bootstrap']);
    case 'migrate':
      return composeArguments(envFile, ['run', '--rm', '--no-deps', 'migrate']);
    case 'bootstrap':
      return composeArguments(envFile, ['run', '--rm', '--no-deps', 'bootstrap']);
    case 'restart': {
      const services =
        extra.length === 0 ? ['api', 'worker'] : selectedServices(extra, restartableServices);
      return composeArguments(envFile, ['restart', ...services]);
    }
    case 'config':
      return composeArguments(envFile, ['config']);
    default:
      fail(`Unsupported command: ${command}`);
  }
}

function main() {
  const command = process.argv[2];
  const extra = process.argv.slice(3);
  if (command === undefined || !commands.has(command)) {
    fail(
      [
        'Usage: node scripts/run-application-deployment.mjs <command>',
        'Commands: up, down, status, logs, build, migrate, bootstrap, restart, config, check',
        'Project: patchpilot-eval. Profile: application.',
        'down keeps named volumes.',
      ].join('\n'),
    );
  }

  if (!existsSync(composeFile) || !existsSync(exampleEnvFile)) {
    fail('Application Compose file or env example is missing.');
  }

  const envFile = resolveEnvFile(command);
  const values = parseEnvFile(envFile);
  if (command !== 'down' && command !== 'status' && command !== 'logs') {
    assertApplicationEnv(values);
  }

  if (command === 'up' || command === 'bootstrap') {
    if (!existsSync(bootstrapScript)) {
      fail(`Missing bootstrap script: ${path.relative(rootDirectory, bootstrapScript)}`);
    }
  }

  if (command === 'check') {
    process.stdout.write(`application env accepted\n${envFile}\n`);
    return;
  }

  const dockerArguments = commandArguments(command, extra, envFile);
  const child = spawn('docker', dockerArguments, {
    stdio: 'inherit',
    cwd: rootDirectory,
    env: childEnvironment(values),
  });

  child.on('error', (error) => {
    process.stderr.write(
      [
        'Failed to execute Docker Compose.',
        `Command: docker ${dockerArguments.join(' ')}`,
        error instanceof Error ? error.message : 'Unknown error',
        'Install Docker, start the daemon, and ensure you can run `docker compose version`.',
      ].join('\n'),
    );
    process.stderr.write('\n');
    process.exit(1);
  });

  child.on('exit', (code) => {
    if (command === 'down' && (code === 0 || code === null)) {
      process.stderr.write(
        'Application services stopped. Named volumes were kept. The evaluation project is patchpilot-eval.\n',
      );
    }
    process.exit(code ?? 1);
  });
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && path.resolve(invokedPath) === fileURLToPath(import.meta.url)) {
  main();
}
