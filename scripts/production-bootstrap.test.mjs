import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bootstrapScriptPath = path.join(rootDirectory, 'scripts', 'production-bootstrap.mjs');
const successMessage = 'Production bootstrap completed without writing data.\n';
const argumentMessage = 'Production bootstrap accepts no arguments.\n';
const deploymentMessage =
  'Production bootstrap requires PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production and writes nothing.\n';

/**
 * @param {string} relativePath
 * @returns {string}
 */
function readRepositoryFile(relativePath) {
  return readFileSync(path.join(rootDirectory, relativePath), 'utf8');
}

/**
 * @param {(cwd: string, home: string) => void} callback
 */
function withIsolatedDirectories(callback) {
  const cwd = mkdtempSync(path.join(os.tmpdir(), 'patchpilot-bootstrap-cwd-'));
  const home = mkdtempSync(path.join(os.tmpdir(), 'patchpilot-bootstrap-home-'));
  try {
    callback(cwd, home);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
}

/**
 * @param {string} directory
 * @param {string} name
 * @param {string} contents
 * @returns {string}
 */
function writeFrozenFile(directory, name, contents) {
  const filePath = path.join(directory, name);
  writeFileSync(filePath, contents);
  const stamp = new Date('2020-01-01T00:00:00.000Z');
  utimesSync(filePath, stamp, stamp);
  return filePath;
}

/**
 * @param {string} directory
 * @param {readonly string[]} expectedNames
 */
function assertDirectoryUnchanged(directory, expectedNames) {
  assert.deepEqual(readdirSync(directory).sort(), [...expectedNames].sort());
  for (const name of expectedNames) {
    const filePath = path.join(directory, name);
    assert.equal(statSync(filePath).mtime.toISOString(), '2020-01-01T00:00:00.000Z');
  }
}

/**
 * @param {string[]} args
 * @param {Record<string, string>} env
 * @param {string} cwd
 * @param {string} home
 * @returns {import('node:child_process').SpawnSyncReturns<string>}
 */
function runBootstrap(args, env, cwd, home) {
  /** @type {NodeJS.ProcessEnv} */
  const childEnv = { HOME: home };
  const pathValue = process.env['PATH'];
  if (pathValue !== undefined) {
    childEnv['PATH'] = pathValue;
  }
  for (const [key, value] of Object.entries(env)) {
    childEnv[key] = value;
  }

  return spawnSync(process.execPath, [bootstrapScriptPath, ...args], {
    cwd,
    env: childEnv,
    encoding: 'utf8',
    timeout: 1000,
  });
}

/**
 * @param {string} composeText
 * @param {string} serviceName
 * @returns {string}
 */
function serviceBlock(composeText, serviceName) {
  const servicesHeader = '\nservices:\n';
  const servicesStart = composeText.indexOf(servicesHeader);
  assert.ok(servicesStart >= 0);
  const volumesStart = composeText.indexOf('\nvolumes:\n', servicesStart);
  assert.ok(volumesStart > servicesStart);
  const services = composeText.slice(servicesStart + servicesHeader.length, volumesStart);
  const marker = `  ${serviceName}:\n`;
  const start = services.indexOf(marker);
  assert.ok(start >= 0, `missing service ${serviceName}`);
  assert.ok(start === 0 || services[start - 1] === '\n');
  const rest = services.slice(start + marker.length);
  const nextMatch = rest.match(/\n {2}[a-z0-9-]+:\n/);
  if (nextMatch === null || nextMatch.index === undefined) {
    return rest;
  }
  return rest.slice(0, nextMatch.index);
}

/**
 * @param {string} composeText
 * @returns {string}
 */
function objectStorageInitCommand(composeText) {
  const block = serviceBlock(composeText, 'object-storage-init');
  const lines = block.split('\n');
  const commandIndex = lines.indexOf('    command:');
  assert.ok(commandIndex >= 0);
  assert.equal(lines[commandIndex + 1], '      - |');
  /** @type {string[]} */
  const scriptLines = [];
  for (const line of lines.slice(commandIndex + 2)) {
    if (line === '') {
      scriptLines.push('');
      continue;
    }
    if (!line.startsWith('        ')) {
      break;
    }
    scriptLines.push(line.slice(8));
  }
  const raw = scriptLines.join('\n');
  assert.match(raw, /set -e/);
  assert.doesNotMatch(raw.replaceAll('$$', ''), /\$/);
  return raw.replaceAll('$$', '$');
}

test('production bootstrap exits 0 only for the production deployment and writes nothing', () => {
  withIsolatedDirectories((cwd, home) => {
    const sentinel = writeFrozenFile(cwd, 'sentinel.txt', 'sentinel');
    const databaseUrl =
      'postgresql://patchpilot:db-secret-should-not-appear@127.0.0.1:1/patchpilot';

    for (const deployment of [
      '',
      '   ',
      'development',
      'test',
      'Production',
      'production ',
      ' production',
      'production\n',
      'sentinel-deployment',
    ]) {
      const result = runBootstrap(
        [],
        {
          NODE_ENV: 'production',
          PATCHPILOT_DEPLOYMENT_ENVIRONMENT: deployment,
          DATABASE_URL: databaseUrl,
        },
        cwd,
        home,
      );
      assert.equal(result.status, 1, deployment);
      assert.equal(result.stdout, '', deployment);
      assert.equal(result.stderr, deploymentMessage, deployment);
      assert.equal(result.stderr.includes('sentinel-deployment'), false);
      assert.equal(result.stderr.includes('db-secret-should-not-appear'), false);
    }

    const unset = runBootstrap(
      [],
      { NODE_ENV: 'production', DATABASE_URL: databaseUrl },
      cwd,
      home,
    );
    assert.equal(unset.status, 1);
    assert.equal(unset.stdout, '');
    assert.equal(unset.stderr, deploymentMessage);

    const succeeded = runBootstrap(
      [],
      {
        NODE_ENV: 'development',
        PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production',
        DATABASE_URL: databaseUrl,
        REDIS_URL: 'redis://:redis-secret-should-not-appear@127.0.0.1:1',
      },
      cwd,
      home,
    );
    assert.equal(succeeded.status, 0, succeeded.stderr ?? undefined);
    assert.equal(succeeded.stdout, successMessage);
    assert.equal(succeeded.stderr, '');
    assert.equal(
      `${succeeded.stdout}${succeeded.stderr}`.includes('db-secret-should-not-appear'),
      false,
    );
    assert.equal(
      `${succeeded.stdout}${succeeded.stderr}`.includes('redis-secret-should-not-appear'),
      false,
    );
    assert.equal(readFileSync(sentinel, 'utf8'), 'sentinel');
    assertDirectoryUnchanged(cwd, ['sentinel.txt']);
    assert.deepEqual(readdirSync(home), []);
  });
});

test('production bootstrap does not read an env file as a grant or a denial', () => {
  withIsolatedDirectories((cwd, home) => {
    writeFrozenFile(
      cwd,
      '.env',
      'PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production\nDATABASE_URL=postgresql://patchpilot:file-secret@postgres/patchpilot\n',
    );
    writeFrozenFile(cwd, 'sentinel.txt', 'sentinel');

    const denied = runBootstrap([], { NODE_ENV: 'production' }, cwd, home);
    assert.equal(denied.status, 1);
    assert.equal(denied.stderr, deploymentMessage);
    assert.equal(denied.stdout, '');
    assert.equal(denied.stderr.includes('file-secret'), false);

    writeFrozenFile(
      cwd,
      '.env',
      'PATCHPILOT_DEPLOYMENT_ENVIRONMENT=development\nDATABASE_URL=postgresql://patchpilot:file-secret@postgres/patchpilot\n',
    );
    const granted = runBootstrap(
      [],
      { PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production' },
      cwd,
      home,
    );
    assert.equal(granted.status, 0, granted.stderr ?? undefined);
    assert.equal(granted.stdout, successMessage);
    assert.equal(granted.stderr, '');
    assertDirectoryUnchanged(cwd, ['.env', 'sentinel.txt']);
    assert.deepEqual(readdirSync(home), []);
  });
});

test('production bootstrap rejects arguments instead of running them', () => {
  withIsolatedDirectories((cwd, home) => {
    writeFrozenFile(cwd, 'sentinel.txt', 'sentinel');
    for (const args of [['db:seed'], ['--help'], [''], ['ensurePublishedBuiltinPriorityPolicy']]) {
      for (const deployment of ['production', 'development']) {
        const result = runBootstrap(
          args,
          { PATCHPILOT_DEPLOYMENT_ENVIRONMENT: deployment },
          cwd,
          home,
        );
        assert.equal(result.status, 1, `${deployment} ${args.join(' ')}`);
        assert.equal(result.stdout, '', args.join(' '));
        assert.equal(result.stderr, argumentMessage, args.join(' '));
      }
    }
    assertDirectoryUnchanged(cwd, ['sentinel.txt']);
    assert.deepEqual(readdirSync(home), []);
  });
});

test('production bootstrap source has no writers, imports, or data commands', () => {
  const source = readRepositoryFile('scripts/production-bootstrap.mjs');
  assert.doesNotMatch(source, /\bimport\b/);
  assert.doesNotMatch(source, /\brequire\s*\(/);
  assert.doesNotMatch(source, /node:(fs|child_process|net|tls|http|https|dgram)/);
  assert.doesNotMatch(
    source,
    /\b(writeFile|appendFile|createWriteStream|mkdir|rmSync|unlink|spawn|exec|fetch)\b/,
  );
  for (const forbidden of [
    'seedDevelopmentData',
    'ensurePublishedBuiltinPriorityPolicy',
    'instance-advisory-authority',
    'offline-npm-osv-import',
    'db:seed',
    'db:reset',
    'db:migrate',
    'initializeDevelopmentBucket',
    'prisma',
    '@patchpilot/config',
    '@patchpilot/database',
    'postgresql://',
    'redis://',
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
  assert.equal(source.split('process.stdout.write').length - 1, 1);
  assert.equal(source.split('process.stderr.write').length - 1, 1);
  assert.equal(source.split('process.exit').length - 1, 1);
});

test('application deployment keeps project patchpilot-eval, the application profile, and volumes', () => {
  const deployment = readRepositoryFile('scripts/run-application-deployment.mjs');
  const compose = readRepositoryFile('deploy/compose/compose.yaml');
  const composeNames = readdirSync(path.join(rootDirectory, 'deploy', 'compose')).filter(
    (name) => name.endsWith('.yaml') || name.endsWith('.yml'),
  );

  assert.deepEqual(composeNames, ['compose.yaml']);
  assert.match(compose, /^name: patchpilot$/m);
  assert.match(deployment, /const projectName = 'patchpilot-eval';/);
  assert.match(deployment, /const composeProfile = 'application';/);
  assert.match(deployment, /'-p',\n\s*projectName,/);
  assert.match(deployment, /'--profile',\n\s*composeProfile,/);
  assert.doesNotMatch(deployment, /--volumes/);
  assert.doesNotMatch(deployment, /['"]-v['"]/);

  const downCase = deployment.slice(
    deployment.indexOf("case 'down':"),
    deployment.indexOf("case 'status':"),
  );
  assert.match(downCase, /return composeArguments\(envFile, \['down'\]\);/);
  assert.doesNotMatch(downCase, /-v|--volumes|db:seed/);

  for (const relativePath of [
    'deploy/compose/compose.yaml',
    'scripts/run-application-deployment.mjs',
    'scripts/run-infrastructure.mjs',
    'scripts/production-bootstrap.mjs',
  ]) {
    const source = readRepositoryFile(relativePath);
    assert.equal(source.includes('db:seed'), false, relativePath);
    assert.equal(source.includes('seedDevelopmentData'), false, relativePath);
    assert.equal(source.includes('ensurePublishedBuiltinPriorityPolicy'), false, relativePath);
    assert.equal(source.includes('instance-advisory-authority'), false, relativePath);
    assert.equal(source.includes('offline-npm-osv-import'), false, relativePath);
  }

  const profiled = ['object-storage-init', 'migrate', 'bootstrap', 'api', 'worker', 'web'];
  for (const name of profiled) {
    assert.match(serviceBlock(compose, name), /profiles: \[application\]/, name);
  }
  for (const name of ['postgres', 'redis', 'minio']) {
    assert.doesNotMatch(serviceBlock(compose, name), /profiles:/, name);
  }

  const migrate = serviceBlock(compose, 'migrate');
  assert.match(migrate, /restart: 'no'/);
  assert.match(migrate, /command: \['pnpm', 'db:migrate:deploy'\]/);
  assert.doesNotMatch(migrate, /db:reset/);

  const bootstrap = serviceBlock(compose, 'bootstrap');
  assert.match(bootstrap, /restart: 'no'/);
  assert.match(bootstrap, /target: migrate/);
  assert.match(bootstrap, /command: \['node', 'scripts\/production-bootstrap\.mjs'\]/);
  assert.match(bootstrap, /source: \.\.\/\.\.\/scripts\/production-bootstrap\.mjs/);
  assert.match(bootstrap, /read_only: true/);
  assert.match(bootstrap, /migrate:\n\s*condition: service_completed_successfully/);
  assert.match(
    bootstrap,
    /PATCHPILOT_DEPLOYMENT_ENVIRONMENT: \$\{PATCHPILOT_DEPLOYMENT_ENVIRONMENT:-\}/,
  );
  assert.doesNotMatch(bootstrap, /env_file|DATABASE_URL/);

  /** @type {NodeJS.ProcessEnv} */
  const usageEnv = {};
  const pathValue = process.env['PATH'];
  if (pathValue !== undefined) {
    usageEnv['PATH'] = pathValue;
  }
  const usage = spawnSync(
    process.execPath,
    [path.join(rootDirectory, 'scripts', 'run-application-deployment.mjs')],
    {
      encoding: 'utf8',
      env: usageEnv,
      timeout: 1000,
    },
  );
  assert.equal(usage.status, 1);
  assert.match(usage.stderr, /Project: patchpilot-eval\. Profile: application\./);
  assert.match(usage.stderr, /down keeps named volumes/);
  assert.doesNotMatch(usage.stderr, /-v|--volumes/);
});

test('development infrastructure does not select the application profile or delete volumes', () => {
  const source = readRepositoryFile('scripts/run-infrastructure.mjs');
  assert.match(
    source,
    /command === 'up'\s*\?\s*\['compose', '-f', composeFile, \.\.\.envFileArguments\(\), 'up', '-d', '--wait'\]/,
  );
  assert.match(
    source,
    /command === 'down'\s*\?\s*\['compose', '-f', composeFile, \.\.\.envFileArguments\(\), 'down'\]/,
  );
  assert.doesNotMatch(source, /--profile/);
  assert.doesNotMatch(source, /patchpilot-eval/);
  assert.doesNotMatch(source, /application\.env/);
  const downArm = source.slice(
    source.indexOf("command === 'down'"),
    source.indexOf("command === 'status'"),
  );
  assert.doesNotMatch(downArm, /-v|--volumes/);

  const packageJson = JSON.parse(readRepositoryFile('package.json'));
  assert.equal(packageJson.scripts['infrastructure:up'], 'node scripts/run-infrastructure.mjs up');
  assert.equal(
    packageJson.scripts['infrastructure:down'],
    'node scripts/run-infrastructure.mjs down',
  );
  assert.equal(packageJson.scripts['db:seed'], 'node scripts/run-database-command.mjs seed');
  for (const [name, command] of Object.entries(packageJson.scripts)) {
    assert.equal(String(command).includes('production-bootstrap'), false, name);
  }
});

test('object-storage init is a private one-shot on the application profile', () => {
  const compose = readRepositoryFile('deploy/compose/compose.yaml');
  const init = serviceBlock(compose, 'object-storage-init');
  const script = objectStorageInitCommand(compose);

  assert.match(compose, /x-minio-image: &minio-image bitnamilegacy\/minio:/);
  assert.match(init, /image: \*minio-image/);
  assert.match(init, /profiles: \[application\]/);
  assert.match(init, /restart: 'no'/);
  assert.match(init, /minio:\n\s*condition: service_healthy/);
  assert.match(init, /MINIO_DEFAULT_BUCKETS: \$\{PATCHPILOT_MINIO_DEFAULT_BUCKETS:-\}/);
  assert.match(init, /entrypoint: \['bash', '-c'\]/);
  assert.doesNotMatch(init, /image: (?!\*minio-image)\S/);
  assert.match(script, /mb "local\/\$bucket"/);
  assert.doesNotMatch(script, /initializeDevelopmentBucket|anonymous|policy|public-read|--public/);

  const worker = serviceBlock(compose, 'worker');
  assert.match(worker, /object-storage-init:\n\s*condition: service_completed_successfully/);

  const syntax = spawnSync('bash', ['--noprofile', '--norc', '-n'], {
    input: script,
    encoding: 'utf8',
    timeout: 1000,
  });
  assert.equal(syntax.status, 0, syntax.stderr);
});

test('object-storage init refuses unsafe buckets before it contacts storage', () => {
  const script = objectStorageInitCommand(readRepositoryFile('deploy/compose/compose.yaml'));
  /** @type {Array<{ name: string, env: Record<string, string>, stderr: string }>} */
  const cases = [
    {
      name: 'missing names',
      env: {},
      stderr: 'MINIO_DEFAULT_BUCKETS must equal OBJECT_STORAGE_BUCKET\n',
    },
    {
      name: 'empty bucket',
      env: { MINIO_DEFAULT_BUCKETS: 'patchpilot' },
      stderr: 'MINIO_DEFAULT_BUCKETS must equal OBJECT_STORAGE_BUCKET\n',
    },
    {
      name: 'mismatched names',
      env: {
        OBJECT_STORAGE_BUCKET: 'sentinel-bucket-secret',
        MINIO_DEFAULT_BUCKETS: 'other-bucket',
      },
      stderr: 'MINIO_DEFAULT_BUCKETS must equal OBJECT_STORAGE_BUCKET\n',
    },
    {
      name: 'development bucket fragment',
      env: {
        OBJECT_STORAGE_BUCKET: 'patchpilot-dev',
        MINIO_DEFAULT_BUCKETS: 'patchpilot-dev',
      },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'not-for-production fragment',
      env: {
        OBJECT_STORAGE_BUCKET: 'not-for-production',
        MINIO_DEFAULT_BUCKETS: 'not-for-production',
      },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'minioadmin fragment',
      env: { OBJECT_STORAGE_BUCKET: 'minioadmin', MINIO_DEFAULT_BUCKETS: 'minioadmin' },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'changeme fragment',
      env: { OBJECT_STORAGE_BUCKET: 'changeme', MINIO_DEFAULT_BUCKETS: 'changeme' },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'password fragment',
      env: { OBJECT_STORAGE_BUCKET: 'secret-password', MINIO_DEFAULT_BUCKETS: 'secret-password' },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'path separator',
      env: { OBJECT_STORAGE_BUCKET: 'team/bucket', MINIO_DEFAULT_BUCKETS: 'team/bucket' },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'parent segment',
      env: { OBJECT_STORAGE_BUCKET: 'team..bucket', MINIO_DEFAULT_BUCKETS: 'team..bucket' },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'uppercase name',
      env: { OBJECT_STORAGE_BUCKET: 'Patchpilot', MINIO_DEFAULT_BUCKETS: 'Patchpilot' },
      stderr: 'Refusing object-storage bucket\n',
    },
    {
      name: 'valid name without credentials',
      env: { OBJECT_STORAGE_BUCKET: 'patchpilot', MINIO_DEFAULT_BUCKETS: 'patchpilot' },
      stderr: 'Object-storage root credentials are required\n',
    },
    {
      name: 'credential fragment is not echoed',
      env: {
        OBJECT_STORAGE_BUCKET: 'patchpilot',
        MINIO_DEFAULT_BUCKETS: 'patchpilot',
        MINIO_ROOT_USER: 'sentinel-root-user',
      },
      stderr: 'Object-storage root credentials are required\n',
    },
  ];

  for (const item of cases) {
    const result = spawnSync('bash', ['--noprofile', '--norc', '-c', script], {
      env: item.env,
      encoding: 'utf8',
      timeout: 1000,
    });
    assert.equal(result.status, 1, `${item.name}\n${result.stdout}\n${result.stderr}`);
    assert.equal(result.stdout, '', item.name);
    assert.equal(result.stderr, item.stderr, item.name);
    assert.equal(result.stderr.includes('sentinel-bucket-secret'), false, item.name);
    assert.equal(result.stderr.includes('sentinel-root-user'), false, item.name);
    assert.equal(result.stderr.includes('initializeDevelopmentBucket'), false, item.name);
  }
});
