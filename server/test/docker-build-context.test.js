import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const {
  SAFE_SERVER_CONFIG_FILES,
  createDockerBuildContext,
  removeDockerBuildContext,
} = require('../../scripts/docker-build-context.cjs');

test('direct Docker builds exclude runtime environment secrets from every image', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  const ignored = new Set(fs.readFileSync(path.join(root, '.dockerignore'), 'utf8').split(/\r?\n/));
  for (const pattern of ['.env', '.env.*', '**/.env', '**/.env.*']) assert.ok(ignored.has(pattern));
  for (const file of fs.readdirSync(path.join(root, 'docker')).filter(name => name.startsWith('Dockerfile'))) {
    const source = fs.readFileSync(path.join(root, 'docker', file), 'utf8');
    assert.doesNotMatch(source, /^\s*(?:COPY|ADD)\s+[^\n]*\.env\b/im, file);
  }
});

function write(root, relativePath, contents) {
  const destination = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, contents);
}

test('Docker builds use an allowlisted context without runtime secrets', () => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-build-source-'));
  let contextRoot;

  try {
    write(fixtureRoot, '.dockerignore', '**/node_modules\n');
    write(fixtureRoot, '.env', 'DATABASE_PASSWORD=must-not-copy\n');
    write(fixtureRoot, 'docker/Dockerfile.server', 'FROM scratch\n');
    write(fixtureRoot, 'scripts/start-server.cjs', '');
    write(fixtureRoot, 'shared/source.js', 'export {};\n');
    write(fixtureRoot, 'workers/ypir/src/lib.rs', '');
    write(fixtureRoot, 'server/server.js', '');
    write(fixtureRoot, 'server/node_modules/package/index.js', 'must not copy');

    for (const filename of SAFE_SERVER_CONFIG_FILES) {
      write(fixtureRoot, `server/config/${filename}`, `// ${filename}\n`);
    }
    write(fixtureRoot, 'server/config/generated-secret.txt', 'must not copy');
    write(fixtureRoot, 'server/config/secrets/hidden-service.key', 'must not copy');
    write(fixtureRoot, 'server/config/tor/hs_ed25519_secret_key', 'must not copy');

    const protectedDirectories = [
      path.join(fixtureRoot, 'server/config/secrets'),
      path.join(fixtureRoot, 'server/config/tor'),
    ];
    for (const directory of protectedDirectories) fs.chmodSync(directory, 0o000);

    contextRoot = createDockerBuildContext(fixtureRoot);

    assert.deepEqual(
      fs.readdirSync(path.join(contextRoot, 'server/config')).sort(),
      [...SAFE_SERVER_CONFIG_FILES].sort()
    );
    assert.equal(fs.existsSync(path.join(contextRoot, 'server/node_modules')), false);
    assert.equal(fs.readFileSync(path.join(contextRoot, '.env'), 'utf8'), '');
    assert.equal(fs.existsSync(path.join(contextRoot, 'docker/Dockerfile.server')), true);
    assert.equal(fs.existsSync(path.join(contextRoot, 'scripts/start-server.cjs')), true);
    assert.equal(fs.existsSync(path.join(contextRoot, 'shared/source.js')), true);

    for (const directory of protectedDirectories) {
      assert.equal(fs.statSync(directory).mode & 0o777, 0);
      fs.chmodSync(directory, 0o700);
    }
  } finally {
    for (const directory of [
      path.join(fixtureRoot, 'server/config/secrets'),
      path.join(fixtureRoot, 'server/config/tor'),
    ]) {
      try {
        fs.chmodSync(directory, 0o700);
      } catch { }
    }
    removeDockerBuildContext(contextRoot);
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

test('Compose routes every image build through the sanitized context override', () => {
  const compose = fs.readFileSync(
    path.resolve(import.meta.dirname, '../../docker/docker-compose.yml'),
    'utf8'
  );
  assert.equal(
    (compose.match(/context: "\$\{QORC_DOCKER_BUILD_CONTEXT:-\.\.\}"/g) || []).length,
    4
  );
});

test('The server image owns one verified qorc PIR worker runtime path', () => {
  const dockerfile = fs.readFileSync(
    path.resolve(import.meta.dirname, '../../docker/Dockerfile.server'),
    'utf8'
  );
  const compose = fs.readFileSync(
    path.resolve(import.meta.dirname, '../../docker/docker-compose.yml'),
    'utf8'
  );
  const launcher = fs.readFileSync(
    path.resolve(import.meta.dirname, '../../scripts/start-docker.cjs'),
    'utf8'
  );

  assert.match(dockerfile, /cargo build --release --offline --bin qorc-pir-worker/);
  assert.match(dockerfile, /\/app\/bin\/qorc-pir-worker/);
  assert.match(dockerfile, /test -x \/app\/bin\/qorc-pir-worker/);
  assert.match(dockerfile, /ENV QORC_PIR_WORKER_PATH=\/app\/bin\/qorc-pir-worker/);
  assert.match(compose, /QORC_PIR_WORKER_PATH=\/app\/bin\/qorc-pir-worker/);
  assert.doesNotMatch(launcher, /serverImageHasCurrentPirWorker|repairServerImage/);
  assert.doesNotMatch(dockerfile, /\/app\/workers\/ypir\/target\/release\/qorc-pir-worker/);
});

test('The production server image installs only lockfile-pinned runtime dependencies', () => {
  const dockerfile = fs.readFileSync(
    path.resolve(import.meta.dirname, '../../docker/Dockerfile.server'),
    'utf8'
  );

  assert.match(dockerfile, /RUN npm ci --omit=dev --no-audit --no-fund/);
  assert.doesNotMatch(dockerfile, /^RUN npm install\s*$/m);
});
