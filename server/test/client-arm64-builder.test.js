import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ensureArm64Builder } = require('../../scripts/client-arm64-builder.cjs');
const scriptsDirectory = path.resolve(import.meta.dirname, '../../scripts');

function fixture({ names = 'default\n', runtime = 'linux\n', env = {}, fail } = {}) {
    const calls = [];
    const options = {
        env,
        log() {},
        run(command, args, execution) {
            assert.equal(command, 'docker');
            assert.equal(execution.env, env);
            calls.push({ args, execution });
            if (fail?.(args)) throw new Error('test command failed');
            if (args[0] === 'version') return runtime;
            if (args[1] === 'ls') return names;
            return '';
        }
    };
    return { calls, options, execute: () => ensureArm64Builder(options) };
}

test('an unconfigured x86 host creates a persistent local container builder', () => {
    const setup = fixture();
    assert.equal(setup.execute(), 'qorc-client-arm64');
    assert.deepEqual(setup.calls.find(call => call.args[1] === 'create').args, [
        'buildx', 'create', '--name', 'qorc-client-arm64', '--driver', 'docker-container'
    ]);
    assert.ok(setup.calls.every(call => !call.args.includes('--use')));
    assert.ok(setup.calls.every(call => !call.args.includes('--privileged')));
    assert.deepEqual(setup.calls.find(call => call.args[1] === 'inspect').args, [
        'buildx', 'inspect', 'qorc-client-arm64', '--bootstrap'
    ]);
});

test('an existing local builder is reused without recreation', () => {
    const setup = fixture({ names: 'default\nqorc-client-arm64\nqorc-client-arm640\n' });
    assert.equal(setup.execute(), 'qorc-client-arm64');
    assert.ok(!setup.calls.some(call => call.args[1] === 'create'));
});

test('a similar builder name does not match the local builder', () => {
    const setup = fixture({ names: 'qorc-client-arm64-other\n' });
    setup.execute();
    assert.ok(setup.calls.some(call => call.args[1] === 'create'));
});

test('an explicit builder is used without creating or selecting another one', () => {
    const setup = fixture({ env: { QORC_ARM64_BUILDER: ' native-arm ' } });
    assert.equal(setup.execute(), 'native-arm');
    assert.ok(!setup.calls.some(call => ['ls', 'create'].includes(call.args[1])));
    assert.ok(setup.calls.find(call => call.args[1] === 'build').args.includes('native-arm'));
});

test('every invocation executes an uncached ARM64 check without uploading source files', () => {
    const setup = fixture({ names: 'qorc-client-arm64\n' });
    setup.execute();
    setup.execute();
    const checks = setup.calls.filter(call => call.args[1] === 'build');
    assert.equal(checks.length, 2);
    for (const check of checks) {
        assert.deepEqual(check.args, [
            'buildx', 'build', '--builder', 'qorc-client-arm64', '--platform', 'linux/arm64',
            '--target', 'arm64-runtime', '--no-cache', '--progress', 'plain',
            '--output', 'type=cacheonly', '-'
        ]);
        assert.match(check.execution.input, /FROM ubuntu:26\.04@sha256:[a-f0-9]{64} AS arm64-runtime/);
        assert.match(check.execution.input, /RUN test "\$\(uname -m\)" = aarch64 && \/bin\/sh -c '\/usr\/bin\/true'/);
        assert.deepEqual(check.execution.stdio, ['pipe', 'inherit', 'inherit']);
    }
});

test('Docker connectivity failures stop before builder setup', () => {
    const setup = fixture({ fail: args => args[0] === 'version' });
    assert.throws(setup.execute, /Docker is unavailable or is not running/);
    assert.equal(setup.calls.length, 1);
});

test('non-Linux Docker daemons are rejected', () => {
    const setup = fixture({ runtime: 'windows\n' });
    assert.throws(setup.execute, /Linux containers/);
    assert.equal(setup.calls.length, 1);
});

test('missing Buildx points to the ARM64 dependency preset', () => {
    const setup = fixture({ fail: args => args[0] === 'buildx' && args[1] === 'version' });
    assert.throws(setup.execute, /install-deps\.cjs --client-arm64/);
    assert.equal(setup.calls.length, 2);
});

test('a failed builder listing does not trigger builder creation', () => {
    const setup = fixture({ fail: args => args[1] === 'ls' });
    assert.throws(setup.execute, /test command failed/);
    assert.ok(!setup.calls.some(call => call.args[1] === 'create'));
});

test('a failed builder creation stops before bootstrapping or building', () => {
    const setup = fixture({ fail: args => args[1] === 'create' });
    assert.throws(setup.execute, /test command failed/);
    assert.ok(!setup.calls.some(call => ['inspect', 'build'].includes(call.args[1])));
});

test('a broken explicitly configured builder fails without switching to local', () => {
    const setup = fixture({ env: { QORC_ARM64_BUILDER: 'native-arm' }, fail: args => args[1] === 'inspect' });
    assert.throws(setup.execute, /Cannot start ARM64 builder 'native-arm'/);
    assert.ok(!setup.calls.some(call => ['create', 'build'].includes(call.args[1])));
});

test('a failed ARM64 runtime probe stops with setup guidance', () => {
    const setup = fixture({ fail: args => args[1] === 'build' });
    assert.throws(setup.execute, /ARM64 execution check failed.*docs\/CONTRIBUTING\.md/);
    assert.equal(setup.calls.filter(call => call.args[1] === 'build').length, 1);
});

test('builder names cannot inject command options', () => {
    for (const name of ['--help', 'bad name', 'remote;echo', '../remote']) {
        const setup = fixture({ env: { QORC_ARM64_BUILDER: name } });
        assert.throws(setup.execute, /valid Buildx builder name/);
        assert.ok(!setup.calls.some(call => ['create', 'inspect', 'build'].includes(call.args[1])));
    }
});

test('the dependency preset prepares the same builder as the build entry point', () => {
    const installer = fs.readFileSync(path.join(scriptsDirectory, 'install-deps.cjs'), 'utf8');
    const builder = fs.readFileSync(path.join(scriptsDirectory, 'build-client-linux-arm64.cjs'), 'utf8');
    assert.match(installer, /'client-arm64': \[[^\]]*'docker-buildx', 'arm64-builder'\]/);
    assert.match(installer, /case 'arm64-builder': \{\s+const \{ ensureArm64Builder \} = require\('\.\/client-arm64-builder\.cjs'\);\s+ensureArm64Builder\(\);/);
    assert.ok(builder.indexOf('ensureArm64Builder();') < builder.indexOf('contextRoot = createClientDockerBuildContext'));
});
