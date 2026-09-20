import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const root = path.resolve(import.meta.dirname, '../..');
const launcher = fs.readFileSync(path.join(root, 'scripts/start-client.cjs'), 'utf8');
const buildBranch = launcher.slice(launcher.indexOf('    const buildCommand ='), launcher.lastIndexOf('\n}'));

function launch(platform) {
    const child = new EventEmitter();
    const calls = [];
    const errors = [];
    const exits = [];
    const stopped = new Error('process exited');
    const completed = [];
    const env = { PATH: 'test-path' };
    const node = platform === 'win32' ? 'C:\\Program Files\\nodejs\\node.exe' : '/usr/bin/node';
    const repoRoot = platform === 'win32' ? 'C:\\Users\\Test User\\Qorc' : '/tmp/Qorc';
    vm.runInNewContext(buildBranch, {
        process: { platform, execPath: node, exit: code => { exits.push(code); throw stopped; } },
        require,
        repoRoot,
        spawn: (...args) => { calls.push(args); return child; },
        clientRuntimeEnv: () => env,
        logErr: message => errors.push(message),
        buildAppImage: () => completed.push('appimage'),
        printBundleArtifacts: () => completed.push('artifacts'),
        pruneClientTargetCache: () => completed.push('prune'),
        launchApp: () => completed.push('launch'),
        allArchitectures: false,
        bundleOnly: false,
    });
    return { child, calls, errors, exits, completed, env, node, repoRoot, stopped };
}

for (const platform of ['win32', 'linux']) {
    test(`${platform} starts the installed Tauri CLI through Node without a package-manager shim`, () => {
        const result = launch(platform);
        const [[command, args, options]] = result.calls;
        assert.equal(command, result.node);
        assert.deepEqual(Array.from(args), [
            require.resolve('@tauri-apps/cli/tauri.js'), 'build',
            ...(platform === 'linux' ? ['--bundles', 'deb,rpm'] : []),
        ]);
        assert.equal(options.cwd, result.repoRoot);
        assert.equal(options.shell, false);
        assert.equal(options.env, result.env);
        result.child.emit('close', 0);
        assert.deepEqual(result.completed, ['appimage', 'artifacts', 'prune', 'launch']);
    });
}

test('Tauri spawn failures are handled and do not launch the app', () => {
    const result = launch('win32');
    assert.throws(() => result.child.emit('error', new Error('spawn node ENOENT')), error => error === result.stopped);
    assert.deepEqual(result.errors, ['Failed to start Tauri build: spawn node ENOENT']);
    assert.deepEqual(result.exits, [1]);
    assert.deepEqual(result.completed, []);
});

test('a failed Tauri build stops before packaging or launching', () => {
    const result = launch('win32');
    assert.throws(() => result.child.emit('close', 7), error => error === result.stopped);
    assert.deepEqual(result.exits, [7]);
    assert.deepEqual(result.completed, []);
});

test('the frontend hook runs the package build script through a shell', () => {
    const calls = [];
    const childProcess = {
        execFileSync: (...args) => calls.push(['file', ...args]),
        execSync: (...args) => calls.push(['shell', ...args]),
    };
    vm.runInNewContext(fs.readFileSync(path.join(root, 'scripts/prepare-tauri-frontend.cjs'), 'utf8'), {
        require: name => name === 'node:child_process' ? childProcess : require(name),
        __dirname: path.join(root, 'scripts'),
        process: { execPath: process.execPath, env: {} },
    });
    assert.equal(calls.length, 2);
    assert.equal(calls[0][1], process.execPath);
    assert.equal(calls[1][0], 'shell');
    assert.equal(calls[1][1], 'pnpm run build');
    assert.equal(calls[1][2].cwd, root);
});
