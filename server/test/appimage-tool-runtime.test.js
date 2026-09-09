import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { prepareAppImageTool, readAppImageRuntimeOffset } = require('../../scripts/appimage-tool-runtime.cjs');

function fixture(t, machine = 183) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-appimage-test-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const file = path.join(directory, 'tool.AppImage');
    const data = Buffer.alloc(70_000, 0x55);
    Buffer.from('7f454c460201010041490200000000000300', 'hex').copy(data);
    data.writeUInt16LE(machine, 18);
    fs.writeFileSync(file, data, { mode: 0o755 });
    return { file, data };
}

test('ARM64 AppImage tools receive the standard ELF padding required by binfmt', t => {
    const { file, data } = fixture(t);
    prepareAppImageTool(file, 'arm64');
    const expected = Buffer.from(data);
    expected.fill(0, 8, 11);
    assert.deepEqual(fs.readFileSync(file), expected);
});

test('cached tools are prepared idempotently', t => {
    const { file } = fixture(t);
    prepareAppImageTool(file, 'arm64');
    const before = fs.readFileSync(file);
    prepareAppImageTool(file, 'arm64');
    assert.deepEqual(fs.readFileSync(file), before);
});

test('x64 tools are also validated and prepared', t => {
    const { file } = fixture(t, 62);
    prepareAppImageTool(file, 'x64');
    assert.equal(fs.readFileSync(file).readUInt16LE(18), 62);
});

test('wrong architecture, invalid ELF, and unknown AppImage headers fail without modifying files', t => {
    for (const mutate of [data => data.writeUInt16LE(62, 18), data => data[0] = 0, data => data[4] = 1, data => data[10] = 3]) {
        const { file, data } = fixture(t);
        mutate(data);
        fs.writeFileSync(file, data);
        assert.throws(() => prepareAppImageTool(file, 'arm64'), /AppImage tool/);
        assert.deepEqual(fs.readFileSync(file), data);
    }
});

test('truncated executables are rejected', t => {
    const { file } = fixture(t);
    fs.writeFileSync(file, Buffer.from('ELF'));
    assert.throws(() => prepareAppImageTool(file, 'arm64'), /valid arm64 ELF/);
});

test('reading the runtime offset preserves the distributed AppImage header', t => {
    const { file, data } = fixture(t);
    let temporary;
    const offset = readAppImageRuntimeOffset(file, 'arm64', (executable, args) => {
        temporary = executable;
        assert.notEqual(executable, file);
        assert.deepEqual(args, ['--appimage-offset']);
        assert.deepEqual(fs.readFileSync(executable).subarray(8, 11), Buffer.alloc(3));
        return '65536\n';
    });
    assert.equal(offset, 65536);
    assert.deepEqual(fs.readFileSync(file), data);
    assert.equal(fs.existsSync(path.dirname(temporary)), false);
});

test('invalid runtime offsets and execution failures leave the output untouched', t => {
    const { file, data } = fixture(t);
    for (const output of ['65536invalid', '12', '70000', '999999999']) {
        let temporary;
        assert.throws(() => readAppImageRuntimeOffset(file, 'arm64', executable => {
            temporary = executable;
            return output;
        }), /runtime/);
        assert.equal(fs.existsSync(path.dirname(temporary)), false);
        assert.deepEqual(fs.readFileSync(file), data);
    }
    let temporary;
    assert.throws(() => readAppImageRuntimeOffset(file, 'arm64', executable => {
        temporary = executable;
        throw new Error('execution failed');
    }), /execution failed/);
    assert.equal(fs.existsSync(path.dirname(temporary)), false);
    assert.deepEqual(fs.readFileSync(file), data);
});

test('both packaging tools are prepared and checked before lengthy compilation', () => {
    const root = path.resolve(import.meta.dirname, '../..');
    const appimage = fs.readFileSync(path.join(root, 'scripts/build-appimage.cjs'), 'utf8');
    const start = fs.readFileSync(path.join(root, 'scripts/start-client.cjs'), 'utf8');
    assert.match(appimage, /prepareAppImageTool\(linuxDeployPath\)/);
    assert.match(appimage, /prepareAppImageTool\(appImagePluginPath\)/);
    assert.ok(appimage.indexOf("process.argv.includes('--check-tools')") < appimage.indexOf('if (!fs.existsSync(binaryPath))'));
    assert.ok(start.indexOf('buildAppImage(true);') < start.indexOf('    buildPirSidecars();'));
});
