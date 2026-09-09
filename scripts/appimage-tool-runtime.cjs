'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function prepareAppImageTool(filePath, architecture = process.arch) {
    const machine = { x64: 62, arm64: 183 }[architecture];
    if (!machine) throw new Error(`Unsupported AppImage tool architecture: ${architecture}`);
    const descriptor = fs.openSync(filePath, 'r+');
    try {
        const header = Buffer.alloc(20);
        if (fs.readSync(descriptor, header, 0, header.length, 0) !== header.length ||
            header.toString('hex', 0, 4) !== '7f454c46' || header[4] !== 2 ||
            header[5] !== 1 || header[6] !== 1 || header.readUInt16LE(18) !== machine) {
            throw new Error(`AppImage tool is not a valid ${architecture} ELF executable: ${filePath}`);
        }
        const marker = header.subarray(8, 11);
        if (marker.equals(Buffer.alloc(3))) return;
        if (!marker.equals(Buffer.from([0x41, 0x49, 0x02]))) {
            throw new Error(`AppImage tool has an unsupported runtime header: ${filePath}`);
        }
        if (fs.writeSync(descriptor, Buffer.alloc(3), 0, 3, 8) !== 3) {
            throw new Error(`Could not prepare AppImage tool header: ${filePath}`);
        }
    } finally {
        fs.closeSync(descriptor);
    }
}

function readAppImageRuntimeOffset(filePath, architecture = process.arch, run = execFileSync) {
    const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-appimage-runtime-'));
    try {
        const executable = path.join(temporaryRoot, 'runtime.AppImage');
        fs.copyFileSync(filePath, executable, fs.constants.COPYFILE_FICLONE);
        fs.chmodSync(executable, 0o755);
        prepareAppImageTool(executable, architecture);
        const output = run(executable, ['--appimage-offset'], {
            encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30_000
        }).trim();
        if (!/^\d+$/.test(output)) throw new Error(`Invalid AppImage runtime offset: ${output}`);
        const offset = Number(output);
        if (!Number.isSafeInteger(offset) || offset < 65536 || offset > 4 * 1024 * 1024 ||
            offset >= fs.statSync(filePath).size) {
            throw new Error(`Unexpected AppImage runtime size: ${offset}`);
        }
        return offset;
    } finally {
        fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
}

module.exports = { prepareAppImageTool, readAppImageRuntimeOffset };
