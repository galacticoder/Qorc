#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { verifyElf } = require('./verify-android-tor.cjs');
const root = path.resolve(__dirname, '../src-tauri/vendor/pir/android');
function verify(directory = root) {
    const pins = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json')));
    for (const abi of ['arm64-v8a', 'x86_64']) {
        const file = path.join(directory, 'jniLibs', abi, 'libqorc_pir_client.so');
        if (!fs.lstatSync(file).isFile()) throw new Error(`Invalid Android PIR file: ${abi}`);
        const bytes = fs.readFileSync(file), pin = pins.abis?.[abi];
        if (!pin || bytes.length !== pin.size || !/^[a-f0-9]{64}$/.test(pin.sha256)
            || crypto.createHash('sha256').update(bytes).digest('hex') !== pin.sha256) {
            throw new Error(`Android PIR release hash/length mismatch: ${abi}`);
        }
        verifyElf(bytes, abi);
    }
    return pins;
}
module.exports = { verify };
if (require.main === module) {
    verify();
    console.log('Verified Android PIR executables: ARM64/x86_64, pinned bytes, 16 KB alignment');
}
