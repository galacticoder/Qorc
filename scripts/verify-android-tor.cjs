#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '../src-tauri/vendor/tor/android');

function verifyElf(bytes, abi) {
    const machine = { 'arm64-v8a': 183, x86_64: 62 }[abi];
    if (!machine || bytes.length < 64 || bytes.subarray(0, 6).toString('hex') !== '7f454c460201'
        || bytes.readUInt16LE(16) !== 3 || bytes.readUInt16LE(18) !== machine) {
        throw new Error(`Expected an Android ${abi} 64-bit PIE executable`);
    }
    const offset = Number(bytes.readBigUInt64LE(32));
    const entrySize = bytes.readUInt16LE(54), count = bytes.readUInt16LE(56);
    if (entrySize !== 56 || count > 128 || offset + entrySize * count > bytes.length) {
        throw new Error('Invalid ELF program headers');
    }
    let interpreter = false, load = false, relro = false, stack = false;
    for (let i = 0; i < count; ++i) {
        const p = offset + i * entrySize, type = bytes.readUInt32LE(p), flags = bytes.readUInt32LE(p + 4);
        if (type === 1) {
            load = true;
            if (bytes.readBigUInt64LE(p + 48) < 16384n || (flags & 3) === 3) {
                throw new Error('ELF must support 16 KB pages and forbid writable executable segments');
            }
        }
        if (type === 3) {
            const start = Number(bytes.readBigUInt64LE(p + 8)), length = Number(bytes.readBigUInt64LE(p + 32));
            interpreter = bytes.subarray(start, start + length).toString() === '/system/bin/linker64\0';
        }
        if (type === 0x6474e552) relro = true;
        if (type === 0x6474e551) stack = (flags & 1) === 0;
    }
    if (!interpreter || !load || !relro || !stack) throw new Error('Missing Android linker, RELRO, or non-executable stack');
}

function verify(directory = root) {
    const pins = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json')));
    const check = (relative, pin) => {
        if (typeof pin !== 'string' || !/^[a-f0-9]{64}$/.test(pin)) throw new Error(`Missing release pin: ${relative}`);
        const file = path.join(directory, relative);
        if (!fs.lstatSync(file).isFile()) throw new Error(`Not a regular artifact: ${relative}`);
        const bytes = fs.readFileSync(file);
        if (crypto.createHash('sha256').update(bytes).digest('hex') !== pin) throw new Error(`Android Tor SHA-256 mismatch: ${relative}`);
        return bytes;
    };
    for (const abi of ['arm64-v8a', 'x86_64']) {
        for (const name of ['libqorc_tor.so', 'libqorc_lyrebird.so']) {
            verifyElf(check(`jniLibs/${abi}/${name}`, pins.abis?.[abi]?.[name]), abi);
        }
    }
    check('tor-data.tar.gz', pins.dataSha256);
    return pins;
}
module.exports = { verify, verifyElf };
if (require.main === module) {
    const pins = verify();
    console.log(`Verified Android Tor ${pins.version}: ARM64/x86_64 binaries and runtime data`);
}
