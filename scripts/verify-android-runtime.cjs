#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');

function verify(directory = root) {
    const lock = fs.readFileSync(path.join(directory, 'src-tauri/Cargo.lock'), 'utf8');
    for (const [name, version] of Object.entries({ tauri: '2.10.2', wry: '0.54.2', 'tauri-plugin-dialog': '2.6.0' })) {
        const entries = [...lock.matchAll(/\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)"/g)]
            .filter(match => match[1] === name);
        if (entries.length !== 1 || entries[0][2] !== version) {
            throw new Error(`Review Android runtime adapters before upgrading ${name} ${version}`);
        }
    }
    const generated = path.join(directory, 'src-tauri/gen/android/app/src/main/java/com/qorc/app/generated');
    for (const [name, expected] of Object.entries({
        'WryActivity.kt': '1213fb0df1aadff3ffb9fbc1d20d53980445ab361e9c8645306d4c127c2551b3',
        'RustWebView.kt': '881d3e64130cfe7ce548b997694cc94ce04d000aa1504a05a03099ac48a14eff',
        'TauriActivity.kt': 'e9b7f265a88589df16cad8dd897e8413602ac394d23380fda204c8b83b0e03ac',
        'RustWebChromeClient.kt': '2529e4774a11ca085582f001c0c0113d1bd465fd938e6002604f0c33addc5e9f',
    })) {
        const file = path.join(generated, name);
        if (!fs.existsSync(file)) continue;
        const hash = crypto.createHash('sha256').update(fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n')).digest('hex');
        if (hash !== expected) throw new Error(`Review Android runtime adapter: generated ${name} changed`);
    }
}
module.exports = { verify };
if (require.main === module) {
    verify();
    console.log('Verified pinned Android runtime adapter contracts');
}
