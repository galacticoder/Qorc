#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');

function appMetadata(config) {
    return {
        label: config.app?.windows?.find(window => window.label === 'main')?.title || config.productName,
        productName: config.productName,
        identifier: config.identifier,
        version: config.version,
        description: config.bundle.longDescription || config.bundle.shortDescription || '',
    };
}

function writeChanged(file, contents) {
    if (fs.existsSync(file) && fs.readFileSync(file).equals(Buffer.from(contents))) return;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
}

function androidString(value) {
    return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll("'", "\\'")
        .replaceAll('\n', '\\n').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function prepare({ config = JSON.parse(fs.readFileSync(path.join(root, 'src-tauri/tauri.conf.json'), 'utf8')) } = {}) {
    const metadata = appMetadata(config);
    const resourceDirectory = path.join(root, 'src-tauri/gen/android/app/src/main/res');
    const icon = path.join(root, 'src-tauri', config.bundle.icon.find(icon => /(?:^|\/)icon\.png$/.test(icon)) || config.bundle.icon.find(icon => icon.endsWith('.png')));
    const stage = path.join(root, '.cache/android-branding');
    fs.mkdirSync(stage, { recursive: true });
    const stamp = path.join(stage, 'source.sha256');
    const sourceHash = crypto.createHash('sha256').update(fs.readFileSync(icon)).update('qorc-android-branding-v1')
        .update(require('@tauri-apps/cli/package.json').version).digest('hex');
    const generated = path.join(stage, 'icons/android');
    if (!fs.existsSync(stamp) || fs.readFileSync(stamp, 'utf8') !== sourceHash || !fs.existsSync(path.join(generated, 'mipmap-anydpi-v26/ic_launcher.xml'))) {
        execFileSync(process.execPath, [require.resolve('@tauri-apps/cli/tauri.js'), 'icon', icon,
            '--output', path.join(stage, 'icons'), '--ios-color', '#0a0a0a'], { cwd: root, stdio: 'pipe' });
        fs.writeFileSync(stamp, sourceHash);
    }
    
    for (const directory of fs.readdirSync(generated, { withFileTypes: true })) {
        if (!directory.isDirectory() || directory.name === 'mipmap-anydpi-v26') continue;
        for (const file of fs.readdirSync(path.join(generated, directory.name))) {
            writeChanged(path.join(resourceDirectory, directory.name, file), fs.readFileSync(path.join(generated, directory.name, file)));
        }
    }
    
    fs.rmSync(path.join(resourceDirectory, 'drawable-v24/ic_launcher_foreground.xml'), { force: true });
    writeChanged(path.join(resourceDirectory, 'drawable-v26/ic_launcher_foreground.xml'), `<?xml version="1.0" encoding="utf-8"?>
<inset xmlns:android="http://schemas.android.com/apk/res/android"
    android:drawable="@mipmap/ic_launcher_foreground" android:inset="22.222222%" />
`);
    writeChanged(path.join(resourceDirectory, 'drawable/ic_launcher_background.xml'), `<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android="http://schemas.android.com/apk/res/android" android:shape="rectangle">
    <solid android:color="@color/ic_launcher_background" />
</shape>
`);
    const adaptive = `<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@drawable/ic_launcher_foreground" />
</adaptive-icon>
`;
    for (const filename of ['ic_launcher.xml', 'ic_launcher_round.xml']) {
        writeChanged(path.join(resourceDirectory, 'mipmap-anydpi-v26', filename), adaptive);
    }
    const strings = { app_name: metadata.label, main_activity_title: metadata.label, app_description: metadata.description };
    writeChanged(path.join(resourceDirectory, 'values/strings.xml'), '<resources>\n' + Object.entries(strings)
        .map(([key, value]) => `    <string name="${key}" translatable="false" formatted="false">${androidString(value)}</string>`).join('\n') + '\n</resources>\n');
    console.log(`[CLIENT] Android branding matches desktop: ${metadata.label} ${metadata.version} (${metadata.identifier}).`);
    return metadata;
}

module.exports = { prepare, appMetadata };
if (require.main === module) prepare();
