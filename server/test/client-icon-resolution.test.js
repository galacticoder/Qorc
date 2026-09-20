import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('window and tray icons embed the full-resolution image', () => {
    const png = fs.readFileSync(path.join(root, 'src-tauri/icons/icon.png'));
    assert.equal(png.subarray(1, 4).toString(), 'PNG');
    assert.ok(png.readUInt32BE(16) >= 256);
    assert.ok(png.readUInt32BE(20) >= 256);
    assert.equal(png[25], 6);
    assert.match(read('src-tauri/src/main.rs'), /set_default_window_icon\(Some\(tauri::include_image!\("icons\/icon\.png"\)\)\)/);
    assert.match(read('src-tauri/src/system/tray.rs'), /\.icon\(tauri::include_image!\("icons\/icon\.png"\)\)/);
    assert.equal(JSON.parse(read('src-tauri/tauri.conf.json')).app.trayIcon.iconPath, 'icons/icon.png');
});

test('Windows installer icon retains multiple native resolutions', () => {
    const ico = fs.readFileSync(path.join(root, 'src-tauri/icons/icon.ico'));
    assert.equal(ico.readUInt16LE(2), 1);
    const sizes = new Set();
    for (let index = 0; index < ico.readUInt16LE(4); index++) {
        const offset = 6 + index * 16;
        const width = ico[offset] || 256;
        const height = ico[offset + 1] || 256;
        assert.equal(width, height);
        sizes.add(width);
    }
    for (const size of [16, 24, 32, 48, 64, 128, 256]) assert.ok(sizes.has(size));
});
