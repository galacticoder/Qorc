#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync, execSync } = require('node:child_process');

const repoRoot = path.resolve(__dirname, '..');

execFileSync(process.execPath, [path.join(__dirname, 'stage-webkitgtk-runtime.cjs')], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
    windowsHide: true
});

if (process.env.QORC_FRONTEND_PREBUILT === '1') {
    const entrypoint = path.join(repoRoot, 'dist', 'index.html');
    if (!fs.statSync(entrypoint, { throwIfNoEntry: false })?.isFile()) {
        throw new Error('QORC_FRONTEND_PREBUILT=1 but dist/index.html is missing');
    }
    console.log('[frontend] using the separately built frontend bundle');
} else {
    execSync('pnpm run build', {
        cwd: repoRoot,
        stdio: 'inherit',
        env: process.env,
        windowsHide: true
    });
}
