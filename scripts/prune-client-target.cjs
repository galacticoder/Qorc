#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const targetDir = path.join(repoRoot, 'src-tauri', 'target');
const releaseDir = path.join(targetDir, 'release');
const force = process.argv.includes('--force');
const dryRun = process.argv.includes('--dry-run');
const defaultLimitGiB = 24;
const configuredLimit = Number.parseFloat(process.env.QOR_CLIENT_TARGET_MAX_GIB || `${defaultLimitGiB}`);

if (!Number.isFinite(configuredLimit) || configuredLimit < 4 || configuredLimit > 1024) {
    console.error('[target-cache] QOR_CLIENT_TARGET_MAX_GIB must be between 4 and 1024');
    process.exit(1);
}

const limitBytes = Math.floor(configuredLimit * 1024 ** 3);

function pathSize(candidate) {
    const metadata = fs.lstatSync(candidate, { throwIfNoEntry: false });
    if (!metadata) return 0;
    if (!metadata.isDirectory()) return metadata.blocks > 0 ? metadata.blocks * 512 : metadata.size;
    let total = metadata.blocks > 0 ? metadata.blocks * 512 : 0;
    for (const entry of fs.readdirSync(candidate)) {
        total += pathSize(path.join(candidate, entry));
    }
    return total;
}

function formatBytes(bytes) {
    return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}

function removeCachePath(candidate) {
    const size = pathSize(candidate);
    if (size === 0) return 0;
    console.log(`[target-cache] ${dryRun ? 'would remove' : 'removing'} ${path.relative(repoRoot, candidate)} (${formatBytes(size)})`);
    if (!dryRun) fs.rmSync(candidate, { recursive: true, force: true });
    return size;
}

function targetTripleDirectories() {
    if (!fs.statSync(targetDir, { throwIfNoEntry: false })?.isDirectory()) return [];
    return fs.readdirSync(targetDir, { withFileTypes: true })
        .filter(entry => entry.isDirectory() && entry.name !== 'debug' && entry.name !== 'release')
        .map(entry => path.join(targetDir, entry.name));
}

function pruneTargetTriple(directory) {
    const bundleDir = path.join(directory, 'release', 'bundle');
    if (!fs.statSync(bundleDir, { throwIfNoEntry: false })?.isDirectory()) {
        return removeCachePath(directory);
    }

    let removed = 0;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (entry.name !== 'release') removed += removeCachePath(path.join(directory, entry.name));
    }
    const tripleReleaseDir = path.join(directory, 'release');
    for (const entry of fs.readdirSync(tripleReleaseDir, { withFileTypes: true })) {
        if (entry.name !== 'bundle') removed += removeCachePath(path.join(tripleReleaseDir, entry.name));
    }
    return removed;
}

function pruneReleaseCompilerCache() {
    let removed = 0;
    for (const entry of ['.fingerprint', 'build', 'deps', 'examples', 'incremental']) {
        removed += removeCachePath(path.join(releaseDir, entry));
    }
    if (fs.statSync(releaseDir, { throwIfNoEntry: false })?.isDirectory()) {
        for (const entry of fs.readdirSync(releaseDir, { withFileTypes: true })) {
            if (entry.isFile() && (
                entry.name === '.cargo-lock' ||
                entry.name.endsWith('.d') ||
                /^libqor(?:_chat_lib)?\.(?:a|rlib|so)$/.test(entry.name)
            )) {
                removed += removeCachePath(path.join(releaseDir, entry.name));
            }
        }
    }
    return removed;
}

if (!fs.statSync(targetDir, { throwIfNoEntry: false })?.isDirectory()) {
    console.log('[target-cache] no client target directory exists');
    process.exit(0);
}

const initialSize = pathSize(targetDir);
if (!force && initialSize <= limitBytes) {
    console.log(`[target-cache] ${formatBytes(initialSize)} is within the ${configuredLimit} GiB limit`);
    process.exit(0);
}

console.log(`[target-cache] client build output is ${formatBytes(initialSize)}; preserving runnable binaries and installer bundles`);
let reclaimed = removeCachePath(path.join(targetDir, 'debug'));
let currentSize = dryRun ? initialSize - reclaimed : pathSize(targetDir);

if (force || currentSize > limitBytes) {
    for (const directory of targetTripleDirectories()) reclaimed += pruneTargetTriple(directory);
    currentSize = dryRun ? initialSize - reclaimed : pathSize(targetDir);
}

if (force || currentSize > limitBytes) {
    reclaimed += pruneReleaseCompilerCache();
}

const finalSize = dryRun ? Math.max(0, initialSize - reclaimed) : pathSize(targetDir);
console.log(`[target-cache] ${dryRun ? 'estimated' : 'current'} size ${formatBytes(finalSize)}; ${dryRun ? 'reclaimable' : 'reclaimed'} ${formatBytes(reclaimed)}`);

