#!/usr/bin/env node
/*
 * Rebuilds and starts the Tauri client
 */

const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
function logErr(...args) { console.error('[CLIENT]', ...args); }

if (process.argv.slice(2).some(arg => arg === '-h' || arg === '--help')) {
    console.log('Usage: node start-client.cjs - Starts Qor-Chat client (Tauri)');
    console.log('Prerequisites: Run `node scripts/install-deps.cjs --client` first');
    process.exit(0);
}

process.chdir(repoRoot);

const criticalDeps = ['pnpm', 'cargo'];
const missing = criticalDeps.filter(cmd => {
    try {
        const checkCmd = process.platform === 'win32' ? 'where' : 'command -v';
        execSync(`${checkCmd} ${cmd}`, { stdio: 'ignore' });
        return false;
    } catch {
        return true;
    }
});

if (missing.length > 0) {
    logErr(`Missing required dependencies: ${missing.join(', ')}`);
    logErr('Please ensure Node.js, pnpm, and Rust are installed.');
    process.exit(1);
}

const nodeModulesPath = path.join(repoRoot, 'node_modules');
if (!fs.existsSync(nodeModulesPath)) {
    console.log('[CLIENT] Installing dependencies...');
    execSync('pnpm install', { stdio: 'inherit', cwd: repoRoot });
}

console.log('[CLIENT] Building Tauri app (release)...');

const buildProc = spawn('pnpm', ['tauri', 'build'], {
    stdio: 'inherit',
    cwd: repoRoot,
    shell: true,
    env: {
        ...process.env,
    }
});

buildProc.on('exit', code => {
    if (code !== 0) {
        logErr(`Tauri build failed with code ${code}`);
        process.exit(code || 1);
    }

    const binName = process.platform === 'win32' ? 'qor-chat.exe' : 'qor-chat';
    const releaseBin = path.join(repoRoot, 'src-tauri', 'target', 'release', binName);
    const debugBin = path.join(repoRoot, 'src-tauri', 'target', 'debug', binName);
    const runPath = fs.existsSync(releaseBin) ? releaseBin : debugBin;

    if (!fs.existsSync(runPath)) {
        logErr('Built Tauri binary not found. Expected at:', releaseBin, 'or', debugBin);
        process.exit(1);
    }

    console.log('[CLIENT] Launching built app...');
    const runProc = spawn(runPath, [], {
        stdio: 'inherit',
        cwd: repoRoot,
        shell: false,
        env: {
            ...process.env,
        }
    });

    runProc.on('exit', exitCode => process.exit(exitCode));
});
