#!/usr/bin/env node
/*
 * Client launcher - cross-platform
 * - Starts the Electron client
 * - Run `node scripts/install-deps.cjs --client` first to install dependencies
 */

const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');

function log(...args) { console.log('[CLIENT]', ...args); }
function logErr(...args) { console.error('[CLIENT]', ...args); }

if (process.argv.slice(2).some(arg => arg === '-h' || arg === '--help')) {
    console.log('Usage: node start-client.cjs - Starts end2end chat client');
    console.log('');
    console.log('Prerequisites: Run `node scripts/install-deps.cjs --client` first');
    process.exit(0);
}

process.chdir(repoRoot);

const criticalDeps = ['pnpm'];
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
    logErr('Run: node scripts/install-deps.cjs --client');
    process.exit(1);
}

const configFiles = [
    'package.json',
    'postcss.config.js',
    'tailwind.config.ts',
    'vite.config.ts',
    'tsconfig.json',
    'tsconfig.app.json',
    'tsconfig.node.json'
];

for (const file of configFiles) {
    const target = path.join(repoRoot, file);
    const source = path.join(repoRoot, 'config', file);

    try {
        fs.unlinkSync(target);
    } catch {
    }

    try {
        if (fs.existsSync(source)) {
            fs.linkSync(source, target);
        }
    } catch (err) {
        try {
            const relativePath = path.relative(path.dirname(target), source);
            fs.symlinkSync(relativePath, target);
        } catch {
            logErr(`Failed to link ${file}:`, err.message);
        }
    }
}

const nodeModulesPath = path.join(repoRoot, 'node_modules');
const pnpmLockPath = path.join(repoRoot, 'config', 'pnpm-lock.yaml');
const modulesYamlPath = path.join(nodeModulesPath, '.modules.yaml');

let needsInstall = false;

if (!fs.existsSync(nodeModulesPath)) {
    needsInstall = true;
} else if (fs.existsSync(pnpmLockPath) && fs.existsSync(modulesYamlPath)) {
    const lockStat = fs.statSync(pnpmLockPath);
    const modulesStat = fs.statSync(modulesYamlPath);
    if (lockStat.mtime > modulesStat.mtime) needsInstall = true;
}

if (needsInstall) {
    execSync('pnpm install --prefer-offline', { stdio: 'inherit', cwd: repoRoot });
}

if (process.platform === 'linux') {
    try {
        const pnpmRoot = execSync('pnpm root', { encoding: 'utf8', cwd: repoRoot }).trim();
        const chromeSandbox = path.join(pnpmRoot, 'electron', 'dist', 'chrome-sandbox');

        if (fs.existsSync(chromeSandbox)) {
            try {
                execSync(`sudo chown root:root "${chromeSandbox}"`, { stdio: 'ignore' });
                execSync(`sudo chmod 4755 "${chromeSandbox}"`, { stdio: 'ignore' });
            } catch { }
        }
    } catch { }
}

const electronProc = spawn('pnpm', ['electron'], {
    stdio: 'inherit',
    cwd: repoRoot,
    shell: true
});

electronProc.on('exit', code => process.exit(code));
