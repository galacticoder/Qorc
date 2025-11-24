#!/usr/bin/env node
/*
 * Client launcher - cross-platform
 * - Starts the Electron client with Vite dev server
 * - Run `node scripts/install-deps.cjs --client` first to install dependencies
 */

const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');

function log(...args) { console.log('[CLIENT]', ...args); }
function logErr(...args) { console.error('[CLIENT]', ...args); }

// Check if help requested
if (process.argv.slice(2).some(arg => arg === '-h' || arg === '--help')) {
    console.log('Usage: node start-client.cjs - Starts end2end chat client');
    console.log('');
    console.log('Prerequisites: Run `node scripts/install-deps.cjs --client` first');
    process.exit(0);
}

process.chdir(repoRoot);

// Check for critical dependencies
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

// Symlink config files
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

    // Remove existing file/link if present
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

// Fix chrome-sandbox permissions on Linux
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

// Kill any existing processes on port 5173
const VITE_PORT = process.env.VITE_PORT || 5173;
process.env.VITE_PORT = String(VITE_PORT);

function killPort(port) {
    try {
        if (process.platform === 'win32') {
            const result = execSync(`netstat -ano | findstr :${port}`, { encoding: 'utf8' });
            const lines = result.split('\n');
            const pids = new Set();

            for (const line of lines) {
                const match = line.trim().match(/LISTENING\s+(\d+)/);
                if (match) pids.add(match[1]);
            }

            for (const pid of pids) {
                try {
                    execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' });
                } catch { }
            }
        } else {
            try {
                const pids = execSync(`lsof -t -i TCP:${port} -sTCP:LISTEN`, { encoding: 'utf8' }).trim();
                if (pids) {
                    execSync(`kill -9 ${pids}`, { stdio: 'ignore' });
                }
            } catch {
                try {
                    execSync(`fuser -k ${port}/tcp`, { stdio: 'ignore' });
                } catch { }
            }
        }
    } catch { }
}

killPort(VITE_PORT);

// Cleanup and retry function
function cleanupAndRetry() {
    const nodeModules = path.join(repoRoot, 'node_modules');
    const pnpmLock = path.join(repoRoot, 'pnpm-lock.yaml');
    const packageLock = path.join(repoRoot, 'package-lock.json');

    if (fs.existsSync(nodeModules)) {
        fs.rmSync(nodeModules, { recursive: true, force: true });
    }
    if (fs.existsSync(pnpmLock)) {
        fs.unlinkSync(pnpmLock);
    }
    if (fs.existsSync(packageLock)) {
        fs.unlinkSync(packageLock);
    }

    const configPnpmLock = path.join(repoRoot, 'config', 'pnpm-lock.yaml');
    if (fs.existsSync(configPnpmLock)) {
        try {
            fs.symlinkSync(path.join('config', 'pnpm-lock.yaml'), pnpmLock);
        } catch { }
    }

    execSync('pnpm install', { stdio: 'inherit', cwd: repoRoot });

    // Restart script
    const scriptPath = __filename;
    const proc = spawn(process.execPath, [scriptPath, ...process.argv.slice(2)], {
        stdio: 'inherit',
        cwd: repoRoot,
        detached: false
    });

    proc.on('exit', code => process.exit(code));
}

// Cleanup handler
let CLIENT_PID = null;
let VITE_PID = null;

function cleanup() {
    if (VITE_PID) {
        try {
            process.kill(VITE_PID);
        } catch { }
    }
    if (CLIENT_PID) {
        try {
            process.kill(CLIENT_PID);
        } catch { }
    }
    process.exit();
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

// Start the client
const START_ELECTRON = process.env.START_ELECTRON !== '0';
const retryFile = path.join(require('os').tmpdir(), 'client_retry_attempted');

if (START_ELECTRON) {
    // Start Vite dev server
    const viteProc = spawn('pnpm', ['exec', 'vite'], {
        stdio: 'inherit',
        cwd: repoRoot,
        shell: true
    });

    VITE_PID = viteProc.pid;

    // Wait for Vite to be ready
    const waitOnProc = spawn('pnpm', ['exec', 'wait-on', `http://localhost:${VITE_PORT}`], {
        stdio: 'pipe',
        cwd: repoRoot,
        shell: true
    });

    waitOnProc.on('exit', code => {
        if (code !== 0) {
            viteProc.kill();

            if (!fs.existsSync(retryFile)) {
                fs.writeFileSync(retryFile, '');
                cleanupAndRetry();
            } else {
                process.exit(1);
            }
        } else {
            // Start Electron
            const electronBin = path.join(repoRoot, 'node_modules', '.bin', 'electron');
            const electronProc = spawn(electronBin, ['.'], {
                stdio: 'inherit',
                cwd: repoRoot,
                shell: process.platform === 'win32'
            });

            CLIENT_PID = electronProc.pid;

            electronProc.on('exit', code => {
                viteProc.kill();
                try {
                    fs.unlinkSync(retryFile);
                } catch { }
                process.exit(code);
            });
        }
    });
} else {
    // Just start Vite
    const viteProc = spawn('pnpm', ['run', 'vite'], {
        stdio: ['inherit', 'pipe', 'inherit'],
        cwd: repoRoot,
        shell: true
    });

    VITE_PID = viteProc.pid;
    CLIENT_PID = viteProc.pid;

    const logFile = path.join(require('os').tmpdir(), 'client_output.log');
    const logStream = fs.createWriteStream(logFile);

    viteProc.stdout.pipe(logStream);
    viteProc.stdout.pipe(process.stdout);

    viteProc.on('exit', code => {
        logStream.end();

        if (code !== 0) {
            try {
                const logContent = fs.readFileSync(logFile, 'utf8');
                if (/ERR_|MODULE_NOT_FOUND|Cannot find/.test(logContent) && !fs.existsSync(retryFile)) {
                    fs.writeFileSync(retryFile, '');
                    cleanupAndRetry();
                }
            } catch { }
        }

        try {
            fs.unlinkSync(retryFile);
        } catch { }

        process.exit(code);
    });
}
