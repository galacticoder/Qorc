#!/usr/bin/env node
/*
 * Rebuilds and starts the Tauri client
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
function logErr(...args) { console.error('[CLIENT]', ...args); }
const tauriDir = path.join(repoRoot, 'src-tauri');

if (process.argv.slice(2).some(arg => arg === '-h' || arg === '--help')) {
    console.log('Usage: node start-client.cjs [--run-only] - Starts Qor-Chat client (Tauri)');
    console.log('  --run-only   Skip the rebuild and just launch the already built binary.');
    console.log('Prerequisites: Run `node scripts/install-deps.cjs --client` first');
    console.log('Logs are mirrored to logs/client-instance-<QOR_INSTANCE_ID>.log');
    process.exit(0);
}

process.chdir(repoRoot);

const runOnly = process.argv.slice(2).some(arg => arg === '--run-only' || arg === '--no-build');

// Save all logs to logs/client-instance-<id>.log
const instanceId = (process.env.QOR_INSTANCE_ID || '1').trim() || '1';
const logsDir = path.join(repoRoot, 'logs');
const logFilePath = path.join(logsDir, `client-instance-${instanceId}.log`);

function clientRuntimeEnv() {
    const env = { ...process.env };
    if (process.platform === 'linux') {
        for (const key of Object.keys(env)) {
            if (
                key.startsWith('SNAP') ||
                key.startsWith('GIO_LAUNCHED_DESKTOP_FILE') ||
                key === 'GIO_MODULE_DIR' ||
                key === 'GTK_EXE_PREFIX' ||
                key === 'GTK_IM_MODULE_FILE' ||
                key === 'GTK_PATH'
            ) {
                delete env[key];
            }
        }
        if (env.XDG_DATA_DIRS_VSCODE_SNAP_ORIG) {
            env.XDG_DATA_DIRS = env.XDG_DATA_DIRS_VSCODE_SNAP_ORIG;
            delete env.XDG_DATA_DIRS_VSCODE_SNAP_ORIG;
        }
        if (env.XDG_CONFIG_DIRS_VSCODE_SNAP_ORIG) {
            env.XDG_CONFIG_DIRS = env.XDG_CONFIG_DIRS_VSCODE_SNAP_ORIG;
            delete env.XDG_CONFIG_DIRS_VSCODE_SNAP_ORIG;
        }
        if (env.LD_LIBRARY_PATH?.includes('/snap/')) {
            delete env.LD_LIBRARY_PATH;
        }
        const localLib = path.join(os.homedir(), '.local', 'lib');
        if (fs.existsSync(localLib)) {
            env.LIBRARY_PATH = env.LIBRARY_PATH ? `${localLib}${path.delimiter}${env.LIBRARY_PATH}` : localLib;
        }
        env.WEBKIT_DISABLE_DMABUF_RENDERER ??= '1';
        env.GST_PLUGIN_FEATURE_RANK ??= 'pulsesrc:512,pulsesink:512';
        if (env.QOR_CHAT_SOFTWARE_RENDERING) {
            env.LIBGL_ALWAYS_SOFTWARE ??= '1';
        }
    }
    return env;
}

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
    logErr('Please check if Node.js, pnpm, and Rust are installed.');
    process.exit(1);
}

const nodeModulesPath = path.join(repoRoot, 'node_modules');
if (!fs.existsSync(nodeModulesPath)) {
    console.log('[CLIENT] Installing dependencies...');
    execSync('pnpm install', { stdio: 'inherit', cwd: repoRoot });
}

function launchApp() {
    const binName = getTauriBinaryName();
    const runPath = path.join(tauriDir, 'target', 'release', binName);

    if (!fs.existsSync(runPath)) {
        logErr('Built Tauri binary not found. Expected at:', runPath);
        logErr('Run without --run-only once to build it.');
        process.exit(1);
    }

    try { fs.mkdirSync(logsDir, { recursive: true }); } catch { }
    const logStream = fs.createWriteStream(logFilePath, { flags: 'w' });
    logStream.write(`# Qor-Chat client (instance ${instanceId}) started ${new Date().toISOString()}\n`);
    console.log(`[CLIENT] Launching built app (instance ${instanceId})... logging to ${path.relative(repoRoot, logFilePath)}`);

    const runProc = spawn(runPath, [], {
        stdio: ['inherit', 'pipe', 'pipe'],
        cwd: repoRoot,
        shell: false,
        env: clientRuntimeEnv()
    });

    // Tee both streams: terminal stays live, file captures everything.
    runProc.stdout.pipe(process.stdout);
    runProc.stdout.pipe(logStream);
    runProc.stderr.pipe(process.stderr);
    runProc.stderr.pipe(logStream);

    runProc.on('exit', exitCode => {
        try { logStream.end(); } catch { }
        process.exit(exitCode);
    });
}

function getTauriBinaryName() {
    try {
        const metadata = JSON.parse(execSync('cargo metadata --format-version 1 --no-deps', {
            cwd: tauriDir,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        }));
        const rootPackage = metadata.packages?.find(pkg => pkg.manifest_path === path.join(tauriDir, 'Cargo.toml'));
        const binTarget = rootPackage?.targets?.find(target => target.kind?.includes('bin'));
        if (binTarget?.name) {
            return process.platform === 'win32' ? `${binTarget.name}.exe` : binTarget.name;
        }
    } catch { }

    return process.platform === 'win32' ? 'qor.exe' : 'qor';
}

function removeOldBundleArtifacts() {
    const bundleDir = path.join(tauriDir, 'target', 'release', 'bundle');
    try {
        fs.rmSync(bundleDir, { recursive: true, force: true });
    } catch (error) {
        logErr('Failed to clear old Tauri bundle artifacts:', error.message);
        process.exit(1);
    }
}

if (runOnly) {
    console.log('[CLIENT] --run-only: skipping rebuild, launching existing binary.');
    launchApp();
} else {
    try {
        execSync(`node ${JSON.stringify(path.join(repoRoot, 'scripts', 'ensure-pir-worker-binaries.cjs'))}`, {
            stdio: 'inherit',
            cwd: repoRoot,
            env: process.env
        });
    } catch (error) {
        logErr('Failed to build the PIR client binary.');
        logErr('It builds from workers/hintless via Docker, so Docker must be installed and running.');
        logErr('(Override the binary path with QOR_PIR_CLIENT_BIN, or build manually: node scripts/build-pir-client.cjs)');
        process.exit(1);
    }

    console.log('[CLIENT] Building Tauri app...');
    removeOldBundleArtifacts();
    const buildProc = spawn('pnpm tauri build', {
        stdio: 'inherit',
        cwd: repoRoot,
        shell: true,
        env: clientRuntimeEnv()
    });

    buildProc.on('exit', code => {
        if (code !== 0) {
            logErr(`Tauri build failed with code ${code}`);
            process.exit(code || 1);
        }
        launchApp();
    });
}
