#!/usr/bin/env node
/*
 * Rebuilds and starts the Tauri client
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, execFileSync, execSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
function logErr(...args) { console.error('[CLIENT]', ...args); }
const tauriDir = path.join(repoRoot, 'src-tauri');
const protocVersion = process.env.QOR_PROTOC_VERSION || '33.0';
const strawberryPerlUrl = process.env.QOR_STRAWBERRY_PERL_URL ||
    'https://github.com/StrawberryPerl/Perl-Dist-Strawberry/releases/download/SP_54221_64bit/strawberry-perl-5.42.2.1-64bit-portable.zip';

if (process.argv.slice(2).some(arg => arg === '-h' || arg === '--help')) {
    console.log('Usage: node scripts/start-client.cjs [--run-only] [--bundle-only]');
    console.log('  --run-only     Skip the rebuild and just launch the already built binary.');
    console.log('  --bundle-only  Build native installer bundles and exit without launching.');
    console.log('Prerequisites: Run `node scripts/install-deps.cjs --client` first');
    console.log('Bundles are written to src-tauri/target/release/bundle for the current OS.');
    console.log('Logs are mirrored to logs/instance-<QOR_INSTANCE_ID>-logs.txt');
    process.exit(0);
}

process.chdir(repoRoot);

const runOnly = process.argv.slice(2).some(arg => arg === '--run-only' || arg === '--no-build');
const bundleOnly = process.argv.slice(2).some(arg => arg === '--bundle-only' || arg === '--no-launch');

if (process.platform !== 'linux' && process.platform !== 'win32') {
    logErr('Qor desktop supports only Linux and Windows.');
    process.exit(1);
}

if (runOnly && bundleOnly) {
    logErr('--run-only and --bundle-only cannot be used together.');
    process.exit(1);
}

const instanceId = (process.env.QOR_INSTANCE_ID || '1').trim() || '1';
if (instanceId.length > 64 || !/^[a-zA-Z0-9_-]+$/.test(instanceId)) {
    logErr('QOR_INSTANCE_ID must contain only letters, numbers, underscores, or hyphens.');
    process.exit(1);
}
const logsDir = path.join(repoRoot, 'logs');
const logFilePath = path.join(logsDir, `instance-${instanceId}-logs.txt`);
const buildLockPath = path.join(repoRoot, '.cache', 'client-build.lock');
const gStreamerPluginsPath = path.join(repoRoot, '.cache', `gstreamer-plugins-${process.arch}`);
const requiredSpaPaths = [
    'audioconvert/libspa-audioconvert.so',
    'libspa.so',
    'support/libspa-dbus.so',
    'support/libspa-journal.so',
    'support/libspa-support.so',
    'videoconvert/libspa-videoconvert.so'
];
let buildLockToken = null;

function spaRuntimeIsComplete(spaRoot) {
    return fs.statSync(spaRoot, { throwIfNoEntry: false })?.isDirectory() &&
        requiredSpaPaths.every(relativePath =>
            fs.statSync(path.join(spaRoot, ...relativePath.split('/')), { throwIfNoEntry: false })?.isFile()
        );
}

function processIsRunning(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch (error) {
        return error?.code === 'EPERM';
    }
}

function readBuildLock() {
    try {
        return JSON.parse(fs.readFileSync(buildLockPath, 'utf8'));
    } catch {
        return null;
    }
}

function releaseBuildLock() {
    if (!buildLockToken) return;
    const owner = readBuildLock();
    if (owner?.token === buildLockToken) {
        try { fs.unlinkSync(buildLockPath); } catch { }
    }
    buildLockToken = null;
}

function acquireBuildLock() {
    fs.mkdirSync(path.dirname(buildLockPath), { recursive: true });
    const owner = {
        pid: process.pid,
        token: crypto.randomUUID(),
        startedAt: new Date().toISOString(),
        command: [process.execPath, ...process.argv.slice(1)].join(' ')
    };

    for (let attempt = 0; attempt < 2; attempt += 1) {
        let descriptor;
        try {
            descriptor = fs.openSync(buildLockPath, 'wx', 0o600);
            fs.writeFileSync(descriptor, `${JSON.stringify(owner, null, 2)}\n`);
            fs.closeSync(descriptor);
            buildLockToken = owner.token;
            process.once('exit', releaseBuildLock);
            for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
                process.once(signal, () => {
                    releaseBuildLock();
                    process.exit(code);
                });
            }
            console.log(`[CLIENT] Acquired build lock (PID ${process.pid}).`);
            return;
        } catch (error) {
            if (descriptor !== undefined) {
                try { fs.closeSync(descriptor); } catch { }
            }
            if (error?.code !== 'EEXIST') throw error;

            const existing = readBuildLock();
            if (existing?.pid && !processIsRunning(existing.pid)) {
                try { fs.unlinkSync(buildLockPath); } catch { }
                continue;
            }
            if (!existing?.pid) {
                try {
                    const ageMs = Date.now() - fs.statSync(buildLockPath).mtimeMs;
                    if (ageMs > 30000) {
                        fs.unlinkSync(buildLockPath);
                        continue;
                    }
                } catch { }
            }

            const identity = existing?.pid ? `PID ${existing.pid}` : 'an initializing process';
            const started = existing?.startedAt ? ` since ${existing.startedAt}` : '';
            const command = existing?.command ? `\n[CLIENT] Active command: ${existing.command}` : '';
            logErr(`Another client bundle build owns the repository lock (${identity}${started}).${command}`);
            logErr('Wait for that build to finish, then run this command again.');
            process.exit(1);
        }
    }

    logErr('Unable to acquire the client bundle build lock.');
    process.exit(1);
}

function clientRuntimeEnv(options = {}) {
    const env = { ...process.env };
    if (process.platform === 'linux') {
        const prependPath = (key, value) => {
            if (!fs.statSync(value, { throwIfNoEntry: false })?.isDirectory()) return;
            const existing = (env[key] || '').split(path.delimiter).filter(Boolean);
            env[key] = [value, ...existing.filter(candidate => candidate !== value)].join(path.delimiter);
        };
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
        if (options.mediaRuntime && fs.statSync(gStreamerPluginsPath, { throwIfNoEntry: false })?.isDirectory()) {
            const runtimePath = path.join(gStreamerPluginsPath, 'runtime');
            const runtimeLibPath = path.join(runtimePath, 'lib');
            const gStreamerCapturePluginsPath = path.join(runtimePath, 'capture-plugins');
            const gStreamerLauncher = path.join(runtimePath, 'bin', 'qor-gst-launch-1.0');
            const gStreamerPluginScanner = path.join(runtimePath, 'bin', 'qor-gst-plugin-scanner');
            const spaPluginPath = path.join(runtimePath, 'spa-0.2');
            prependPath('GST_PLUGIN_PATH_1_0', gStreamerPluginsPath);
            prependPath('LD_LIBRARY_PATH', runtimeLibPath);
            env.QOR_GSTREAMER_REQUIRE_BUNDLED = '1';
            if (fs.statSync(gStreamerCapturePluginsPath, { throwIfNoEntry: false })?.isDirectory()) {
                env.QOR_GSTREAMER_CAPTURE_PLUGINS = gStreamerCapturePluginsPath;
            } else {
                delete env.QOR_GSTREAMER_CAPTURE_PLUGINS;
            }
            env.QOR_GSTREAMER_RUNTIME_LIB = runtimeLibPath;
            delete env.SPA_PLUGIN_DIR;
            delete env.QOR_GSTREAMER_SPA_PLUGINS;
            if (spaRuntimeIsComplete(spaPluginPath)) {
                env.SPA_PLUGIN_DIR = spaPluginPath;
                env.QOR_GSTREAMER_SPA_PLUGINS = spaPluginPath;
            }
            if (fs.statSync(gStreamerLauncher, { throwIfNoEntry: false })?.isFile()) {
                env.QOR_GSTREAMER_LAUNCH = gStreamerLauncher;
            }
            if (fs.statSync(gStreamerPluginScanner, { throwIfNoEntry: false })?.isFile()) {
                env.GST_PLUGIN_SCANNER_1_0 = gStreamerPluginScanner;
                env.QOR_GSTREAMER_PLUGIN_SCANNER = gStreamerPluginScanner;
            }
        }
        const localLib = path.join(os.homedir(), '.local', 'lib');
        if (fs.existsSync(localLib)) {
            env.LIBRARY_PATH = env.LIBRARY_PATH ? `${localLib}${path.delimiter}${env.LIBRARY_PATH}` : localLib;
        }
        env.WEBKIT_DMABUF_RENDERER_FORCE_SHM ??= '1';
        env.GST_PLUGIN_FEATURE_RANK ??= 'pulsesrc:512,pulsesink:512';
        if (env.QOR_CHAT_SOFTWARE_RENDERING) {
            env.LIBGL_ALWAYS_SOFTWARE ??= '1';
        }
    }
    return env;
}

function commandPath(cmd) {
    try {
        const checkCmd = process.platform === 'win32' ? 'where' : 'command -v';
        const output = execSync(`${checkCmd} ${cmd}`, {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        });
        return output.split(/\r?\n/).map(line => line.trim()).find(Boolean) || null;
    } catch {
        return null;
    }
}

function checkProtocEnv() {
    if (process.env.PROTOC && fs.existsSync(process.env.PROTOC)) {
        return;
    }

    const found = commandPath(process.platform === 'win32' ? 'protoc.exe' : 'protoc') || commandPath('protoc');
    if (found) {
        process.env.PROTOC = found;
        return;
    }

    if (process.platform !== 'win32') {
        logErr('Missing required dependency: protoc');
        logErr('Install protobuf-compiler/protobuf, or set PROTOC to a protoc binary.');
        process.exit(1);
    }

    const protocExe = checkWindowsProtoc();
    process.env.PROTOC = protocExe;
    process.env.PATH = `${path.dirname(protocExe)}${path.delimiter}${process.env.PATH || ''}`;
}

function checkWindowsProtoc() {
    const cacheDir = path.join(repoRoot, '.cache', 'protoc', `v${protocVersion}`);
    const protocExe = path.join(cacheDir, 'bin', 'protoc.exe');
    if (fs.existsSync(protocExe)) {
        return protocExe;
    }

    const zipPath = path.join(repoRoot, '.cache', 'protoc', `protoc-${protocVersion}-win64.zip`);
    const url = process.env.QOR_PROTOC_URL ||
        `https://github.com/protocolbuffers/protobuf/releases/download/v${protocVersion}/protoc-${protocVersion}-win64.zip`;
    console.log(`[CLIENT] protoc not found; downloading ${url}`);

    const script = [
        '& { param([string]$url, [string]$zipPath, [string]$cacheDir)',
        "$ErrorActionPreference = 'Stop'",
        '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12',
        'New-Item -ItemType Directory -Force -Path (Split-Path -Parent $zipPath) | Out-Null',
        'Invoke-WebRequest -Uri $url -OutFile $zipPath',
        'if (Test-Path -LiteralPath $cacheDir) { Remove-Item -LiteralPath $cacheDir -Recurse -Force }',
        'Expand-Archive -LiteralPath $zipPath -DestinationPath $cacheDir -Force',
        '}'
    ].join('; ');

    try {
        execFileSync('powershell.exe', [
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-Command',
            script,
            url,
            zipPath,
            cacheDir
        ], { stdio: 'inherit', cwd: repoRoot, windowsHide: true });
    } catch (error) {
        logErr(`Failed to download protoc ${protocVersion}: ${error.message}`);
        logErr('Install protoc manually or set PROTOC to a protoc.exe path.');
        process.exit(1);
    }

    if (!fs.existsSync(protocExe)) {
        logErr('Downloaded protoc archive did not contain the expected binary:', protocExe);
        process.exit(1);
    }
    return protocExe;
}

function checkWindowsPerlEnv() {
    if (process.platform !== 'win32') {
        return;
    }

    const existingPerl = commandPath('perl.exe') || commandPath('perl');
    if (existingPerl && perlUsable(existingPerl)) {
        prependPerlPath(existingPerl);
        return;
    }

    prependPerlPath(checkPortableStrawberryPerl());
}

function perlPathEntries(perlExe) {
    const perlBin = path.dirname(perlExe);
    const perlDir = path.dirname(perlBin);
    const rootDir = path.dirname(perlDir);
    return [
        perlBin,
        path.join(perlDir, 'site', 'bin'),
        path.join(rootDir, 'c', 'bin')
    ].filter((entry) => fs.existsSync(entry));
}

function prependPerlPath(perlExe) {
    process.env.PATH = `${perlPathEntries(perlExe).join(path.delimiter)}${path.delimiter}${process.env.PATH || ''}`;
}

function perlUsable(perlExe) {
    try {
        execFileSync(perlExe, [
            '-MLocale::Maketext::Simple',
            '-MIPC::Cmd',
            '-e',
            'print "ok"'
        ], {
            stdio: 'ignore',
            windowsHide: true,
            env: {
                ...process.env,
                PATH: `${perlPathEntries(perlExe).join(path.delimiter)}${path.delimiter}${process.env.PATH || ''}`
            }
        });
        return true;
    } catch {
        return false;
    }
}

function checkPortableStrawberryPerl() {
    const cacheDir = path.join(repoRoot, '.cache', 'strawberry-perl', 'portable');
    const existing = findUsablePerl(cacheDir);
    if (existing) {
        return existing;
    }

    const zipPath = path.join(repoRoot, '.cache', 'strawberry-perl', 'strawberry-perl-portable.zip');
    console.log('[CLIENT] usable Perl not found; downloading portable Strawberry Perl...');

    const script = [
        '& { param([string]$url, [string]$zipPath, [string]$cacheDir)',
        "$ErrorActionPreference = 'Stop'",
        '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12',
        'New-Item -ItemType Directory -Force -Path (Split-Path -Parent $zipPath) | Out-Null',
        'Write-Host "[CLIENT] Downloading $url"',
        'Invoke-WebRequest -Uri $url -OutFile $zipPath',
        'if (Test-Path -LiteralPath $cacheDir) { Remove-Item -LiteralPath $cacheDir -Recurse -Force }',
        'Expand-Archive -LiteralPath $zipPath -DestinationPath $cacheDir -Force',
        '}'
    ].join('; ');

    try {
        execFileSync('powershell.exe', [
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-Command',
            script,
            strawberryPerlUrl,
            zipPath,
            cacheDir
        ], { stdio: 'inherit', cwd: repoRoot, windowsHide: true });
    } catch (error) {
        logErr(`Failed to download portable Strawberry Perl: ${error.message}`);
        logErr('Install Strawberry Perl manually or add a complete Perl to PATH.');
        process.exit(1);
    }

    const perlExe = findUsablePerl(cacheDir);
    if (!perlExe) {
        logErr('Portable Strawberry Perl did not contain a usable perl.exe.');
        process.exit(1);
    }
    return perlExe;
}

function findUsablePerl(rootDir) {
    if (!fs.existsSync(rootDir)) return null;
    const stack = [rootDir];
    while (stack.length > 0) {
        const dir = stack.pop();
        let entries = [];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
            continue;
        }
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                stack.push(fullPath);
            } else if (entry.name.toLowerCase() === 'perl.exe' && perlUsable(fullPath)) {
                return fullPath;
            }
        }
    }
    return null;
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
    const binaryPath = path.join(tauriDir, 'target', 'release', binName);
    const productName = JSON.parse(fs.readFileSync(path.join(tauriDir, 'tauri.conf.json'), 'utf8')).productName;
    const appDirPath = path.join(tauriDir, 'target', 'release', 'bundle', 'appimage', `${productName}.AppDir`);
    const appRunPath = path.join(appDirPath, 'AppRun');
    const runPath = process.platform === 'linux' && fs.existsSync(appRunPath) ? appRunPath : binaryPath;
    const runCwd = runPath === appRunPath ? appDirPath : repoRoot;

    if (!fs.existsSync(runPath)) {
        logErr('Built Tauri binary not found. Expected at:', runPath);
        logErr('Run without --run-only once to build it.');
        process.exit(1);
    }

    try { fs.mkdirSync(logsDir, { recursive: true }); } catch { }
    const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
    logStream.write(`# Qor client (instance ${instanceId}) started ${new Date().toISOString()}\n`);
    console.log(`[CLIENT] Launching built app (instance ${instanceId})... logging to ${path.relative(repoRoot, logFilePath)}`);

    const runProc = spawn(runPath, [], {
        stdio: ['inherit', 'pipe', 'pipe'],
        cwd: runCwd,
        shell: false,
        env: clientRuntimeEnv({ mediaRuntime: runPath !== appRunPath })
    });

    runProc.stdout.pipe(process.stdout);
    runProc.stdout.pipe(logStream);
    runProc.stderr.pipe(process.stderr);
    runProc.stderr.pipe(logStream);

    runProc.on('error', error => {
        const line = `[CLIENT] Failed to launch app: ${error.message}\n`;
        process.stderr.write(line);
        logStream.write(line);
    });

    runProc.on('close', (exitCode, signal) => {
        const line = `# Qor client stopped ${new Date().toISOString()} code=${exitCode ?? 'null'} signal=${signal || 'none'}\n`;
        logStream.end(line, () => process.exit(exitCode ?? 1));
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
    const installerPattern = /\.(appimage|deb|exe|msi|rpm)$/i;
    try {
        const pending = [bundleDir];
        while (pending.length > 0) {
            const directory = pending.pop();
            if (!fs.existsSync(directory)) continue;
            for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
                const fullPath = path.join(directory, entry.name);
                if (entry.isDirectory()) pending.push(fullPath);
                else if (installerPattern.test(entry.name)) fs.unlinkSync(fullPath);
            }
        }
    } catch (error) {
        logErr('Failed to clear old Tauri bundle artifacts:', error.message);
        process.exit(1);
    }
}

function collectBundleArtifacts() {
    const bundleDir = path.join(tauriDir, 'target', 'release', 'bundle');
    const artifacts = [];
    const installerPattern = /\.(appimage|deb|exe|msi|rpm)$/i;

    function walk(dir) {
        if (!fs.existsSync(dir)) return;
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(fullPath);
            } else if (installerPattern.test(entry.name)) {
                artifacts.push(fullPath);
            }
        }
    }

    walk(bundleDir);
    return artifacts.sort();
}

function printBundleArtifacts() {
    const artifacts = collectBundleArtifacts();
    if (artifacts.length === 0) {
        console.log('[CLIENT] No installer bundle artifacts were found.');
        return;
    }

    console.log('[CLIENT] Bundle artifacts:');
    for (const artifact of artifacts) {
        console.log(`  - ${path.relative(repoRoot, artifact)}`);
    }
}

function buildPirSidecars() {
    const buildScript = path.join(repoRoot, 'scripts', 'build-pir-sidecars.cjs');
    console.log('[CLIENT] Building and staging PIR sidecars...');
    try {
        execFileSync(process.execPath, [buildScript], {
            cwd: repoRoot,
            stdio: 'inherit',
            env: clientRuntimeEnv(),
            windowsHide: true
        });
    } catch (error) {
        const code = Number.isInteger(error?.status) ? error.status : 1;
        logErr(`PIR sidecar build failed with code ${code}`);
        process.exit(code || 1);
    }
}

function stageWebKitGtkRuntime() {
    if (process.platform !== 'linux') return;
    const stageScript = path.join(repoRoot, 'scripts', 'stage-webkitgtk-runtime.cjs');
    console.log('[CLIENT] Staging bundled WebKitGTK runtime...');
    try {
        execFileSync(process.execPath, [stageScript], {
            cwd: repoRoot,
            stdio: 'inherit',
            env: clientRuntimeEnv(),
            windowsHide: true
        });
    } catch (error) {
        const code = Number.isInteger(error?.status) ? error.status : 1;
        logErr(`WebKitGTK runtime staging failed with code ${code}`);
        process.exit(code || 1);
    }
}

function stageGStreamerPlugins() {
    if (process.platform !== 'linux') return;
    const stageScript = path.join(repoRoot, 'scripts', 'stage-gstreamer-plugins.cjs');
    console.log('[CLIENT] Staging curated GStreamer plugins...');
    try {
        execFileSync(process.execPath, [stageScript], {
            cwd: repoRoot,
            stdio: 'inherit',
            env: clientRuntimeEnv(),
            windowsHide: true
        });
        process.env.GSTREAMER_PLUGINS_DIR = gStreamerPluginsPath;
    } catch (error) {
        const code = Number.isInteger(error?.status) ? error.status : 1;
        logErr(`GStreamer plugin staging failed with code ${code}`);
        process.exit(code || 1);
    }
}

function buildAppImage() {
    if (process.platform !== 'linux') return;
    const buildScript = path.join(repoRoot, 'scripts', 'build-appimage.cjs');
    console.log('[CLIENT] Building cached AppImage...');
    try {
        execFileSync(process.execPath, [buildScript], {
            cwd: repoRoot,
            stdio: 'inherit',
            env: clientRuntimeEnv(),
            windowsHide: true
        });
    } catch (error) {
        const code = Number.isInteger(error?.status) ? error.status : 1;
        logErr(`AppImage build failed with code ${code}`);
        process.exit(code || 1);
    }
}

if (runOnly) {
    console.log('[CLIENT] --run-only: skipping rebuild, launching existing binary.');
    launchApp();
} else {
    console.log('[CLIENT] Building Tauri app...');
    acquireBuildLock();
    checkProtocEnv();
    checkWindowsPerlEnv();
    stageWebKitGtkRuntime();
    stageGStreamerPlugins();
    buildPirSidecars();
    removeOldBundleArtifacts();
    const buildCommand = process.platform === 'linux'
        ? ['tauri', 'build', '--bundles', 'deb,rpm']
        : ['tauri', 'build'];
    const buildProc = spawn('pnpm', buildCommand, {
        stdio: 'inherit',
        cwd: repoRoot,
        shell: false,
        env: clientRuntimeEnv()
    });

    buildProc.on('exit', code => {
        if (code !== 0) {
            logErr(`Tauri build failed with code ${code}`);
            process.exit(code || 1);
        }
        buildAppImage();
        printBundleArtifacts();
        if (bundleOnly) {
            console.log('[CLIENT] --bundle-only: build complete.');
            process.exit(0);
        }
        launchApp();
    });
}
