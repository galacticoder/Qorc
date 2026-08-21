#!/usr/bin/env node
/*
 * Rebuilds and starts the Tauri client
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
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

function ensureProtocEnv() {
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

    const protocExe = ensureWindowsProtoc();
    process.env.PROTOC = protocExe;
    process.env.PATH = `${path.dirname(protocExe)}${path.delimiter}${process.env.PATH || ''}`;
}

function ensureWindowsProtoc() {
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

function ensureWindowsPerlEnv() {
    if (process.platform !== 'win32') {
        return;
    }

    const existingPerl = commandPath('perl.exe') || commandPath('perl');
    if (existingPerl && perlUsable(existingPerl)) {
        prependPerlPath(existingPerl);
        return;
    }

    prependPerlPath(ensurePortableStrawberryPerl());
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

function ensurePortableStrawberryPerl() {
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
    const runPath = path.join(tauriDir, 'target', 'release', binName);

    if (!fs.existsSync(runPath)) {
        logErr('Built Tauri binary not found. Expected at:', runPath);
        logErr('Run without --run-only once to build it.');
        process.exit(1);
    }

    try { fs.mkdirSync(logsDir, { recursive: true }); } catch { }
    const logStream = fs.createWriteStream(logFilePath, { flags: 'a' });
    logStream.write(`# Qor-Chat client (instance ${instanceId}) started ${new Date().toISOString()}\n`);
    console.log(`[CLIENT] Launching built app (instance ${instanceId})... logging to ${path.relative(repoRoot, logFilePath)}`);

    const runProc = spawn(runPath, [], {
        stdio: ['inherit', 'pipe', 'pipe'],
        cwd: repoRoot,
        shell: false,
        env: clientRuntimeEnv()
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
        const line = `# Qor-Chat client stopped ${new Date().toISOString()} code=${exitCode ?? 'null'} signal=${signal || 'none'}\n`;
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
    try {
        fs.rmSync(bundleDir, { recursive: true, force: true });
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

if (runOnly) {
    console.log('[CLIENT] --run-only: skipping rebuild, launching existing binary.');
    launchApp();
} else {
    console.log('[CLIENT] Building Tauri app...');
    ensureProtocEnv();
    ensureWindowsPerlEnv();
    buildPirSidecars();
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
        printBundleArtifacts();
        if (bundleOnly) {
            console.log('[CLIENT] --bundle-only: build complete.');
            process.exit(0);
        }
        launchApp();
    });
}
