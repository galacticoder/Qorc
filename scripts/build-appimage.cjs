#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const tauriDir = path.join(repoRoot, 'src-tauri');
const tauriConfig = JSON.parse(fs.readFileSync(path.join(tauriDir, 'tauri.conf.json'), 'utf8'));
const productName = tauriConfig.productName;
const version = tauriConfig.version;
const archNames = {
    x64: { appImage: 'x86_64', package: 'amd64' },
    arm64: { appImage: 'aarch64', package: 'aarch64' },
    ia32: { appImage: 'i686', package: 'i386' }
};
const arch = archNames[process.arch];

if (process.platform !== 'linux') process.exit(0);
if (!arch) {
    console.error(`[appimage] unsupported architecture: ${process.arch}`);
    process.exit(1);
}

const bundleDir = path.join(tauriDir, 'target', 'release', 'bundle', 'appimage');
const appDir = path.join(bundleDir, `${productName}.AppDir`);
const outputPath = path.join(bundleDir, `${productName}_${version}_${arch.package}.AppImage`);
const binaryPath = path.join(tauriDir, 'target', 'release', 'qor');
const appDirBinaryPath = path.join(appDir, 'usr', 'bin', 'qor');
const pluginsDir = path.join(repoRoot, '.cache', `gstreamer-plugins-${process.arch}`);
const appDirPluginsDir = path.join(appDir, 'usr', 'lib', 'gstreamer-1.0');
const captureManifestName = 'capture-runtime-manifest.json';
const capturePluginNames = [
    'libgstcoreelements.so',
    'libgstjpeg.so',
    'libgstpipewire.so',
    'libgstvideoconvertscale.so',
    'libgstvideorate.so'
];
const requiredSpaPaths = [
    'spa-0.2/audioconvert/libspa-audioconvert.so',
    'spa-0.2/libspa.so',
    'spa-0.2/support/libspa-dbus.so',
    'spa-0.2/support/libspa-journal.so',
    'spa-0.2/support/libspa-support.so',
    'spa-0.2/videoconvert/libspa-videoconvert.so'
];
const appDirCaptureRuntimeDir = path.join(appDir, 'usr', 'lib', productName, 'screen-capture');
const appDirCapturePluginsDir = path.join(appDirCaptureRuntimeDir, 'gstreamer-1.0');
const appDirCaptureManifest = path.join(appDirCaptureRuntimeDir, captureManifestName);
const pipeWireRuntimeDir = path.join(pluginsDir, 'runtime');
const pipeWirePlugin = 'libgstpipewire.so';
const appDirPipeWireLibrary = path.join(appDir, 'usr', 'lib', 'libpipewire-0.3.so.0');
const appDirGStreamerControllerLibrary = path.join(appDir, 'usr', 'lib', 'libgstcontroller-1.0.so.0');
const appDirGStreamerLauncher = path.join(appDir, 'usr', 'bin', 'qor-gst-launch-1.0');
const appDirGStreamerPluginScanner = path.join(appDir, 'usr', 'bin', 'qor-gst-plugin-scanner');
const appDirSpaDir = path.join(appDir, 'usr', 'lib', 'spa-0.2');
const webKitSourceDir = path.join(tauriDir, 'resources', 'webkitgtk');
const webKitSourceLibDir = path.join(webKitSourceDir, 'usr', 'lib', 'x86_64-linux-gnu');
const appDirLibDir = path.join(appDir, 'usr', 'lib');
const webKitAppMetadataPath = path.join(appDirLibDir, productName, 'webkitgtk-runtime.json');
const legacyPipeWireAppDir = path.join(appDirLibDir, productName, 'pipewire');
const packagedWebKitAppDir = path.join(appDirLibDir, productName, 'webkitgtk');
const webKitUpstreamVersion = '2.52.6';
const webKitLibraries = [
    'libwebkit2gtk-4.1.so.0',
    'libjavascriptcoregtk-4.1.so.0'
];
const webKitHelpers = [
    'WebKitGPUProcess',
    'WebKitNetworkProcess',
    'WebKitWebProcess',
    path.join('injected-bundle', 'libwebkit2gtkinjectedbundle.so')
];
const cacheMetadataPath = path.join(repoRoot, '.cache', `appimage-${process.arch}.json`);
const runtimeCachePath = path.join(repoRoot, '.cache', `appimage-runtime-${arch.appImage}`);
const appImagePluginPath = path.join(os.homedir(), '.cache', 'tauri', 'linuxdeploy-plugin-appimage.AppImage');
const adoptCurrent = process.argv.includes('--adopt-current');

function sha256File(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function captureRuntimeFiles(runtimeDir) {
    const files = [];
    const visit = (directory, relativeDirectory) => {
        if (!fs.statSync(directory, { throwIfNoEntry: false })?.isDirectory()) {
            throw new Error(`capture runtime directory is missing: ${relativeDirectory}`);
        }
        for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
            const relativePath = path.posix.join(relativeDirectory, entry.name);
            const absolutePath = path.join(directory, entry.name);
            if (entry.isDirectory()) visit(absolutePath, relativePath);
            else if (entry.isFile()) files.push(relativePath);
            else throw new Error(`capture runtime contains an unsupported entry: ${relativePath}`);
        }
    };
    for (const directory of ['bin', 'capture-plugins', 'lib', 'spa-0.2']) {
        visit(path.join(runtimeDir, directory), directory);
    }
    return files.sort();
}

function appDirCaptureArtifactPath(relativePath) {
    if (relativePath.startsWith('bin/')) {
        return path.join(appDir, 'usr', 'bin', relativePath.slice('bin/'.length));
    }
    if (relativePath.startsWith('capture-plugins/')) {
        return path.join(appDirCapturePluginsDir, relativePath.slice('capture-plugins/'.length));
    }
    if (relativePath.startsWith('lib/')) {
        return path.join(appDirLibDir, relativePath.slice('lib/'.length));
    }
    if (relativePath.startsWith('spa-0.2/')) {
        return path.join(appDirSpaDir, relativePath.slice('spa-0.2/'.length));
    }
    throw new Error(`unsupported capture runtime artifact path: ${relativePath}`);
}

function validateCaptureRuntime(manifestPath, resolveArtifactPath, strictInventoryRoot = null) {
    if (!fs.lstatSync(manifestPath, { throwIfNoEntry: false })?.isFile()) {
        throw new Error('GStreamer capture runtime manifest is missing');
    }
    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch {
        throw new Error('GStreamer capture runtime manifest is invalid JSON');
    }
    if (manifest.format !== 'qor-gstreamer-capture-runtime' || manifest.formatVersion !== 1 ||
        manifest.platform !== 'linux' || manifest.architecture !== process.arch ||
        typeof manifest.gstLaunchVersion !== 'string' || !manifest.gstLaunchVersion.trim() ||
        !Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) {
        throw new Error('GStreamer capture runtime manifest has invalid metadata');
    }
    const expectedRole = relativePath => {
        if (typeof relativePath !== 'string') return null;
        if (relativePath === 'bin/qor-gst-launch-1.0') return 'launcher';
        if (relativePath === 'bin/qor-gst-plugin-scanner') return 'plugin-scanner';
        if (relativePath.startsWith('capture-plugins/')) return 'plugin';
        if (relativePath.startsWith('lib/')) return 'library';
        if (relativePath.startsWith('spa-0.2/')) return 'spa';
        return null;
    };
    const paths = [];
    const uniquePaths = new Set();
    for (const artifact of manifest.artifacts) {
        const relativePath = artifact?.path;
        const segments = typeof relativePath === 'string' ? relativePath.split('/') : [];
        const role = expectedRole(relativePath);
        if (!relativePath || relativePath.includes('\\') || path.posix.isAbsolute(relativePath) ||
            segments.some(segment => !segment || segment === '.' || segment === '..') || !role ||
            artifact.role !== role || !Number.isSafeInteger(artifact.size) || artifact.size < 0 ||
            typeof artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.sha256) ||
            uniquePaths.has(relativePath)) {
            throw new Error('GStreamer capture runtime manifest contains an invalid artifact');
        }
        uniquePaths.add(relativePath);
        paths.push(relativePath);
        const filePath = resolveArtifactPath(relativePath);
        const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
        if (!stat?.isFile()) throw new Error(`GStreamer capture runtime artifact is missing: ${relativePath}`);
        if (stat.size !== artifact.size || sha256File(filePath) !== artifact.sha256) {
            throw new Error(`GStreamer capture runtime artifact failed integrity validation: ${relativePath}`);
        }
    }
    if (paths.join('\n') !== [...paths].sort().join('\n')) {
        throw new Error('GStreamer capture runtime manifest artifacts are not canonical');
    }
    for (const requiredPath of [
        'bin/qor-gst-launch-1.0',
        'bin/qor-gst-plugin-scanner',
        ...capturePluginNames.map(plugin => `capture-plugins/${plugin}`),
        ...requiredSpaPaths
    ]) {
        if (!uniquePaths.has(requiredPath)) {
            throw new Error(`GStreamer capture runtime manifest is missing: ${requiredPath}`);
        }
    }
    const manifestedPlugins = paths.filter(relativePath => relativePath.startsWith('capture-plugins/'));
    const expectedPlugins = capturePluginNames.map(plugin => `capture-plugins/${plugin}`).sort();
    if (manifestedPlugins.join('\n') !== expectedPlugins.join('\n') ||
        !paths.some(relativePath => relativePath.startsWith('lib/')) ||
        !paths.some(relativePath => relativePath.startsWith('spa-0.2/'))) {
        throw new Error('GStreamer capture runtime manifest has an invalid artifact inventory');
    }
    if (strictInventoryRoot) {
        const inventory = captureRuntimeFiles(strictInventoryRoot);
        if (inventory.join('\n') !== paths.join('\n')) {
            throw new Error('GStreamer capture runtime files do not match the manifest inventory');
        }
    }
    return {
        manifest,
        sha256: sha256File(manifestPath)
    };
}

function validateSourceCaptureRuntime() {
    const manifestPath = path.join(pipeWireRuntimeDir, captureManifestName);
    return validateCaptureRuntime(
        manifestPath,
        relativePath => path.join(pipeWireRuntimeDir, ...relativePath.split('/')),
        pipeWireRuntimeDir
    );
}

function validateInstalledCaptureRuntime() {
    return validateCaptureRuntime(appDirCaptureManifest, appDirCaptureArtifactPath);
}

function updateHashWithPath(hash, target, label) {
    hash.update(`${label}\0`);
    if (!fs.existsSync(target)) {
        hash.update('missing\0');
        return;
    }
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) {
        hash.update(`link\0${fs.readlinkSync(target)}\0`);
        return;
    }
    if (stat.isDirectory()) {
        hash.update('directory\0');
        for (const entry of fs.readdirSync(target).sort()) {
            updateHashWithPath(hash, path.join(target, entry), `${label}/${entry}`);
        }
        return;
    }
    hash.update(`file\0${stat.mode}\0${stat.size}\0`);
    hash.update(fs.readFileSync(target));
}

function commandOutput(command, args) {
    try {
        return execFileSync(command, args, {
            cwd: repoRoot,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
            maxBuffer: 32 * 1024 * 1024
        });
    } catch {
        return '';
    }
}

function filesAreIdentical(leftPath, rightPath) {
    const leftStat = fs.statSync(leftPath, { throwIfNoEntry: false });
    const rightStat = fs.statSync(rightPath, { throwIfNoEntry: false });
    if (!leftStat?.isFile() || !rightStat?.isFile() || leftStat.size !== rightStat.size) return false;
    const left = fs.openSync(leftPath, 'r');
    const right = fs.openSync(rightPath, 'r');
    const leftBuffer = Buffer.allocUnsafe(1024 * 1024);
    const rightBuffer = Buffer.allocUnsafe(1024 * 1024);
    try {
        for (let offset = 0; offset < leftStat.size; offset += leftBuffer.length) {
            const length = Math.min(leftBuffer.length, leftStat.size - offset);
            if (fs.readSync(left, leftBuffer, 0, length, offset) !== length ||
                fs.readSync(right, rightBuffer, 0, length, offset) !== length ||
                !leftBuffer.subarray(0, length).equals(rightBuffer.subarray(0, length))) return false;
        }
        return true;
    } finally {
        fs.closeSync(left);
        fs.closeSync(right);
    }
}

function computeFingerprint() {
    const hash = crypto.createHash('sha256');
    hash.update(`node=${process.version}\0arch=${process.arch}\0`);
    const inputs = [
        path.join(tauriDir, 'tauri.conf.json'),
        path.join(tauriDir, 'tauri.linux.conf.json'),
        path.join(tauriDir, 'Cargo.toml'),
        path.join(tauriDir, 'icons'),
        path.join(tauriDir, 'linux'),
        path.join(repoRoot, 'LICENSE'),
        __filename,
        path.join(repoRoot, 'scripts', 'stage-gstreamer-plugins.cjs'),
        path.join(repoRoot, 'scripts', 'stage-webkitgtk-runtime.cjs'),
        pluginsDir,
        webKitSourceDir,
        path.join(os.homedir(), '.cache', 'tauri', 'AppRun-x86_64'),
        path.join(os.homedir(), '.cache', 'tauri', 'linuxdeploy-x86_64.AppImage'),
        path.join(os.homedir(), '.cache', 'tauri', 'linuxdeploy-plugin-appimage.AppImage'),
        path.join(os.homedir(), '.cache', 'tauri', 'linuxdeploy-plugin-gstreamer.sh'),
        path.join(os.homedir(), '.cache', 'tauri', 'linuxdeploy-plugin-gtk.sh')
    ];
    for (const input of inputs) {
        updateHashWithPath(hash, input, path.relative(repoRoot, input));
    }
    hash.update(commandOutput('readelf', ['-d', binaryPath]).split(/\r?\n/)
        .filter(line => /NEEDED|RPATH|RUNPATH|SONAME/.test(line)).join('\n'));
    const packageInventory = commandOutput('dpkg-query', ['-W', '-f=${binary:Package}=${Version}\n']) ||
        commandOutput('rpm', ['-qa', '--qf', '%{NAME}=%{VERSION}-%{RELEASE}.%{ARCH}\n']);
    hash.update(packageInventory);
    updateHashWithPath(hash, '/etc/os-release', 'os-release');
    return hash.digest('hex');
}

function selectedPluginNames(directory) {
    if (!fs.existsSync(directory)) return [];
    return fs.readdirSync(directory, { withFileTypes: true })
        .filter(entry => entry.isFile() && entry.name.endsWith('.so'))
        .map(entry => entry.name)
        .sort();
}

function appDirIsComplete() {
    if (!fs.existsSync(path.join(appDir, 'AppRun')) || !fs.existsSync(appDirBinaryPath)) return false;
    try {
        const metadata = JSON.parse(fs.readFileSync(webKitAppMetadataPath, 'utf8'));
        if (metadata.upstreamVersion !== webKitUpstreamVersion) return false;
        const sourceCaptureRuntime = validateSourceCaptureRuntime();
        const installedCaptureRuntime = validateInstalledCaptureRuntime();
        if (sourceCaptureRuntime.sha256 !== installedCaptureRuntime.sha256 ||
            metadata.gStreamerCaptureRuntime?.manifest !== path.posix.join('screen-capture', captureManifestName) ||
            metadata.gStreamerCaptureRuntime?.manifestSha256 !== sourceCaptureRuntime.sha256 ||
            metadata.gStreamerCaptureRuntime?.gstLaunchVersion !== sourceCaptureRuntime.manifest.gstLaunchVersion) return false;
    } catch {
        return false;
    }
    for (const library of webKitLibraries) {
        if (!fs.statSync(path.join(appDirLibDir, library), { throwIfNoEntry: false })?.isFile()) return false;
    }
    const helperDir = path.join(appDirLibDir, 'x86_64-linux-gnu', 'webkit2gtk-4.1');
    for (const helper of webKitHelpers) {
        if (!fs.statSync(path.join(helperDir, helper), { throwIfNoEntry: false })?.isFile()) return false;
    }
    const selected = selectedPluginNames(pluginsDir);
    const bundled = selectedPluginNames(appDirPluginsDir);
    return selected.includes(pipeWirePlugin) && selected.length === bundled.length &&
        selected.every((plugin, index) => plugin === bundled[index]) &&
        fs.statSync(appDirGStreamerControllerLibrary, { throwIfNoEntry: false })?.isFile() &&
        fs.statSync(appDirPipeWireLibrary, { throwIfNoEntry: false })?.isFile() &&
        fs.statSync(appDirGStreamerLauncher, { throwIfNoEntry: false })?.isFile() &&
        fs.statSync(appDirGStreamerPluginScanner, { throwIfNoEntry: false })?.isFile() &&
        fs.statSync(path.join(appDirCapturePluginsDir, pipeWirePlugin), { throwIfNoEntry: false })?.isFile() &&
        requiredSpaPaths.every(relativePath =>
            fs.statSync(appDirCaptureArtifactPath(relativePath), { throwIfNoEntry: false })?.isFile()
        );
}

function replaceBytes(filePath, sourceText, replacementText) {
    const source = Buffer.from(sourceText);
    const replacement = Buffer.from(replacementText);
    if (source.length !== replacement.length) {
        throw new Error('WebKit path replacement must preserve the binary size');
    }
    const contents = fs.readFileSync(filePath);
    let count = 0;
    let offset = 0;
    while ((offset = contents.indexOf(source, offset)) !== -1) {
        replacement.copy(contents, offset);
        offset += source.length;
        count += 1;
    }
    if (count === 0) {
        throw new Error(`WebKit executable path was not found in ${path.basename(filePath)}`);
    }
    fs.writeFileSync(filePath, contents);
    return count;
}

function installSharedLibrary(libraryName) {
    const sourceLink = path.join(webKitSourceLibDir, libraryName);
    if (!fs.lstatSync(sourceLink, { throwIfNoEntry: false })?.isSymbolicLink()) {
        throw new Error(`WebKit runtime has no versioned link for ${libraryName}`);
    }
    const versionedName = fs.readlinkSync(sourceLink);
    if (path.basename(versionedName) !== versionedName || !versionedName.startsWith(`${libraryName}.`)) {
        throw new Error(`WebKit runtime has an unsafe library target for ${libraryName}`);
    }
    for (const entry of fs.readdirSync(appDirLibDir)) {
        if (entry === libraryName || entry.startsWith(`${libraryName}.`)) {
            fs.rmSync(path.join(appDirLibDir, entry), { force: true });
        }
    }
    fs.copyFileSync(path.join(webKitSourceLibDir, versionedName), path.join(appDirLibDir, versionedName));
    fs.symlinkSync(versionedName, path.join(appDirLibDir, libraryName));
    return versionedName;
}

function installWebKitGtkRuntime() {
    const metadataPath = path.join(webKitSourceDir, 'runtime-version.json');
    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    if (metadata.upstreamVersion !== webKitUpstreamVersion || metadata.target !== 'linux-x86_64') {
        throw new Error('staged WebKitGTK runtime does not match the AppImage target');
    }
    fs.mkdirSync(appDirLibDir, { recursive: true });
    const installedLibraries = Object.fromEntries(webKitLibraries.map(library => [library, installSharedLibrary(library)]));
    const helperSourceDir = path.join(webKitSourceLibDir, 'webkit2gtk-4.1');
    const helperAppDir = path.join(appDirLibDir, 'x86_64-linux-gnu', 'webkit2gtk-4.1');
    fs.rmSync(helperAppDir, { recursive: true, force: true });
    for (const helper of webKitHelpers) {
        const source = path.join(helperSourceDir, helper);
        const destination = path.join(helperAppDir, helper);
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        fs.copyFileSync(source, destination);
        fs.chmodSync(destination, fs.statSync(source).mode & 0o777);
    }
    const executablePath = '/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1';
    const appImagePath = '././/lib/x86_64-linux-gnu/webkit2gtk-4.1';
    const patchedOccurrences = replaceBytes(
        path.join(appDirLibDir, installedLibraries['libwebkit2gtk-4.1.so.0']),
        executablePath,
        appImagePath
    );
    for (const packageName of ['libwebkit2gtk-4.1-0', 'libjavascriptcoregtk-4.1-0']) {
        const sourceDocs = path.join(webKitSourceDir, 'usr', 'share', 'doc', packageName);
        const appDocs = path.join(appDir, 'usr', 'share', 'doc', packageName);
        fs.rmSync(appDocs, { recursive: true, force: true });
        fs.cpSync(sourceDocs, appDocs, { recursive: true, dereference: true });
    }
    fs.mkdirSync(path.dirname(webKitAppMetadataPath), { recursive: true });
    fs.writeFileSync(webKitAppMetadataPath, `${JSON.stringify({
        ...metadata,
        installedLibraries,
        patchedOccurrences
    }, null, 2)}\n`);
}

function prepareAppRun() {
    const appRunPath = path.join(appDir, 'AppRun');
    const contents = fs.readFileSync(appRunPath, 'utf8');
    if (contents.includes('qor_appdir_was_set=')) return;
    const withAppDir = contents.replace(
        'this_dir="$(readlink -f "$(dirname "$0")")"\n',
        'this_dir="$(readlink -f "$(dirname "$0")")"\nqor_appdir_was_set="${APPDIR+x}"\nexport APPDIR="${APPDIR:-$this_dir}"\n'
    );
    const prepared = withAppDir.replace(
        'exec "$this_dir"/AppRun.wrapped "$@"\n',
        'if [[ -z "$qor_appdir_was_set" ]]; then unset APPDIR; fi\n\nexec "$this_dir"/AppRun.wrapped "$@"\n'
    );
    if (prepared === contents || !prepared.includes('qor_appdir_was_set=')) {
        throw new Error('unable to prepare AppRun for extracted launches');
    }
    fs.writeFileSync(appRunPath, prepared, { mode: fs.statSync(appRunPath).mode & 0o777 });
}

function installPipeWireRuntime() {
    const sourceCaptureRuntime = validateSourceCaptureRuntime();
    const pluginSource = path.join(pluginsDir, pipeWirePlugin);
    const controllerLibrarySource = path.join(pipeWireRuntimeDir, 'lib', 'libgstcontroller-1.0.so.0');
    const librarySource = path.join(pipeWireRuntimeDir, 'lib', 'libpipewire-0.3.so.0');
    const launcherSource = path.join(pipeWireRuntimeDir, 'bin', 'qor-gst-launch-1.0');
    const scannerSource = path.join(pipeWireRuntimeDir, 'bin', 'qor-gst-plugin-scanner');
    const capturePluginsSource = path.join(pipeWireRuntimeDir, 'capture-plugins');
    const spaSource = path.join(pipeWireRuntimeDir, 'spa-0.2');
    if (!fs.statSync(pluginSource, { throwIfNoEntry: false })?.isFile() ||
        !fs.statSync(controllerLibrarySource, { throwIfNoEntry: false })?.isFile() ||
        !fs.statSync(librarySource, { throwIfNoEntry: false })?.isFile() ||
        !fs.statSync(launcherSource, { throwIfNoEntry: false })?.isFile() ||
        !fs.statSync(scannerSource, { throwIfNoEntry: false })?.isFile() ||
        !fs.statSync(capturePluginsSource, { throwIfNoEntry: false })?.isDirectory() ||
        !fs.statSync(spaSource, { throwIfNoEntry: false })?.isDirectory() ||
        !requiredSpaPaths.every(relativePath =>
            fs.statSync(path.join(pipeWireRuntimeDir, ...relativePath.split('/')), { throwIfNoEntry: false })?.isFile()
        )) {
        throw new Error('staged PipeWire screen-capture runtime is incomplete');
    }
    fs.rmSync(appDirPluginsDir, { recursive: true, force: true });
    fs.mkdirSync(appDirPluginsDir, { recursive: true });
    for (const plugin of selectedPluginNames(pluginsDir)) {
        fs.copyFileSync(path.join(pluginsDir, plugin), path.join(appDirPluginsDir, plugin));
    }
    fs.rmSync(appDirCaptureRuntimeDir, { recursive: true, force: true });
    fs.mkdirSync(appDirCaptureRuntimeDir, { recursive: true });
    fs.cpSync(capturePluginsSource, appDirCapturePluginsDir, { recursive: true });
    for (const entry of fs.readdirSync(path.join(pipeWireRuntimeDir, 'lib'), { withFileTypes: true })) {
        if (entry.isFile()) {
            const destination = path.join(appDirLibDir, entry.name);
            fs.rmSync(destination, { force: true });
            fs.copyFileSync(
                path.join(pipeWireRuntimeDir, 'lib', entry.name),
                destination
            );
        }
    }
    fs.rmSync(appDirGStreamerLauncher, { force: true });
    fs.copyFileSync(launcherSource, appDirGStreamerLauncher);
    fs.chmodSync(appDirGStreamerLauncher, 0o755);
    fs.rmSync(appDirGStreamerPluginScanner, { force: true });
    fs.copyFileSync(scannerSource, appDirGStreamerPluginScanner);
    fs.chmodSync(appDirGStreamerPluginScanner, 0o755);
    fs.rmSync(appDirSpaDir, { recursive: true, force: true });
    fs.cpSync(spaSource, appDirSpaDir, { recursive: true });
    fs.copyFileSync(path.join(pipeWireRuntimeDir, captureManifestName), appDirCaptureManifest);
    const installedCaptureRuntime = validateInstalledCaptureRuntime();
    if (sourceCaptureRuntime.sha256 !== installedCaptureRuntime.sha256) {
        throw new Error('GStreamer capture runtime manifest changed while installing the AppImage');
    }
    const appMetadata = JSON.parse(fs.readFileSync(webKitAppMetadataPath, 'utf8'));
    fs.writeFileSync(webKitAppMetadataPath, `${JSON.stringify({
        ...appMetadata,
        gStreamerCaptureRuntime: {
            manifest: path.posix.join('screen-capture', captureManifestName),
            manifestSha256: sourceCaptureRuntime.sha256,
            gstLaunchVersion: sourceCaptureRuntime.manifest.gstLaunchVersion
        }
    }, null, 2)}\n`);
}

function readCachedFingerprint() {
    try {
        return JSON.parse(fs.readFileSync(cacheMetadataPath, 'utf8')).fingerprint || null;
    } catch {
        return null;
    }
}

function writeCachedFingerprint(fingerprint) {
    fs.mkdirSync(path.dirname(cacheMetadataPath), { recursive: true });
    const temporaryPath = `${cacheMetadataPath}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryPath, `${JSON.stringify({ fingerprint }, null, 2)}\n`);
    fs.renameSync(temporaryPath, cacheMetadataPath);
}

function cacheRuntimeFromAppImage() {
    const offset = Number.parseInt(execFileSync(outputPath, ['--appimage-offset'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore']
    }).trim(), 10);
    if (!Number.isInteger(offset) || offset < 65536 || offset > 4 * 1024 * 1024) {
        throw new Error(`unexpected AppImage runtime size: ${offset}`);
    }
    const descriptor = fs.openSync(outputPath, 'r');
    const runtime = Buffer.alloc(offset);
    try {
        let bytesRead = 0;
        while (bytesRead < offset) {
            const count = fs.readSync(descriptor, runtime, bytesRead, offset - bytesRead, bytesRead);
            if (count === 0) break;
            bytesRead += count;
        }
        if (bytesRead !== offset || runtime[0] !== 0x7f || runtime.toString('ascii', 1, 4) !== 'ELF') {
            throw new Error('unable to extract a valid AppImage runtime');
        }
    } finally {
        fs.closeSync(descriptor);
    }
    const temporaryPath = `${runtimeCachePath}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryPath, runtime, { mode: 0o755 });
    fs.renameSync(temporaryPath, runtimeCachePath);
}

function syncMutableFiles() {
    if (!filesAreIdentical(binaryPath, appDirBinaryPath)) fs.copyFileSync(binaryPath, appDirBinaryPath);
    fs.chmodSync(appDirBinaryPath, 0o755);
    fs.rmSync(legacyPipeWireAppDir, { recursive: true, force: true });
    fs.rmSync(packagedWebKitAppDir, { recursive: true, force: true });
    installWebKitGtkRuntime();
    installPipeWireRuntime();
    prepareAppRun();
}

function rebuildPreparedAppDir() {
    console.log('[appimage] prepared AppDir cache is stale, rebuilding...');
    execFileSync('pnpm', ['tauri', 'bundle', '--bundles', 'appimage'], {
        cwd: repoRoot,
        stdio: 'inherit',
        env: process.env
    });
    syncMutableFiles();
    if (!appDirIsComplete()) {
        throw new Error('linuxdeploy produced an incomplete AppDir');
    }
    writeCachedFingerprint(computeFingerprint());
    packPreparedAppDir('[appimage] packing AppDir with WebKitGTK...');
}

function packPreparedAppDir(message) {
    if (!fs.existsSync(appImagePluginPath)) {
        throw new Error(`AppImage plugin not found: ${appImagePluginPath}`);
    }
    fs.rmSync(outputPath, { force: true });
    const env = {
        ...process.env,
        ARCH: arch.appImage,
        LDAI_OUTPUT: outputPath,
        LDAI_NO_APPSTREAM: '1'
    };
    delete env.DEBUG;
    if (fs.existsSync(runtimeCachePath)) env.LDAI_RUNTIME_FILE = runtimeCachePath;
    console.log(message);
    execFileSync(appImagePluginPath, ['--appimage-extract-and-run', '--appdir', appDir], {
        cwd: repoRoot,
        stdio: 'inherit',
        env
    });
    cacheRuntimeFromAppImage();
}

function packCachedAppDir() {
    syncMutableFiles();
    if (!appDirIsComplete()) {
        throw new Error('cached AppDir is incomplete after syncing runtime files');
    }
    packPreparedAppDir('[appimage] reusing prepared AppDir, packing updated application...');
}

if (!fs.existsSync(binaryPath)) {
    console.error(`[appimage] release binary not found: ${binaryPath}`);
    process.exit(1);
}

const fingerprint = computeFingerprint();
const canReuse = appDirIsComplete() && (readCachedFingerprint() === fingerprint || adoptCurrent);

try {
    if (!canReuse) {
        rebuildPreparedAppDir();
    } else {
        if (adoptCurrent) writeCachedFingerprint(fingerprint);
        packCachedAppDir();
    }
    console.log(`[appimage] ready: ${path.relative(repoRoot, outputPath)}`);
} catch (error) {
    console.error(`[appimage] ${error.message}`);
    process.exit(1);
}
