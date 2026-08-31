#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const outputDir = path.join(repoRoot, '.cache', `gstreamer-plugins-${process.arch}`);
const stagingDir = `${outputDir}.staging-${process.pid}`;
const captureManifestName = 'capture-runtime-manifest.json';
const requiredSpaPaths = [
    'spa-0.2/audioconvert/libspa-audioconvert.so',
    'spa-0.2/libspa.so',
    'spa-0.2/support/libspa-dbus.so',
    'spa-0.2/support/libspa-journal.so',
    'spa-0.2/support/libspa-support.so',
    'spa-0.2/videoconvert/libspa-videoconvert.so'
];
const linuxLibraryTriplets = {
    x64: 'x86_64-linux-gnu',
    arm64: 'aarch64-linux-gnu'
};

const plugins = [
    'libgstadaptivedemux2.so',
    'libgstalaw.so',
    'libgstapetag.so',
    'libgstapp.so',
    'libgstaudiobuffersplit.so',
    'libgstaudioconvert.so',
    'libgstaudiolatency.so',
    'libgstaudiomixer.so',
    'libgstaudiomixmatrix.so',
    'libgstaudioparsers.so',
    'libgstaudiorate.so',
    'libgstaudioresample.so',
    'libgstauparse.so',
    'libgstautoconvert.so',
    'libgstautodetect.so',
    'libgstavi.so',
    'libgstcompositor.so',
    'libgstcoreelements.so',
    'libgstdeinterlace.so',
    'libgstdtls.so',
    'libgstencoding.so',
    'libgstfaad.so',
    'libgstflac.so',
    'libgstflv.so',
    'libgstgdkpixbuf.so',
    'libgsticydemux.so',
    'libgstid3demux.so',
    'libgstimagefreeze.so',
    'libgstinterleave.so',
    'libgstisomp4.so',
    'libgstjpeg.so',
    'libgstlame.so',
    'libgstlevel.so',
    'libgstmatroska.so',
    'libgstmpg123.so',
    'libgstmulaw.so',
    'libgstmultifile.so',
    'libgstmultipart.so',
    'libgstogg.so',
    'libgstopenh264.so',
    'libgstopengl.so',
    'libgstopus.so',
    'libgstopusparse.so',
    'libgstoverlaycomposition.so',
    'libgstpbtypes.so',
    'libgstplayback.so',
    'libgstpipewire.so',
    'libgstpng.so',
    'libgstpulseaudio.so',
    'libgstrawparse.so',
    'libgstreplaygain.so',
    'libgstrtp.so',
    'libgstrtpmanager.so',
    'libgstsctp.so',
    'libgstsoup.so',
    'libgstsrtp.so',
    'libgstsubparse.so',
    'libgsttaglib.so',
    'libgsttcp.so',
    'libgsttranscode.so',
    'libgsttypefindfunctions.so',
    'libgstudp.so',
    'libgstvideo4linux2.so',
    'libgstvideobox.so',
    'libgstvideoconvertscale.so',
    'libgstvideocrop.so',
    'libgstvideofilter.so',
    'libgstvideoparsersbad.so',
    'libgstvideorate.so',
    'libgstvolume.so',
    'libgstvoaacenc.so',
    'libgstvorbis.so',
    'libgstvpx.so',
    'libgstwavenc.so',
    'libgstwavpack.so',
    'libgstwavparse.so',
    'libgstwebrtc.so',
    'libgstwebrtcdsp.so',
    'libgstx264.so',
    'libgstxingmux.so'
];

const requiredPlugins = [
    'libgstapp.so',
    'libgstaudioconvert.so',
    'libgstaudioresample.so',
    'libgstautodetect.so',
    'libgstcoreelements.so',
    'libgstjpeg.so',
    'libgstopengl.so',
    'libgstopus.so',
    'libgstplayback.so',
    'libgstpipewire.so',
    'libgstpulseaudio.so',
    'libgstrtp.so',
    'libgstrtpmanager.so',
    'libgsttranscode.so',
    'libgsttypefindfunctions.so',
    'libgstvideo4linux2.so',
    'libgstvideoconvertscale.so',
    'libgstvideorate.so',
    'libgstvolume.so',
    'libgstvpx.so'
];
const capturePlugins = [
    'libgstcoreelements.so',
    'libgstjpeg.so',
    'libgstpipewire.so',
    'libgstvideoconvertscale.so',
    'libgstvideorate.so'
];

function sha256File(filePath) {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readLauncherVersion(launcherPath, runtimeLibDir) {
    const output = execFileSync(launcherPath, ['--version'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
            ...process.env,
            LD_LIBRARY_PATH: [runtimeLibDir, process.env.LD_LIBRARY_PATH].filter(Boolean).join(':')
        }
    }).trim();
    const version = output.match(/^gst-launch-1\.0 version\s+(\S+)$/m)?.[1] ||
        output.match(/^GStreamer\s+(\S+)$/m)?.[1];
    if (!version) throw new Error('unable to determine the staged gst-launch-1.0 version');
    return version;
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
            if (entry.isDirectory()) {
                visit(absolutePath, relativePath);
            } else if (entry.isFile()) {
                files.push(relativePath);
            } else {
                throw new Error(`capture runtime contains an unsupported entry: ${relativePath}`);
            }
        }
    };
    for (const directory of ['bin', 'capture-plugins', 'lib', 'spa-0.2']) {
        visit(path.join(runtimeDir, directory), directory);
    }
    return files.sort();
}

function writeCaptureManifest(runtimeDir, gstLaunchVersion) {
    const roleForPath = relativePath => {
        if (relativePath === 'bin/qorc-gst-launch-1.0') return 'launcher';
        if (relativePath === 'bin/qorc-gst-plugin-scanner') return 'plugin-scanner';
        if (relativePath.startsWith('capture-plugins/')) return 'plugin';
        if (relativePath.startsWith('lib/')) return 'library';
        if (relativePath.startsWith('spa-0.2/')) return 'spa';
        throw new Error(`unsupported capture runtime artifact path: ${relativePath}`);
    };
    const artifacts = captureRuntimeFiles(runtimeDir).map(relativePath => {
        const filePath = path.join(runtimeDir, ...relativePath.split('/'));
        return {
            path: relativePath,
            role: roleForPath(relativePath),
            size: fs.statSync(filePath).size,
            sha256: sha256File(filePath)
        };
    });
    const manifest = {
        format: 'qorc-gstreamer-capture-runtime',
        formatVersion: 1,
        platform: process.platform,
        architecture: process.arch,
        gstLaunchVersion,
        artifacts
    };
    fs.writeFileSync(
        path.join(runtimeDir, captureManifestName),
        `${JSON.stringify(manifest, null, 2)}\n`,
        { mode: 0o644 }
    );
}

function resolvePluginsDir() {
    if (process.env.QORC_GSTREAMER_SYSTEM_PLUGINS_DIR) {
        return path.resolve(process.env.QORC_GSTREAMER_SYSTEM_PLUGINS_DIR);
    }
    try {
        const resolved = execFileSync('pkg-config', ['--variable=pluginsdir', 'gstreamer-1.0'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        }).trim();
        if (resolved) return resolved;
    } catch { }
    const libraryTriplet = linuxLibraryTriplets[process.arch];
    const candidates = [
        libraryTriplet ? `/usr/lib/${libraryTriplet}/gstreamer-1.0` : null,
        '/usr/lib64/gstreamer-1.0',
        '/usr/lib/gstreamer-1.0'
    ].filter(Boolean);
    return candidates.find(candidate => fs.existsSync(candidate)) || null;
}

if (process.platform !== 'linux') {
    process.exit(0);
}

const sourceDir = resolvePluginsDir();
if (!sourceDir || !fs.statSync(sourceDir).isDirectory()) {
    console.error('[gstreamer] unable to locate the system GStreamer plugin directory');
    process.exit(1);
}

const systemLibDir = path.dirname(sourceDir);
const pipeWireRuntimeFiles = [
    ['libgstcontroller-1.0.so.0', path.join('runtime', 'lib', 'libgstcontroller-1.0.so.0')],
    ['libpipewire-0.3.so.0', path.join('runtime', 'lib', 'libpipewire-0.3.so.0')],
    ['libgstreamer-1.0.so.0', path.join('runtime', 'lib', 'libgstreamer-1.0.so.0')],
    ['libgstbase-1.0.so.0', path.join('runtime', 'lib', 'libgstbase-1.0.so.0')],
    ['libgstvideo-1.0.so.0', path.join('runtime', 'lib', 'libgstvideo-1.0.so.0')],
    ['libgstaudio-1.0.so.0', path.join('runtime', 'lib', 'libgstaudio-1.0.so.0')],
    ['libgstallocators-1.0.so.0', path.join('runtime', 'lib', 'libgstallocators-1.0.so.0')],
    ['libgstpbutils-1.0.so.0', path.join('runtime', 'lib', 'libgstpbutils-1.0.so.0')],
    ['libgsttag-1.0.so.0', path.join('runtime', 'lib', 'libgsttag-1.0.so.0')],
    ['libglib-2.0.so.0', path.join('runtime', 'lib', 'libglib-2.0.so.0')],
    ['libgobject-2.0.so.0', path.join('runtime', 'lib', 'libgobject-2.0.so.0')],
    ['libgmodule-2.0.so.0', path.join('runtime', 'lib', 'libgmodule-2.0.so.0')],
    ['liborc-0.4.so.0', path.join('runtime', 'lib', 'liborc-0.4.so.0')],
    ['libjpeg.so.8', path.join('runtime', 'lib', 'libjpeg.so.8')],
    ['libdrm.so.2', path.join('runtime', 'lib', 'libdrm.so.2')],
    ['libpcre2-8.so.0', path.join('runtime', 'lib', 'libpcre2-8.so.0')],
    ['libffi.so.8', path.join('runtime', 'lib', 'libffi.so.8')],
    ['libatomic.so.1', path.join('runtime', 'lib', 'libatomic.so.1')],
    ['libz.so.1', path.join('runtime', 'lib', 'libz.so.1')],
    ...requiredSpaPaths.map(relativePath => [
        relativePath,
        path.join('runtime', ...relativePath.split('/'))
    ])
];
fs.rmSync(stagingDir, { recursive: true, force: true });
fs.mkdirSync(stagingDir, { recursive: true });

const copied = [];
for (const plugin of plugins) {
    const source = path.join(sourceDir, plugin);
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) continue;
    fs.copyFileSync(source, path.join(stagingDir, plugin));
    copied.push(plugin);
}

const missing = requiredPlugins.filter(plugin => !copied.includes(plugin));
if (missing.length > 0) {
    fs.rmSync(stagingDir, { recursive: true, force: true });
    console.error(`[gstreamer] missing required plugins: ${missing.join(', ')}`);
    process.exit(1);
}

const capturePluginsDir = path.join(stagingDir, 'runtime', 'capture-plugins');
fs.mkdirSync(capturePluginsDir, { recursive: true });
for (const plugin of capturePlugins) {
    fs.copyFileSync(path.join(stagingDir, plugin), path.join(capturePluginsDir, plugin));
}

for (const [sourceRelative, destinationRelative] of pipeWireRuntimeFiles) {
    const source = path.join(systemLibDir, sourceRelative);
    if (!fs.statSync(source, { throwIfNoEntry: false })?.isFile()) {
        fs.rmSync(stagingDir, { recursive: true, force: true });
        console.error(`[gstreamer] missing required PipeWire runtime file: ${sourceRelative}`);
        process.exit(1);
    }
    const destination = path.join(stagingDir, destinationRelative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(source, destination);
}

const gStreamerLauncher = process.env.QORC_GSTREAMER_LAUNCH_SOURCE || [
    '/usr/bin/gst-launch-1.0',
    '/bin/gst-launch-1.0'
].find(candidate => fs.statSync(candidate, { throwIfNoEntry: false })?.isFile());
if (!gStreamerLauncher || !fs.statSync(gStreamerLauncher, { throwIfNoEntry: false })?.isFile()) {
    fs.rmSync(stagingDir, { recursive: true, force: true });
    console.error('[gstreamer] missing gst-launch-1.0 for native screen capture');
    process.exit(1);
}
const stagedLauncher = path.join(stagingDir, 'runtime', 'bin', 'qorc-gst-launch-1.0');
fs.mkdirSync(path.dirname(stagedLauncher), { recursive: true });
fs.copyFileSync(gStreamerLauncher, stagedLauncher);
fs.chmodSync(stagedLauncher, 0o755);

const pluginScanner = process.env.QORC_GSTREAMER_PLUGIN_SCANNER_SOURCE || [
    path.join(systemLibDir, 'gstreamer1.0', 'gstreamer-1.0', 'gst-plugin-scanner'),
    '/usr/libexec/gstreamer-1.0/gst-plugin-scanner'
].find(candidate => fs.statSync(candidate, { throwIfNoEntry: false })?.isFile());
if (!pluginScanner || !fs.statSync(pluginScanner, { throwIfNoEntry: false })?.isFile()) {
    fs.rmSync(stagingDir, { recursive: true, force: true });
    console.error('[gstreamer] missing gst-plugin-scanner for native screen capture');
    process.exit(1);
}
const stagedScanner = path.join(stagingDir, 'runtime', 'bin', 'qorc-gst-plugin-scanner');
fs.copyFileSync(pluginScanner, stagedScanner);
fs.chmodSync(stagedScanner, 0o755);

const captureRuntimeDir = path.join(stagingDir, 'runtime');
let gstLaunchVersion;
try {
    gstLaunchVersion = readLauncherVersion(stagedLauncher, path.join(captureRuntimeDir, 'lib'));
    writeCaptureManifest(captureRuntimeDir, gstLaunchVersion);
} catch (error) {
    fs.rmSync(stagingDir, { recursive: true, force: true });
    console.error(`[gstreamer] ${error.message}`);
    process.exit(1);
}

fs.rmSync(outputDir, { recursive: true, force: true });
fs.renameSync(stagingDir, outputDir);
console.log(`[gstreamer] staged ${copied.length} curated plugins with GStreamer ${gstLaunchVersion} from ${sourceDir}`);
