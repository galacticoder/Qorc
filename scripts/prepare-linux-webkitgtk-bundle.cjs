#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

if (process.platform !== 'linux') process.exit(0);
if (process.arch !== 'x64') {
  console.error(`[webkitgtk-bundle] unsupported architecture: ${process.arch}`);
  process.exit(1);
}

const repoRoot = path.resolve(__dirname, '..');
const tauriDir = path.join(repoRoot, 'src-tauri');
const tauriConfig = JSON.parse(fs.readFileSync(path.join(tauriDir, 'tauri.conf.json'), 'utf8'));
const productName = tauriConfig.productName;
const sourceDir = path.join(tauriDir, 'resources', 'webkitgtk');
const sourceLibDir = path.join(sourceDir, 'usr', 'lib', 'x86_64-linux-gnu');
const resourcesDir = path.join(tauriDir, 'resources');
const outputDir = path.join(resourcesDir, 'webkitgtk-bundle');
const stagingDir = path.join(resourcesDir, `.webkitgtk-bundle-staging-${process.pid}`);
const gStreamerSourceDir = process.env.GSTREAMER_PLUGINS_DIR
  ? path.resolve(process.env.GSTREAMER_PLUGINS_DIR)
  : path.join(repoRoot, '.cache', `gstreamer-plugins-${process.arch}`);
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
const gStreamerPlugins = [
  'libgstcoreelements.so',
  'libgstjpeg.so',
  'libgstopengl.so',
  'libgstpipewire.so',
  'libgstvideoconvertscale.so',
  'libgstvideorate.so'
];
const binaryPath = path.join(tauriDir, 'target', 'release', 'qor');
const libraries = [
  'libwebkit2gtk-4.1.so.0',
  'libjavascriptcoregtk-4.1.so.0'
];
const helpers = [
  'WebKitGPUProcess',
  'WebKitNetworkProcess',
  'WebKitWebProcess',
  path.join('injected-bundle', 'libwebkit2gtkinjectedbundle.so')
];

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

function validateCaptureRuntime(runtimeDir, strictInventory) {
  const manifestPath = path.join(runtimeDir, captureManifestName);
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
  const expectedRoles = relativePath => {
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
    const role = expectedRoles(relativePath);
    if (!relativePath || relativePath.includes('\\') || path.posix.isAbsolute(relativePath) ||
        segments.some(segment => !segment || segment === '.' || segment === '..') || !role ||
        artifact.role !== role || !Number.isSafeInteger(artifact.size) || artifact.size < 0 ||
        typeof artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.sha256) ||
        uniquePaths.has(relativePath)) {
      throw new Error('GStreamer capture runtime manifest contains an invalid artifact');
    }
    uniquePaths.add(relativePath);
    paths.push(relativePath);
    const filePath = path.join(runtimeDir, ...segments);
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
  if (strictInventory) {
    const inventory = captureRuntimeFiles(runtimeDir);
    if (inventory.join('\n') !== paths.join('\n')) {
      throw new Error('GStreamer capture runtime files do not match the manifest inventory');
    }
  }
  return {
    manifest,
    sha256: sha256File(manifestPath)
  };
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
  if (count === 0) throw new Error('WebKit executable path was not found');
  fs.writeFileSync(filePath, contents);
  return count;
}

function copyLibrary(libraryName) {
  const sourceLink = path.join(sourceLibDir, libraryName);
  if (!fs.lstatSync(sourceLink, { throwIfNoEntry: false })?.isSymbolicLink()) {
    throw new Error(`runtime has no versioned link for ${libraryName}`);
  }
  const versionedName = fs.readlinkSync(sourceLink);
  if (path.basename(versionedName) !== versionedName || !versionedName.startsWith(`${libraryName}.`)) {
    throw new Error(`runtime has an unsafe library target for ${libraryName}`);
  }
  const outputLibDir = path.join(stagingDir, 'lib');
  fs.mkdirSync(outputLibDir, { recursive: true });
  fs.copyFileSync(path.join(sourceLibDir, versionedName), path.join(outputLibDir, libraryName));
  return libraryName;
}

function main() {
  execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'stage-webkitgtk-runtime.cjs')], {
    cwd: repoRoot,
    stdio: 'inherit'
  });
  if (!fs.statSync(binaryPath, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`release binary not found: ${binaryPath}`);
  }
  const metadata = JSON.parse(fs.readFileSync(path.join(sourceDir, 'runtime-version.json'), 'utf8'));
  if (metadata.upstreamVersion !== '2.52.6' || metadata.target !== 'linux-x86_64') {
    throw new Error('staged WebKitGTK runtime does not match the Linux bundle target');
  }

  fs.rmSync(stagingDir, { recursive: true, force: true });
  fs.mkdirSync(stagingDir, { recursive: true, mode: 0o755 });
  try {
    const installedLibraries = Object.fromEntries(libraries.map(library => [library, copyLibrary(library)]));
    const pipeWireRuntimeSource = path.join(gStreamerSourceDir, 'runtime');
    const captureRuntime = validateCaptureRuntime(pipeWireRuntimeSource, true);
    for (const plugin of gStreamerPlugins) {
      if (!fs.statSync(path.join(gStreamerSourceDir, plugin), { throwIfNoEntry: false })?.isFile()) {
        throw new Error(`required GStreamer plugin is missing: ${plugin}`);
      }
    }
    if (!fs.statSync(pipeWireRuntimeSource, { throwIfNoEntry: false })?.isDirectory()) {
      throw new Error('required PipeWire runtime is missing');
    }
    const pipeWirePluginDir = path.join(stagingDir, 'gstreamer-1.0');
    fs.mkdirSync(pipeWirePluginDir, { recursive: true });
    for (const plugin of gStreamerPlugins) {
      fs.copyFileSync(path.join(gStreamerSourceDir, plugin), path.join(pipeWirePluginDir, plugin));
    }
    fs.cpSync(
      path.join(pipeWireRuntimeSource, 'capture-plugins'),
      path.join(stagingDir, 'capture-plugins'),
      { recursive: true, force: true }
    );
    fs.cpSync(path.join(pipeWireRuntimeSource, 'lib'), path.join(stagingDir, 'lib'), {
      recursive: true,
      force: true
    });
    fs.cpSync(path.join(pipeWireRuntimeSource, 'spa-0.2'), path.join(stagingDir, 'spa-0.2'), {
      recursive: true,
      force: true
    });
    const gStreamerLauncher = 'qor-gst-launch-1.0';
    fs.mkdirSync(path.join(stagingDir, 'bin'), { recursive: true });
    fs.copyFileSync(
      path.join(pipeWireRuntimeSource, 'bin', gStreamerLauncher),
      path.join(stagingDir, 'bin', gStreamerLauncher)
    );
    fs.chmodSync(path.join(stagingDir, 'bin', gStreamerLauncher), 0o755);
    const gStreamerPluginScanner = 'qor-gst-plugin-scanner';
    fs.copyFileSync(
      path.join(pipeWireRuntimeSource, 'bin', gStreamerPluginScanner),
      path.join(stagingDir, 'bin', gStreamerPluginScanner)
    );
    fs.chmodSync(path.join(stagingDir, 'bin', gStreamerPluginScanner), 0o755);
    fs.copyFileSync(
      path.join(pipeWireRuntimeSource, captureManifestName),
      path.join(stagingDir, captureManifestName)
    );
    const installedCaptureRuntime = validateCaptureRuntime(stagingDir, false);
    if (installedCaptureRuntime.sha256 !== captureRuntime.sha256) {
      throw new Error('GStreamer capture runtime manifest changed while staging');
    }
    const sourceHelperDir = path.join(sourceLibDir, 'webkit2gtk-4.1');
    for (const helper of helpers) {
      const source = path.join(sourceHelperDir, helper);
      const destination = path.join(stagingDir, 'helpers', helper);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(source, destination);
      fs.chmodSync(destination, fs.statSync(source).mode & 0o777);
    }

    const sourceExecutablePath = '/usr/lib/x86_64-linux-gnu/webkit2gtk-4.1';
    const executablePrefix = `/usr/lib/${productName}/webkitgtk/`;
    const executableDirectoryName = 'helpers';
    const packagedExecutablePath = `${executablePrefix}${'/'.repeat(sourceExecutablePath.length - executablePrefix.length - executableDirectoryName.length)}${executableDirectoryName}`;
    const patchedOccurrences = replaceBytes(
      path.join(stagingDir, 'lib', installedLibraries['libwebkit2gtk-4.1.so.0']),
      sourceExecutablePath,
      packagedExecutablePath
    );

    const licenseDir = path.join(stagingDir, 'licenses');
    fs.mkdirSync(licenseDir, { recursive: true });
    fs.copyFileSync(
      path.join(sourceDir, 'usr', 'share', 'doc', 'libwebkit2gtk-4.1-0', 'copyright'),
      path.join(licenseDir, 'libwebkit2gtk-4.1-0-copyright')
    );
    fs.copyFileSync(
      path.join(sourceDir, 'usr', 'share', 'doc', 'libjavascriptcoregtk-4.1-0', 'copyright'),
      path.join(licenseDir, 'libjavascriptcoregtk-4.1-0-copyright')
    );
    const finalizedCaptureRuntime = validateCaptureRuntime(stagingDir, false);
    if (finalizedCaptureRuntime.sha256 !== captureRuntime.sha256) {
      throw new Error('GStreamer capture runtime changed before bundle finalization');
    }
    fs.writeFileSync(path.join(stagingDir, 'runtime-version.json'), `${JSON.stringify({
      ...metadata,
      installedLibraries,
      gStreamerPlugins,
      gStreamerLauncher,
      gStreamerPluginScanner,
      gStreamerCaptureRuntime: {
        manifest: captureManifestName,
        manifestSha256: captureRuntime.sha256,
        gstLaunchVersion: captureRuntime.manifest.gstLaunchVersion
      },
      executablePath: packagedExecutablePath,
      patchedOccurrences
    }, null, 2)}\n`, { mode: 0o644 });
    fs.rmSync(outputDir, { recursive: true, force: true });
    fs.renameSync(stagingDir, outputDir);
  } catch (error) {
    fs.rmSync(stagingDir, { recursive: true, force: true });
    throw error;
  }

  const runpath = `$ORIGIN/../lib/${productName}/webkitgtk/lib`;
  execFileSync('patchelf', ['--set-rpath', runpath, binaryPath], { stdio: 'inherit' });
  const installedRunpath = execFileSync('patchelf', ['--print-rpath', binaryPath], { encoding: 'utf8' }).trim();
  if (installedRunpath !== runpath) throw new Error('failed to install the private WebKitGTK runpath');
  console.log(`[webkitgtk-bundle] prepared ${metadata.upstreamVersion} for Linux packages`);
}

try {
  main();
} catch (error) {
  console.error(`[webkitgtk-bundle] ${error.message}`);
  process.exit(1);
}
