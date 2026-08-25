#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { execFileSync } = require('node:child_process');

const version = '2.52.6-1ubuntu1';
const upstreamVersion = '2.52.6';
const target = 'linux-x86_64';
const architecture = 'amd64';
const repoRoot = path.resolve(__dirname, '..');
const cacheDir = path.join(repoRoot, '.cache', `webkitgtk-${target}-${version}`);
const resourcesDir = path.join(repoRoot, 'src-tauri', 'resources');
const runtimeDir = path.join(resourcesDir, 'webkitgtk');
const stagingDir = path.join(resourcesDir, `.webkitgtk-staging-${process.pid}`);
const packageBaseUrl = 'https://archive.ubuntu.com/ubuntu/pool/main/w/webkit2gtk';
const packages = [
  {
    name: 'libwebkit2gtk-4.1-0',
    file: `libwebkit2gtk-4.1-0_${version}_${architecture}.deb`,
    sha256: '91d1e6678db6b6cd5dd586b1cddc8e693aa1f706ef9964f98bfc374e31ffac6a'
  },
  {
    name: 'libjavascriptcoregtk-4.1-0',
    file: `libjavascriptcoregtk-4.1-0_${version}_${architecture}.deb`,
    sha256: '6894a5b1384e82d7c520d4a0888c05da91ac2e133901eff4b6779d6909cc96a5'
  }
];
const requiredFiles = [
  'usr/lib/x86_64-linux-gnu/libwebkit2gtk-4.1.so.0',
  'usr/lib/x86_64-linux-gnu/libjavascriptcoregtk-4.1.so.0',
  'usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitGPUProcess',
  'usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitNetworkProcess',
  'usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/WebKitWebProcess',
  'usr/lib/x86_64-linux-gnu/webkit2gtk-4.1/injected-bundle/libwebkit2gtkinjectedbundle.so'
];

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function packageIsValid(entry, packagePath) {
  if (!fs.statSync(packagePath, { throwIfNoEntry: false })?.isFile()) return false;
  if (sha256(packagePath) !== entry.sha256) return false;
  try {
    const field = name => execFileSync('dpkg-deb', ['-f', packagePath, name], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
    return field('Package') === entry.name
      && field('Version') === version
      && field('Architecture') === architecture;
  } catch {
    return false;
  }
}

async function downloadPackage(entry, packagePath) {
  fs.mkdirSync(cacheDir, { recursive: true });
  const temporaryPath = `${packagePath}.${process.pid}.tmp`;
  fs.rmSync(temporaryPath, { force: true });
  const response = await fetch(`${packageBaseUrl}/${entry.file}`, { redirect: 'follow' });
  if (!response.ok || !response.body) {
    throw new Error(`download failed for ${entry.file}: HTTP ${response.status}`);
  }
  try {
    await pipeline(response.body, fs.createWriteStream(temporaryPath, { mode: 0o644 }));
    if (!packageIsValid(entry, temporaryPath)) {
      throw new Error(`downloaded package failed validation: ${entry.file}`);
    }
    fs.renameSync(temporaryPath, packagePath);
  } catch (error) {
    fs.rmSync(temporaryPath, { force: true });
    throw error;
  }
}

function runtimeIsCurrent() {
  try {
    const metadata = JSON.parse(fs.readFileSync(path.join(runtimeDir, 'runtime-version.json'), 'utf8'));
    return metadata.version === version
      && metadata.upstreamVersion === upstreamVersion
      && metadata.target === target
      && requiredFiles.every(relative => fs.statSync(path.join(runtimeDir, relative), { throwIfNoEntry: false })?.isFile());
  } catch {
    return false;
  }
}

async function main() {
  if (process.platform !== 'linux') return;
  if (process.arch !== 'x64') {
    throw new Error(`No bundled WebKitGTK runtime is available for Linux ${process.arch}`);
  }
  if (runtimeIsCurrent()) {
    console.log(`[webkitgtk] staged runtime ${upstreamVersion} is current`);
    return;
  }

  const packagePaths = [];
  for (const entry of packages) {
    const packagePath = path.join(cacheDir, entry.file);
    if (!packageIsValid(entry, packagePath)) {
      fs.rmSync(packagePath, { force: true });
      console.log(`[webkitgtk] downloading ${entry.file}...`);
      await downloadPackage(entry, packagePath);
    }
    packagePaths.push(packagePath);
  }

  fs.mkdirSync(resourcesDir, { recursive: true });
  fs.rmSync(stagingDir, { recursive: true, force: true });
  fs.mkdirSync(stagingDir, { recursive: true, mode: 0o755 });

  try {
    for (const packagePath of packagePaths) {
      execFileSync('dpkg-deb', ['-x', packagePath, stagingDir], { stdio: 'inherit' });
    }
    for (const relative of requiredFiles) {
      if (!fs.statSync(path.join(stagingDir, relative), { throwIfNoEntry: false })?.isFile()) {
        throw new Error(`runtime file is missing: ${relative}`);
      }
    }
    const metadata = {
      version,
      upstreamVersion,
      target,
      architecture,
      packages: packages.map(({ name, file, sha256: checksum }) => ({ name, file, sha256: checksum }))
    };
    fs.writeFileSync(path.join(stagingDir, 'runtime-version.json'), `${JSON.stringify(metadata, null, 2)}\n`, { mode: 0o644 });
    fs.rmSync(runtimeDir, { recursive: true, force: true });
    fs.renameSync(stagingDir, runtimeDir);
  } catch (error) {
    fs.rmSync(stagingDir, { recursive: true, force: true });
    throw error;
  }

  console.log(`[webkitgtk] staged app-private runtime ${upstreamVersion}`);
}

main().catch(error => {
  console.error(`[webkitgtk] ${error.message}`);
  process.exit(1);
});
