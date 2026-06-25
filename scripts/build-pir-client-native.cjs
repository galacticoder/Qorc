#!/usr/bin/env node

/*
 * Builds the pinned HintlessPIR client helper for the current host platform
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..');
const hintlessDir = path.join(repoRoot, 'workers', 'hintless');
const upstreamDir = path.join(hintlessDir, 'upstream');
const outDir = path.join(repoRoot, 'src-tauri', 'binaries');
const exeSuffix = process.platform === 'win32' ? '.exe' : '';
const clientOutPath = path.join(outDir, `qor-pir-client${exeSuffix}`);
const keepBuildDir = process.env.QOR_PIR_KEEP_NATIVE_BUILD === '1';
const bazeliskVersion = 'v1.25.0';

function log(...args) {
  console.log('[PIR-BINARIES]', ...args);
}

function commandExists(command) {
  try {
    if (process.platform === 'win32') {
      execFileSync('where', [command], { stdio: 'ignore', windowsHide: true });
    } else {
      execFileSync('sh', ['-lc', `command -v ${command}`], { stdio: 'ignore' });
    }
    return true;
  } catch {
    return false;
  }
}

function bazeliskAssetName() {
  const arch = os.arch();
  if (process.platform === 'win32' && arch === 'x64') return 'bazelisk-windows-amd64.exe';
  if (process.platform === 'darwin' && arch === 'x64') return 'bazelisk-darwin-amd64';
  if (process.platform === 'darwin' && arch === 'arm64') return 'bazelisk-darwin-arm64';
  if (process.platform === 'linux' && arch === 'x64') return 'bazelisk-linux-amd64';
  throw new Error(`No pinned Bazelisk binary is configured for ${process.platform}/${arch}`);
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        response.resume();
        downloadFile(response.headers.location, dest).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`Download failed with HTTP ${response.statusCode}: ${url}`));
        return;
      }
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      const output = fs.createWriteStream(dest, { mode: 0o755 });
      response.pipe(output);
      output.on('finish', () => {
        output.close(() => {
          if (process.platform !== 'win32') fs.chmodSync(dest, 0o755);
          resolve();
        });
      });
      output.on('error', reject);
    });
    request.on('error', reject);
  });
}

async function ensureBazelisk() {
  const asset = bazeliskAssetName();
  const localPath = path.join(repoRoot, '.cache', 'bazelisk-bin', asset);
  if (!fs.existsSync(localPath)) {
    const url = `https://github.com/bazelbuild/bazelisk/releases/download/${bazeliskVersion}/${asset}`;
    log(`Bazelisk not found. Downloading ${url}`);
    await downloadFile(url, localPath);
  }
  return localPath;
}

async function findBazelCommand() {
  if (process.env.BAZEL) return process.env.BAZEL;
  if (commandExists('bazelisk')) return 'bazelisk';
  if (commandExists('bazel')) return 'bazel';
  return ensureBazelisk();
}

function run(command, args, options = {}) {
  execFileSync(command, args, {
    cwd: options.cwd || repoRoot,
    stdio: options.stdio || 'inherit',
    env: {
      ...process.env,
      BAZELISK_HOME: process.env.BAZELISK_HOME || path.join(repoRoot, '.cache', 'bazelisk')
    },
    windowsHide: true
  });
}

function copyOverlay(workDir) {
  const qorDir = path.join(workDir, 'qor');
  fs.mkdirSync(path.join(qorDir, 'third_party'), { recursive: true });
  fs.copyFileSync(path.join(hintlessDir, 'BUILD.overlay'), path.join(qorDir, 'BUILD'));
  fs.copyFileSync(path.join(hintlessDir, 'src', 'qor_pir_common.h'), path.join(qorDir, 'qor_pir_common.h'));
  fs.copyFileSync(path.join(hintlessDir, 'src', 'qor_pir_worker.cc'), path.join(qorDir, 'qor_pir_worker.cc'));
  fs.copyFileSync(path.join(hintlessDir, 'src', 'qor_pir_client.cc'), path.join(qorDir, 'qor_pir_client.cc'));
  fs.copyFileSync(path.join(hintlessDir, 'third_party', 'httplib.h'), path.join(qorDir, 'third_party', 'httplib.h'));
  fs.copyFileSync(path.join(hintlessDir, 'third_party', 'json.hpp'), path.join(qorDir, 'third_party', 'json.hpp'));
}

function validateClientBinary(file) {
  const stdout = execFileSync(file, [], {
    input: '{"operation":"ping"}',
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    timeout: 10000,
    windowsHide: true
  });
  const parsed = JSON.parse(stdout);
  if (parsed.success !== true) {
    throw new Error(`PIR client ping failed: ${stdout.trim()}`);
  }
}

async function main() {
  fs.mkdirSync(outDir, { recursive: true });

  const bazel = await findBazelCommand();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'qor-pir-native-'));
  const workDir = path.join(tempRoot, 'workspace');

  try {
    log(`Building native PIR client with ${bazel}`);
    fs.cpSync(upstreamDir, workDir, { recursive: true });
    copyOverlay(workDir);

    run(bazel, ['build', '-c', 'opt', '//qor:qor_pir_client'], { cwd: workDir });

    const bazelBin = execFileSync(bazel, ['info', 'bazel-bin'], {
      cwd: workDir,
      encoding: 'utf8',
      env: {
        ...process.env,
        BAZELISK_HOME: process.env.BAZELISK_HOME || path.join(repoRoot, '.cache', 'bazelisk')
      },
      windowsHide: true
    }).trim();

    const builtCandidates = [
      path.join(bazelBin, 'qor', `qor_pir_client${exeSuffix}`),
      path.join(bazelBin, 'qor', 'qor_pir_client.exe'),
      path.join(bazelBin, 'qor', 'qor_pir_client')
    ];
    const builtClient = builtCandidates.find((candidate) => fs.existsSync(candidate));
    if (!builtClient) {
      throw new Error(`Built PIR client was not found under ${path.join(bazelBin, 'qor')}`);
    }

    fs.copyFileSync(builtClient, clientOutPath);
    if (process.platform !== 'win32') {
      fs.chmodSync(clientOutPath, 0o755);
    }
    validateClientBinary(clientOutPath);
    log(`Wrote ${path.relative(repoRoot, clientOutPath)}`);
  } finally {
    if (keepBuildDir) {
      log(`Kept native build directory: ${tempRoot}`);
    } else {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  console.error('[PIR-BINARIES] Native PIR client build failed:', error.message);
  process.exit(1);
});
