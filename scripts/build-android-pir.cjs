#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { verifyElf } = require('./verify-android-tor.cjs');
const root = path.resolve(__dirname, '..');
const destination = path.join(root, 'src-tauri/vendor/pir/android');
const args = process.argv.slice(2);
let update = false;
const abis = [];
const targets = { 'arm64-v8a': 'aarch64-linux-android', x86_64: 'x86_64-linux-android' };
for (let index = 0; index < args.length; ++index) {
    if (args[index] === '--update-pins') update = true;
    else if (args[index] === '--abi' && targets[args[index + 1]]) abis.push(args[++index]);
    else throw new Error('Usage: node scripts/build-android-pir.cjs [--abi arm64-v8a|x86_64] [--update-pins]');
}
const ndk = process.env.NDK_HOME;
if (process.platform !== 'linux' || !ndk || !/27\.3\.13750724/.test(fs.readFileSync(path.join(ndk, 'source.properties'), 'utf8'))) {
    throw new Error('Use Linux/WSL and set NDK_HOME to Android NDK 27.3.13750724');
}
const run = (command, argv, options = {}) => execFileSync(command, argv, { cwd: path.join(root, 'workers/ypir'), stdio: 'inherit', ...options });
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const manifestPath = path.join(destination, 'manifest.json');
const previous = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath)) : { abis: {} };
if (!update && !fs.existsSync(manifestPath)) throw new Error('Missing reviewed Android PIR pins');
const source = crypto.createHash('sha256');
const walk = directory => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
        if (['vendor', 'target', '.git'].includes(entry.name)) continue;
        const file = path.join(directory, entry.name);
        if (entry.isDirectory()) walk(file);
        else if (entry.isFile() && /(?:\.rs|\.cpp|Cargo\.(?:toml|lock)|config\.toml)$/.test(entry.name)) {
            source.update(path.relative(root, file).split(path.sep).join('/') + '\0');
            source.update(fs.readFileSync(file));
            source.update('\0');
        }
    }
};
walk(path.join(root, 'workers/ypir'));
walk(path.join(root, 'workers/spiral-rs'));
const sourceSha256 = source.digest('hex');
if (!update && previous.sourceSha256 !== sourceSha256) throw new Error('PIR sources differ from the reviewed Android build');
const targetDirectory = process.env.QORC_ANDROID_PIR_TARGET_DIR || path.join(root, '.cache/android-pir-build/target');
const tools = path.join(ndk, 'toolchains/llvm/prebuilt/linux-x86_64/bin');
const pins = { ...previous, sourceSha256, ndk: '27.3.13750724', minSdk: 24,
    rustc: run('rustc', ['--version'], { encoding: 'utf8', stdio: 'pipe' }).trim() };
for (const abi of abis.length ? abis : Object.keys(targets)) {
    const target = targets[abi], normalized = target.replaceAll('-', '_');
    const compiler = path.join(tools, `${target}24-clang`);
    const flags = [process.env.RUSTFLAGS, `--remap-path-prefix=${root}=qorc-source`,
        '-C link-arg=-Wl,-z,max-page-size=16384', '-C link-arg=-Wl,-z,relro,-z,now,-z,noexecstack'].filter(Boolean).join(' ');
    const env = { ...process.env, CARGO_TARGET_DIR: targetDirectory, CARGO_BUILD_JOBS: '2', RUSTFLAGS: flags,
        [`CARGO_TARGET_${normalized.toUpperCase()}_LINKER`]: compiler,
        [`CC_${normalized}`]: compiler, [`CXX_${normalized}`]: path.join(tools, `${target}24-clang++`),
        [`AR_${normalized}`]: path.join(tools, 'llvm-ar'),
        [`CXXFLAGS_${normalized}`]: `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -ffile-prefix-map=${root}=qorc-source` };
    console.log(`Building Android PIR client: ${abi}`);
    run('cargo', ['build', '--release', '--locked', '--offline', '--target', target, '--bin', 'qorc-pir-client'], { env });
    const built = path.join(targetDirectory, target, 'release/qorc-pir-client');
    run(path.join(tools, 'llvm-strip'), ['--strip-unneeded', built]);
    const bytes = fs.readFileSync(built);
    verifyElf(bytes, abi);
    const dynamic = run(path.join(tools, 'llvm-readelf'), ['--dynamic', built], { encoding: 'utf8', stdio: 'pipe' });
    for (const [, name] of dynamic.matchAll(/\(NEEDED\).*?\[([^\]]+)\]/g)) {
        if (!['libc.so', 'libdl.so', 'libm.so', 'liblog.so'].includes(name)) throw new Error(`Unbundled Android dependency: ${name}`);
    }
    const pin = { sha256: sha(bytes), size: bytes.length };
    if (!update && JSON.stringify(previous.abis[abi]) !== JSON.stringify(pin)) throw new Error(`Rebuild differs from reviewed Android PIR pins: ${abi}`);
    const directory = path.join(destination, 'jniLibs', abi);
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'libqorc_pir_client.so'), bytes, { mode: 0o755 });
    pins.abis[abi] = pin;
    console.log(`Verified ${abi} PIR client: ${pin.sha256}`);
}
if (update) fs.writeFileSync(manifestPath, JSON.stringify(pins, null, 2) + '\n');
const licenseParts = [];
const licenseRoots = [path.join(root, 'workers/ypir'), path.join(root, 'workers/spiral-rs'),
    ...fs.readdirSync(path.join(root, 'workers/ypir/vendor'), { withFileTypes: true })
        .filter(entry => entry.isDirectory()).map(entry => path.join(root, 'workers/ypir/vendor', entry.name))];
for (const directory of licenseRoots.sort()) {
    for (const file of fs.readdirSync(directory).sort()) {
        if (/^(LICENSE|COPYING|NOTICE)/i.test(file) && fs.statSync(path.join(directory, file)).isFile()) {
            licenseParts.push(`\n${path.relative(root, directory)}/${file}\n${'='.repeat(72)}\n${fs.readFileSync(path.join(directory, file), 'utf8')}`);
        }
    }
}
fs.mkdirSync(path.join(destination, 'licenses'), { recursive: true });
fs.writeFileSync(path.join(destination, 'licenses/QORC_PIR_THIRD_PARTY_LICENSES.txt'), licenseParts.join('\n'));
