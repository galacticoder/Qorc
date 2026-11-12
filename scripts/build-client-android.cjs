#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const targets = { arm64: 'aarch64', x64: 'x86_64' };
const abis = { arm64: 'arm64-v8a', x64: 'x86_64' };

function buildRequests(architectures) {
    const selected = [...new Set(architectures)];
    if (!selected.length) throw new Error('Select at least one Android architecture');
    for (const arch of selected) if (!targets[arch]) throw new Error(`Unsupported Android architecture: ${arch}`);
    const requestedTargets = selected.map(arch => targets[arch]);
    const split = selected.length > 1;
    const requests = [{ targets: requestedTargets, split, artifacts: selected.map(arch => ({
        name: arch, flavor: split ? arch === 'x64' ? 'x86_64' : 'arm64' : 'universal', abis: [abis[arch]],
    })) }];
    if (split) requests.push({ targets: requestedTargets, split: false,
        artifacts: [{ name: 'universal', flavor: 'universal', abis: selected.map(arch => abis[arch]) }] });
    return requests;
}

function verifyApkDescription(description, artifact, metadata) {
    const packagedAbis = [...(description.match(/^native-code:(.*)$/m)?.[1] || '').matchAll(/'([^']+)'/g)].map(match => match[1]);
    if (!description.includes(`package: name='${metadata.identifier}'`) ||
        !description.includes(`versionName='${metadata.version}'`) ||
        !description.includes(`application-label:'${metadata.label}'`) ||
        [...packagedAbis].sort().join(',') !== [...artifact.abis].sort().join(',')) {
        throw new Error(`APK identity or native architecture does not match ${artifact.name}: expected ${metadata.identifier} ${metadata.version}, ${metadata.label}, ${artifact.abis.join(', ')}`);
    }
    return {
        label: metadata.label, identifier: metadata.identifier, version: metadata.version, abis: packagedAbis,
        minSdk: Number(description.match(/^(?:minSdkVersion|sdkVersion):'(\d+)'/m)?.[1]),
        targetSdk: Number(description.match(/^targetSdkVersion:'(\d+)'/m)?.[1]),
    };
}

function signingEnvironment(env) {
    const names = ['QORC_ANDROID_KEYSTORE', 'QORC_ANDROID_KEY_ALIAS', 'QORC_ANDROID_KEYSTORE_PASSWORD', 'QORC_ANDROID_KEY_PASSWORD'];
    if (names.some(name => env[name])) {
        if (!names.every(name => env[name])) throw new Error(`Configure all Android signing values: ${names.join(', ')}`);
        return env;
    }
    const directory = path.join(root, '.cache/android-signing');
    const metadata = path.join(directory, 'local-signing.json');
    const keystore = path.join(directory, 'qorc-local.jks');
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== 'win32' && fs.statSync(directory).mode & 0o077) throw new Error('Android signing directory must have owner-only permissions');
    if (fs.existsSync(metadata)) {
        const stat = fs.lstatSync(metadata);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096 || process.platform !== 'win32' && stat.mode & 0o077) throw new Error('Invalid local Android signing metadata permissions');
        const saved = JSON.parse(fs.readFileSync(metadata, 'utf8'));
        if (!fs.existsSync(keystore) || typeof saved.password !== 'string' || saved.password.length < 32) throw new Error('Local Android signing identity is incomplete; restore its original key and metadata');
        return { ...env, QORC_ANDROID_KEYSTORE: keystore, QORC_ANDROID_KEY_ALIAS: 'qorc-local', QORC_ANDROID_KEYSTORE_PASSWORD: saved.password, QORC_ANDROID_KEY_PASSWORD: saved.password };
    }
    if (fs.existsSync(keystore)) throw new Error('Android signing key exists without its metadata; it will not be replaced');
    const password = crypto.randomBytes(32).toString('base64url');
    const signing = { ...env, QORC_ANDROID_KEYSTORE: keystore, QORC_ANDROID_KEY_ALIAS: 'qorc-local', QORC_ANDROID_KEYSTORE_PASSWORD: password, QORC_ANDROID_KEY_PASSWORD: password };
    const tool = env.JAVA_HOME ? path.join(env.JAVA_HOME, 'bin', process.platform === 'win32' ? 'keytool.exe' : 'keytool') : 'keytool';
    execFileSync(tool, ['-genkeypair', '-keystore', keystore, '-storetype', 'JKS', '-alias', 'qorc-local',
        '-keyalg', 'RSA', '-keysize', '3072', '-validity', '10000', '-dname', 'CN=Qorc local build',
        '-storepass:env', 'QORC_ANDROID_KEYSTORE_PASSWORD', '-keypass:env', 'QORC_ANDROID_KEY_PASSWORD', '-noprompt'], { env: signing, stdio: 'inherit' });
    fs.chmodSync(keystore, 0o600);
    fs.writeFileSync(metadata, JSON.stringify({ password }) + '\n', { mode: 0o600, flag: 'wx' });
    console.log('[CLIENT] Created a private local Android signing identity in .cache/android-signing. Retain it for compatible app updates.');
    return signing;
}

function build({ architectures = ['arm64'], debug = false, env = process.env } = {}) {
    const sdk = env.ANDROID_HOME || env.ANDROID_SDK_ROOT;
    if (!sdk || !env.JAVA_HOME) throw new Error('Android builds require JAVA_HOME and ANDROID_HOME; install Android SDK 36 and NDK 27 first');
    const requests = buildRequests(architectures);
    require('./verify-android-tor.cjs').verify();
    require('./verify-android-pir.cjs').verify();
    const buildEnv = debug ? { ...env } : signingEnvironment({ ...env });
    const metadata = require('./prepare-android-branding.cjs').prepare();
    const sdkNdk = path.join(sdk, 'ndk/27.3.13750724');
    let ndk = env.NDK_HOME || sdkNdk;
    // Tauri's first Rust pass selects the SDK's NDK path. If NDK_HOME is a
    // symlink to that same installation, use the same spelling in Gradle too;
    // different linker paths otherwise invalidate every Cargo dependency.
    if (fs.existsSync(sdkNdk) && fs.existsSync(ndk) && fs.realpathSync(sdkNdk) === fs.realpathSync(ndk)) ndk = sdkNdk;
    const host = { linux: 'linux-x86_64', win32: 'windows-x86_64', darwin: 'darwin-x86_64' }[process.platform];
    const tools = path.join(ndk, 'toolchains/llvm/prebuilt', host || '', 'bin');
    if (!fs.existsSync(tools)) throw new Error('Android NDK toolchain is missing; set NDK_HOME');
    buildEnv.NDK_HOME = ndk;
    buildEnv.ANDROID_NDK_HOME = ndk;
    buildEnv.ANDROID_NDK_ROOT = ndk;
    buildEnv.PATH = tools + path.delimiter + (buildEnv.PATH || '');
    
    for (const triple of ['aarch64-linux-android', 'x86_64-linux-android']) {
        const normalized = triple.replaceAll('-', '_');
        const clangSuffix = process.platform === 'win32' ? '.cmd' : '';
        const executableSuffix = process.platform === 'win32' ? '.exe' : '';
        buildEnv[`CC_${normalized}`] = path.join(tools, `${triple}24-clang${clangSuffix}`);
        buildEnv[`CXX_${normalized}`] = path.join(tools, `${triple}24-clang++${clangSuffix}`);
        buildEnv[`AR_${normalized}`] = path.join(tools, `llvm-ar${executableSuffix}`);
        buildEnv[`RANLIB_${normalized}`] = path.join(tools, `llvm-ranlib${executableSuffix}`);
        buildEnv[`CARGO_TARGET_${normalized.toUpperCase()}_LINKER`] = buildEnv[`CC_${normalized}`];
    }
    buildEnv.RUSTFLAGS = [buildEnv.RUSTFLAGS, '-C link-arg=-Wl,-z,max-page-size=16384'].filter(Boolean).join(' ');
    
    const cli = require.resolve('@tauri-apps/cli/tauri.js');
    const profile = debug ? 'debug' : 'release';
    const output = path.join(root, 'src-tauri/target', profile, 'bundle/android');
    fs.mkdirSync(output, { recursive: true });
    for (const request of requests) {
        console.log(`[CLIENT] Building Android ${request.artifacts.map(artifact => artifact.name).join(' + ')} ${profile} APK...`);
        execFileSync(process.execPath, [cli, 'android', 'build', '--apk', '--target', ...request.targets,
            ...(request.split ? ['--split-per-abi'] : []), ...(debug ? ['--debug'] : [])], {
            cwd: root, env: buildEnv, stdio: 'inherit',
        });

        buildEnv.QORC_FRONTEND_PREBUILT = '1';
        const apkRoot = path.join(root, 'src-tauri/gen/android/app/build/outputs/apk');
        const apks = [];
        const walk = directory => {
            if (!fs.existsSync(directory)) return;
            for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
                const file = path.join(directory, item.name);
                if (item.isDirectory()) walk(file);
                else if (item.name.endsWith('.apk') && !/unsigned|androidTest/.test(file) && file.includes(`${path.sep}${profile}${path.sep}`)) apks.push(file);
            }
        };
        walk(apkRoot);
        const buildTools = fs.readdirSync(path.join(sdk, 'build-tools')).filter(version => /^\d/.test(version)).sort((a, b) => b.localeCompare(a, 'en', { numeric: true }))[0];
        if (!buildTools) throw new Error('Install Android SDK build-tools');
        const toolDirectory = path.join(sdk, 'build-tools', buildTools);
        const aapt = path.join(toolDirectory, process.platform === 'win32' ? 'aapt2.exe' : 'aapt2');
        const java = path.join(env.JAVA_HOME, 'bin', process.platform === 'win32' ? 'java.exe' : 'java');
        for (const artifact of request.artifacts) {
            
            const candidates = apks.filter(file => file.includes(`${path.sep}${artifact.flavor}${path.sep}`));
            if (!candidates.length) throw new Error(`Android build produced no signed ${artifact.name} APK`);
            candidates.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
            const description = execFileSync(aapt, ['dump', 'badging', candidates[0]], { env: buildEnv, encoding: 'utf8' });
            const info = verifyApkDescription(description, artifact, metadata);
            const signature = execFileSync(java, ['-jar', path.join(toolDirectory, 'lib/apksigner.jar'), 'verify', '--verbose', '--print-certs',
                '--min-sdk-version', String(info.minSdk), '--max-sdk-version', String(info.targetSdk), candidates[0]], { env: buildEnv, encoding: 'utf8' });
            execFileSync(path.join(toolDirectory, process.platform === 'win32' ? 'zipalign.exe' : 'zipalign'),
                ['-c', '-P', '16', '4', candidates[0]], { env: buildEnv, stdio: 'pipe' });
            const destination = path.join(output, `qorc-android-${artifact.name}-${profile}.apk`);
            const bytes = fs.readFileSync(candidates[0]);
            const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
            const temporary = destination + `.${crypto.randomUUID()}.tmp`;
            try {
                fs.writeFileSync(temporary, bytes, { flag: 'wx' });
                fs.renameSync(temporary, destination);
            } finally {
                fs.rmSync(temporary, { force: true });
            }
            fs.writeFileSync(destination + '.sha256', `${sha256}  ${path.basename(destination)}\n`);
            fs.writeFileSync(destination + '.json', JSON.stringify({ ...info, description: metadata.description,
                bytes: bytes.length, sha256, signatureVerified: true, zipAlignmentVerified: true,
                signerCertificateSha256: signature.match(/Signer #1 certificate SHA-256 digest: (\w+)/)?.[1] }, null, 2) + '\n');
            console.log(`[CLIENT] Verified signed Android APK (${info.abis.join(', ')}): ${destination}`);
        }
    }
}
module.exports = { build, signingEnvironment, buildRequests, verifyApkDescription };
