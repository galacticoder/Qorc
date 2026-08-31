#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const {
    createClientDockerBuildContext,
    removeClientDockerBuildContext
} = require('./client-docker-build-context.cjs');

const repoRoot = path.resolve(__dirname, '..');
const dockerfile = path.join('docker', 'Dockerfile.client-bundle');
const imageName = 'qorc-client-bundle:linux-arm64';
const buildCacheDirectory = path.join(repoRoot, '.cache', 'buildkit', 'client-linux-arm64');
const outputDirectory = path.join(
    repoRoot,
    'src-tauri',
    'target',
    'aarch64-unknown-linux-gnu',
    'release',
    'bundle'
);

function docker(args, options = {}) {
    return execFileSync('docker', args, {
        cwd: repoRoot,
        stdio: 'inherit',
        windowsHide: true,
        ...options
    });
}

function checkDocker() {
    let runtime;
    try {
        runtime = execFileSync('docker', ['version', '--format', '{{.Server.Os}}'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim().toLowerCase();
    } catch (error) {
        throw new Error(`Docker is unavailable or is not running: ${error.message}`);
    }
    if (runtime !== 'linux') {
        throw new Error('ARM64 client bundles require Docker running Linux containers');
    }

    const configuredBuilderName = (process.env.QORC_ARM64_BUILDER || '').trim();
    if (!configuredBuilderName) {
        throw new Error(
            'ARM64 cross-builds require a native ARM64 Buildx builder. Set QORC_ARM64_BUILDER, or run the build directly on an ARM64 machine.'
        );
    }
    const builderName = configuredBuilderName;
    try {
        execFileSync('docker', ['buildx', 'version'], {
            stdio: ['ignore', 'ignore', 'pipe']
        });
    } catch {
        throw new Error('Docker Buildx is required for persistent ARM64 build caches. Run `node scripts/install-deps.cjs --client-arm64`.');
    }

    try {
        const inspectArguments = ['buildx', 'inspect'];
        inspectArguments.push(builderName);
        inspectArguments.push('--bootstrap');
        const inspection = execFileSync('docker', inspectArguments, {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        });
        if (!inspection.includes('linux/arm64')) {
            throw new Error('selected builder does not advertise linux/arm64');
        }
    } catch {
        throw new Error('QORC_ARM64_BUILDER must select a reachable native ARM64 Buildx builder that advertises linux/arm64. Emulated ARM64 builders are unsupported.');
    }
    return builderName;
}

function collectArtifacts(root) {
    const artifacts = [];
    const pending = [root];
    while (pending.length > 0) {
        const directory = pending.pop();
        if (!fs.statSync(directory, { throwIfNoEntry: false })?.isDirectory()) continue;
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const candidate = path.join(directory, entry.name);
            if (entry.isDirectory()) pending.push(candidate);
            else if (/\.(appimage|deb|rpm)$/i.test(entry.name)) artifacts.push(candidate);
        }
    }
    return artifacts.sort();
}

function validateArtifacts(artifacts) {
    const names = artifacts.map(artifact => path.basename(artifact));
    const checks = [
        { extension: '.deb', pattern: /(?:_|-)arm64\.deb$/i, architecture: 'arm64' },
        { extension: '.rpm', pattern: /(?:\.|-)aarch64\.rpm$/i, architecture: 'aarch64' },
        { extension: '.AppImage', pattern: /(?:_|-)aarch64\.AppImage$/i, architecture: 'aarch64' }
    ];
    for (const check of checks) {
        const matching = names.filter(name => name.toLowerCase().endsWith(check.extension.toLowerCase()));
        if (matching.length === 0) throw new Error(`ARM64 build produced no ${check.extension} bundle`);
        if (matching.some(name => !check.pattern.test(name))) {
            throw new Error(`ARM64 build produced a mislabeled ${check.extension} bundle: ${matching.join(', ')}`);
        }
    }

    for (const artifact of artifacts) {
        if (/\.appimage$/i.test(artifact)) {
            const header = Buffer.alloc(20);
            const descriptor = fs.openSync(artifact, 'r');
            try {
                if (fs.readSync(descriptor, header, 0, header.length, 0) !== header.length) {
                    throw new Error('AppImage ELF header is truncated');
                }
            } finally {
                fs.closeSync(descriptor);
            }
            const isElf64LittleEndian = header.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
                && header[4] === 2 && header[5] === 1;
            const machine = header.readUInt16LE(18);
            if (!isElf64LittleEndian || machine !== 183) {
                throw new Error('AppImage runtime is not an ARM64 ELF executable');
            }
        }
    }
}

function main() {
    if (process.platform !== 'linux') {
        throw new Error('Cross-building Linux ARM64 client bundles is supported only from Linux');
    }
    const builderName = checkDocker();

    console.log(`[CLIENT] Using native ARM64 Buildx builder '${builderName}'.`);

    let contextRoot;
    let containerId;
    let extractedRoot;
    let nextCacheDirectory;
    try {
        console.log('[CLIENT] Preparing a secret-free ARM64 client build context...');
        contextRoot = createClientDockerBuildContext(repoRoot);
        console.log('[CLIENT] Building native Linux ARM64 installers in Docker...');
        nextCacheDirectory = `${buildCacheDirectory}.next-${process.pid}`;
        fs.rmSync(nextCacheDirectory, { recursive: true, force: true });
        fs.mkdirSync(path.dirname(buildCacheDirectory), { recursive: true });
        const buildArguments = [
            'buildx', 'build',
            '--load',
            '--progress', 'plain',
            '--platform', 'linux/arm64',
            '--file', path.join(contextRoot, dockerfile),
            '--tag', imageName,
            '--cache-to', `type=local,dest=${nextCacheDirectory},mode=max`
        ];
        buildArguments.push('--builder', builderName);
        if (fs.statSync(path.join(buildCacheDirectory, 'index.json'), { throwIfNoEntry: false })?.isFile()) {
            buildArguments.push('--cache-from', `type=local,src=${buildCacheDirectory}`);
        }
        buildArguments.push(contextRoot);
        docker(buildArguments);

        fs.rmSync(buildCacheDirectory, { recursive: true, force: true });
        fs.renameSync(nextCacheDirectory, buildCacheDirectory);
        nextCacheDirectory = null;

        containerId = execFileSync('docker', ['create', imageName, 'true'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim();
        if (!/^[a-f0-9]{12,64}$/i.test(containerId)) {
            throw new Error('Docker returned an invalid ARM64 bundle container identifier');
        }

        extractedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-arm64-output-'));
        docker(['cp', `${containerId}:/bundle/.`, extractedRoot]);
        const artifacts = collectArtifacts(extractedRoot);
        validateArtifacts(artifacts);

        fs.rmSync(outputDirectory, { recursive: true, force: true });
        fs.mkdirSync(outputDirectory, { recursive: true });
        fs.cpSync(extractedRoot, outputDirectory, { recursive: true, force: true });

        console.log('[CLIENT] Linux ARM64 bundle artifacts:');
        for (const artifact of collectArtifacts(outputDirectory)) {
            console.log(`  - ${path.relative(repoRoot, artifact)}`);
        }
    } finally {
        if (containerId) {
            try { execFileSync('docker', ['rm', '-f', containerId], { stdio: 'ignore' }); } catch { }
        }
        if (extractedRoot) fs.rmSync(extractedRoot, { recursive: true, force: true });
        if (nextCacheDirectory) fs.rmSync(nextCacheDirectory, { recursive: true, force: true });
        if (contextRoot) removeClientDockerBuildContext(contextRoot);
    }
}

try {
    main();
} catch (error) {
    console.error(`[CLIENT] ARM64 bundle build failed: ${error.message}`);
    process.exit(1);
}
