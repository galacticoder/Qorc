'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const localBuilderName = 'qorc-client-arm64';
const dockerfile = path.resolve(__dirname, '../docker/Dockerfile.client-bundle');

function ensureArm64Builder({ run = execFileSync, env = process.env, log = console.log } = {}) {
    const capture = { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env };
    let runtime;
    try {
        runtime = run('docker', ['version', '--format', '{{.Server.Os}}'], capture).trim();
    } catch (error) {
        throw new Error(`Docker is unavailable or is not running: ${error.message}`);
    }
    if (runtime !== 'linux') throw new Error('ARM64 client bundles require Docker running Linux containers');

    try {
        run('docker', ['buildx', 'version'], capture);
    } catch {
        throw new Error('Docker Buildx is required. Run `node scripts/install-deps.cjs --client-arm64`.');
    }

    const configuredBuilder = (env.QORC_ARM64_BUILDER || '').trim();
    const builderName = configuredBuilder || localBuilderName;
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(builderName)) {
        throw new Error('QORC_ARM64_BUILDER must be a valid Buildx builder name');
    }

    if (!configuredBuilder) {
        const names = run('docker', ['buildx', 'ls', '--format', '{{.Name}}'], capture)
            .split(/\r?\n/).map(name => name.trim());
        if (!names.includes(builderName)) {
            log(`[CLIENT] Creating local ARM64 builder '${builderName}' with QEMU support...`);
            run('docker', ['buildx', 'create', '--name', builderName, '--driver', 'docker-container'], {
                stdio: 'inherit', env
            });
        }
    }

    try {
        run('docker', ['buildx', 'inspect', builderName, '--bootstrap'], { stdio: 'inherit', env });
    } catch (error) {
        throw new Error(`Cannot start ARM64 builder '${builderName}': ${error.message}`);
    }

    log(`[CLIENT] Checking ARM64 execution on builder '${builderName}'...`);
    try {
        run('docker', [
            'buildx', 'build', '--builder', builderName,
            '--platform', 'linux/arm64', '--target', 'arm64-runtime',
            '--no-cache', '--progress', 'plain', '--output', 'type=cacheonly', '-'
        ], {
            input: fs.readFileSync(dockerfile, 'utf8'),
            stdio: ['pipe', 'inherit', 'inherit'],
            env
        });
    } catch (error) {
        throw new Error(
            `ARM64 execution check failed on '${builderName}'. ` +
            'Check the Docker output above for image-download or QEMU errors. ' +
            'The builder must be able to execute linux/arm64 containers before compiling. ' +
            'See docs/CONTRIBUTING.md for ARM64 setup. ' + error.message
        );
    }

    return builderName;
}

module.exports = { ensureArm64Builder };
