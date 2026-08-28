'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const BUILD_CONTEXT_PREFIX = 'qor-chat-docker-build-';
const SAFE_SERVER_CONFIG_FILES = Object.freeze([
    'audiences.js',
    'config.js',
    'constants.js',
    'error-codes.js',
    'infrastructure.js',
    'protocol-keys.js',
    'redis-keys.js',
    'secure-credentials.js'
]);

function copyTree(source, destination, options = {}) {
    fs.cpSync(source, destination, {
        recursive: true,
        preserveTimestamps: true,
        ...options
    });
}

function removeDockerBuildContext(contextRoot) {
    if (!contextRoot) return;

    const resolvedContext = path.resolve(contextRoot);
    const resolvedTemp = path.resolve(os.tmpdir());
    if (
        path.dirname(resolvedContext) !== resolvedTemp
        || !path.basename(resolvedContext).startsWith(BUILD_CONTEXT_PREFIX)
    ) {
        throw new Error(`Refusing to remove unexpected Docker build context: ${resolvedContext}`);
    }

    fs.rmSync(resolvedContext, { recursive: true, force: true });
}

function createDockerBuildContext(repositoryRoot) {
    const sourceRoot = path.resolve(repositoryRoot);
    const contextRoot = fs.mkdtempSync(path.join(os.tmpdir(), BUILD_CONTEXT_PREFIX));

    try {
        for (const directory of ['docker', 'scripts', 'shared']) {
            copyTree(path.join(sourceRoot, directory), path.join(contextRoot, directory));
        }

        copyTree(
            path.join(sourceRoot, 'workers'),
            path.join(contextRoot, 'workers'),
            { filter: (src) => path.basename(src) !== 'target' }
        );

        const sourceServer = path.join(sourceRoot, 'server');
        const contextServer = path.join(contextRoot, 'server');
        fs.mkdirSync(contextServer);

        for (const entry of fs.readdirSync(sourceServer, { withFileTypes: true })) {
            if (entry.name === 'config' || entry.name === 'node_modules') continue;
            copyTree(path.join(sourceServer, entry.name), path.join(contextServer, entry.name));
        }

        const contextConfig = path.join(contextServer, 'config');
        fs.mkdirSync(contextConfig);
        for (const filename of SAFE_SERVER_CONFIG_FILES) {
            fs.copyFileSync(
                path.join(sourceServer, 'config', filename),
                path.join(contextConfig, filename)
            );
        }

        fs.copyFileSync(
            path.join(sourceRoot, '.dockerignore'),
            path.join(contextRoot, '.dockerignore')
        );

        fs.writeFileSync(path.join(contextRoot, '.env'), '', { mode: 0o600 });

        return contextRoot;
    } catch (error) {
        removeDockerBuildContext(contextRoot);
        throw error;
    }
}

module.exports = {
    SAFE_SERVER_CONFIG_FILES,
    createDockerBuildContext,
    removeDockerBuildContext
};
