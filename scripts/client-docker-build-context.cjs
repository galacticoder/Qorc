'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const BUILD_CONTEXT_PREFIX = 'qor-chat-client-build-';
const ROOT_DIRECTORIES = Object.freeze([
    '.cargo',
    'data',
    'public',
    'scripts',
    'shared',
    'src',
    'src-tauri',
    'test-chat',
    'vendor',
    'workers'
]);
const ROOT_FILES = Object.freeze([
    'LICENSE',
    'index.html',
    'package.json',
    'pnpm-lock.yaml',
    'pnpm-workspace.yaml',
    'postcss.config.js',
    'tailwind.config.js',
    'tailwind.config.ts',
    'tsconfig.app.json',
    'tsconfig.json',
    'tsconfig.node.json',
    'vite.config.simple.ts'
]);

function normalizedRelative(root, candidate) {
    return path.relative(root, candidate).split(path.sep).join('/');
}

function includeClientSource(repositoryRoot, candidate) {
    const relative = normalizedRelative(repositoryRoot, candidate);
    if (!relative) return true;
    const segments = relative.split('/');
    if (segments.includes('node_modules') || segments.includes('target')) return false;
    if (relative === 'src-tauri/binaries' || relative.startsWith('src-tauri/binaries/')) return false;
    if (relative === 'src-tauri/resources/webkitgtk' || relative.startsWith('src-tauri/resources/webkitgtk/')) return false;
    if (relative === 'src-tauri/resources/webkitgtk-bundle' || relative.startsWith('src-tauri/resources/webkitgtk-bundle/')) return false;
    if (segments.some(segment => segment.startsWith('.webkitgtk-'))) return false;
    return true;
}

function copyTree(repositoryRoot, source, destination) {
    fs.cpSync(source, destination, {
        recursive: true,
        preserveTimestamps: true,
        filter: candidate => includeClientSource(repositoryRoot, candidate)
    });
}

function removeClientDockerBuildContext(contextRoot) {
    if (!contextRoot) return;
    const resolvedContext = path.resolve(contextRoot);
    const temporaryRoot = path.resolve(os.tmpdir());
    if (
        path.dirname(resolvedContext) !== temporaryRoot ||
        !path.basename(resolvedContext).startsWith(BUILD_CONTEXT_PREFIX)
    ) {
        throw new Error(`Refusing to remove unexpected client build context: ${resolvedContext}`);
    }
    fs.rmSync(resolvedContext, { recursive: true, force: true });
}

function createClientDockerBuildContext(repositoryRoot) {
    const sourceRoot = path.resolve(repositoryRoot);
    const contextRoot = fs.mkdtempSync(path.join(os.tmpdir(), BUILD_CONTEXT_PREFIX));

    try {
        for (const directory of ROOT_DIRECTORIES) {
            const source = path.join(sourceRoot, directory);
            if (fs.statSync(source, { throwIfNoEntry: false })?.isDirectory()) {
                copyTree(sourceRoot, source, path.join(contextRoot, directory));
            }
        }
        for (const filename of ROOT_FILES) {
            const source = path.join(sourceRoot, filename);
            if (fs.statSync(source, { throwIfNoEntry: false })?.isFile()) {
                fs.copyFileSync(source, path.join(contextRoot, filename));
            }
        }

        const dockerDirectory = path.join(contextRoot, 'docker');
        fs.mkdirSync(dockerDirectory);
        fs.copyFileSync(
            path.join(sourceRoot, 'docker', 'Dockerfile.client-bundle'),
            path.join(dockerDirectory, 'Dockerfile.client-bundle')
        );
        fs.writeFileSync(path.join(contextRoot, '.dockerignore'), '', { mode: 0o644 });
        return contextRoot;
    } catch (error) {
        removeClientDockerBuildContext(contextRoot);
        throw error;
    }
}

module.exports = {
    createClientDockerBuildContext,
    removeClientDockerBuildContext
};
