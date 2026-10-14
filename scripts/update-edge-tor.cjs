const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

process.umask(0o077);
const repo = path.resolve(__dirname, '..');
const source = JSON.parse(fs.readFileSync(path.join(repo, 'docker/tor/manifest.json'), 'utf8'));
const image = fs.readFileSync(path.join(repo, 'docker/Dockerfile.loadbalancer'), 'utf8');
const patch = fs.readFileSync(path.join(repo, 'docker/tor', source.patch));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
if (hash(patch) !== source.patch_sha256) throw new Error('Tor publication patch does not match its manifest');
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--amd64' || args[2] !== '--arm64') {
    throw new Error('Usage: node scripts/update-edge-tor.cjs --amd64 /path/to/tor --arm64 /path/to/tor');
}
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-edge-tor-'));
const results = [];
try {
    for (const [architecture, target, machine, binaryPath] of [
        ['amd64', 'x86_64', 62, args[1]], ['arm64', 'arm64', 183, args[3]],
    ]) {
        const binary = fs.readFileSync(path.resolve(binaryPath));
        if (binary.length < 64 || !binary.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70])) ||
            binary[4] !== 2 || binary[5] !== 1 || binary.readUInt16LE(18) !== machine) {
            throw new Error(`Tor binary does not match Linux ${architecture}`);
        }
        const archivePath = path.join(repo, `docker/edge-runtime/qorc-edge-runtime-linux-${target}-v1.tar.gz`);
        const expected = image.match(new RegExp(`${architecture}\\) archive=[^;]+; expected=([a-f0-9]{64})`))?.[1];
        if (!expected || hash(fs.readFileSync(archivePath)) !== expected) throw new Error(`Existing ${architecture} runtime failed authentication`);
        const directory = path.join(temporary, architecture);
        fs.mkdirSync(directory, { mode: 0o700 });
        execFileSync('tar', ['-xzf', archivePath, '-C', directory, '--no-same-owner'], { stdio: 'inherit' });
        const runtime = path.join(directory, 'qorc-edge');
        const manifestPath = path.join(runtime, 'manifest.json');
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        if (manifest.format !== 'qorc-edge-runtime-v1' || manifest.target !== `linux-${target}-glibc-2.35`) {
            throw new Error(`Unexpected ${architecture} runtime manifest`);
        }
        for (const [relative, expectedHash] of Object.entries(manifest.files)) {
            if (relative.includes('..') || path.isAbsolute(relative) || hash(fs.readFileSync(path.join(runtime, relative))) !== expectedHash) {
                throw new Error(`Existing runtime file failed authentication: ${relative}`);
            }
        }
        const destination = path.join(runtime, 'tor/tor');
        fs.writeFileSync(destination, binary, { mode: 0o755 });
        fs.chmodSync(destination, 0o755);
        manifest.tor = { version: source.version, source_sha256: source.source_sha256, patch_sha256: source.patch_sha256, binary_sha256: hash(binary) };
        manifest.files['tor/tor'] = manifest.tor.binary_sha256;
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o644 });
        fs.chmodSync(manifestPath, 0o644);
        const packed = path.join(temporary, `${architecture}.tar.gz`);
        execFileSync('tar', ['--sort=name', '--mtime=@0', '--owner=0', '--group=0', '--numeric-owner', '-czf', packed, '-C', directory, 'qorc-edge'], { stdio: 'inherit' });
        results.push({ architecture, packed, archivePath, sha256: hash(fs.readFileSync(packed)), binarySha256: manifest.tor.binary_sha256 });
    }
    for (const result of results) {
        const staged = `${result.archivePath}.${crypto.randomBytes(8).toString('hex')}.tmp`;
        fs.copyFileSync(result.packed, staged, fs.constants.COPYFILE_EXCL);
        result.staged = staged;
        fs.chmodSync(staged, 0o644);
    }
    for (const result of results) {
        fs.renameSync(result.staged, result.archivePath);
        result.staged = null;
        process.stdout.write(JSON.stringify({ architecture: result.architecture, archive: path.relative(repo, result.archivePath), sha256: result.sha256, binarySha256: result.binarySha256 }) + '\n');
    }
} finally {
    for (const result of results) {
        if (result.staged) fs.rmSync(result.staged, { force: true });
    }
    fs.rmSync(temporary, { recursive: true, force: true });
}
