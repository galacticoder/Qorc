import { spawn, execSync } from 'child_process';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { extract } from 'tar';
import { findInPath } from './lb-utils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const HIDDEN_SERVICE_INTRO_POINTS = (() => {
    const parsed = Number.parseInt(process.env.TOR_HS_INTRO_POINTS || '', 10);
    return Number.isInteger(parsed) && parsed >= 3 && parsed <= 20 ? parsed : 3;
})();

export class TorManager {
    constructor(scriptsDir) {
        this.scriptsDir = scriptsDir;
        this.dataDir = path.resolve(__dirname, '..', 'config', 'tor');
        this.hiddenServiceDir = path.join(this.dataDir, 'hidden_service');
        this.torBundleDir = path.join(this.dataDir, 'bundle');
        this.torrcPath = path.join(this.dataDir, 'torrc');
        this.pidPath = path.join(this.dataDir, 'tor.pid');
        this.logPath = path.join(this.dataDir, 'tor.log');
        this.hsLogPath = path.join(this.dataDir, 'tor-hs.log');
        this.torProcess = null;
        this._onionAddress = null;
        this.lastCheck = 0;
        this.checkInterval = 5000;
        this.isRunningState = false;
        this.isPublishedState = false;
        this.platform = process.platform;
        this.arch = process.arch;
    }

    async getOnionAddress() {
        if (this._onionAddress) return this._onionAddress;
        try {
            const hostnameFile = path.join(this.hiddenServiceDir, 'hostname');
            if (existsSync(hostnameFile)) {
                const content = await fs.readFile(hostnameFile, 'utf8');
                this._onionAddress = content.trim();
                return this._onionAddress;
            }
        } catch { }
        return null;
    }

    getTorBinaryPath() {
        return path.join(this.torBundleDir, 'tor');
    }

    getTorEnvironment(torBin) {
        const env = { ...process.env };

        delete env.OPENSSL_CONF;
        delete env.OPENSSL_MODULES;
        delete env.OQS_PROVIDER_MODULE;

        if (path.resolve(torBin) !== path.resolve(this.getTorBinaryPath())) {
            return env;
        }

        const bundledLibraryDirs = [
            this.torBundleDir,
            path.join(this.torBundleDir, 'lib64'),
            path.join(this.torBundleDir, 'lib')
        ].filter((directory) => existsSync(directory));
        const inheritedLibraryDirs = (process.env.LD_LIBRARY_PATH || '')
            .split(path.delimiter)
            .filter(Boolean);
        env.LD_LIBRARY_PATH = [...new Set([
            ...bundledLibraryDirs,
            ...inheritedLibraryDirs
        ])].join(path.delimiter);

        if (this.platform === 'darwin') {
            const inheritedDyldDirs = (process.env.DYLD_LIBRARY_PATH || '')
                .split(path.delimiter)
                .filter(Boolean);
            env.DYLD_LIBRARY_PATH = [...new Set([
                ...bundledLibraryDirs,
                ...inheritedDyldDirs
            ])].join(path.delimiter);
        }
        return env;
    }

    async getTorLogSize() {
        return this.getLogSize(this.logPath);
    }

    async getHsLogSize() {
        return this.getLogSize(this.hsLogPath);
    }

    async getLogSize(logPath) {
        try {
            return (await fs.stat(logPath)).size;
        } catch {
            return 0;
        }
    }

    async hasBootstrappedSince(startOffset) {
        return this.logContainsSince(
            this.logPath,
            startOffset,
            'Bootstrapped 100% (done): Done'
        );
    }

    async hasPublishedDescriptorsSince(startOffset) {
        const currentPublished = await this.logContainsSince(
            this.hsLogPath,
            startOffset,
            'QOR_HS_DESC_PUBLISHED current'
        );
        if (!currentPublished) return false;
        return this.logContainsSince(
            this.hsLogPath,
            startOffset,
            'QOR_HS_DESC_PUBLISHED next'
        );
    }

    async logContainsSince(logPath, startOffset, marker) {
        let logFile;
        try {
            logFile = await fs.open(logPath, 'r');
            const { size } = await logFile.stat();
            const normalizedOffset = size >= startOffset ? startOffset : 0;
            if (size <= normalizedOffset) return false;
            const maxReadBytes = 256 * 1024;
            const readOffset = Math.max(normalizedOffset, size - maxReadBytes);
            const buffer = Buffer.allocUnsafe(size - readOffset);
            const { bytesRead } = await logFile.read(buffer, 0, buffer.length, readOffset);
            return buffer.subarray(0, bytesRead)
                .includes(Buffer.from(marker));
        } catch {
            return false;
        } finally {
            await logFile?.close().catch(() => {});
        }
    }

    async getTorBinary() {
        const configuredTor = process.env.LB_TOR_BIN?.trim();
        if (configuredTor) {
            try {
                await fs.access(configuredTor, fs.constants.X_OK);
                return configuredTor;
            } catch {
                console.error(`[TOR] Configured LB_TOR_BIN is not executable: ${configuredTor}`);
                return null;
            }
        }

        // Check for latest bundled tor version
        const bundledTor = this.getTorBinaryPath();
        if (existsSync(bundledTor)) {
            try {
                await fs.access(bundledTor, fs.constants.X_OK);
                return bundledTor;
            } catch {
                console.log('[TOR] Bundled tor is invalid, removing...');
                await fs.rm(this.torBundleDir, { recursive: true, force: true }).catch(() => {});
            }
        }

        // Try to download latest version
        console.log('[TOR] Downloading latest Tor bundle...');
        const downloaded = await this.downloadTor();
        if (downloaded && existsSync(bundledTor)) {
            return bundledTor;
        }

        // Fall back to system tor
        const systemTor = findInPath('tor');
        if (systemTor) {
            console.warn('[TOR] Using system tor (download failed, may be outdated)');
            return systemTor;
        }

        return null;
    }

    async fetchLatestVersion() {
        try {
            const response = await fetch('https://dist.torproject.org/torbrowser/');
            const html = await response.text();
            
            const versionRegex = /href="(\d+\.\d+\.\d+)\/"/g;
            const versions = [];
            let match;
            
            while ((match = versionRegex.exec(html)) !== null) {
                versions.push(match[1]);
            }
            
            versions.sort((a, b) => {
                const aParts = a.split('.').map(Number);
                const bParts = b.split('.').map(Number);
                for (let i = 0; i < 3; i++) {
                    if (aParts[i] !== bParts[i]) {
                        return bParts[i] - aParts[i];
                    }
                }
                return 0;
            });
            
            return versions[0] || '15.0.3';
        } catch (err) {
            console.warn('[TOR] Failed to fetch latest version:', err.message);
            return '15.0.3';
        }
    }

    async getDownloadUrl() {
        const arch = this.arch === 'arm64' ? 'linux-aarch64' : 'linux-x86_64';
        const version = await this.fetchLatestVersion();
        
        return `https://dist.torproject.org/torbrowser/${version}/tor-expert-bundle-${arch}-${version}.tar.gz`;
    }

    async downloadTor() {
        try {
            const url = await this.getDownloadUrl();
            const filename = path.basename(url);
            const archivePath = path.join(this.dataDir, filename);

            console.log(`[TOR] Downloading from ${url}...`);

            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            await fs.mkdir(this.dataDir, { recursive: true });
            const fileStream = createWriteStream(archivePath);
            await pipeline(response.body, fileStream);

            console.log('[TOR] Extracting...');

            await fs.mkdir(this.torBundleDir, { recursive: true });
            await extract({
                file: archivePath,
                cwd: this.torBundleDir,
                strip: 1,
                filter: (path) => {
                    const allowed = ['tor', 'lib', 'lib64', 'obfs4proxy', 
                                   'snowflake-client', 'lyrebird', 'geoip', 'geoip6', 
                                   'pluggable_transports'];
                    return allowed.some(a => path.includes(a));
                }
            });

            const torBin = this.getTorBinaryPath();
            await fs.chmod(torBin, 0o755);
            await fs.unlink(archivePath).catch(() => {});

            console.log('[TOR] Tor bundle installed');
            return true;
        } catch (err) {
            console.error('[TOR] Download failed:', err.message);
            return false;
        }
    }

    async isRunning() {
        try {
            if (existsSync(this.pidPath)) {
                const pid = parseInt(await fs.readFile(this.pidPath, 'utf8'), 10);
                try {
                    process.kill(pid, 0);
                    if (process.platform === 'linux') {
                        try {
                            const comm = await fs.readFile(`/proc/${pid}/comm`, 'utf8');
                            if (!comm.trim().includes('tor')) {
                                return false;
                            }
                        } catch {
                        }
                    }
                    return true;
                } catch {
                    return false;
                }
            }
        } catch { }
        return false;
    }

    isPublished() {
        return this.isPublishedState;
    }

    async ensureConfig(listenPort) {
        await fs.mkdir(this.dataDir, { recursive: true, mode: 0o700 });
        await fs.mkdir(this.hiddenServiceDir, { recursive: true, mode: 0o700 });

        if (typeof process.getuid === 'function') {
            try {
                execSync(`chown -R ${process.getuid()}:${process.getgid()} "${this.dataDir}"`);
            } catch (err) {
                console.warn('[TOR] Failed to chown tor directories:', err.message);
            }
        }

        const torrcContent = [
            `DataDirectory ${this.dataDir}`,
            `PidFile ${this.pidPath}`,
            `Log notice file ${this.logPath}`,
            `Log [rend]info file ${this.hsLogPath}`,
            `HiddenServiceDir ${this.hiddenServiceDir}`,
            `HiddenServicePort 443 127.0.0.1:${listenPort}`,
            `HiddenServiceNumIntroductionPoints ${HIDDEN_SERVICE_INTRO_POINTS}`,
            `SocksPort 0`,
            `RunAsDaemon 0`,
        ].join('\n');

        await fs.writeFile(this.torrcPath, torrcContent, { mode: 0o600 });
    }

    async start(listenPort) {
        await this.ensureConfig(listenPort);

        if (await this.isRunning()) {
            console.log('[TOR] Tor is already running.');
            this.isRunningState = true;
            return true;
        }

        console.log('[TOR] Starting Tor Hidden Service...');
        this.isPublishedState = false;

        const torBin = await this.getTorBinary();
        if (!torBin) {
            console.error('[TOR] tor binary not found and download failed.');
            return false;
        }

        try {
            const startupLogOffset = await this.getTorLogSize();
            const startupHsLogOffset = await this.getHsLogSize();
            const logStream = await fs.open(this.logPath, 'a');
            this.torProcess = spawn(torBin, ['-f', this.torrcPath], {
                detached: true,
                stdio: ['ignore', logStream.fd, logStream.fd],
                env: this.getTorEnvironment(torBin)
            });
            this.torProcess.unref();
            await logStream.close();

            console.log('[TOR] Waiting for bootstrap and confirmed descriptor publication...');
            for (let i = 0; ; i++) {
                if (this.torProcess.exitCode !== null) {
                    console.error(`[TOR] Tor exited during startup (${this.torProcess.exitCode}).`);
                    return false;
                }
                const addr = await this.getOnionAddress();
                const bootstrapped = await this.hasBootstrappedSince(startupLogOffset);
                const published = await this.hasPublishedDescriptorsSince(startupHsLogOffset);
                if (addr && bootstrapped && published) {
                    console.log(`[TOR] Onion URL: https://${addr}`);
                    console.log('[TOR] Hidden-service descriptor accepted by an HSDir.');
                    this.isRunningState = true;
                    this.isPublishedState = true;
                    return true;
                }
                if (i > 0 && i % 300 === 0) {
                    console.warn('[TOR] Descriptor publication is still pending');
                }
                await new Promise((resolve) => setTimeout(resolve, 1000));
            }
        } catch (err) {
            console.error('[TOR] Failed to start Tor:', err.message);
            return false;
        }
    }

    async stop() {
        try {
            if (existsSync(this.pidPath)) {
                const pid = parseInt(await fs.readFile(this.pidPath, 'utf8'), 10);
                console.log(`[TOR] Stopping Tor (PID: ${pid})...`);
                try { process.kill(pid, 'SIGTERM'); } catch { }
                await fs.unlink(this.pidPath).catch(() => { });
            }
            this.isRunningState = false;
            this.isPublishedState = false;
        } catch (err) {
            console.error('[TOR] Error stopping Tor:', err.message);
        }
    }

    async monitor(listenPort) {
        const now = Date.now();
        if (now - this.lastCheck < this.checkInterval) return;
        this.lastCheck = now;

        const stillRunning = await this.isRunning();
        if (!stillRunning && this.isRunningState) {
            console.log('[TOR] Tor service died unexpectedly, restarting...');
            await this.start(listenPort);
        }
    }
}
