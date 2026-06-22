import { spawn, execSync } from 'child_process';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { extract } from 'tar';
import { findInPath, sleep } from './lb-utils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class TorManager {
    constructor(scriptsDir) {
        this.scriptsDir = scriptsDir;
        this.dataDir = path.resolve(__dirname, '..', 'config', 'tor');
        this.hiddenServiceDir = path.join(this.dataDir, 'hidden_service');
        this.torBundleDir = path.join(this.dataDir, 'bundle');
        this.torrcPath = path.join(this.dataDir, 'torrc');
        this.pidPath = path.join(this.dataDir, 'tor.pid');
        this.logPath = path.join(this.dataDir, 'tor.log');
        this.torProcess = null;
        this._onionAddress = null;
        this.lastCheck = 0;
        this.checkInterval = 5000;
        this.isRunningState = false;
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

    async getTorBinary() {
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
            `HiddenServiceDir ${this.hiddenServiceDir}`,
            `HiddenServicePort 443 127.0.0.1:${listenPort}`,
            `SocksPort 0`,
            `RunAsDaemon 0`,
        ].join('\n');

        await fs.writeFile(this.torrcPath, torrcContent, { mode: 0o600 });
    }

    async start(listenPort) {
        if (await this.isRunning()) {
            console.log('[TOR] Tor is already running.');
            this.isRunningState = true;
            return true;
        }

        console.log('[TOR] Starting Tor Hidden Service...');
        await this.ensureConfig(listenPort);

        const torBin = await this.getTorBinary();
        if (!torBin) {
            console.error('[TOR] tor binary not found and download failed.');
            return false;
        }

        try {
            const logStream = await fs.open(this.logPath, 'a');
            this.torProcess = spawn(torBin, ['-f', this.torrcPath], {
                detached: true,
                stdio: ['ignore', logStream.fd, logStream.fd]
            });
            this.torProcess.unref();
            await logStream.close();

            // Wait for hostname to be generated
            console.log('[TOR] Waiting for .onion address generation...');
            for (let i = 0; i < 60; i++) {
                const addr = await this.getOnionAddress();
                if (addr) {
                    console.log(`[TOR] Onion URL: https://${addr}`);
                    this.isRunningState = true;
                    return true;
                }
                await sleep(1000);
            }

            console.error('[TOR] Timed out waiting for .onion address.');
            return false;
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
