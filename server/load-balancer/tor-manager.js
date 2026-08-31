import { spawn, execFileSync } from 'child_process';
import fs from 'fs/promises';
import { constants, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EDGE_RUNTIME_ROOT = '/opt/qorc-edge';
const BUNDLED_TOR_DIR = path.join(EDGE_RUNTIME_ROOT, 'tor');
const BUNDLED_LIBRARY_DIR = path.join(EDGE_RUNTIME_ROOT, 'lib');

const HIDDEN_SERVICE_INTRO_POINTS = (() => {
    const parsed = Number.parseInt(process.env.TOR_HS_INTRO_POINTS || '', 10);
    return Number.isInteger(parsed) && parsed >= 3 && parsed <= 20 ? parsed : 3;
})();

export class TorManager {
    constructor() {
        this.dataDir = path.resolve(__dirname, '..', 'config', 'tor');
        this.hiddenServiceDir = path.join(this.dataDir, 'hidden_service');
        this.torBundleDir = BUNDLED_TOR_DIR;
        this.torExecutableName = 'tor';
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
    }

    async getOnionAddress() {
        if (this._onionAddress) return this._onionAddress;
        try {
            const hostnameFile = path.join(this.hiddenServiceDir, 'hostname');
            if (existsSync(hostnameFile)) {
                const content = await fs.readFile(hostnameFile, 'utf8');
                const hostname = content.trim().toLowerCase();
                if (!/^[a-z2-7]{56}\.onion$/.test(hostname)) return null;
                this._onionAddress = hostname;
                return this._onionAddress;
            }
        } catch { }
        return null;
    }

    getTorBinaryPath() {
        return path.join(this.torBundleDir, this.torExecutableName);
    }

    getTorEnvironment() {
        const env = { ...process.env };

        delete env.OPENSSL_CONF;
        delete env.OPENSSL_MODULES;
        delete env.OQS_PROVIDER_MODULE;
        delete env.LD_PRELOAD;

        const bundledLibraryDirs = [
            BUNDLED_LIBRARY_DIR,
            this.torBundleDir,
            path.join(this.torBundleDir, 'lib64'),
            path.join(this.torBundleDir, 'lib')
        ].filter((directory) => existsSync(directory));
        env.LD_LIBRARY_PATH = [...new Set(bundledLibraryDirs)].join(path.delimiter);

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
            'QORC_HS_DESC_READY current'
        );
        if (!currentPublished) return false;
        return this.logContainsSince(
            this.hsLogPath,
            startOffset,
            'QORC_HS_DESC_READY next'
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
        const bundledTor = this.getTorBinaryPath();
        try {
            const stat = await fs.stat(bundledTor);
            if (!stat.isFile()) throw new Error('not a regular file');
            await fs.access(bundledTor, constants.X_OK);
            return bundledTor;
        } catch (error) {
            console.error('[TOR] Bundled Tor executable is unavailable:', error.message);
            return null;
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
                            const [runningExecutable, bundledExecutable] = await Promise.all([
                                fs.readlink(`/proc/${pid}/exe`),
                                fs.realpath(this.getTorBinaryPath())
                            ]);
                            if (path.resolve(runningExecutable) !== path.resolve(bundledExecutable)) return false;
                        } catch {
                            return false;
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

    async validateConfig(listenPort) {
        await fs.mkdir(this.dataDir, { recursive: true, mode: 0o700 });
        await fs.mkdir(this.hiddenServiceDir, { recursive: true, mode: 0o700 });

        if (typeof process.getuid === 'function') {
            try {
                execFileSync('chown', [
                    '-R',
                    `${process.getuid()}:${process.getgid()}`,
                    this.dataDir
                ], { stdio: 'ignore' });
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
        await this.validateConfig(listenPort);

        if (await this.isRunning()) {
            console.log('[TOR] Tor is already running.');
            this.isRunningState = true;
            return true;
        }

        console.log('[TOR] Starting Tor Hidden Service...');
        this.isPublishedState = false;

        const torBin = await this.getTorBinary();
        if (!torBin) {
            console.error('[TOR] The bundled Tor runtime is missing or invalid.');
            return false;
        }

        try {
            const startupLogOffset = await this.getTorLogSize();
            const startupHsLogOffset = await this.getHsLogSize();
            const logStream = await fs.open(this.logPath, 'a');
            this.torProcess = spawn(torBin, ['-f', this.torrcPath], {
                detached: true,
                stdio: ['ignore', logStream.fd, logStream.fd],
                env: this.getTorEnvironment()
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
