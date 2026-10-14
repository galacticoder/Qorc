import { spawn, execFileSync } from 'child_process';
import fs from 'fs/promises';
import { constants, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
    TOR_BOOTSTRAP_TIMEOUT_MS,
    TOR_PUBLICATION_TIMEOUT_MS,
    TOR_PROCESS_STOP_TIMEOUT_MS,
    TOR_HEALTH_CHECK_INTERVAL_MS,
    TOR_HEALTH_CHECK_TIMEOUT_MS,
    TOR_HEALTH_LEASE_MS,
} from '../config/infrastructure.js';
import { probeOnionHttps } from './onion-health.js';
import {
    processMatchesExecutable,
    readProcessIdFileSnapshot,
    removeUnchangedProcessIdFile,
} from '../utils/process-identity.js';

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
        this.proxyPath = path.join(this.dataDir, 'health-proxy.sock');
        this.torProcess = null;
        this._onionAddress = null;
        this.lastCheck = 0;
        this.checkInterval = 5000;
        this.isRunningState = false;
        this.isPublishedState = false;
        this.isBootstrappedState = false;
        this.publicationState = { offset: null, current: false, next: false };
        this.startupLogOffset = 0;
        this.startupHsLogOffset = 0;
        this.startedAt = 0;
        this.startPromise = null;
        this.stopPromise = null;
        this.startController = null;
        this.isStopping = false;
        this.healthProbePromise = null;
        this.healthController = null;
        this.healthGeneration = 0;
        this.lastHealthCheckAt = 0;
        this.lastReachableAt = 0;
        this.unreachableSince = 0;
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

        env.LD_LIBRARY_PATH = BUNDLED_LIBRARY_DIR;

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
        if (this.publicationState.offset !== startOffset) {
            this.publicationState = { offset: startOffset, current: false, next: false };
        }
        this.publicationState.current ||= await this.logContainsSince(
            this.hsLogPath, startOffset, 'QORC_HS_DESC_READY current'
        );
        this.publicationState.next ||= await this.logContainsSince(
            this.hsLogPath, startOffset, 'QORC_HS_DESC_READY next'
        );
        return this.publicationState.current && this.publicationState.next;
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
            throw new Error(`Bundled Tor executable is unavailable: ${error.message}`);
        }
    }

    async isRunning() {
        try {
            if (this.torProcess && this.torProcess.exitCode === null &&
                this.torProcess.signalCode === null &&
                await processMatchesExecutable(this.torProcess.pid, this.getTorBinaryPath())) {
                return true;
            }
            const snapshot = await readProcessIdFileSnapshot(this.pidPath);
            return Boolean(snapshot?.pid && await processMatchesExecutable(snapshot.pid, this.getTorBinaryPath()));
        } catch { }
        return false;
    }

    isPublished() {
        return this.isPublishedState && Date.now() - this.lastReachableAt < TOR_HEALTH_LEASE_MS;
    }

    probeReachability(onionAddress, signal) {
        const certificatePath = process.env.TLS_CERT_PATH;
        if (typeof certificatePath !== 'string' || certificatePath.length === 0) {
            return Promise.reject(new Error('TLS_CERT_PATH is required for onion health verification'));
        }
        return probeOnionHttps({
            proxyPath: this.proxyPath,
            onionAddress,
            certificatePath: path.resolve(__dirname, '..', '..', certificatePath),
            timeoutMs: TOR_HEALTH_CHECK_TIMEOUT_MS,
            signal,
        });
    }

    checkReachability(onionAddress) {
        if (this.healthProbePromise || this.isStopping) return;
        const generation = this.healthGeneration;
        this.lastHealthCheckAt = Date.now();
        this.healthController = new AbortController();
        this.healthProbePromise = this.probeReachability(onionAddress, this.healthController.signal)
            .catch(error => {
                if (generation === this.healthGeneration && !this.isStopping) {
                    console.warn('[TOR-HEALTH] Reachability verification failed', {
                        errorCode: error.code || error.name,
                        elapsedMs: Date.now() - this.lastHealthCheckAt,
                    });
                }
                return false;
            })
            .then(reachable => {
                if (generation !== this.healthGeneration || this.isStopping) return;
                if (reachable !== this.isPublishedState) {
                    console.info('[TOR-HEALTH] Verified readiness changed', { reachable });
                }
                this.isPublishedState = reachable;
                if (reachable) {
                    this.lastReachableAt = Date.now();
                    this.unreachableSince = 0;
                } else {
                    this.unreachableSince ||= Date.now();
                }
            })
            .finally(() => {
                if (generation === this.healthGeneration) this.healthProbePromise = null;
            });
    }

    resetReachability() {
        this.healthGeneration++;
        this.healthController?.abort();
        this.healthController = null;
        this.healthProbePromise = null;
        this.lastHealthCheckAt = 0;
        this.lastReachableAt = 0;
        this.unreachableSince = 0;
        this.isPublishedState = false;
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
            `Log notice file ${this.logPath}`,
            `Log [rend]info file ${this.hsLogPath}`,
            `HiddenServiceDir ${this.hiddenServiceDir}`,
            `HiddenServicePort 443 127.0.0.1:${listenPort}`,
            `HiddenServiceNumIntroductionPoints ${HIDDEN_SERVICE_INTRO_POINTS}`,
            `SocksPort unix:${this.proxyPath} IsolateSOCKSAuth`,
            `SafeSocks 1`,
            `RunAsDaemon 0`,
        ].join('\n');

        await fs.writeFile(this.torrcPath, torrcContent, { mode: 0o600 });
    }

    start(listenPort) {
        if (this.isStopping) return Promise.resolve(false);
        if (this.startPromise) return this.startPromise;
        this.startController = new AbortController();
        this.startPromise = this.launch(listenPort, this.startController.signal).finally(() => {
            this.startPromise = null;
        });
        return this.startPromise;
    }

    async launch(listenPort, signal) {
        await this.validateConfig(listenPort);
        if (signal.aborted) return false;
        const torBin = await this.getTorBinary();
        await this.stopProcess();
        if (signal.aborted) return false;

        console.log('[TOR] Starting Tor Hidden Service...');
        this.isPublishedState = false;
        this.resetReachability();
        this.isBootstrappedState = false;
        this.publicationState = { offset: null, current: false, next: false };
        this._onionAddress = null;

        try {
            this.startupLogOffset = await this.getTorLogSize();
            this.startupHsLogOffset = await this.getHsLogSize();
            const logStream = await fs.open(this.logPath, 'a');
            try {
                if (signal.aborted) return false;
                this.torProcess = spawn(torBin, ['-f', this.torrcPath], {
                    detached: true,
                    stdio: ['ignore', logStream.fd, logStream.fd],
                    env: this.getTorEnvironment(),
                    signal,
                });
                const child = this.torProcess;
                child.on('exit', () => {
                    if (this.torProcess !== child) return;
                    this.isRunningState = false;
                    this.resetReachability();
                });
                await new Promise((resolve, reject) => {
                    child.once('spawn', resolve);
                    child.on('error', (error) => {
                        if (this.torProcess === child) {
                            this.isRunningState = false;
                            this.resetReachability();
                        }
                        reject(error);
                    });
                });
                child.unref();
                const pidFile = await fs.open(this.pidPath,
                    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
                    0o600);
                let pidStat;
                try {
                    pidStat = await pidFile.stat();
                    await pidFile.writeFile(`${child.pid}\n`, { encoding: 'utf8' });
                    await pidFile.sync();
                } catch (error) {
                    if (pidStat) await removeUnchangedProcessIdFile(this.pidPath, { device: pidStat.dev, inode: pidStat.ino });
                    throw error;
                } finally {
                    await pidFile.close();
                }
            } finally {
                await logStream.close();
            }
            if (signal.aborted) return false;
            if (this.torProcess.exitCode !== null || this.torProcess.signalCode !== null) {
                throw new Error(`Tor exited during startup (${this.torProcess.exitCode ?? this.torProcess.signalCode})`);
            }
            this.isRunningState = true;
            this.startedAt = Date.now();
            this.lastCheck = 0;
            console.log('[TOR] Waiting for bootstrap and confirmed descriptor publication...');
            return true;
        } catch (err) {
            if (signal.aborted) return false;
            console.error('[TOR] Failed to start Tor:', err.message);
            throw err;
        }
    }

    stop() {
        if (this.stopPromise) return this.stopPromise;
        this.isStopping = true;
        this.isPublishedState = false;
        this.startController?.abort();
        this.stopPromise = (async () => {
            await this.startPromise?.catch(() => {});
            await this.stopProcess();
            this.isRunningState = false;
            this.isBootstrappedState = false;
        })();
        return this.stopPromise;
    }

    async stopProcess() {
        this.resetReachability();
        try {
            const child = this.torProcess;
            if (child && !child.killed && child.exitCode === null && child.signalCode === null) {
                child.kill('SIGTERM');
            }
            const snapshot = await readProcessIdFileSnapshot(this.pidPath);
            const ownsSnapshot = !child || snapshot?.pid === child.pid;
            if (snapshot) {
                const { pid } = snapshot;
                if (ownsSnapshot && pid && await processMatchesExecutable(pid, this.getTorBinaryPath())) {
                    console.log(`[TOR] Stopping Tor (PID: ${pid})...`);
                    if (pid !== child?.pid || !child.killed) {
                        try { process.kill(pid, 'SIGTERM'); } catch (error) {
                            if (error.code !== 'ESRCH') throw error;
                        }
                    }
                } else {
                    console.warn('[TOR] Refusing to signal a PID not owned by bundled Tor');
                }
            }
            const ownedPids = new Set([ownsSnapshot ? snapshot?.pid : null, child?.pid].filter(pid => Number.isSafeInteger(pid) && pid > 0));
            const deadline = Date.now() + TOR_PROCESS_STOP_TIMEOUT_MS;
            for (const pid of ownedPids) {
                while (await processMatchesExecutable(pid, this.getTorBinaryPath())) {
                    if (Date.now() >= deadline) throw new Error('Tor did not stop before its shutdown deadline');
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
            }
            if (snapshot && ownsSnapshot) {
                if (!await removeUnchangedProcessIdFile(this.pidPath, snapshot)) {
                    throw new Error('Tor PID file changed while stopping');
                }
            }
            this.isRunningState = false;
            this.isPublishedState = false;
            this.torProcess = null;
        } catch (err) {
            console.error('[TOR] Error stopping Tor:', err.message);
            throw err;
        }
    }

    async monitor(listenPort) {
        if (this.isStopping) return;
        const now = Date.now();
        if (now - this.lastCheck < this.checkInterval) return;
        this.lastCheck = now;

        const stillRunning = await this.isRunning();
        if (this.isStopping) return;
        if (!stillRunning || this.startedAt === 0) {
            if (this.startedAt > 0) console.log('[TOR] Tor service died unexpectedly, restarting...');
            this.isPublishedState = false;
            await this.start(listenPort);
            return;
        }

        this.isBootstrappedState ||= await this.hasBootstrappedSince(this.startupLogOffset);
        const published = await this.hasPublishedDescriptorsSince(this.startupHsLogOffset);
        const addr = await this.getOnionAddress();
        if (this.isStopping) return;
        if (addr && this.isBootstrappedState && published) {
            if (this.lastHealthCheckAt === 0 || now - this.lastHealthCheckAt >= TOR_HEALTH_CHECK_INTERVAL_MS) {
                this.checkReachability(addr);
            }
            if (this.isPublished()) return;
        }
        if (this.lastReachableAt > 0) {
            if (this.unreachableSince > 0 && now - this.unreachableSince >= TOR_PUBLICATION_TIMEOUT_MS) {
                await this.start(listenPort);
            }
            return;
        }
        const timeout = this.isBootstrappedState ? TOR_PUBLICATION_TIMEOUT_MS : TOR_BOOTSTRAP_TIMEOUT_MS;
        if (Date.now() - this.startedAt >= timeout) await this.start(listenPort);
    }
}
