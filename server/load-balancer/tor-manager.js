import { spawn } from 'child_process';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { findInPath, sleep } from './lb-utils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class TorManager {
    constructor(scriptsDir) {
        this.scriptsDir = scriptsDir;
        this.dataDir = path.resolve(__dirname, '..', 'config', 'tor');
        this.hiddenServiceDir = path.join(this.dataDir, 'hidden_service');
        this.torrcPath = path.join(this.dataDir, 'torrc');
        this.pidPath = path.join(this.dataDir, 'tor.pid');
        this.logPath = path.join(this.dataDir, 'tor.log');
        this.torProcess = null;
        this._onionAddress = null;
        this.lastCheck = 0;
        this.checkInterval = 5000;
        this.isRunningState = false;
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

    async isRunning() {
        try {
            if (existsSync(this.pidPath)) {
                const pid = parseInt(await fs.readFile(this.pidPath, 'utf8'), 10);
                try {
                    process.kill(pid, 0);
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

        const torrcContent = [
            `DataDirectory ${this.dataDir}`,
            `PidFile ${this.pidPath}`,
            `Log notice file ${this.logPath}`,
            `HiddenServiceDir ${this.hiddenServiceDir}`,
            `HiddenServicePort 443 127.0.0.1:${listenPort}`,
            `HiddenServicePort 80 127.0.0.1:${listenPort}`,
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

        const torBin = findInPath('tor');
        if (!torBin) {
            console.error('[TOR] tor binary not found. Please install tor.');
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
                    console.log(`[TOR] Onion URL: http://${addr}`);
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
