import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { findInPath, sleep, execFileAsync } from './lb-utils.js';
import { spawn } from 'child_process';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const DEFAULT_HTTPS_PORT = parseInt(process.env.HAPROXY_HTTPS_PORT || '8443', 10);

export class TunnelManager {
    constructor(scriptsDir) {
        this.scriptsDir = scriptsDir;
        this.lastCheck = 0;
        this.checkInterval = 1000;
        this.lastRestart = 0;
        this.restartFailures = 0;
        this.maxRestartFailures = 5;
        this.backoffMs = 10000;
        this.disabled = false;
    }

    static async deleteCloudflaredTunnels() {
        try {
            const pidPath = path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'config', 'tunnel', 'pid'));
            if (existsSync(pidPath)) {
                const pid = parseInt(await fs.readFile(pidPath, 'utf8'), 10);
                try { process.kill(pid, 'SIGTERM'); } catch { }
                await fs.unlink(pidPath).catch(() => { });
            }
        } catch { }

        if (process.platform !== 'win32') {
            try {
                await execFileAsync('pkill', ['cloudflared']);
            } catch { }
        }
    }

    // Check if cloudflared tunnel is running
    async isRunning() {
        try {
            const pidPath = path.join(this.scriptsDir, 'config', 'tunnel', 'pid');

            if (existsSync(pidPath)) {
                const pidContent = await fs.readFile(pidPath, 'utf8');
                const pid = parseInt(pidContent, 10);

                try {
                    process.kill(pid, 0);
                    return true;
                } catch {
                    return false;
                }
            }

            return false;
        } catch {
            return false;
        }
    }

    // Get tunnel URL from cloudflared log
    async getTunnelUrl() {
        try {
            const logPath = path.join(this.scriptsDir, 'config', 'tunnel', 'cloudflared.log');
            if (!existsSync(logPath)) return null;

            const content = await fs.readFile(logPath, 'utf8');
            const lines = content.split('\n');
            for (let i = lines.length - 1; i >= 0; i--) {
                const match = lines[i].match(/https?:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com(?:\/)?/);
                if (match) {
                    return match[0].replace(/\/$/, '');
                }
            }
            return null;
        } catch (_err) {
            return null;
        }
    }

    // Restart cloudflared tunnel
    async restart(listenPort) {
        try {
            console.log('\n[TUNNEL] Restarting tunnel...');

            const pidPath = path.join(this.scriptsDir, 'config', 'tunnel', 'pid');
            if (existsSync(pidPath)) {
                try {
                    const pid = parseInt(await fs.readFile(pidPath, 'utf8'), 10);
                    process.kill(pid, 'SIGTERM');
                } catch { }
                await fs.unlink(pidPath).catch(() => { });
            }

            const logPath = path.join(this.scriptsDir, 'config', 'tunnel', 'cloudflared.log');
            const port = listenPort || DEFAULT_HTTPS_PORT;

            await fs.mkdir(path.dirname(logPath), { recursive: true, mode: 0o700 });
            await fs.mkdir(path.dirname(pidPath), { recursive: true, mode: 0o700 });

            const cloudflaredBin = findInPath('cloudflared');
            if (!cloudflaredBin) {
                console.error('[TUNNEL] cloudflared not found');
                return false;
            }

            try {
                await fs.writeFile(logPath, '', { mode: 0o600 });
            } catch {
            }

            const args = ['tunnel', '--url', `https://127.0.0.1:${port}`, '--no-tls-verify'];

            let logFile;
            try {
                logFile = await fs.open(logPath, 'a', 0o600);
            } catch {
                logFile = null;
            }

            const child = spawn(cloudflaredBin, args, {
                detached: true,
                stdio: ['ignore', logFile ? logFile.fd : 'ignore', logFile ? logFile.fd : 'ignore'],
                env: { ...process.env }
            });
            child.unref();
            if (logFile) {
                try { await logFile.close(); } catch { }
            }
            await fs.writeFile(pidPath, String(child.pid), { mode: 0o600 });

            console.log('[TUNNEL] Waiting for tunnel URL to appear in log...');
            let tunnelUrl = null;
            for (let i = 0; i < 40 && !tunnelUrl; i += 1) {
                await sleep(1000);
                tunnelUrl = await this.getTunnelUrl();
                try {
                    process.kill(child.pid, 0);
                } catch {
                    break;
                }
                if (i > 0 && i % 5 === 0 && !tunnelUrl) {
                    console.log(`[TUNNEL] Still waiting... (${i} seconds)`);
                }
            }

            if (tunnelUrl) {
                try { const u = new URL(tunnelUrl); tunnelUrl = `https://${u.hostname}`; } catch { }
                console.log(`[TUNNEL] Tunnel restarted: ${tunnelUrl}`);
                return true;
            }

            console.log('[TUNNEL] Tunnel started but no public URL was detected within 40 seconds');

            try {
                const content = await fs.readFile(logPath, 'utf8');
                const lines = content.split('\n').filter(Boolean);
                const tail = lines.slice(Math.max(0, lines.length - 30));
                if (tail.length > 0) {
                    console.log('[TUNNEL] cloudflared log tail:');
                    for (const line of tail) {
                        console.log(`  ${line.slice(0, 500)}`);
                    }
                }
            } catch {
            }
            return false;
        } catch (error) {
            cryptoLogger.error('[AUTO-LB] Failed to restart tunnel', error);
            console.error('[TUNNEL] Failed to restart:', error.message);
            return false;
        }
    }

    // Check and maintain tunnel
    async monitor(listenPort) {
        if (this.disabled) return;

        const now = Date.now();
        if (now - this.lastCheck > this.checkInterval) {
            this.lastCheck = now;

            const running = await this.isRunning();

            if (!running) {
                const sinceLastRestart = now - (this.lastRestart || 0);

                if (this.restartFailures >= this.maxRestartFailures) {
                    if (!this.disabled) {
                        console.error(`\n[TUNNEL] Disabling automatic tunnel restart after ${this.restartFailures} failed attempts.`);
                        console.error('[TUNNEL] Check cloudflared installation/config (CLOUDFLARED_TOKEN, connectivity) and restart the load balancer.');
                        this.disabled = true;
                    }
                } else if (sinceLastRestart >= this.backoffMs) {
                    console.log('\n[WARNING] Tunnel is not running, attempting restart...');
                    const ok = await this.restart(listenPort);
                    this.lastRestart = Date.now();

                    if (!ok) {
                        this.restartFailures += 1;
                        this.backoffMs = Math.min(this.backoffMs * 2, 5 * 60 * 1000);
                    } else {
                        this.restartFailures = 0;
                        this.backoffMs = 10000;
                    }
                }
            } else {
                this.restartFailures = 0;
                this.backoffMs = 10000;
            }
        }
    }
}
