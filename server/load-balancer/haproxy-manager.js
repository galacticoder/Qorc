
import { execFileAsync, findInPath } from './lb-utils.js';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import {
    HAPROXY_PID_FILE as HAPROXY_PID_FILENAME,
    IS_ROOT,
    TEMP_DIRECTORY,
    haproxyStatsDashboardUrl,
} from '../config/infrastructure.js';

const HAPROXY_CONFIG_PATH = process.env.HAPROXY_CONFIG_PATH ||
    path.join('/app/server/config', 'haproxy-auto.cfg');
const HAPROXY_PID_FILE = process.env.HAPROXY_PID_FILE ||
    (IS_ROOT && process.platform !== 'win32' ? `/var/run/${HAPROXY_PID_FILENAME}` : path.join(TEMP_DIRECTORY, HAPROXY_PID_FILENAME));

export class HAProxyManager {
    constructor() {
        this.haproxyPid = null;
        this.isRunning = false;
        this.consecutiveFailures = 0;
        this.maxConsecutiveFailures = 3;
        this.configPath = HAPROXY_CONFIG_PATH;
        this.pidFile = HAPROXY_PID_FILE;
        this.haproxyBin = process.env.LB_HAPROXY_BIN || process.env.HAPROXY_BIN || 'haproxy';
    }

    // Check if HAProxy is installed
    async isInstalled() {
        try {
            if (path.isAbsolute(this.haproxyBin)) {
                return existsSync(this.haproxyBin);
            }
            return !!findInPath(this.haproxyBin);
        } catch {
            return false;
        }
    }

    // Display HAProxy status
    async displayStatus(pid, activeServers = []) {
        console.log(`\n[OK] HAProxy Load Balancer Running`);
        console.log(`\tPID: ${pid}`);
        console.log(`\tActive Servers: ${activeServers.length}`);
        if (activeServers.length > 0) {
            activeServers.forEach(s => {
                console.log(`\t  - ${s.serverId} (${s.host}:${s.port})`);
            });
        }
        console.log(`\tStats Dashboard: ${haproxyStatsDashboardUrl()}`);
    }

    // Start HAProxy with generated configuration
    async start() {
        if (!await this.isInstalled()) {
            console.warn('[AUTO-LB] HAProxy not installed');
            console.log('[WARNING] HAProxy not installed. Install it first (e.g., run: node scripts/install-deps.cjs haproxy), then retry.');
            return false;
        }

        try {
            if (existsSync(this.pidFile)) {
                const pid = parseInt(await fs.readFile(this.pidFile, 'utf8'), 10);
                try {
                    process.kill(pid, 0);
                    this.haproxyPid = pid;
                    this.isRunning = true;
                    return true;
                } catch {
                    await fs.unlink(this.pidFile);
                }
            }

            // Start HAProxy
            const env = { ...process.env };
            if (process.platform !== 'win32' && process.env.LD_LIBRARY_PATH) {
                env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
            }
            let openssl_conf = '';
            if (process.platform !== 'win32' && process.env.OPENSSL_CONF) {
                try {
                    if (existsSync(process.env.OPENSSL_CONF)) openssl_conf = process.env.OPENSSL_CONF;
                } catch { }
            }
            if (openssl_conf) {
                env.OPENSSL_CONF = openssl_conf;
            }

            let oqs_module = '';
            if (process.platform !== 'win32' && process.env.OQS_PROVIDER_MODULE) {
                try {
                    if (existsSync(process.env.OQS_PROVIDER_MODULE)) oqs_module = process.env.OQS_PROVIDER_MODULE;
                } catch { }
            }
            if (oqs_module) {
                env.OQS_PROVIDER_MODULE = oqs_module;
            }

            // Clean up stale stats socket if present
            try {
                const uid = (typeof process.getuid === 'function') ? String(process.getuid()) : 'nouid';
                const statsSock = process.env.HAPROXY_STATS_SOCKET || path.join(TEMP_DIRECTORY, `haproxy-admin-${uid}.sock`);
                if (existsSync(statsSock)) { await fs.unlink(statsSock).catch(() => { }); }
            } catch { }

            await execFileAsync(this.haproxyBin, ['-f', this.configPath, '-D', '-p', this.pidFile], { env });

            const pid = parseInt(await fs.readFile(this.pidFile, 'utf8'), 10);
            this.haproxyPid = pid;
            this.isRunning = true;
            this.consecutiveFailures = 0;

            return true;
        } catch (error) {
            console.error('[AUTO-LB] Failed to start HAProxy', error);
            console.error('[ERROR] Failed to start HAProxy:', error.message);

            this.consecutiveFailures++;
            if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
                console.error(`\n[FATAL] HAProxy failed ${this.consecutiveFailures} times consecutively.`);
                console.error('[FATAL] Configuration issues detected. Please check the HAProxy config.');
                console.error('[FATAL] Exiting to prevent endless retry loop.\n');
                process.exit(1);
            }

            return false;
        }
    }

    // Stop HAProxy
    async stop() {
        try {
            if (existsSync(this.pidFile)) {
                const pid = parseInt(await fs.readFile(this.pidFile, 'utf8'), 10);

                try {
                    process.kill(pid, 'SIGTERM');
                    console.log('[AUTO-LB] Stopped HAProxy', { pid });
                    console.log(`[STOPPED] HAProxy stopped (PID: ${pid})`);
                } catch (_killError) {
                    console.log(`[WARN] HAProxy process ${pid} not found (may have already exited)`);
                }

                try {
                    await fs.unlink(this.pidFile);
                } catch (unlinkError) {
                    if (unlinkError.code !== 'ENOENT') {
                        throw unlinkError;
                    }
                }

                this.isRunning = false;
                this.haproxyPid = null;
            } else {
                console.log('[INFO] No HAProxy PID file found (already stopped)');
            }
        } catch (error) {
            console.error('[AUTO-LB] Failed to stop HAProxy', error);
            console.error(`[ERROR] Failed to stop HAProxy: ${error.message}`);
        }
    }

    // Reload HAProxy
    async reload() {
        if (!this.isRunning || !existsSync(this.pidFile)) {
            return await this.start();
        }

        try {
            const env = { ...process.env };
            if (process.platform !== 'win32') {
                if (process.env.LD_LIBRARY_PATH) {
                    env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
                }
                if (process.env.OPENSSL_CONF) {
                    env.OPENSSL_CONF = process.env.OPENSSL_CONF;
                }
                if (process.env.OQS_PROVIDER_MODULE) {
                    env.OQS_PROVIDER_MODULE = process.env.OQS_PROVIDER_MODULE;
                }
            }

            const { stdout: validationOutput } = await execFileAsync(this.haproxyBin, ['-f', this.configPath, '-c'], { env });
            console.log('[AUTO-LB] HAProxy config validated', { output: validationOutput.trim() });

            const oldPid = parseInt(await fs.readFile(this.pidFile, 'utf8'), 10);
            await execFileAsync(this.haproxyBin, ['-f', this.configPath, '-D', '-p', this.pidFile, '-sf', String(oldPid)], { env });

            const newPid = parseInt(await fs.readFile(this.pidFile, 'utf8'), 10);
            this.haproxyPid = newPid;

            console.log('[AUTO-LB] Reloaded HAProxy', { oldPid, newPid });
            console.log(`\n[RELOADED] HAProxy configuration updated`);
            console.log(`\tOld PID: ${oldPid} → New PID: ${newPid}`);
            console.log(`\tReload successful\n`);

            this.consecutiveFailures = 0;
            return true;
        } catch (error) {
            console.error('[AUTO-LB] Failed to reload HAProxy', error);
            console.error('[ERROR] Failed to reload HAProxy:', error.message);

            if (error.stderr) {
                console.error('[ERROR] HAProxy stderr:', error.stderr);
            }

            this.consecutiveFailures++;
            if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
                console.error(`\n[FATAL] HAProxy reload failed ${this.consecutiveFailures} times consecutively.`);
                console.error('[FATAL] Configuration issues detected. Exiting.\n');
                process.exit(1);
            }

            return false;
        }
    }
}
