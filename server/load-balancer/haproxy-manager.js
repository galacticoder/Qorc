
import { execFileAsync } from './lb-utils.js';
import fs from 'fs/promises';
import { constants, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
    HAPROXY_PID_FILE as HAPROXY_PID_FILENAME,
    IS_ROOT,
    TEMP_DIRECTORY,
    haproxyStatsSocketPath,
    haproxyStatsDashboardUrl,
} from '../config/infrastructure.js';
import {
    processMatchesExecutable,
    readProcessIdFileSnapshot,
    removeUnchangedProcessIdFile,
} from '../utils/process-identity.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HAPROXY_CONFIG_PATH = path.join(__dirname, '../config/haproxy-auto.cfg');
const HAPROXY_PID_FILE = IS_ROOT
    ? `/var/run/${HAPROXY_PID_FILENAME}`
    : path.join(TEMP_DIRECTORY, HAPROXY_PID_FILENAME);
const BUNDLED_HAPROXY_BIN = '/opt/qorc-edge/bin/haproxy';
const BUNDLED_LIBRARY_DIR = '/opt/qorc-edge/lib';
const BUNDLED_OQS_MODULE = '/opt/qorc-edge/lib/ossl-modules/oqsprovider.so';

export class HAProxyManager {
    constructor() {
        this.haproxyPid = null;
        this.isRunning = false;
        this.configPath = HAPROXY_CONFIG_PATH;
        this.pidFile = HAPROXY_PID_FILE;
        this.haproxyBin = BUNDLED_HAPROXY_BIN;
    }

    // Only the immutable bundled executable is accepted.
    async isInstalled() {
        try {
            if (!path.isAbsolute(this.haproxyBin)) return false;
            const stat = await fs.stat(this.haproxyBin);
            if (!stat.isFile()) return false;
            await fs.access(this.haproxyBin, constants.X_OK);
            return true;
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
            throw new Error('Bundled HAProxy runtime is unavailable');
        }

        try {
            const existing = await readProcessIdFileSnapshot(this.pidFile);
            if (existing) {
                if (existing.pid && await processMatchesExecutable(existing.pid, this.haproxyBin)) {
                    this.haproxyPid = existing.pid;
                    this.isRunning = true;
                    return true;
                }
                if (!await removeUnchangedProcessIdFile(this.pidFile, existing)) {
                    throw new Error('HAProxy PID file changed while stale state was being removed');
                }
            }

            // Start HAProxy
            const env = { ...process.env };
            if (!process.env.OPENSSL_CONF || !existsSync(process.env.OPENSSL_CONF)) {
                throw new Error('OPENSSL_CONF is required and must be readable');
            }
            delete env.LD_PRELOAD;
            env.LD_LIBRARY_PATH = BUNDLED_LIBRARY_DIR;
            env.OPENSSL_MODULES = path.dirname(BUNDLED_OQS_MODULE);
            env.OQS_PROVIDER_MODULE = BUNDLED_OQS_MODULE;
            env.OPENSSL_CONF = process.env.OPENSSL_CONF;

            // Clean up stale stats socket if present
            try {
                const statsSock = haproxyStatsSocketPath();
                if (existsSync(statsSock)) { await fs.unlink(statsSock).catch(() => { }); }
            } catch { }

            await execFileAsync(this.haproxyBin, ['-f', this.configPath, '-D', '-p', this.pidFile], { env });

            const started = await readProcessIdFileSnapshot(this.pidFile);
            if (!started?.pid || !await processMatchesExecutable(started.pid, this.haproxyBin)) {
                throw new Error('HAProxy did not create a valid owned PID file');
            }
            this.haproxyPid = started.pid;
            this.isRunning = true;

            return true;
        } catch (error) {
            console.error('[AUTO-LB] Failed to start HAProxy', error);
            console.error('[ERROR] Failed to start HAProxy:', error.message);

            throw error;
        }
    }

    // Stop HAProxy
    async stop() {
        try {
            const snapshot = await readProcessIdFileSnapshot(this.pidFile);
            if (snapshot) {
                const { pid } = snapshot;

                if (pid && await processMatchesExecutable(pid, this.haproxyBin)) {
                    try {
                        process.kill(pid, 'SIGTERM');
                        console.log('[AUTO-LB] Stopped HAProxy', { pid });
                        console.log(`[STOPPED] HAProxy stopped (PID: ${pid})`);
                    } catch (_killError) {
                        console.log(`[WARN] HAProxy process ${pid} not found (may have already exited)`);
                    }
                } else {
                    console.warn('[AUTO-LB] Refusing to signal a PID not owned by bundled HAProxy');
                }

                if (!await removeUnchangedProcessIdFile(this.pidFile, snapshot)) {
                    throw new Error('HAProxy PID file changed while stopping');
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
        if (!this.isRunning) {
            throw new Error('HAProxy is not running');
        }

        try {
            const env = { ...process.env };
            if (!process.env.OPENSSL_CONF || !existsSync(process.env.OPENSSL_CONF)) {
                throw new Error('OPENSSL_CONF is required and must be readable');
            }
            delete env.LD_PRELOAD;
            env.LD_LIBRARY_PATH = BUNDLED_LIBRARY_DIR;
            env.OPENSSL_MODULES = path.dirname(BUNDLED_OQS_MODULE);
            env.OQS_PROVIDER_MODULE = BUNDLED_OQS_MODULE;
            env.OPENSSL_CONF = process.env.OPENSSL_CONF;

            const { stdout: validationOutput } = await execFileAsync(this.haproxyBin, ['-f', this.configPath, '-c'], { env });
            console.log('[AUTO-LB] HAProxy config validated', { output: validationOutput.trim() });

            const oldSnapshot = await readProcessIdFileSnapshot(this.pidFile);
            const oldPid = oldSnapshot?.pid;
            if (!oldPid || !await processMatchesExecutable(oldPid, this.haproxyBin)) {
                throw new Error('HAProxy PID file does not identify the bundled runtime');
            }
            await execFileAsync(this.haproxyBin, ['-f', this.configPath, '-D', '-p', this.pidFile, '-sf', String(oldPid)], { env });

            const newSnapshot = await readProcessIdFileSnapshot(this.pidFile);
            const newPid = newSnapshot?.pid;
            if (!newPid || !await processMatchesExecutable(newPid, this.haproxyBin)) {
                throw new Error('HAProxy reload did not create a valid owned PID file');
            }
            this.haproxyPid = newPid;

            console.log('[AUTO-LB] Reloaded HAProxy', { oldPid, newPid });
            console.log(`\n[RELOADED] HAProxy configuration updated`);
            console.log(`\tOld PID: ${oldPid} → New PID: ${newPid}`);
            console.log(`\tReload successful\n`);

            return true;
        } catch (error) {
            console.error('[AUTO-LB] Failed to reload HAProxy', error);
            console.error('[ERROR] Failed to reload HAProxy:', error.message);

            if (error.stderr) {
                console.error('[ERROR] HAProxy stderr:', error.stderr);
            }

            throw error;
        }
    }
}
