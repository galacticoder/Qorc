#!/usr/bin/env node
/**
 * Docker deployment helper script
 * Usage:
 *   node scripts/start-docker.cjs all
 *   node scripts/start-docker.cjs server
 *   node scripts/start-docker.cjs loadbalancer
 *   node scripts/start-docker.cjs server --build
 *   node scripts/start-docker.cjs stop all
 */

const { execFileSync, execSync, spawn } = require('child_process');
const path = require('path');
const readline = require('readline');
const fs = require('fs');
const net = require('net');
const { randomBytes } = require('crypto');
const {
    createDockerBuildContext,
    removeDockerBuildContext
} = require('./docker-build-context.cjs');

const args = process.argv.slice(2);
const command = args[0];
const flags = args.slice(1);

if (!['linux', 'win32', 'darwin'].includes(process.platform)) {
    console.error('[DOCKER] qorc deployment supports Linux, Windows, and macOS hosts running Docker Linux containers.');
    process.exit(1);
}

const validProfiles = ['server', 'loadbalancer', 'all'];
const validServices = ['redis', 'postgres', 'server', 'loadbalancer'];

function showHelp() {
    console.log('Docker Deployment Helper');
    console.log('');
    console.log('Usage:');
    console.log('  node scripts/start-docker.cjs all                    - Start the complete deployment');
    console.log('  node scripts/start-docker.cjs <profile>              - Start profile stack');
    console.log('  node scripts/start-docker.cjs <profile> --build      - Rebuild and start profile');
    console.log('  node scripts/start-docker.cjs all --build            - Build and start the complete deployment');
    console.log('  node scripts/start-docker.cjs stop <service>      - Stop specific service (server, loadbalancer, postgres, redis)');
    console.log('  node scripts/start-docker.cjs stop all            - Stop all services');
    console.log('  node scripts/start-docker.cjs delete <service>    - Stop, remove containers, and delete images');
    console.log('  node scripts/start-docker.cjs reset               - Stop all services and remove volumes');
    console.log('  node scripts/start-docker.cjs logs [service]      - View all logs or one service');
    console.log('');
    process.exit(0);
}

if (!command || command === '-h' || command === '--help') {
    showHelp();
}

const repoRoot = path.resolve(__dirname, '..');
const envPath = path.join(repoRoot, '.env');
const hostLogsPath = path.join(repoRoot, 'logs');
const composeFilePath = path.join(repoRoot, 'docker/docker-compose.yml');

// Helper to check if a port is in use
function isPortInUse(port) {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                resolve(true);
            } else {
                reject(err);
            }
        });
        server.once('listening', () => {
            server.close();
            resolve(false);
        });
        server.listen(port);
    });
}

function isComposeServiceUsingPort(service, containerPort, hostPort) {
    try {
        const output = execFileSync('docker', [
            'compose',
            '--env-file', envPath,
            '-f', path.join(repoRoot, 'docker/docker-compose.yml'),
            'port', service, String(containerPort)
        ], {
            cwd: repoRoot,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        });
        return output.split(/\r?\n/).some((line) => {
            const match = line.match(/:(\d+)\s*$/);
            return match && Number(match[1]) === hostPort;
        });
    } catch {
        return false;
    }
}

async function requireAvailablePort(name, value, composeService, containerPort) {
    const port = Number(value);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
        throw new Error(`${name} must be an integer from 1 through 65535`);
    }
    if (await isPortInUse(port) && !isComposeServiceUsingPort(composeService, containerPort, port)) {
        throw new Error(`${name} port ${port} is already in use`);
    }
}

// Helper to read .env file
function readEnv() {
    if (!fs.existsSync(envPath)) return {};
    const content = fs.readFileSync(envPath, 'utf8');
    const env = {};
    content.split('\n').forEach(line => {
        const match = line.match(/^([^=]+)=(.*)$/);
        if (match) {
            env[match[1].trim()] = match[2].trim();
        }
    });
    return env;
}

// Helper to update .env file
function updateEnvFile(updates) {
    let content = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';

    for (const [key, value] of Object.entries(updates)) {
        const regex = new RegExp(`^${key}=.*`, 'm');
        if (regex.test(content)) {
            content = content.replace(regex, `${key}=${value}`);
        } else {
            if (!content.endsWith('\n')) content += '\n';
            content += `${key}=${value}\n`;
        }
    }

    fs.writeFileSync(envPath, content, 'utf8');
    try { fs.chmodSync(envPath, 0o600); } catch { }
    console.log(`[INFO] Updated .env: ${Object.keys(updates).map((key) => (
        /(PASSWORD|SEED|KEY|SECRET|TOKEN)/i.test(key) ? `${key}=[generated]` : `${key}=${updates[key]}`
    )).join(', ')}`);
}

async function checkDockerEnvironment(env, needsServerPassword, needsLoadBalancerCredentials) {
    const updates = {};
    const defaults = {
        DB_PORT: '5432',
        DB_NAME: 'qorc',
        REDIS_URL: 'rediss://redis:6379',
        REDIS_EXTERNAL_PORT: '6379',
        REDIS_TLS_SERVERNAME: 'redis',
        REDIS_CA_CERT_PATH: '/app/redis-certs/redis-ca.crt',
        REDIS_CLIENT_CERT_PATH: '/app/redis-certs/redis-client.crt',
        REDIS_CLIENT_KEY_PATH: '/app/redis-certs/redis-client.key',
        PGSSLROOTCERT: '/app/postgres-certs/root.crt',
        DB_TLS_SERVERNAME: 'postgres',
        TLS_CERT_PATH: 'server/config/certs/localhost.crt',
        TLS_KEY_PATH: 'server/config/certs/localhost.key',
        PORT: '3000',
        CLUSTER_PRIMARY: 'true',
        CLUSTER_AUTO_APPROVE: 'false',
        HAPROXY_HTTPS_PORT: '8443',
        HAPROXY_STATS_PORT: '8404'
    };

    for (const [key, value] of Object.entries(defaults)) {
        if (!env[key]) updates[key] = value;
    }
    if (!env.DATABASE_PASSWORD) updates.DATABASE_PASSWORD = randomBytes(32).toString('base64url');
    if (!env.REDIS_PASSWORD) {
        updates.REDIS_PASSWORD = randomBytes(32).toString('base64url');
    } else if (env.REDIS_PASSWORD.length < 32 || !/^[A-Za-z0-9_-]+$/.test(env.REDIS_PASSWORD)) {
        throw new Error('REDIS_PASSWORD must contain at least 32 base64url characters');
    }

    if (needsServerPassword) {
        const serverPassword = typeof env.SERVER_PASSWORD === 'string'
            ? env.SERVER_PASSWORD.trim()
            : '';
        if (!serverPassword) {
            throw new Error('SERVER_PASSWORD is required in .env. Add a 12-512 character value and run this command again.');
        }
        if (serverPassword.length < 12 || serverPassword.length > 512) {
            throw new Error('SERVER_PASSWORD in .env must contain between 12 and 512 characters.');
        }
    }

    if (needsLoadBalancerCredentials) {
        const statsUsername = typeof env.HAPROXY_STATS_USERNAME === 'string'
            ? env.HAPROXY_STATS_USERNAME.trim()
            : '';
        const statsPassword = typeof env.HAPROXY_STATS_PASSWORD === 'string'
            ? env.HAPROXY_STATS_PASSWORD
            : '';
        if (!statsUsername || !statsPassword) {
            throw new Error('HAPROXY_STATS_USERNAME and HAPROXY_STATS_PASSWORD are required in .env for the load balancer.');
        }
    }

    if (Object.keys(updates).length > 0) {
        updateEnvFile(updates);
        Object.assign(env, updates);
    }

}

function checkSupportedDockerRuntime() {
    let runtime;
    try {
        runtime = execFileSync('docker', ['version', '--format', '{{.Server.Os}}/{{.Server.Arch}}'], {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim().toLowerCase();
    } catch (error) {
        throw new Error(`Docker is unavailable or is not running: ${error.message}`);
    }

    const [operatingSystem, rawArchitecture] = runtime.split('/');
    const architecture = rawArchitecture === 'x86_64' ? 'amd64'
        : rawArchitecture === 'aarch64' ? 'arm64'
            : rawArchitecture;
    if (operatingSystem !== 'linux') {
        throw new Error(`Docker is running ${operatingSystem || 'an unknown container mode'}. Switch Docker to Linux containers.`);
    }
    if (!['amd64', 'arm64'].includes(architecture)) {
        throw new Error(`Docker architecture '${rawArchitecture || 'unknown'}' is unsupported. qorc server images support amd64 and arm64.`);
    }

    console.log(`[INFO] Docker runtime: linux/${architecture}`);
}

function checkDockerIdentitySeeds(env) {
    const updates = {};
    for (const key of ['AUTH_ROOT_SEED', 'SERVER_TRANSPORT_IDENTITY_SEED']) {
        const configured = env[key];
        if (!configured) {
            updates[key] = randomBytes(32).toString('hex');
            continue;
        }
        if (!/^[0-9a-fA-F]{64}$/.test(configured)) {
            throw new Error(`${key} must be exactly 32 bytes encoded as 64 hexadecimal characters`);
        }
    }

    if (Object.keys(updates).length > 0) {
        updateEnvFile(updates);
        Object.assign(env, updates);
        console.log('[INFO] Generated missing server identity seeds. Preserve these .env values across restarts and authorized cluster nodes.');
    }
}

async function main() {
    try {
        if (command === 'stop') {
            const serviceToStop = flags[0];

            if (!serviceToStop) {
                console.error('[ERROR] Please specify a service to stop or use "all"');
                console.error('');
                console.error('Usage:');
                console.error('  node scripts/start-docker.cjs stop server        - Stop server');
                console.error('  node scripts/start-docker.cjs stop loadbalancer  - Stop loadbalancer');
                console.error('  node scripts/start-docker.cjs stop postgres      - Stop postgres');
                console.error('  node scripts/start-docker.cjs stop all           - Stop all services');
                console.error('');
                process.exit(1);
            }

            if (serviceToStop === 'all') {
                // Stop all services
                try {
                    const psOutput = execSync('docker compose --env-file .env -f docker/docker-compose.yml --profile "*" ps --services --filter "status=running"', {
                        cwd: repoRoot,
                        encoding: 'utf8'
                    });
                    const runningServices = psOutput.trim().split('\n').filter(Boolean);

                    if (runningServices.length === 0) {
                        console.log('[INFO] No running services to stop');
                        process.exit(0);
                    }

                    console.log(`[INFO] Stopping ${runningServices.length} service(s): ${runningServices.join(', ')}`);
                    execSync('docker compose --env-file .env -f docker/docker-compose.yml --profile "*" down', { cwd: repoRoot, stdio: 'inherit' });
                    console.log(`[SUCCESS] Stopped: ${runningServices.join(', ')}`);
                } catch (error) {
                    console.log('[INFO] Stopping all Docker services...');
                    execSync('docker compose --env-file .env -f docker/docker-compose.yml --profile "*" down', { cwd: repoRoot, stdio: 'inherit' });
                }
                process.exit(0);
            }

            if (!validServices.includes(serviceToStop)) {
                console.error(`[ERROR] Unknown service: ${serviceToStop}`);
                process.exit(1);
            }

            // Stop specific service
            try {
                const psOutput = execSync('docker compose --env-file .env -f docker/docker-compose.yml --profile "*" ps --services --filter "status=running"', {
                    cwd: repoRoot,
                    encoding: 'utf8'
                });
                const runningServices = psOutput.trim().split('\n').filter(Boolean);

                if (!runningServices.includes(serviceToStop)) {
                    console.log(`[INFO] Service '${serviceToStop}' is not running`);
                    process.exit(0);
                }

                console.log(`[INFO] Stopping service: ${serviceToStop}`);
                execSync(`docker compose --env-file .env -f docker/docker-compose.yml --profile "*" stop ${serviceToStop}`, { cwd: repoRoot, stdio: 'inherit' });
                console.log(`[SUCCESS] Stopped: ${serviceToStop}`);
            } catch (error) {
                console.error(`[ERROR] Failed to stop service: ${serviceToStop}`);
                process.exit(1);
            }
            process.exit(0);
        }

        if (command === 'delete') {
            const serviceToDelete = flags[0];

            if (!serviceToDelete || !validServices.includes(serviceToDelete)) {
                console.error('[ERROR] Please specify a valid service to delete');
                console.error('');
                console.error('Usage:');
                console.error('  node scripts/start-docker.cjs delete server        - Delete server containers and images');
                console.error('  node scripts/start-docker.cjs delete loadbalancer  - Delete loadbalancer containers and images');
                console.error('  node scripts/start-docker.cjs delete redis         - Delete redis containers and images');
                console.error('  node scripts/start-docker.cjs delete postgres      - Delete postgres containers and images');
                console.error('');
                process.exit(1);
            }

            console.log(`[INFO] Deleting ${serviceToDelete} service...`);
            console.log('[INFO] Step 1/3: Stopping containers...');

            try {
                execSync(`docker compose --env-file .env -f docker/docker-compose.yml --profile "*" stop ${serviceToDelete}`, {
                    cwd: repoRoot,
                    stdio: 'inherit'
                });
                console.log(`[SUCCESS] Stopped ${serviceToDelete} container`);
            } catch (error) {
                console.log(`[INFO] No running ${serviceToDelete} container to stop`);
            }

            console.log('[INFO] Step 2/3: Removing containers...');
            try {
                execSync(`docker compose --env-file .env -f docker/docker-compose.yml --profile "*" rm -f ${serviceToDelete}`, {
                    cwd: repoRoot,
                    stdio: 'inherit'
                });
                console.log(`[SUCCESS] Removed ${serviceToDelete} container`);
            } catch (error) {
                console.log(`[INFO] No ${serviceToDelete} container to remove`);
            }

            console.log('[INFO] Step 3/3: Deleting images...');
            let imageDeleted = false;
            try {
                const imageName = `docker-${serviceToDelete}:latest`;
                execSync(`docker image rm ${imageName} -f`, {
                    cwd: repoRoot,
                    stdio: 'pipe',
                    encoding: 'utf8'
                });
                console.log(`[SUCCESS] Deleted ${imageName} image`);
                imageDeleted = true;
            } catch (error) {
                const errorMessage = error.message || '';
                if (errorMessage.includes('No such image')) {
                    console.log(`[INFO] Image docker-${serviceToDelete}:latest does not exist`);
                } else {
                    console.log(`[INFO] Could not delete ${serviceToDelete} image: ${errorMessage}`);
                }
            }

            console.log('');
            if (imageDeleted) {
                console.log(`[SUCCESS] Deleted ${serviceToDelete} service completely!`);
            } else {
                console.log(`[SUCCESS] Removed ${serviceToDelete} containers (no image to delete)`);
            }
            console.log('');
            process.exit(0);
        }

        if (command === 'logs') {
            const service = flags[0] || '';
            if (service && !validServices.includes(service)) {
                console.error(`[ERROR] Unknown service: ${service}`);
                process.exit(1);
            }
            console.log(`[INFO] Viewing logs${service ? ` for ${service}` : ''}...`);
            execSync(`docker compose --env-file .env -f docker/docker-compose.yml --profile "*" logs -f ${service}`, { cwd: repoRoot, stdio: 'inherit' });
            process.exit(0);
        }

        if (command === 'reset') {
            console.log('[INFO] Stopping containers and removing volumes...');
            try {
                execSync('docker compose --env-file .env -f docker/docker-compose.yml --profile "*" down -v', { cwd: repoRoot, stdio: 'inherit' });
                console.log('[SUCCESS] Reset complete.');
            } catch (error) {
                console.error('[ERROR] Failed to reset:', error.message);
                process.exit(1);
            }
            process.exit(0);
        }

        if (!validProfiles.includes(command)) {
            console.error(`[ERROR] Invalid profile: ${command}`);
            console.error(`[ERROR] Valid profiles: ${validProfiles.join(', ')}`);
            console.error('');
            showHelp();
        }

        checkSupportedDockerRuntime();
        fs.mkdirSync(hostLogsPath, { recursive: true });

        const env = readEnv();
        await checkDockerEnvironment(
            env,
            command === 'server' || command === 'all',
            command === 'loadbalancer' || command === 'all'
        );
        checkDockerIdentitySeeds(env);
        await requireAvailablePort('REDIS_EXTERNAL_PORT', env.REDIS_EXTERNAL_PORT, 'redis', 6379);
        if (command === 'server' || command === 'all') {
            await requireAvailablePort('DB_PORT', env.DB_PORT, 'postgres', 5432);
            await requireAvailablePort('PORT', env.PORT, 'server', 3000);
        }
        if (command === 'loadbalancer' || command === 'all') {
            await requireAvailablePort('HAPROXY_HTTPS_PORT', env.HAPROXY_HTTPS_PORT, 'loadbalancer', 8443);
            await requireAvailablePort('HAPROXY_STATS_PORT', env.HAPROXY_STATS_PORT, 'loadbalancer', 8404);
        }

        const shouldBuild = flags.includes('--build');

        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        rl.question('Run in background (detached mode)? [Y/n]: ', (answer) => {
            rl.close();

            const runDetached = !answer || answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';
            let dockerBuildContext;

            console.log(`[INFO] Starting Docker with profile: ${command}`);

            try {
                dockerBuildContext = createDockerBuildContext(repoRoot);
                process.env.QORC_DOCKER_BUILD_CONTEXT = dockerBuildContext;
                const targetServices = command === 'all' ? 'server loadbalancer' : command;
                const buildServices = command === 'all'
                    ? 'postgres redis server loadbalancer'
                    : command === 'server'
                        ? 'postgres redis server'
                        : 'redis loadbalancer';
                const profileFlags = command === 'all'
                    ? '--profile server --profile loadbalancer'
                    : `--profile ${command}`;
                let sharedServices = 'redis';
                if (command === 'server' || command === 'all') sharedServices = 'postgres redis';

                if (shouldBuild) {
                    execSync(`docker compose --env-file .env -f docker/docker-compose.yml build ${buildServices}`, { cwd: repoRoot, stdio: 'inherit' });
                }

                const sharedRecreateFlag = shouldBuild ? '' : '--no-recreate';
                execSync(`docker compose --env-file .env -f docker/docker-compose.yml up -d --wait --remove-orphans ${sharedRecreateFlag} ${sharedServices}`, { cwd: repoRoot, stdio: 'inherit' });

                if (runDetached) {
                    process.env.NO_GUI = 'true';

                    const runCommand = `docker compose --env-file .env -f docker/docker-compose.yml ${profileFlags} up -d --remove-orphans ${targetServices}`;
                    execSync(runCommand, { cwd: repoRoot, stdio: 'inherit' });
                } else {
                    const foregroundArgs = command === 'all'
                        ? ['compose', '--env-file', '.env', '-f', 'docker/docker-compose.yml', '--profile', 'server', '--profile', 'loadbalancer', 'up', '--remove-orphans', 'server', 'loadbalancer']
                        : ['compose', '--env-file', '.env', '-f', 'docker/docker-compose.yml', 'run', '--no-deps', '--service-ports', '-it', '--rm', command];
                    const dockerRun = spawn('docker', foregroundArgs, {
                        cwd: repoRoot,
                        stdio: 'inherit',
                        env: { ...process.env }
                    });

                    dockerRun.on('exit', (code) => {
                        removeDockerBuildContext(dockerBuildContext);
                        process.exit(code);
                    });

                    dockerRun.on('error', (error) => {
                        removeDockerBuildContext(dockerBuildContext);
                        console.error('[ERROR] Docker command failed: ', error);
                        process.exit(1);
                    });
                }

                if (runDetached) {
                    removeDockerBuildContext(dockerBuildContext);
                    dockerBuildContext = undefined;
                    console.log('');
                    console.log(`[SUCCESS] Docker ${command} stack started in background!`);
                    console.log('');
                    console.log('View logs:');
                    console.log(command === 'all'
                        ? '  node scripts/start-docker.cjs logs'
                        : `  node scripts/start-docker.cjs logs ${command}`);
                    console.log('');
                    console.log('Stop services:');
                    console.log(`  node scripts/start-docker.cjs stop ${command}`);
                }
            } catch (error) {
                removeDockerBuildContext(dockerBuildContext);
                console.error('[ERROR] Docker command failed: ', error);
                if (error.message && error.message.includes('Cannot connect to the Docker daemon')) {
                    console.error('[ERROR] Docker Desktop is not running. Please start Docker Desktop and try again.');
                }
                process.exit(1);
            }
        });

    } catch (error) {
        const message = error && typeof error.message === 'string'
            ? error.message
            : 'Docker command failed';
        console.error(`[ERROR] ${message}`);
        if (message.includes('Cannot connect to the Docker daemon')) {
            console.error('[ERROR] Docker Desktop is not running. Please start Docker Desktop and try again.');
        }
        process.exit(1);
    }
}

main();
