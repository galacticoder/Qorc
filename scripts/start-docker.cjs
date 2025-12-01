#!/usr/bin/env node
/**
 * Docker deployment helper script
 * Usage:
 *   node scripts/start-docker.cjs server
 *   node scripts/start-docker.cjs loadbalancer
 *   node scripts/start-docker.cjs server --build
 *   node scripts/start-docker.cjs stop all
 */

const { execSync, spawn } = require('child_process');
const path = require('path');
const readline = require('readline');
const fs = require('fs');
const net = require('net');

const args = process.argv.slice(2);
const command = args[0];
const flags = args.slice(1);

const validProfiles = ['server', 'loadbalancer'];
const validServices = ['redis', 'postgres', 'server', 'loadbalancer'];

function showHelp() {
    console.log('Docker Deployment Helper');
    console.log('');
    console.log('Usage:');
    console.log('  node scripts/start-docker.cjs server              - Start server stack');
    console.log('  node scripts/start-docker.cjs loadbalancer        - Start load balancer');
    console.log('  node scripts/start-docker.cjs server --build      - Rebuild and start server');
    console.log('  node scripts/start-docker.cjs loadbalancer --build - Rebuild and start loadbalancer');
    console.log('  node scripts/start-docker.cjs stop <service>      - Stop specific service (server, loadbalancer, postgres)');
    console.log('  node scripts/start-docker.cjs stop all            - Stop all services');
    console.log('  node scripts/start-docker.cjs delete <service>    - Stop, remove containers, and delete images (server, loadbalancer, redis, postgres)');
    console.log('  node scripts/start-docker.cjs logs [service]      - View logs');
    console.log('');
    process.exit(0);
}

if (!command || command === '-h' || command === '--help') {
    showHelp();
}

const repoRoot = path.resolve(__dirname, '..');
const envPath = path.join(repoRoot, '.env');

// Helper to check if a port is in use
function isPortInUse(port) {
    return new Promise((resolve) => {
        const server = net.createServer();
        server.once('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                resolve(true);
            } else {
                resolve(false);
            }
        });
        server.once('listening', () => {
            server.close();
            resolve(false);
        });
        server.listen(port);
    });
}

// Helper to find the next available port
async function findAvailablePort(startPort) {
    let port = parseInt(startPort, 10);
    while (await isPortInUse(port)) {
        port++;
    }
    return port;
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
    if (!fs.existsSync(envPath)) return;
    let content = fs.readFileSync(envPath, 'utf8');

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
    console.log(`[INFO] Updated .env: ${Object.keys(updates).map(k => `${k}=${updates[k]}`).join(', ')}`);
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
                    const psOutput = execSync('docker compose -f docker/docker-compose.yml ps --services --filter "status=running"', {
                        cwd: repoRoot,
                        encoding: 'utf8'
                    });
                    const runningServices = psOutput.trim().split('\n').filter(Boolean);

                    if (runningServices.length === 0) {
                        console.log('[INFO] No running services to stop');
                        process.exit(0);
                    }

                    console.log(`[INFO] Stopping ${runningServices.length} service(s): ${runningServices.join(', ')}`);
                    execSync('docker compose -f docker/docker-compose.yml down', { cwd: repoRoot, stdio: 'inherit' });
                    console.log(`[SUCCESS] Stopped: ${runningServices.join(', ')}`);
                } catch (error) {
                    console.log('[INFO] Stopping all Docker services...');
                    execSync('docker compose -f docker/docker-compose.yml down', { cwd: repoRoot, stdio: 'inherit' });
                }
                process.exit(0);
            }

            // Stop specific service
            try {
                const psOutput = execSync(`docker compose -f docker/docker-compose.yml ps --services --filter "status=running"`, {
                    cwd: repoRoot,
                    encoding: 'utf8'
                });
                const runningServices = psOutput.trim().split('\n').filter(Boolean);

                if (!runningServices.includes(serviceToStop)) {
                    console.log(`[INFO] Service '${serviceToStop}' is not running`);
                    process.exit(0);
                }

                console.log(`[INFO] Stopping service: ${serviceToStop}`);
                execSync(`docker compose -f docker/docker-compose.yml stop ${serviceToStop}`, { cwd: repoRoot, stdio: 'inherit' });
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
                execSync(`docker compose --env-file .env -f docker/docker-compose.yml stop ${serviceToDelete}`, {
                    cwd: repoRoot,
                    stdio: 'inherit'
                });
                console.log(`[SUCCESS] Stopped ${serviceToDelete} container`);
            } catch (error) {
                console.log(`[INFO] No running ${serviceToDelete} container to stop`);
            }

            console.log('[INFO] Step 2/3: Removing containers...');
            try {
                execSync(`docker compose --env-file .env -f docker/docker-compose.yml rm -f ${serviceToDelete}`, {
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
            console.log(`[INFO] Viewing logs${service ? ` for ${service}` : ''}...`);
            execSync(`docker compose --env-file .env -f docker/docker-compose.yml logs -f ${service}`, { cwd: repoRoot, stdio: 'inherit' });
            process.exit(0);
        }

        if (!validProfiles.includes(command)) {
            console.error(`[ERROR] Invalid profile: ${command}`);
            console.error(`[ERROR] Valid profiles: ${validProfiles.join(', ')}`);
            console.error('');
            showHelp();
        }

        console.log('[INFO] Checking for port conflicts...');
        const env = readEnv();
        const updates = {};

        // 1. Postgres
        const dbPort = parseInt(env.DB_PORT || '5432', 10);
        const availableDbPort = await findAvailablePort(dbPort);
        if (availableDbPort !== dbPort) {
            console.log(`[WARN] Port ${dbPort} is in use. Switching Postgres to ${availableDbPort}.`);
            updates.DB_PORT = availableDbPort;
        }

        // 2. Server
        const serverPort = parseInt(env.PORT || '3000', 10);
        const availableServerPort = await findAvailablePort(serverPort);
        if (availableServerPort !== serverPort) {
            console.log(`[WARN] Port ${serverPort} is in use. Switching Server to ${availableServerPort}.`);
            updates.PORT = availableServerPort;
        }

        // 3. Redis
        const redisPort = parseInt(env.REDIS_EXTERNAL_PORT || '6379', 10);
        const availableRedisPort = await findAvailablePort(redisPort);
        if (availableRedisPort !== redisPort) {
            console.log(`[WARN] Port ${redisPort} is in use. Switching Redis to ${availableRedisPort}.`);
            updates.REDIS_EXTERNAL_PORT = availableRedisPort;
        }

        // 4. Load Balancer (only if profile is loadbalancer)
        if (command === 'loadbalancer') {
            const httpPort = parseInt(env.HAPROXY_HTTP_PORT || '8080', 10);
            const availableHttpPort = await findAvailablePort(httpPort);
            if (availableHttpPort !== httpPort) {
                console.log(`[WARN] Port ${httpPort} is in use. Switching LoadBalancer HTTP to ${availableHttpPort}.`);
                updates.HAPROXY_HTTP_PORT = availableHttpPort;
            }

            const httpsPort = parseInt(env.HAPROXY_HTTPS_PORT || '8443', 10);
            const availableHttpsPort = await findAvailablePort(httpsPort);
            if (availableHttpsPort !== httpsPort) {
                console.log(`[WARN] Port ${httpsPort} is in use. Switching LoadBalancer HTTPS to ${availableHttpsPort}.`);
                updates.HAPROXY_HTTPS_PORT = availableHttpsPort;
            }

            const statsPort = parseInt(env.HAPROXY_STATS_PORT || '8404', 10);
            const availableStatsPort = await findAvailablePort(statsPort);
            if (availableStatsPort !== statsPort) {
                console.log(`[WARN] Port ${statsPort} is in use. Switching LoadBalancer Stats to ${availableStatsPort}.`);
                updates.HAPROXY_STATS_PORT = availableStatsPort;
            }
        }

        if (Object.keys(updates).length > 0) {
            updateEnvFile(updates);
            // Reload env into process.env for the current execution
            for (const [key, value] of Object.entries(updates)) {
                process.env[key] = value;
            }
        }
        // --------------------------------

        const buildFlag = flags.includes('--build') ? '--build' : '';

        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        rl.question('Run in background (detached mode)? [Y/n]: ', (answer) => {
            rl.close();

            const runDetached = !answer || answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';

            console.log(`[INFO] Starting Docker with profile: ${command}`);

            try {
                if (runDetached) {
                    process.env.NO_GUI = true;
                    const runCommand = `docker compose --env-file .env -f docker/docker-compose.yml --profile ${command} up -d ${buildFlag}`;
                    execSync(runCommand, { cwd: repoRoot, stdio: 'inherit' });
                } else {
                    execSync(`docker compose --env-file .env -f docker/docker-compose.yml up -d postgres`, { cwd: repoRoot, stdio: 'inherit' });

                    if (buildFlag) {
                        execSync(`docker compose --env-file .env -f docker/docker-compose.yml build ${command}`, { cwd: repoRoot, stdio: 'inherit' });
                    }

                    const dockerRun = spawn('docker', ['compose', '--env-file', '.env', '-f', 'docker/docker-compose.yml', 'run', '--service-ports', '-it', '--rm', command], {
                        cwd: repoRoot,
                        stdio: 'inherit'
                    });

                    dockerRun.on('exit', (code) => {
                        process.exit(code);
                    });
                }

                if (runDetached) {
                    console.log('');
                    console.log(`[SUCCESS] Docker ${command} stack started in background!`);
                    console.log('');
                    console.log('View logs:');
                    console.log(`  node scripts/start-docker.cjs logs ${command}`);
                    console.log('');
                    console.log('Stop services:');
                    console.log(`  node scripts/start-docker.cjs stop ${command}`);
                }
            } catch (error) {
                console.error('[ERROR] Docker command failed: ', error);
                if (error.message && error.message.includes('Cannot connect to the Docker daemon')) {
                    console.error('[ERROR] Docker Desktop is not running. Please start Docker Desktop and try again.');
                }
                process.exit(1);
            }
        });

    } catch (error) {
        console.error('[ERROR] Docker command failed');
        if (error.message && error.message.includes('Cannot connect to the Docker daemon')) {
            console.error('[ERROR] Docker Desktop is not running. Please start Docker Desktop and try again.');
        }
        process.exit(1);
    }
}

main();
