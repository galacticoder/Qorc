# Set up and connect to a Qorc server

## 1. Prepare the host

Install Node.js 18 or newer, then download the Qorc repository or clone it:

```bash
git clone https://github.com/galacticoder/Qorc.git
cd Qorc
```

On Linux, the dependency script can install Docker and Buildx:

```bash
node scripts/install-deps.cjs docker docker-buildx
```

Start Docker and run `docker compose version` to check that Compose v2 is installed. The installer does not install Compose. On Windows or macOS, install and start Docker Desktop with Linux containers. It includes Compose and Buildx. The Docker build installs server dependencies, Redis, PostgreSQL, and Tor automatically.

Open the included `.env` in the repository root and edit these fields:

| Field | What to set |
| --- | --- |
| `SERVER_PASSWORD` | A unique, random server access password, 12–512 characters. Share it with invited users. |
| `HAPROXY_STATS_USERNAME` | Your private administrator username. |
| `HAPROXY_STATS_PASSWORD` | A different, long random password. Keep it private. |
| `SERVER_NAME` | The name people see when saving your server. |

For a **brand-new server**, also empty `DATABASE_PASSWORD`, `REDIS_PASSWORD`, `AUTH_ROOT_SEED`, and `SERVER_TRANSPORT_IDENTITY_SEED`. The launcher generates unique replacements. Preserve those generated values on later starts. Keep the other included defaults for a normal single-server setup.

## 2. Start the server

From the repository root:

```bash
node scripts/start-docker.cjs all --build
```

Press Enter to run in the background. The first build downloads and installs dependencies automatically and can take a while.

Find the server address in the load-balancer logs:

```bash
node scripts/start-docker.cjs logs loadbalancer
```

Look for `Onion URL: https://…onion`. Use the same hostname with `wss://` in Qorc: `wss://…onion`. Share this full address and the server access password with people you invite. Keep the admin credentials private.

## 3. Connect from Qorc

1. Open Qorc and finish or skip the introduction.
2. Enter the address under **Connect to a server**, then select **Connect**. Qorc starts Tor automatically.
3. Create an account or sign in, and enter the server access password when prompted. Your personal account password and passphrase are separate from the shared server password.
4. Save the server in **Settings → Servers → Manage servers**. Inspect its identity details and compare the full fingerprint with the owner through a trusted channel.
5. Have contacts join the same server. Open **New conversation** in Chats and search for their username.

## Basic upkeep

Run these from the repository root:

```bash
node scripts/start-docker.cjs logs
node scripts/start-docker.cjs stop all
node scripts/start-docker.cjs all
```

Keep private backups of `.env`, `server/config`, and the Docker volumes to preserve identity and data. Avoid `reset`: it deletes the volumes. After updating the repository, run `node scripts/start-docker.cjs all --build` again.

For connection problems, check the logs and wait for Tor readiness. Use bridges in Qorc’s **Tor settings** if your network blocks Tor. Advanced configuration is in [Environment variables](ENVIRONMENT_VARIABLES.md).
