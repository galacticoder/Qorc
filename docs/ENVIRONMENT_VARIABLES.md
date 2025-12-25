# Environment variables

This document lists environment variables recognized by the app

Values shown in parentheses indicate typical defaults when the variable is unset.

---

## Server core and networking

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `PORT` | `(8443)` or `dynamic` | `server/config/config.js`, `server/server.js`, `scripts/start-server.cjs`, `server/cluster/cluster-manager.js` | HTTPS listen port. `dynamic` is treated as port `0` (kernel-assigned); when started via `scripts/start-server.cjs`, a free port is auto-selected if `PORT` is empty. |
| `BIND_ADDRESS` | `(127.0.0.1)` | `server/bootstrap/server-bootstrap.js`, `server/server.js`, `scripts/start-server.cjs` | IP/interface the HTTPS server binds to. Must be a loopback address (`127.0.0.1`, `::1`, or `localhost`) or startup will fail. |
| `ALLOWED_CORS_ORIGINS` | `('http://localhost:5173,http://127.0.0.1:5173')` | `scripts/start-server.cjs`, `server/config/constants.js` | Comma-separated list of allowed CORS origins for HTTP and WebSocket requests. Parsed into `CORS_CONFIG.ALLOWED_ORIGINS`; when unset, the launcher provides localhost defaults. |
| `SERVER_ID` | auto-generated (`server-<hostname>-<timestamp>` when using `start-server.cjs`) | `server/server.js`, `server/session/pq-session-storage.js`, `server/messaging/pq-envelope-handler.js`, `server/websocket/gateway.js`, `server/cluster/*` | Logical identifier for this server instance, used in logs, PQ envelopes, WebSocket delivery, and cluster registration. |
| `SERVER_HOST` | empty  auto-detected IP | `scripts/start-server.cjs`, `server/cluster/cluster-manager.js` | Public host/IP advertised to the cluster and HAProxy. When empty, `start-server.cjs` resolves the first non-loopback address or falls back to `127.0.0.1`. |
| `HOST` | OS hostname | `server/cluster/cluster-manager.js` | Fallback hostname used when `SERVER_HOST` is not set. |
| `HOSTNAME` | OS hostname | `server/cluster/cluster-integration.js` | Used when generating a random server ID for clustering if `SERVER_ID` is not provided. |
| `ENABLE_CLUSTERING` | `('true')` | `scripts/start-server.cjs`, `server/server.js`, `server/authentication/auth-utils.js` | Enables Redis-backed clustering and HAProxy integration when set to `'true'`. |
| `CLUSTER_WORKERS` | `('1')` | `scripts/start-server.cjs`, `server/bootstrap/server-bootstrap.js` | Number of Node worker processes. Values >1 enable clustered workers on a single machine. |
| `CLUSTER_PRIMARY` | empty | `scripts/start-server.cjs`, `server/cluster/cluster-integration.js`, `server/server.js` | When `'true'`, forces this node to act as primary cluster node. If unset, primary status is chosen based on Redis state. |
| `CLUSTER_AUTO_APPROVE` | `('true')` | `scripts/start-server.cjs`, `server/cluster/cluster-integration.js`, `server/server.js` | When `'true'`, new cluster nodes are automatically approved instead of requiring manual approval. |
| `SERVER_ROLE` | empty | `server/cluster/cluster-integration.js` | Optional alternative for marking a node as `primary` (`SERVER_ROLE=primary`) during cluster initialization. |
| `NO_GUI` | `('false')` | `scripts/start-server.cjs`, `scripts/start-loadbalancer.cjs` | When `'true'`, disables the interactive TUI for the server or load balancer; processes run in standard console mode. |
| `USE_REDIS` | `('true')` | `scripts/start-server.cjs` | Launcher flag read by `scripts/start-server.cjs` and forwarded into the server environment for Redis-related configuration. |
| `DISABLE_CONNECTION_LIMIT` | `('true')` | `scripts/start-server.cjs` | Launcher flag forwarded into the server environment; named for configuration of global connection limiting. |
| `MAX_CONNECTIONS` | `(1000)` | `server/authentication/auth-utils.js` | Upper bound on concurrent connections enforced via a Redis-backed connection counter. |

---

## TLS and certificates

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `TLS_CERT_PATH` | **required** | `scripts/start-server.cjs`, `server/bootstrap/server-bootstrap.js`, `server/server.js`, `scripts/start-loadbalancer.cjs`, `scripts/simple-tunnel.cjs` | Absolute or project-relative path to the HTTPS certificate for the server (and for the local TLS Redis helper). Required for the server to start. |
| `TLS_KEY_PATH` | **required** | same as above | Path to the private key corresponding to `TLS_CERT_PATH`. Required for server startup and TLS Redis auto-start. |
| `DB_CA_CERT_PATH` | auto-generated to `server/config/certs/postgres-root-cas.pem` when using `scripts/start-server.cjs` | `server/database/database.js`, `scripts/start-server.cjs` | Optional PEM bundle of Postgres root CAs. When set, Postgres connections use this bundle instead of system CAs. `start-server.cjs` can generate this by probing the remote TLS chain. |
| `PGSSLROOTCERT` | unset | `server/database/database.js`, `scripts/start-server.cjs` | Alternative to `DB_CA_CERT_PATH` for specifying the Postgres root CA bundle. |
| `DB_TLS_SERVERNAME` | derived or unset | `server/database/database.js`, `scripts/start-server.cjs` | SNI/hostname used for Postgres TLS hostname verification. Auto-set by `ensureDbCaBundleEnv()` when probing the remote certificate. |
| `DB_CONNECT_HOST` | derived or `(localhost)` | `server/database/database.js`, `scripts/start-server.cjs` | Host used for TCP connections to Postgres when `DATABASE_URL` is not set. Auto-populated by `scripts/start-server.cjs` when generating the CA bundle. |
| `REDIS_TLS_SERVERNAME` | derived from HTTPS certificate when possible | `server/presence/presence.js`, `server/rate-limiting/distributed-rate-limiter.js`, `scripts/start-server.cjs` | SNI hostname used for TLS connections to Redis. When unset and a local TLS Redis is used, `start-server.cjs` derives it from the HTTPS certificate CN. |
| `OPENSSL_CONF` | unset | `scripts/setup-quantum-haproxy.cjs`, `scripts/build-quantum-haproxy.cjs`, `scripts/start-loadbalancer.cjs`, `scripts/start-server.cjs`, `server/cluster/auto-loadbalancer.js` | OpenSSL configuration file. Quantum scripts set this to a local `openssl-oqs.cnf` that loads the OQS provider for PQ TLS. |
| `OPENSSL_MODULES` | unset | same as above | Directory containing OpenSSL provider modules. Set by quantum setup scripts so the `oqsprovider` module can be loaded. |
| `LD_LIBRARY_PATH` | unset | `scripts/setup-quantum-haproxy.cjs`, `scripts/build-quantum-haproxy.cjs`, `server/cluster/haproxy-config-generator.js`, `server/cluster/auto-loadbalancer.js` | Library search path used when invoking `haproxy` or OpenSSL with the PQ provider installed in non-standard locations. |
| `LB_OPENSSL_CONF` | derived from `OPENSSL_CONF` | `scripts/start-loadbalancer.cjs`, `server/cluster/auto-loadbalancer.js` | OpenSSL configuration used by the load balancer process. Normally set by `scripts/start-loadbalancer.cjs` to point at `server/config/openssl-oqs.cnf`. |
| `LB_HAPROXY_CFG` | derived (`server/config/haproxy-quantum.cfg`) | `scripts/start-loadbalancer.cjs`, `server/cluster/auto-loadbalancer.js` | Path to the quantum-enabled HAProxy configuration used by the auto-loadbalancer. |
| `TLS_REDIS_SERVER` | auto-written by `scripts/install-deps.cjs` | `scripts/start-server.cjs` | Path to a project-local `redis-server` binary compiled with TLS support. When set, `start-server.cjs` prefers this over the system Redis. |

---

## Database (Postgres)

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `DATABASE_URL` | unset | `server/database/database.js`, `scripts/start-server.cjs` | Primary Postgres connection string. When set, all other DB connection parameters are ignored and this URL is used directly. |
| `PGHOST` | `(localhost)` | `server/database/database.js`, `scripts/start-server.cjs` | Host for Postgres when `DATABASE_URL` is not set. |
| `PGPORT` | `(5432)` | same as above | Port for Postgres when `DATABASE_URL` is not set. |
| `PGDATABASE` | `(Qor)` | `server/database/database.js`, `scripts/start-server.cjs` | Database name in fallback/local mode; also used when auto-creating a database via `sudo -u postgres`. |
| `PGUSER` | current OS user | `server/database/database.js`, `scripts/start-server.cjs` | Fallback Postgres user when `DATABASE_USER` is not set. |
| `PGPASSWORD` | unset | `server/database/database.js`, `scripts/start-server.cjs` | Fallback Postgres password when `DATABASE_PASSWORD` is not set. |
| `DATABASE_USER` | unset | `server/database/database.js`, `scripts/start-server.cjs` | Preferred Postgres user for local/fallback connections when `DATABASE_URL` is not set. |
| `DATABASE_PASSWORD` | unset | same as above | Preferred Postgres password for local/fallback connections and DB auto-creation. |
| `DB_POOL_MAX` | `(20)` (clamped 1–100) | `server/database/database.js` | Maximum Postgres client pool size. Invalid values are clamped and logged. |
| `DB_IDLE_TIMEOUT` | `(30000)` ms (clamped 1000–300000) | `server/database/database.js` | Idle timeout for Postgres pool connections. |
| `DB_CONNECT_TIMEOUT` | `(2000)` ms (clamped 500–30000) | `server/database/database.js` | Connection timeout for new Postgres connections. |
| `PASSWORD_HASH_PEPPER` | auto-generated if unset | `server/database/database.js`, `server/server.js`, `server/rate-limiting/distributed-rate-limiter.js` | Optional in-memory password hash pepper. When unset, a random pepper is generated and persisted to `PASSWORD_HASH_PEPPER_FILE`. |
| `PASSWORD_HASH_PEPPER_FILE` | `server/config/generated-pepper.txt` | `server/database/database.js` | File path where the password hash pepper is stored when not supplied via env. |
| `USER_ID_SALT` | auto-generated if unset | `server/database/database.js`, `server/server.js`, `server/rate-limiting/distributed-rate-limiter.js`, `server/authentication/token-service.js` | Salt used for user identifier hashing. Generated and persisted to `USER_ID_SALT_FILE` if not provided. |
| `USER_ID_SALT_FILE` | `server/config/generated-user-id-salt.txt` | `server/database/database.js` | File path where the user ID salt is stored when not supplied via env. |
| `DB_FIELD_KEY` | auto-generated if unset | `server/database/database.js`, `server/server.js`, `server/authentication/token-database.js` | Master key for field-level database encryption. Must be at least 32 bytes when provided via env; otherwise a random key is generated and persisted to `DB_FIELD_KEY_FILE`. |
| `DB_FIELD_KEY_FILE` | `server/config/generated-db-field-key.txt` | `server/database/database.js` | File path where the master DB field key is stored when not supplied via env. |

---

## TURN Server (coturn)

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `TURN_EXTERNAL_IP` | auto-detected | `docker/coturn-entrypoint.sh`, `server/server.js` | Public IP address of the TURN server. The entrypoint script attempts to auto-detect this if not set. |
| `TURN_PORT` | `(3478)` | `docker/coturn-entrypoint.sh`, `server/server.js` | UDP/TCP listening port for plain TURN/STUN. |
| `TURNS_PORT` | `(5349)` | `docker/coturn-entrypoint.sh` | TCP listening port for TURN over TLS (TURNS). |
| `TURN_TLS_CERT` | unset | `docker/coturn-entrypoint.sh` | Path to the TLS certificate file for TURNS. If set, this file path (inside the container) is added to the turnserver configuration. |
| `TURN_TLS_KEY` | unset | `docker/coturn-entrypoint.sh` | Path to the TLS private key file for TURNS. |
| `TURN_REALM` | `(turn.local)` | `docker/coturn-entrypoint.sh` | Authentication realm for the TURN server. |
| `TURN_USERNAME` | `(turnuser)` | `docker/coturn-entrypoint.sh`, `server/server.js` | Username for the static TURN credentials. |
| `TURN_PASSWORD` | `(turnpassword)` | `docker/coturn-entrypoint.sh`, `server/server.js` | Password for the static TURN credentials. |
| `TURN_MIN_PORT` | `(49152)` | `docker/coturn-entrypoint.sh` | Start of the UDP relay port range. |
| `TURN_MAX_PORT` | `(65535)` | `docker/coturn-entrypoint.sh` | End of the UDP relay port range. |
| `TURN_HEALTHCHECK_HOST` | unset | `server/server.js` | Hostname or IP to use when the main server checks TURN server connectivity. Useful if `coturn` is unreachable via `TURN_EXTERNAL_IP`. |

---

## Redis, presence, and rate limiting

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `REDIS_URL` | **required** | `server/presence/presence.js`, `server/rate-limiting/distributed-rate-limiter.js`, `scripts/start-server.cjs`, `scripts/start-loadbalancer.cjs`, `server/cluster/auto-loadbalancer.js` | Redis connection URL. Must use `rediss://` with TLS; plaintext `redis://` is treated as an error in production paths. |
| `REDIS_CLUSTER_NODES` | unset | `server/presence/presence.js` | Comma-separated `host:port` list enabling ioredis cluster mode for presence and messaging when set. |
| `REDIS_USERNAME` | unset | `server/presence/presence.js`, `server/rate-limiting/distributed-rate-limiter.js` | Redis ACL username used for both presence and rate limiter clients. |
| `REDIS_PASSWORD` | unset | same as above | Redis ACL password. |
| `REDIS_POOL_MIN` | `(4)` (clamped 1–100) | `server/presence/presence.js` | Minimum number of Redis connections in the generic-pool-based client pool. |
| `REDIS_POOL_MAX` | `(50)` (clamped 10–500) | same as above | Maximum number of Redis connections in the pool. |
| `REDIS_POOL_ACQUIRE_TIMEOUT` | `(15000)` ms (clamped 1000–60000) | same as above | Timeout for acquiring a Redis client from the pool. |
| `REDIS_POOL_IDLE_TIMEOUT` | `(30000)` ms (clamped 10000–120000) | same as above | Idle timeout for pooled Redis clients. |
| `REDIS_POOL_EVICTION_INTERVAL` | `(60000)` ms (clamped 10000–120000) | same as above | Interval for evicting idle Redis connections from the pool. |
| `REDIS_CONNECT_TIMEOUT` | `(15000)` ms (clamped 1000–60000) | `server/presence/presence.js` | Network connection timeout for Redis clients. |
| `REDIS_COMMAND_TIMEOUT` | `(10000)` ms (clamped 1000–30000) | `server/presence/presence.js` | Timeout for individual Redis commands. |
| `REDIS_DUPLICATE_POOL_MAX` | `(5)` (clamped 1–20) | `server/presence/presence.js` | Upper bound on duplicate Redis connections used for pub/sub and specialized operations. |
| `PRESENCE_REDIS_QUIET_ERRORS` | `('true')` in load balancer, else `('false')` | `server/presence/presence.js`, `scripts/start-loadbalancer.cjs` | When `'true'`, repeated identical Redis errors are throttled and logged less frequently. Load balancer startup enforces `'true'` by default. |
| `REDIS_ERROR_THROTTLE_MS` | `(5000)` ms (clamped 1000–60000) | `server/presence/presence.js` | Minimum interval before the same Redis error message is logged again when `PRESENCE_REDIS_QUIET_ERRORS` is enabled. |
| `RATE_LIMIT_REDIS_URL` | unset → falls back to `REDIS_URL` | `server/rate-limiting/distributed-rate-limiter.js` | Redis URL override specifically for the distributed rate limiter. Must also use `rediss://`. |
| `RATE_LIMIT_REDIS_CONNECT_TIMEOUT` | `(10000)` ms (clamped 1000–60000) | `server/rate-limiting/distributed-rate-limiter.js` | Connection timeout for the rate limiter Redis client. |
| `REDIS_CA_CERT_PATH` | unset | `server/presence/presence.js`, `server/rate-limiting/distributed-rate-limiter.js` | Path to Redis CA certificate used to validate the Redis server's TLS certificate. When set, enables full mutual TLS for Redis connections. In Docker environments, typically `/app/redis-certs/redis-ca.crt`. |
| `REDIS_CLIENT_CERT_PATH` | unset | same as above | Path to client certificate used for mutual TLS authentication with Redis. Required when Redis is configured with `--tls-auth-clients yes`. In Docker, typically `/app/redis-certs/redis-client.crt`. |
| `REDIS_CLIENT_KEY_PATH` | unset | same as above | Path to client private key corresponding to `REDIS_CLIENT_CERT_PATH`. Used for mutual TLS authentication with Redis. In Docker, typically `/app/redis-certs/redis-client.key`. |

**Note:** in security-sensitive code paths, `REDIS_URL` and `RATE_LIMIT_REDIS_URL` must use TLS (`rediss://`).

---

## Authentication, tokens, and key material

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `KEY_ENCRYPTION_SECRET` | **required** (≥32 characters) | `server/authentication/token-service.js`, `server/crypto/unified-key-encryption.js`, `scripts/start-server.cjs` | High-entropy secret used as input to Argon2id to derive the key-encryption key (KEK) for server-side private key protection and token integrity keys. |
| `MAX_ACTIVE_REFRESH_TOKENS` | `(2)` (clamped 1–10) | `server/authentication/token-database.js` | Per-user cap on active refresh tokens. When exceeded, older tokens are revoked or issuance is rejected. |
| `SERVER_PASSWORD_HASH` | unset | `server/authentication/auth-utils.js`, `server/cluster/cluster-manager.js` | Argon2id hash string for the server password. When set, used directly without hashing `SERVER_PASSWORD`. Also propagated into cluster shared configuration. |
| `SERVER_PASSWORD` | unset | `server/authentication/auth-utils.js` | Plaintext server password. On startup, hashed using the server’s Argon2 parameters; the hash is stored in memory and `SERVER_PASSWORD` is removed from `process.env`. |
| `DEVICE_BINDING_SECRET` | auto-generated file when unset | `server/authentication/token-middleware.js` | Secret material for deterministic device binding HMACs. If not set, a random secret is generated and persisted at `server/config/device_binding.secret`. |
| `DEVICE_ID_KEY` | `('derive-device-id-key')` | `server/authentication/authentication.js` | Secret key used to derive a deterministic device ID from connection metadata using BLAKE3. When unset, a built-in constant string is used. |
| `AUTH_AUDIT_HMAC_KEY` | auto-generated file when unset | `server/authentication/token-security.js` | HMAC key for protecting the integrity of authentication audit log events. When unset, a random key is created and stored at `server/config/auth_audit.hmac`. |
| `TOKEN_PEPPER` | auto-generated file when unset | `server/authentication/token-database.js` | HMAC pepper used when hashing refresh tokens for storage. If unset or too short, a random pepper is created and stored at `server/config/token.pepper`. |
| `INSTANCE_ID` | `('default')` | `server/authentication/token-security.js`, Electron preload | Logical instance identifier used in distributed security events published via Redis and exposed in the Electron renderer. |
| `SESSION_STORE_KEY` | **required** (≥32 bytes after decoding) | `server/session/pq-session-storage.js`, `scripts/start-server.cjs` | Master secret used to derive encryption keys for PQ WebSocket session keys stored in Redis. `start-server.cjs` generates and persists a random value at `server/config/secrets/SESSION_STORE_KEY` if unset. |

Several of these secrets (`KEY_ENCRYPTION_SECRET`, `TOKEN_PEPPER`, `AUTH_AUDIT_HMAC_KEY`, `SESSION_STORE_KEY`, `PASSWORD_HASH_PEPPER`, `USER_ID_SALT`, `DB_FIELD_KEY`) are persisted to files under `server/config` when not provided via env; losing both the environment values and those files will render encrypted data unrecoverable.

---

## Cryptography configuration and logging

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `ARGON2_TIME` | `(4)` (clamped 3–10) | `server/crypto/unified-crypto.js`, `server/authentication/token-service.js` | Argon2id time cost (iterations) for password hashing and data hashing. Values outside the range are clamped. |
| `ARGON2_MEMORY` | `(262144)` KiB (256 MiB; clamped 131072–1048576) | same as above | Argon2id memory cost used by the unified crypto layer. |
| `ARGON2_PARALLELISM` | `(2)` (clamped 1–16) | same as above | Argon2id parallelism parameter. |
| `UNIFIED_ARGON2_MEMORY` | `(262144)` KiB (clamped 131072–524288) | `server/crypto/unified-key-encryption.js` | Argon2id memory cost used specifically for key-encryption master key derivation. |
| `UNIFIED_ARGON2_TIME` | `(4)` (clamped 2–8) | same as above | Argon2id time cost for key-encryption master key derivation. |
| `UNIFIED_ARGON2_PARALLELISM` | `(2)` (clamped 1–8) | same as above | Argon2id parallelism for key-encryption master key derivation. |
| `CRYPTO_DEBUG` | `('false')` | `server/crypto/crypto-logger.js`, `server/authentication/token-service.js` | When `'true'`, enables verbose cryptographic debugging logs (key lengths, verification outcomes) in selected modules. |
| `CRYPTO_LOG_LEVEL` | `(debug if CRYPTO_DEBUG=true, else 'info')` | `server/crypto/crypto-logger.js` | Minimum severity for the crypto logger (`debug`, `info`, `warn`, `error`). |
| `COMPAT_DEBUG` | `('false')` | `server/crypto/helpers.js` | When `'true'`, prints extra diagnostics in compatibility helpers (e.g., key and signature lengths) to aid debugging. |

---

## Clustering, HAProxy, and load balancer

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `HAPROXY_HTTPS_PORT` | if root: `(443)`, else `(8443)` | `scripts/start-loadbalancer.cjs`, `server/cluster/haproxy-config-generator.js`, `server/cluster/auto-loadbalancer.js`, `scripts/simple-tunnel.cjs` | External HTTPS listen port for the HAProxy load balancer. |
| `HAPROXY_HTTP_PORT` | if root: `(80)`, else `(8080)` | same as above | Optional HTTP listen port used to redirect HTTP to HTTPS. |
| `HAPROXY_STATS_PORT` | `(8404)` | same as above | Port for the HAProxy statistics dashboard. |
| `HAPROXY_STATS_USERNAME` | `'admin'` when first created | `scripts/start-loadbalancer.cjs`, `server/cluster/haproxy-config-generator.js`, `server/cluster/auto-loadbalancer.js` | Username for the HAProxy stats HTTP interface and the PQ command-encryption keypair. When unset, tooling loads it from encrypted credentials or initializes it to `admin`. |
| `HAPROXY_STATS_PASSWORD` | generated or prompted when first created | same as above | Password for the HAProxy stats HTTP interface and PQ command-encryption keypair. When unset, tooling either unlocks the stored value or prompts/generates a strong random password and stores it encrypted under `server/config/.haproxy-*`. |
| `HAPROXY_CERT_PATH` | `server/config/certs` (generator) or `/etc/haproxy/certs` (auto-LB) | `server/cluster/haproxy-config-generator.js`, `server/cluster/auto-loadbalancer.js` | Directory containing certificates used by HAProxy for TLS termination. |
| `HAPROXY_CERT_FILE` | `cert.pem` inside `HAPROXY_CERT_PATH` | `server/cluster/haproxy-config-generator.js` | Specific certificate file that the generated HAProxy config should reference. |
| `HAPROXY_CONFIG_PATH` | `/etc/haproxy/haproxy-auto.cfg` when root; temp file otherwise | `server/cluster/cluster-integration.js`, `server/cluster/auto-loadbalancer.js` | Path to the HAProxy configuration file written and reloaded by cluster tools. |
| `HAPROXY_PID_FILE` | `/var/run/haproxy-auto.pid` when root; temp file otherwise | `server/cluster/auto-loadbalancer.js`, `server/cluster/haproxy-config-generator.js` | PID file used to detect and control the HAProxy process. |
| `HAPROXY_STATS_SOCKET` | `${TMPDIR}/haproxy-admin-<uid>.sock` | `server/cluster/haproxy-config-generator.js`, `server/cluster/auto-loadbalancer.js` | Unix domain socket path for HAProxy admin commands. Can be overridden explicitly. |
| `LOADBALANCER_LOCK_FILE` | `/var/run/auto-loadbalancer.pid` when root; temp file otherwise | `server/cluster/auto-loadbalancer.js` | Lock file ensuring only one auto-loadbalancer process is running. |
| `HAPROXY_AUTO_CONFIG` | `('false')` | `server/cluster/cluster-integration.js` | When `'true'` and this node is primary, cluster integration automatically writes HAProxy configuration from Redis cluster state. |
| `HAPROXY_AUTO_RELOAD` | `('false')` | `server/cluster/cluster-integration.js` | When `'true'`, HAProxy is automatically validated and reloaded after configuration updates. |
| `HAPROXY_UPDATE_INTERVAL` | `(60000)` ms | `server/cluster/cluster-integration.js` | Interval for periodic HAProxy configuration regeneration in the primary node. |
| `HAPROXY_BIN` | `('haproxy')` | `server/cluster/auto-loadbalancer.js` | Name or path of the HAProxy binary used by the auto-loadbalancer process. |
| `LB_HAPROXY_BIN` | derived | `scripts/start-loadbalancer.cjs`, `server/cluster/auto-loadbalancer.js` | Effective HAProxy binary to run (system or project-built), chosen after config validation. |
| `HAPROXY_VERSION` | `(3.2.0)` | `scripts/build-quantum-haproxy.cjs` | HAProxy source version to download and compile for the quantum build. |
| `CLUSTER_API_URL` | `(https://localhost:3000/api/cluster)` | `server/cluster/cluster-cli.js` | Base URL for the cluster management HTTP API used by the CLI tool. |
| `CLUSTER_ADMIN_TOKEN` | **required** | `server/cluster/cluster-cli.js` | Static admin token used by the CLI to authenticate cluster management operations. |

---

## Redis TLS helper, quantum OpenSSL, and build tooling

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `REDIS_SERVER_BIN` | `('redis-server')` | `scripts/start-server.cjs` | Name or path of the system Redis server binary used when no project-local TLS Redis is configured. |
| `REDIS_TLS_SOURCE_URL` | `https://download.redis.io/releases/redis-7.2.5.tar.gz` | `scripts/install-deps.cjs` | Source tarball URL for building a local TLS-enabled `redis-server` when needed. |
| `OQS_PROVIDER_MODULE` | auto-detected or user-provided path | `scripts/setup-quantum-haproxy.cjs`, `scripts/build-quantum-haproxy.cjs`, `scripts/start-loadbalancer.cjs` | Absolute path to the Open Quantum Safe (`oqsprovider`) module for OpenSSL. Overrides the auto-detected path for quantum TLS. |
| `OQS_SIG` | unset | `scripts/setup-quantum-haproxy.cjs` | Optional preferred PQ signature algorithm name for generating PQ-only certificates (for future use). |
| `FORCE_REBUILD` | `('0')` | `scripts/install-deps.cjs`, `scripts/build-quantum-haproxy.cjs`, `scripts/start-loadbalancer.cjs` | When `'1'`, forces rebuilding quantum dependencies such as `liboqs` or `oqs-provider` even if existing installations are detected. |

---

## Scripts and testing helpers

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `NODE_TLS_REJECT_UNAUTHORIZED` | set to `'0'` within script | `scripts/run-artillery.cjs` | Artillery runner sets this to `0` in its own environment to allow self-signed certificates during load tests. Not used by the main server directly. |
| `CLOUDFLARED_TOKEN` | unset | `scripts/simple-tunnel.cjs` | Optional Cloudflare Tunnel token. When set, creates a persistent tunnel using this token. If unset, a quick tunnel (trycloudflare.com) is created. |

---

## Tailscale, Tor, and network tooling

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `TAILSCALE_HOSTNAME` | `('Qor-chat')` (JSON-encoded in `.env`) | `scripts/generate_ts_tls.cjs` | Device name requested from Tailscale when issuing a TLS certificate. |
| `TS_AUTHKEY` | **required** for Tailscale certificate generation | `scripts/generate_ts_tls.cjs` | Tailscale auth key used to authenticate the node when requesting TLS certificates via `tailscale cert`. |
| `TOR_VERSION` | `(15.0a4)` | `electron/prepare-tor-bundles.cjs` | Tor Browser expert bundle version to download for Electron packaging. |
| `TOR_BASE_URL` | `https://dist.torproject.org/torbrowser/${TOR_VERSION}` | `electron/prepare-tor-bundles.cjs` | Base URL for Tor bundle and checksum downloads. |

---

## Web client (Vite) and development

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `VITE_WS_URL` | unset | `src/components/setup/ConnectSetup.tsx`, `src/lib/cluster-key-manager.ts`, Electron main | Base WebSocket URL for the web client (e.g. `wss://localhost:8443`). Used both in browser and Electron contexts. |
| `VITE_PORT` | `(5173)` | `start-client.cjs` | Port on which the Vite dev server listens during local development. |

---

## Electron desktop client

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `ELECTRON_INSTANCE_ID` | unset → `'1'` | `electron/main.cjs`, `electron/preload.cjs` | When set, each instance uses a separate `userData` directory (`<base>-instance-<id>`) and is exposed to the renderer as `electronAPI.instanceId`. |
| `INSTANCE_ID` | unset → `'1'` in preload | `electron/preload.cjs`, `server/authentication/token-security.js` | Generic instance identifier used by Electron and embedded in distributed security events; the preload script falls back to this when `ELECTRON_INSTANCE_ID` is not set. |

---

## Client launcher (start-client.cjs)

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `START_ELECTRON` | `(1)` | `start-client.cjs` | When set to `0`, runs only the Vite dev server without starting Electron. |
| `FORCE_ELECTRON_REBUILD` | unset | `start-client.cjs` | When set (any non-empty value), forces `@electron/rebuild` to rebuild native modules for the current Electron version even if a cache marker exists. |

---

## Notes

- Secrets and key material are often auto-generated and persisted under `server/config` if not provided via environment variables.
- `REDIS_URL` is required for normal operation; presence, rate limiting, PQ session storage, and cluster coordination all depend on Redis.
- TLS certificate paths (`TLS_CERT_PATH`, `TLS_KEY_PATH`) must be configured explicitly; separate scripts can be used to obtain certificates (for example, via Tailscale).
