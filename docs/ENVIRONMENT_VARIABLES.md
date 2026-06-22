# Environment variables

This document lists environment variables recognized by the app

Values shown in parentheses indicate typical defaults when the variable is unset.

---

## Server core and networking

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `PORT` | `(8443)` or `dynamic` | `server/config/config.js`, `server/server.js`, `scripts/start-server.cjs`, `server/cluster/cluster-manager.js` | HTTPS listen port. `dynamic` is treated as port `0` (kernel-assigned). When started via `scripts/start-server.cjs`, a free port is auto-selected if `PORT` is empty. |
| `BIND_ADDRESS` | `(127.0.0.1)` | `server/bootstrap/server-bootstrap.js`, `server/server.js`, `scripts/start-server.cjs` | IP/interface the HTTPS server binds to. Must be a loopback address (`127.0.0.1`, `::1`, or `localhost`) or startup will fail. |
| `ALLOWED_CORS_ORIGINS` | `('http://localhost:5173,http://127.0.0.1:5173')` | `scripts/start-server.cjs`, `server/config/constants.js` | Comma-separated list of allowed CORS origins for HTTP and WebSocket requests. Parsed into `CORS_CONFIG.ALLOWED_ORIGINS`. When unset, the launcher provides localhost defaults. |
| `WS_BANDWIDTH_QUOTA_BYTES` | `(536870912)` | `server/config/constants.js`, `server/websocket/gateway.js` | Per-window WebSocket byte budget. The minimum is clamped to 512 MiB because active opaque PIR sends many large encrypted query envelopes. |
| `WS_BANDWIDTH_WINDOW_MS` | `(60000)` ms | same as above | Window duration for the WebSocket byte budget. |
| `SERVER_ID` | auto-generated (`server-<hostname>-<timestamp>` when using `start-server.cjs`) | `server/server.js`, `server/session/pq-session-storage.js`, `server/messaging/pq-envelope-handler.js`, `server/websocket/gateway.js`, `server/cluster/*` | Logical identifier for this server instance, used in logs, PQ envelopes, WebSocket delivery, and cluster registration. |
| `SERVER_HOST` | empty  auto-detected IP | `scripts/start-server.cjs`, `server/cluster/cluster-manager.js` | Public host/IP advertised to the cluster and HAProxy. When empty, `start-server.cjs` resolves the first non-loopback address or falls back to `127.0.0.1`. |
| `HOST` | OS hostname | `server/cluster/cluster-manager.js` | Fallback hostname used when `SERVER_HOST` is not set. |
| `HOSTNAME` | OS hostname | `server/cluster/cluster-integration.js` | Used when generating a random server ID for clustering if `SERVER_ID` is not provided. |
| `ENABLE_CLUSTERING` | `('true')` | `scripts/start-server.cjs`, `server/server.js`, `server/authentication/auth-utils.js` | Enables Redis-backed clustering and HAProxy integration when set to `'true'`. |
| `CLUSTER_WORKERS` | `('1')` | `scripts/start-server.cjs`, `server/bootstrap/server-bootstrap.js` | Number of Node worker processes. Values >1 enable clustered workers on a single machine. |
| `CLUSTER_PRIMARY` | empty | `scripts/start-server.cjs`, `server/cluster/cluster-integration.js`, `server/server.js` | When `'true'`, forces this node to act as primary cluster node. If unset, primary status is chosen based on Redis state. |
| `CLUSTER_AUTO_APPROVE` | `('true')` | `scripts/start-server.cjs`, `server/cluster/cluster-integration.js`, `server/server.js` | When `'true'`, new cluster nodes are automatically approved instead of requiring manual approval. |
| `SERVER_ROLE` | empty | `server/cluster/cluster-integration.js` | Optional alternative for marking a node as `primary` (`SERVER_ROLE=primary`) during cluster initialization. |
| `NO_GUI` | `('false')` | `scripts/start-server.cjs`, `scripts/start-loadbalancer.cjs` | When `'true'`, disables the interactive TUI for the server or load balancer. Processes run in standard console mode. |
| `USE_REDIS` | `('true')` | `scripts/start-server.cjs` | Launcher flag read by `scripts/start-server.cjs` and forwarded into the server environment for Redis-related configuration. |
| `DISABLE_CONNECTION_LIMIT` | `('true')` | `scripts/start-server.cjs` | Launcher flag forwarded into the server environment. Named for configuration of global connection limiting. |
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
| `REDIS_TLS_SERVERNAME` | derived from HTTPS certificate when possible | `server/session/redis-client.js`, `server/rate-limiting/distributed-rate-limiter.js`, `scripts/start-server.cjs` | SNI hostname used for TLS connections to Redis. When unset and a local TLS Redis is used, `start-server.cjs` derives it from the HTTPS certificate CN. |
| `OPENSSL_CONF` | unset | `scripts/setup-quantum-haproxy.cjs`, `scripts/build-quantum-haproxy.cjs`, `scripts/start-loadbalancer.cjs`, `scripts/start-server.cjs`, `server/load-balancer/auto-loadbalancer.js` | OpenSSL configuration file. Quantum scripts set this to a local `openssl-oqs.cnf` that loads the OQS provider for PQ TLS. |
| `OPENSSL_MODULES` | unset | same as above | Directory containing OpenSSL provider modules. Set by quantum setup scripts so the `oqsprovider` module can be loaded. |
| `LD_LIBRARY_PATH` | unset | `scripts/setup-quantum-haproxy.cjs`, `scripts/build-quantum-haproxy.cjs`, `server/cluster/haproxy-config-generator.js`, `server/load-balancer/auto-loadbalancer.js` | Library search path used when invoking `haproxy` or OpenSSL with the PQ provider installed in non-standard locations. |
| `LB_OPENSSL_CONF` | derived from `OPENSSL_CONF` | `scripts/start-loadbalancer.cjs`, `server/load-balancer/auto-loadbalancer.js` | OpenSSL configuration used by the load balancer process. Normally set by `scripts/start-loadbalancer.cjs` to point at `server/config/openssl-oqs.cnf`. |
| `LB_HAPROXY_CFG` | derived (`server/config/haproxy-quantum.cfg`) | `scripts/start-loadbalancer.cjs`, `server/load-balancer/auto-loadbalancer.js` | Path to the quantum-enabled HAProxy configuration used by the auto-loadbalancer. |
| `TLS_REDIS_SERVER` | auto-written by `scripts/install-deps.cjs` | `scripts/start-server.cjs` | Path to a project-local `redis-server` binary compiled with TLS support. When set, `start-server.cjs` prefers this over the system Redis. |

---

## Database (Postgres)

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `DATABASE_URL` | unset | `server/database/database.js`, `scripts/start-server.cjs` | Primary Postgres connection string. When set, all other DB connection parameters are ignored and this URL is used directly. |
| `PGHOST` | `(localhost)` | `server/database/database.js`, `scripts/start-server.cjs` | Host for Postgres when `DATABASE_URL` is not set. |
| `PGPORT` | `(5432)` | same as above | Port for Postgres when `DATABASE_URL` is not set. |
| `PGDATABASE` | `(Qor)` | `server/database/database.js`, `scripts/start-server.cjs` | Database name in fallback/local mode. Also used when auto-creating a database via `sudo -u postgres`. |
| `PGUSER` | current OS user | `server/database/database.js`, `scripts/start-server.cjs` | Fallback Postgres user when `DATABASE_USER` is not set. |
| `PGPASSWORD` | unset | `server/database/database.js`, `scripts/start-server.cjs` | Fallback Postgres password when `DATABASE_PASSWORD` is not set. |
| `DATABASE_USER` | unset | `server/database/database.js`, `scripts/start-server.cjs` | Preferred Postgres user for local/fallback connections when `DATABASE_URL` is not set. |
| `DATABASE_PASSWORD` | unset | same as above | Preferred Postgres password for local/fallback connections and DB auto-creation. |
| `PASSWORD_HASH_PEPPER` | unset | `server/rate-limiting/distributed-rate-limiter.js` | Optional fallback HMAC pepper for hashing IP-based rate-limit keys when `USER_ID_SALT` is unavailable. |
| `USER_ID_SALT` | auto-generated if unset | `server/database/database.js`, `server/server.js`, `server/rate-limiting/distributed-rate-limiter.js`, `server/authentication/token-service.js` | Salt used for user identifier hashing. Generated and persisted to `USER_ID_SALT_FILE` if not provided. |
| `USER_ID_SALT_FILE` | `server/config/generated-user-id-salt.txt` | `server/database/database.js` | File path where the user ID salt is stored when not supplied via env. |
| `DB_FIELD_KEY` | auto-generated if unset | `server/database/database.js`, `server/server.js`, `server/authentication/token-database.js` | Master key for field-level database encryption. Must be at least 32 bytes when provided via env. Otherwise a random key is generated and persisted to `DB_FIELD_KEY_FILE`. |
| `DB_FIELD_KEY_FILE` | `server/config/generated-db-field-key.txt` | `server/database/database.js` | File path where the master DB field key is stored when not supplied via env. |

---

## Redis, presence, and rate limiting

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `REDIS_URL` | **required** | `server/session/redis-client.js`, `server/rate-limiting/distributed-rate-limiter.js`, `scripts/start-server.cjs`, `scripts/start-loadbalancer.cjs`, `server/load-balancer/auto-loadbalancer.js` | Redis connection URL. Must use `rediss://` with TLS. Plaintext `redis://` is treated as an error. |
| `REDIS_CLUSTER_NODES` | unset | `server/session/redis-client.js` | Comma-separated `host:port` list enabling ioredis cluster mode for presence and messaging when set. |
| `REDIS_USERNAME` | unset | `server/session/redis-client.js`, `server/rate-limiting/distributed-rate-limiter.js` | Redis ACL username used for both presence and rate limiter clients. |
| `REDIS_PASSWORD` | unset | same as above | Redis ACL password. |
| `REDISCLI_AUTH` | derived from `REDIS_URL` | `scripts/start-server.cjs` | Used to securely pass the Redis password to `redis-cli`, preventing the "insecure password" warning in TUI/logs. |
| `REDIS_POOL_MIN` | `(4)` (clamped 1–100) | `server/session/redis-client.js` | Minimum number of Redis connections in the generic-pool-based client pool. |
| `REDIS_POOL_MAX` | `(50)` (clamped 10–500) | same as above | Maximum number of Redis connections in the pool. |
| `REDIS_POOL_ACQUIRE_TIMEOUT` | `(15000)` ms (clamped 1000–60000) | same as above | Timeout for acquiring a Redis client from the pool. |
| `REDIS_POOL_IDLE_TIMEOUT` | `(30000)` ms (clamped 10000–120000) | same as above | Idle timeout for pooled Redis clients. |
| `REDIS_POOL_EVICTION_INTERVAL` | `(60000)` ms (clamped 10000–120000) | same as above | Interval for evicting idle Redis connections from the pool. |
| `REDIS_CONNECT_TIMEOUT` | `(15000)` ms (clamped 1000–60000) | `server/session/redis-client.js` | Network connection timeout for Redis clients. |
| `REDIS_COMMAND_TIMEOUT` | `(10000)` ms (clamped 1000–30000) | `server/session/redis-client.js` | Timeout for individual Redis commands. |
| `REDIS_DUPLICATE_POOL_MAX` | `(5)` (clamped 1–20) | `server/session/redis-client.js` | Upper bound on duplicate Redis connections used for pub/sub and specialized operations. |
| `PRESENCE_REDIS_QUIET_ERRORS` | `('true')` in load balancer, else `('false')` | `server/session/redis-client.js`, `scripts/start-loadbalancer.cjs` | When `'true'`, repeated identical Redis errors are throttled and logged less frequently. Load balancer startup enforces `'true'` by default. |
| `REDIS_ERROR_THROTTLE_MS` | `(5000)` ms (clamped 1000–60000) | `server/session/redis-client.js` | Minimum interval before the same Redis error message is logged again when `PRESENCE_REDIS_QUIET_ERRORS` is enabled. |
| `RATE_LIMIT_REDIS_URL` | unset → falls back to `REDIS_URL` | `server/rate-limiting/distributed-rate-limiter.js` | Redis URL override specifically for the distributed rate limiter. Must also use `rediss://`. |
| `RATE_LIMIT_REDIS_CONNECT_TIMEOUT` | `(10000)` ms (clamped 1000–60000) | `server/rate-limiting/distributed-rate-limiter.js` | Connection timeout for the rate limiter Redis client. |
| `REDIS_CA_CERT_PATH` | unset | `server/session/redis-client.js`, `server/rate-limiting/distributed-rate-limiter.js` | Path to Redis CA certificate used to validate the Redis server's TLS certificate. When set, enables full mutual TLS for Redis connections. In Docker environments, typically `/app/redis-certs/redis-ca.crt`. |
| `REDIS_CLIENT_CERT_PATH` | unset | same as above | Path to client certificate used for mutual TLS authentication with Redis. Required when Redis is configured with `--tls-auth-clients yes`. In Docker, typically `/app/redis-certs/redis-client.crt`. |
| `REDIS_CLIENT_KEY_PATH` | unset | same as above | Path to client private key corresponding to `REDIS_CLIENT_CERT_PATH`. Used for mutual TLS authentication with Redis. In Docker, typically `/app/redis-certs/redis-client.key`. |

**Note:** in security-sensitive code paths, `REDIS_URL` and `RATE_LIMIT_REDIS_URL` must use TLS (`rediss://`).

---

## Authentication, tokens, and key material

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `KEY_ENCRYPTION_SECRET` | **required** (≥32 characters) | `server/authentication/token-service.js`, `server/crypto/unified-key-encryption.js`, `scripts/start-server.cjs` | High-entropy secret used as input to Argon2id to derive the key-encryption key (KEK) for server-side private key protection and token integrity keys. |
| `SERVER_PASSWORD` | unset (**required** for blind server entry) | `server/authentication/auth-utils.js` | Plaintext server password. On startup it is hashed, the gatekeeper is initialized with the plaintext (the actual verifier of blind server-entry submissions), the hash is kept in memory, and `SERVER_PASSWORD` is then deleted from `process.env`. A server with no plaintext password (and not joining an existing cluster) refuses to boot. |
| `SERVER_PASSWORD_HASH` | set internally | `server/authentication/auth-utils.js`, `server/cluster/cluster-manager.js` | **Not a user boot option.** The server derives this from the plaintext `SERVER_PASSWORD` at boot and shares it into the cluster's Redis config so a secondary node can validate already-granted (Redis-shared) server-entry sessions. A node started with only `SERVER_PASSWORD_HASH` and no plaintext `SERVER_PASSWORD` cannot initialize the gatekeeper, so the legacy hash-only boot path was removed. |
| `SESSION_STORE_KEY` | **required** (≥32 bytes after decoding) | `server/session/pq-session-storage.js`, `scripts/start-server.cjs` | Master secret used to derive encryption keys for PQ WebSocket session keys stored in Redis. `start-server.cjs` generates and persists a random value at `server/config/secrets/SESSION_STORE_KEY` if unset. |
| `BLIND_SIGNATURE_KEY_PATH` | auto-generated file when unset | `server/security/blind-signatures.js` | Path to the blind-signature keypair used to issue/verify the anonymous server-entry tokens (the gatekeeper). A keypair is generated and persisted here on first boot if absent. |
| `PQ_SESSION_CACHE_MAX` | `(5000)` (clamped 0–50000) | `server/session/pq-session-storage.js` | Max number of decrypted PQ WebSocket sessions kept in the in-memory LRU (Redis is the source of truth. This bounds RAM). |
| `PQ_SESSION_CACHE_TTL_MS` | `(300000)` ms (clamped 1000–3600000) | `server/session/pq-session-storage.js` | TTL for cached in-memory PQ sessions before they are dropped and re-loaded from Redis. |

Several of these secrets (`KEY_ENCRYPTION_SECRET`, `SESSION_STORE_KEY`, `USER_ID_SALT`, `DB_FIELD_KEY`) are persisted to files under `server/config` when not provided via env. Losing both the environment values and those files will render encrypted data unrecoverable.

---

## Cryptography configuration and logging

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `ARGON2_TIME` | `(4)` (clamped 3–10) | `server/crypto/unified-crypto.js`, `server/authentication/token-service.js` | Argon2id time cost (iterations) for password hashing and data hashing. Values outside the range are clamped. |
| `ARGON2_MEMORY` | `(262144)` KiB (256 MiB. Clamped 131072–1048576) | same as above | Argon2id memory cost used by the unified crypto layer. |
| `ARGON2_PARALLELISM` | `(2)` (clamped 1–16) | same as above | Argon2id parallelism parameter. |
| `UNIFIED_ARGON2_MEMORY` | `(262144)` KiB (clamped 131072–524288) | `server/crypto/unified-key-encryption.js` | Argon2id memory cost used specifically for key-encryption master key derivation. |
| `UNIFIED_ARGON2_TIME` | `(4)` (clamped 2–8) | same as above | Argon2id time cost for key-encryption master key derivation. |
| `UNIFIED_ARGON2_PARALLELISM` | `(2)` (clamped 1–8) | same as above | Argon2id parallelism for key-encryption master key derivation. |
| `CRYPTO_LOG_LEVEL` | `('warn')` | `server/crypto/crypto-logger.js` | Minimum severity for the crypto logger (`warn`, `error`). The app should not emit verbose cryptographic diagnostics. |

---

## Discovery and PIR privacy

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `PIR_WORKER_URL` | `(http://127.0.0.1:8787)`, Docker `http://pir-worker:8787` | `server/pir/pir-worker-client.js`, `docker/docker-compose.yml` | URL of the isolated reviewed PIR worker. |
| `PIR_REQUIRE_WORKER` | `('true')` | `server/pir/pir-worker-client.js`, `docker/docker-compose.yml` | When true, server startup and PIR availability fail closed if the worker is unavailable or fails pin validation. |
| `PIR_WORKER_PARAMETER_ID` | `hintless-simplepir-rlwe64-v1` | same as above | Pinned worker parameter id that must match the server and worker health response. |
| `PIR_WORKER_SOURCE_COMMIT` | `49434e086ec56d19546ca6e97353671b690ba19b` | `server/pir/pir-worker-client.js`, `workers/hintless/hintless.lock.json` | Expected upstream `hintless_pir` source commit reported by worker health. |
| `PIR_WORKER_TOKEN` | unset | `server/pir/pir-worker-client.js`, `workers/hintless/src/qor_pir_worker.cc` | Optional bearer token shared between server and PIR worker. |
| `PIR_WORKER_TIMEOUT_MS` | `(300000)` ms | `server/pir/pir-worker-client.js` | Timeout for worker health, upload, public-params, and opaque query requests. |
| `PIR_MAX_QUERY_CHARS` | `(8388608)` | `server/handlers/pir-handlers.js` | Maximum encoded opaque PIR query length accepted by the WebSocket handler. |
| `PIR_WORKER_MAX_UPLOAD_BODY_BYTES` | `(201326592)` bytes | `server/pir/pir-worker-client.js` | Server-side upload body guard for PIR database uploads. If unset, the legacy `PIR_WORKER_MAX_REQUEST_BYTES` value is used as the fallback input. |
| `PIR_WORKER_MAX_RESPONSE_BODY_BYTES` | `(67108864)` bytes | `server/pir/pir-worker-client.js` | Maximum worker response body accepted by the server. |
| `PIR_WORKER_MAX_REQUEST_BYTES` | worker Docker `(268435456)` bytes | `docker/docker-compose.yml`, `workers/hintless/src/qor_pir_worker.cc`, `server/pir/pir-worker-client.js` | Worker-side request limit. Also used as the server upload fallback when `PIR_WORKER_MAX_UPLOAD_BODY_BYTES` is unset. |
| `PIR_WORKER_MAX_DATABASE_BYTES` | worker `(2147483648)` bytes | `workers/hintless/src/qor_pir_worker.cc` | Worker-side decoded database size limit. |
| `PIR_EPOCH_GRACE_MS` | `(7200000)` ms | `server/pir/pir-databases.js` | Grace period for serving a recently-rotated PIR epoch (so an in-flight lookup against the previous epoch still resolves). |
| `DISCOVERY_BUCKET_COUNT` | `(256)` | `server/pir/page-layout.js` | Fixed number of k-anonymity buckets for the discovery keys-blob store. The client derives its own `bucketId = sha256(domain‖epoch‖slotKey) % BUCKET_COUNT` from its OPRF token (the server never sees the token), so this must be a stable, client-agreed constant — it is **not** derived from the record count. |
| `DISCOVERY_BUCKET_TARGET_SIZE` | `(32)` | `server/pir/page-layout.js` | k-anonymity set K — each bucket is padded up to K entries with deterministic, secret-keyed decoys (generated at response time, not stored). A looker fetches its target's whole bucket and decrypt-filters, so the server learns only the bucket (target = 1-of-K). Bigger K = stronger anonymity, more bandwidth (~K × 131 KB/lookup, so K=32 ≈ 4 MB). The padding is generated per request in the `/api/discovery/bucket` handler, so this is a server-side knob (no client rebuild). Note: lookup latency is dominated by Tor round-trips + the `forceFresh` manifest fetch, not bucket size. |
| `DISCOVERY_BUCKET_MAX_IDS` | `(4)` | `server/routes/api-routes.js` | Max bucket ids per `/api/discovery/bucket` request (target + cover buckets). Bounds response size. |
| `DISCOVERY_OPRF_HTTP_MAX_INFLIGHT` | `(8)` | `server/routes/api-routes.js` | Concurrent in-flight cap on the anonymous discovery OPRF-eval HTTP route. Excess gets 503. |
| `DISCOVERY_PIR_HTTP_MAX_INFLIGHT` | `(8)` | `server/routes/api-routes.js` | Concurrent in-flight cap on the anonymous discovery PIR query HTTP route. |
| `OPRF_GLOBAL_MAX_PER_MIN` | `(1200)` | `server/crypto/oprf-discovery.js` | Global (server-wide) cap on discovery OPRF evaluations per rolling minute, on top of the per-session limit. Bounds online username probing through the live OPRF service when an attacker holds many anonymous tokens (the per-token limit doesn't bind a token-rich attacker, but a global cap does). See `docs/app/USERNAME_ENUMERATION_RESISTANCE.md`. |
| `DISCOVERY_BUCKET_MAX_INFLIGHT` | `(8)` | `server/routes/api-routes.js` | Concurrent in-flight cap on the anonymous `/api/discovery/bucket` route. |
| `DISCOVERY_BUCKET_COVER_COUNT` | `(0)` | `src/lib/pir/pir-client.ts` (client const) | Extra random cover buckets fetched alongside the real one. 0 = just the target bucket (K-anonymity). >0 multiplies bandwidth but hides which fetched bucket is real. |
| `YPIR_TIER2_WORKER_URL` | unset (**deprecated**) | `server/pir/ypir-tier2.js`, `docker/docker-compose.yml` | DEPRECATED: the oblivious YPIR tier-2 was removed (PIR can't build a DB for the ~131 KB keys-blob — it OOMs). Replaced by the k-anonymous bucket fetch above. The ypir-worker/`YPIR_*` vars are dormant and slated for removal. |
| `YPIR_BLOB_LEN` | Docker `(131072)` bytes | `docker/docker-compose.yml`, `workers/ypir/src/bin/ypir_worker.rs` | Per-slot byte budget of the YPIR tier-2 record (worker side). Holds only the small discovery keys-blob (the avatar moved to the unlinkable content store), so 128 KiB is generous headroom. Must match `YPIR_TIER2_BLOB_LEN`. |
| `YPIR_TIER2_BLOB_LEN` | Docker `(131072)` bytes | `server/pir/ypir-tier2.js`, `docker/docker-compose.yml` | Server-side mirror of `YPIR_BLOB_LEN`. The per-slot size the server pads keys-blobs to before upload. A keys-blob exceeding this is logged and rejected (so keep both in sync). |
| `YPIR_WORKER_CPUS` | auto (~2/3 cores) | `scripts/start-docker.cjs`, `docker/docker-compose.yml` | CPU cap for the YPIR worker container (mirrors `PIR_WORKER_CPUS`), so a setup spike can't starve the host. |
| `YPIR_MIN_UPLOAD_INTERVAL_MS` | `(60000)` ms | `server/pir/ypir-tier2.js` | Minimum time between YPIR tier-2 DB rebuilds/uploads. The worker is single-threaded and rebuilds the whole SimplePIR DB per upload, so this (plus an in-flight guard) stops overlapping/too-frequent uploads that would reset the connection (`socket hang up`). The DB only needs to be roughly fresh. Tier-1 is unaffected. |
| `AVATAR_HTTP_MAX_INFLIGHT` | `(16)` | `server/routes/api-routes.js` | Concurrent in-flight cap across the anonymous avatar content-store routes (`/api/avatar/blob/put`, `/blob/get`, `/pool`). Excess gets 503. |
| `AVATAR_GET_MAX_BATCH` | `(16)` | `server/routes/api-routes.js` | Max ids per cover-traffic batch fetch (`/api/avatar/blob/get`). Bounds the per-request response size. The client mixes its real target with decoys up to this cap (client default is `AVATAR_COVER_TOTAL_IDS` = 10). Each id returns one uniform-size PURB, so this directly sets the per-lookup bandwidth ceiling. |
| `AVATAR_MISS_SECRET` | per-process random | `server/routes/api-routes.js` | Secret keying the deterministic synthetic "miss" blob so a non-existent id returns an identically-sized, byte-stable, unpredictable response (hits and misses indistinguishable). Set explicitly only to keep misses stable across restarts. |

Client-side avatar cover knobs (compile-time constants in `src/lib/avatar/avatar-store-client.ts`, not env): `AVATAR_COVER_TOTAL_IDS` (k, default 10 — anonymity-set size per fetch and the bandwidth multiplier), `COVER_BLOBS_PER_CLIENT` (default 12 — cover PURBs each client keeps in the pool so k-anonymity holds even with few real users), and `DECOY_CACHE_TTL_MS` (how long a target's stable decoy set is reused, to defeat the set-intersection attack). The avatar PURB size is `AVATAR_PURB_CAPACITY` (256 KiB, in `src/lib/crypto/avatar-blob-crypto.ts`, mirrored by `AVATAR_PURB_WIRE_BYTES` in `server/database/avatar-blob-db.js`).

Hintless SimplePIR has no client hint download. The per-epoch public params
(~350 bytes) ride inline in the PIR manifest.
| `PIR_MANIFEST_INCLUDE_RECORD_DIGESTS` | `('false')` | `server/pir/pir-databases.js` | Optional manifest record digests for tests/audits. Normal clients verify encrypted payload digests and worker database digests. |
| `PIR_MANIFEST_INCLUDE_PAYLOAD_DIGESTS` | `('false')` | `server/pir/pir-databases.js` | Optional payload digest map for tests/audits. |
| `PIR_DISCOVERY_RECORD_FLOOR` | privacy floor | `server/pir/page-layout.js` | Minimum padded record count for the discovery PIR database (anonymity floor). |
| `PIR_DISCOVERY_EPOCH_MS` | `(21600000)` ms | `server/pir/page-layout.js` | Discovery PIR epoch duration (changes only on discovery-membership change). |
| `PIR_DISCOVERY_MAX_SOURCE_RECORDS` | bound | `server/pir/page-layout.js` | Maximum source records admitted before padding/layout for the discovery database. |
| `PIR_DISCOVERY_SLOT_PROBE_COUNT` | `(96)` | `server/pir/page-layout.js` | Deterministic client-side collision probe count for token-derived slots. |

Offline-message retrieval no longer uses computational PIR. The retired opaque
PIR path has been replaced by the uniform spool snapshot. The spool window is
served by:

| `SPOOL_SNAPSHOT_EPOCH_MS` | `(30000)` ms | `server/routing/spool-snapshot-service.js` | Epoch duration for the uniform per-epoch encrypted spool snapshot (cache window). |
| `SPOOL_SNAPSHOT_PADDING_FLOOR` | `(256)` | `server/routing/spool-snapshot-service.js` | Minimum padded entry count (hides the real spool size). |
| `SPOOL_SNAPSHOT_MAX_ROWS` | `(512)` | `server/routing/spool-snapshot-service.js` | Maximum spool envelopes considered for one snapshot before byte-budget trimming. |
| `SPOOL_SNAPSHOT_MAX_PLAINTEXT_BYTES` | `(134217728)` bytes | `server/routing/spool-snapshot-service.js` | Approximate plaintext snapshot budget. Large cover-heavy windows trim rows/padding instead of allocating multi-GB JSON. |
| `SPOOL_SNAPSHOT_GZIP_LEVEL` | `(6)` | `server/routing/spool-snapshot-service.js` | Gzip level for the spool snapshot. |
| `DISCOVERY_SNAPSHOT_EPOCH_MS` | `(600000)` ms | `server/discovery/snapshot-service.js` | Epoch duration for compressed padded discovery snapshots. |
| `DISCOVERY_SNAPSHOT_PADDING_FLOOR` | `(128)` | `server/discovery/snapshot-service.js` | Minimum padded entry count for no-selector discovery snapshots. |
| `DISCOVERY_SNAPSHOT_MAX_ROWS` | `(200000)` | `server/discovery/snapshot-service.js` | Maximum source rows admitted into one discovery snapshot. |
| `DISCOVERY_SNAPSHOT_DUMMY_BLOB_CHARS` | `(2048)` | `server/discovery/snapshot-service.js` | Size of opaque decoy blobs used for snapshot padding. |
| `DISCOVERY_SNAPSHOT_GZIP_LEVEL` | `(9)` | `server/discovery/snapshot-service.js` | Gzip level for snapshot compression. |
| `DISCOVERY_PUBLICATION_DELAY_MIN_MS` | `(2000)` ms | `server/discovery/publication-privacy.js` | Minimum delay before a real discovery publication leaves the Redis delay pool. |
| `DISCOVERY_PUBLICATION_DELAY_MAX_MS` | `(10000)` ms | same as above | Maximum publication delay before relay release. |
| `DISCOVERY_PUBLICATION_FLUSH_MIN_MS` | `(1000)` ms | same as above | Minimum publication relay flush interval. |
| `DISCOVERY_PUBLICATION_FLUSH_MAX_MS` | `(4000)` ms | same as above | Maximum publication relay flush interval. |
| `DISCOVERY_PUBLICATION_BATCH_MAX` | `(32)` | same as above | Maximum delayed publication batch size per flush. |
| `DISCOVERY_PUBLICATION_COVER_WRITES_MIN` | `(1)` | same as above | Minimum cover writes injected with real publication flushes. |
| `DISCOVERY_PUBLICATION_COVER_WRITES_MAX` | `(3)` | same as above | Maximum cover writes injected with real publication flushes. |
| `DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MIN` | `(0)` | same as above | Minimum cover writes during idle relay flushes. |
| `DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MAX` | `(0)` | same as above | Maximum cover writes during idle relay flushes. |
| `DISCOVERY_PUBLICATION_COVER_TOKEN_BATCH_SIZE` | `(122)` | same as above | Number of OPRF-shaped cover tokens per cover publication. |
| `DISCOVERY_PUBLICATION_COVER_BLOB_CHARS` | `(16384)` | same as above | Minimum opaque cover blob size when no larger recent real blob is available. |
| `DISCOVERY_PIR_REFRESH_MIN_INTERVAL_MS` | `(1800000)` ms | `server/discovery/publication-privacy.js` | Minimum interval between opaque PIR database rebuilds after delayed publication batches. Rebuilds are coalesced so clients can reuse downloaded setup. |
| `DISCOVERY_PUBLICATION_COVER_LEASE_MS` | `(2592000000)` ms | same as above | Lease duration used for cover publication material. |
| `DISCOVERY_PUBLICATION_POOL_TTL_SECONDS` | `(604800)` seconds | same as above | Redis TTL for delayed publication pool state. |
| `DISCOVERY_PUBLICATION_REDIS_ENQUEUE_TIMEOUT_MS` | `(2500)` ms | same as above | Timeout for enqueueing delayed publication state. |
| `DISCOVERY_PUBLICATION_REDIS_FLUSH_TIMEOUT_MS` | `(3000)` ms | same as above | Timeout for relay flush Redis operations. |

---

## Clustering, HAProxy, and load balancer

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `HAPROXY_HTTPS_PORT` | if root: `(443)`, else `(8443)` | `scripts/start-loadbalancer.cjs`, `server/cluster/haproxy-config-generator.js`, `server/load-balancer/auto-loadbalancer.js`, `scripts/simple-tunnel.cjs` | External HTTPS listen port for the HAProxy load balancer. |
| `HAPROXY_STATS_PORT` | `(8404)` | same as above | Port for the HAProxy statistics dashboard. |
| `HAPROXY_STATS_USERNAME` | `'admin'` when first created | `scripts/start-loadbalancer.cjs`, `server/cluster/haproxy-config-generator.js`, `server/load-balancer/auto-loadbalancer.js` | Username for the HAProxy stats HTTP interface and the PQ command-encryption keypair. When unset, tooling loads it from encrypted credentials or initializes it to `admin`. |
| `HAPROXY_STATS_PASSWORD` | generated or prompted when first created | same as above | Password for the HAProxy stats HTTP interface and PQ command-encryption keypair. When unset, tooling either unlocks the stored value or prompts/generates a strong random password and stores it encrypted under `server/config/.haproxy-*`. |
| `HAPROXY_CERT_PATH` | `server/config/certs` (generator) or `/etc/haproxy/certs` (auto-LB) | `server/cluster/haproxy-config-generator.js`, `server/load-balancer/auto-loadbalancer.js` | Directory containing certificates used by HAProxy for TLS termination. |
| `HAPROXY_CERT_FILE` | `cert.pem` inside `HAPROXY_CERT_PATH` | `server/cluster/haproxy-config-generator.js` | Specific certificate file that the generated HAProxy config should reference. |
| `HAPROXY_CONFIG_PATH` | `/etc/haproxy/haproxy-auto.cfg` when root. Temp file otherwise | `server/cluster/cluster-integration.js`, `server/load-balancer/auto-loadbalancer.js` | Path to the HAProxy configuration file written and reloaded by cluster tools. |
| `HAPROXY_PID_FILE` | `/var/run/haproxy-auto.pid` when root. Temp file otherwise | `server/load-balancer/auto-loadbalancer.js`, `server/cluster/haproxy-config-generator.js` | PID file used to detect and control the HAProxy process. |
| `HAPROXY_STATS_SOCKET` | `${TMPDIR}/haproxy-admin-<uid>.sock` | `server/cluster/haproxy-config-generator.js`, `server/load-balancer/auto-loadbalancer.js` | Unix domain socket path for HAProxy admin commands. Can be overridden explicitly. |
| `LOADBALANCER_LOCK_FILE` | `/var/run/auto-loadbalancer.pid` when root. Temp file otherwise | `server/load-balancer/auto-loadbalancer.js` | Lock file ensuring only one auto-loadbalancer process is running. |
| `HAPROXY_AUTO_CONFIG` | `('false')` | `server/cluster/cluster-integration.js` | When `'true'` and this node is primary, cluster integration automatically writes HAProxy configuration from Redis cluster state. |
| `HAPROXY_AUTO_RELOAD` | `('false')` | `server/cluster/cluster-integration.js` | When `'true'`, HAProxy is automatically validated and reloaded after configuration updates. |
| `HAPROXY_UPDATE_INTERVAL` | `(60000)` ms | `server/cluster/cluster-integration.js` | Interval for periodic HAProxy configuration regeneration in the primary node. |
| `HAPROXY_BIN` | `('haproxy')` | `server/load-balancer/auto-loadbalancer.js` | Name or path of the HAProxy binary used by the auto-loadbalancer process. |
| `LB_HAPROXY_BIN` | derived | `scripts/start-loadbalancer.cjs`, `server/load-balancer/auto-loadbalancer.js` | Effective HAProxy binary to run (system or project-built), chosen after config validation. |
| `HAPROXY_VERSION` | `(3.2.0)` | `scripts/build-quantum-haproxy.cjs` | HAProxy source version to download and compile for the quantum build. |
| `CLUSTER_API_URL` | `(https://localhost:3000/api/cluster)` | `scripts/cluster-cli.js` | Base URL for the cluster management HTTP API used by the CLI tool. |
| `CLUSTER_ADMIN_TOKEN` | **required** | `scripts/cluster-cli.js` | Static admin token used by the CLI to authenticate cluster management operations. |

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

## Tailscale, Tor, and network tooling

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `TAILSCALE_HOSTNAME` | `('Qor-chat')` (JSON-encoded in `.env`) | `scripts/generate_ts_tls.cjs` | Device name requested from Tailscale when issuing a TLS certificate. |
| `TS_AUTHKEY` | **required** for Tailscale certificate generation | `scripts/generate_ts_tls.cjs` | Tailscale auth key used to authenticate the node when requesting TLS certificates via `tailscale cert`. |

---

## Web Client Build

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `VITE_WS_URL` | unset | `src/components/setup/ConnectSetup.tsx`, `src/lib/cluster-key-manager.ts` | Base WebSocket URL for the packaged web client (e.g. `wss://localhost:8443`). Qor-Chat has one packaged runtime. No Vite server runtime is supported. |

---

## Qor desktop client

| Name | Default / required | Used by | Description |
| ---- | ------------------ | ------- | ----------- |
| `QOR_INSTANCE_ID` | unset → `'1'` | `src-tauri/src/main.rs`, `scripts/start-client.cjs` | When set, each instance uses a separate data directory (`<base>-instance-<id>`) so you can run multiple isolated instances (e.g. for 2-instance testing). Also names the client log file `logs/client-instance-<id>.log`. |
| `QOR_PIR_CLIENT_BIN` / `QOR_YPIR_CLIENT_BIN` | bundled path | `src-tauri/src/*` | Override paths to the bundled PIR / YPIR client daemon binaries (normally resolved next to the app). |

---

## Notes

- Secrets and key material are often auto-generated and persisted under `server/config` if not provided via environment variables.
- `REDIS_URL` is required for normal operation. Presence, rate limiting, PQ session storage, and cluster coordination all depend on Redis.
- TLS certificate paths (`TLS_CERT_PATH`, `TLS_KEY_PATH`) must be configured explicitly. Separate scripts can be used to obtain certificates (for example, via Tailscale).
