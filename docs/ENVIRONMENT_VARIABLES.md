# Environment variables

This is the inventory of supported Qor Chat runtime and deployment environment
variables. Defaults are the values used after parsing.

## Required security material

| Name | Requirement | Owner | Purpose |
| ---- | ----------- | ----- | ------- |
| `SERVER_PASSWORD` | Required: 12-512 characters | `server/authentication/auth-utils.js` | Password for the anonymous server entry OPAQUE gate. Startup fails on invalid input and deletes the plaintext from `process.env` after initialization.|
| `AUTH_ROOT_SEED` | Required: exactly 32 random bytes as 64 hex characters | `server/crypto/auth-root.js` | Root seed for deriving authentication, discovery, privacy-pass, routing, decoy, and avatar privacy keys. It must remain consistent across authorized nodes and restarts. The first derivation copies it to private process memory and deletes it from `process.env`. |
| `SERVER_TRANSPORT_IDENTITY_SEED` | Required: exactly 32 random bytes as 64 hex characters | `server/server.js` | Deterministically derives the server's ML-KEM-1024, ML-DSA-87, and X25519 transport identity. Nodes behind one advertised identity must share it. Startup deletes the environment copy after derivation. Rotating it intentionally changes the client visible server fingerprint. |
| `TLS_CERT_PATH` | Required | `server/bootstrap/server-bootstrap.js`, launchers | HTTPS certificate path. Relative paths are resolved from the repository by the launchers. |
| `TLS_KEY_PATH` | Required | `server/bootstrap/server-bootstrap.js`, launchers  | Private key corresponding to `TLS_CERT_PATH`. |
| `REDIS_URL` | Required by the runtime and must use `rediss://` | `server/session/redis-client.js` | TLS Redis endpoint used for anonymous coordination, routing, rate limits, discovery relay, and clustering. `scripts/start-server.cjs` and `scripts/start-loadbalancer.cjs` default to local `rediss://127.0.0.1:6379` while preparing a local deployment. Plaintext `redis://` is rejected by runtime clients. |
| `PGSSLROOTCERT` | One of this or `DATABASE_CA_CERT` is required | `server/database/core.js` | Path to an explicitly trusted PostgreSQL CA bundle. The launcher validates the file but never learns a CA from the endpoint it is about to trust. |
| `DATABASE_CA_CERT` | One of this or `PGSSLROOTCERT` is required | `server/database/core.js` | Inline PEM alternative to `PGSSLROOTCERT`. PostgreSQL always uses `rejectUnauthorized: true`. |

Use independent random values for `AUTH_ROOT_SEED` and
`SERVER_TRANSPORT_IDENTITY_SEED`. Do not derive either from `SERVER_PASSWORD`.
The Docker startup helper generates independent values when either variable is
absent and saves them to `.env`. It never replaces a
present malformed value or rotates an existing value. Every authorized node
behind the same logical server identity must use the same values.

For the single-host Docker deployment, `scripts/start-docker.cjs` also fills
missing container connection defaults and generates independent
`DATABASE_PASSWORD` and `REDIS_PASSWORD` values. Existing values are preserved
except when `REDIS_PASSWORD` cannot satisfy the bundled Redis ACL policy. A
Redis password shorter than 32 characters or containing characters outside the
base64url alphabet is replaced before the containers start so Redis cannot be
left permanently unhealthy by an incompatible saved credential.

## Server and HTTPS

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `PORT` | `8443`, `dynamic` selects port `0`, Docker runtime uses `3000` | `server/config/config.js`, launchers | HTTPS listen port. `scripts/start-server.cjs` selects an available port beginning at 8443 when unset. |
| `BIND_ADDRESS` | `127.0.0.1` | `server/bootstrap/server-bootstrap.js` | HTTPS bind interface. Docker sets `0.0.0.0`. |
| `ALLOWED_CORS_ORIGINS` | Empty in the runtime, launcher supplies localhost development origins | `server/config/constants.js` | Comma separated browser origins. The fixed first-party Tauri origins are always included. Unknown browser origins receive no CORS grant and websocket upgrades with an unknown `Origin` are rejected. |
| `HTTPS_REQUEST_TIMEOUT_MS` | `180000`, 5000-300000 | `server/bootstrap/server-bootstrap.js` | Complete HTTPS request timeout. The default admits a fixed 2 MiB anonymous PIR upload over a fresh Tor circuit. |
| `HTTPS_HEADERS_TIMEOUT_MS` | `15000`, 5000 to request timeout | same | Header receive timeout. |
| `HTTPS_KEEP_ALIVE_TIMEOUT_MS` | `5000`, 1000-30000 | same | Idle keep-alive timeout. |
| `HTTPS_SOCKET_IDLE_TIMEOUT_MS` | `120000`, 30000-600000 | same | General socket idle timeout. |
| `HTTPS_MAX_HEADER_COUNT` | `64`, 16-256 | same | Maximum headers per request. |
| `HTTPS_MAX_REQUESTS_PER_SOCKET` | `128`, 1-1024 | same | Maximum requests accepted on one socket. |
| `HTTPS_MAX_CONNECTIONS` | `8192`, 64-100000 | same | Process level HTTPS connection ceiling. |
| `MAX_NEW_CONNECTIONS_PER_MIN` | `600`, 1-100000 | `server/config/config.js` | Anonymous global new websocket connection ceiling. |
| `CONNECTION_BLOCK_MS` | `1000`, 1000-60000 | same | Global connection admission block after the ceiling is exceeded. |

## websocket and PQ envelope admission

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `WS_MAX_PAYLOAD_BYTES` | 16 MiB, 64 KiB-16 MiB | `server/server.js` | Protocol level `ws` frame cap applied during receive. |
| `WS_BANDWIDTH_QUOTA_BYTES` | 64 MiB, 8-512 MiB | `server/config/constants.js` | Per connection inbound byte budget. |
| `WS_BANDWIDTH_WINDOW_MS` | `60000`, 5000-600000 | same | Bandwidth budget window. |
| `WS_FRAME_MAX_PER_WINDOW` | `500`, 50-100000 | same | Per connection inbound frame count. |
| `WS_FRAME_WINDOW_MS` | `60000`, 5000-600000 | same | Frame count window. |
| `WS_HEARTBEAT_MISSED_LIMIT` | `6`, 3-20 | `server/websocket/gateway.js` | Missed heartbeat limit before disconnect. |
| `WS_LARGE_FRAME_WINDOW_MS` | `60000`, 1000-600000 | same | Large frame admission window. |
| `WS_LARGE_FRAME_MAX_COUNT` | `64`, 1-10000 | same | Large frames admitted in one window. |
| `WS_LARGE_FRAME_MAX_BYTES` | 32 MiB, 1 MiB-1 GiB | same | Aggregate large frame bytes in one window. |
| `WS_PENDING_MESSAGE_MAX_COUNT` | `64`, 4-4096 | same | Messages waiting behind the ordered per-socket handler. |
| `WS_PENDING_MESSAGE_MAX_BYTES` | 16 MiB, 1-256 MiB | same | Bytes waiting behind the ordered per-socket handler. |
| `WS_MAX_CONCURRENT_CONNECTIONS` | `4096`, 64-100000 | same | Per process websocket ceiling. |
| `WS_MESSAGE_HANDLER_TIMEOUT_MS` | `30000`, 1000-120000 | same | Timeout for one ordered application message handler. |
| `WS_MAX_ENCRYPTED_RESPONSE_BYTES` | 12 MiB, 1-64 MiB | `server/messaging/pq-envelope-handler.js` | Maximum serialized encrypted server response. |
| `WS_MAX_ENCRYPTED_REQUEST_CIPHERTEXT_BYTES` | 8 MiB, 1-16 MiB | same | Maximum request ciphertext before decode/decryption. |
| `WS_ENCRYPTED_SEND_QUEUE_MAX_COUNT` | `64`, 4-1024 | same | Per socket encrypted response queue count. |
| `WS_ENCRYPTED_SEND_QUEUE_MAX_BYTES` | 24 MiB, 4-256 MiB | same | Per socket encrypted response queue bytes. |
| `WS_DELIVERY_TIMEOUT_MS` | `30000`, 1000-120000 | same | Maximum wait for encrypted websocket delivery/drain. |
| `SECURE_CHUNK_BYTES` | 1 MiB, 256 KiB-6 MiB | same | Chunk target for oversized encrypted responses. |
| `SECURE_CHUNK_SINGLE_MAX_BYTES` | 4 MiB, 64 KiB-8 MiB | same | Largest response sent without chunking. |
| `PQ_HANDSHAKE_MAX_PER_MIN` | `20`, 1-600 | same | Per connection PQ handshake/rehandshake ceiling. |
| `PQ_HANDSHAKE_MAX_CONCURRENCY` | `2`, 1-16 | same | Process level concurrent ML-KEM handshake work. |
| `PQ_HANDSHAKE_MAX_QUEUE` | `16`, 0-64 | same | Bounded handshake waiters. |
| `PQ_HANDSHAKE_QUEUE_TIMEOUT_MS` | `15000`, 1000-60000 | same | Maximum wait for a handshake slot. |
| `PQ_HANDSHAKE_CONFIRM_TIMEOUT_MS` | `45000`, 5000-120000 | same | Maximum time a staged session may wait for encrypted peer confirmation before the socket is closed and its pending/current transport state is wiped. |

## PostgreSQL

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `DATABASE_URL` | Optional alternative to discrete credentials | `server/database/core.js` | `postgres://` or `postgresql://` URL supplying port, user, password, database, and default certificate name. `DB_CONNECT_HOST`, `DB_TLS_SERVERNAME`, and the explicit CA configuration still apply. |
| `DB_CONNECT_HOST` | URL host, otherwise unset | same | TCP destination override. Useful when connecting to an IP while verifying a DNS certificate name. |
| `PGHOST`, `DB_HOST` | Required in discrete mode, `PGHOST` wins | same | PostgreSQL host and default TLS certificate name. |
| `PGPORT`, `DB_PORT` | Required in discrete mode, `PGPORT` wins, 1-65535 | same | PostgreSQL port. |
| `PGUSER`, `DATABASE_USER` | Required in discrete mode, `PGUSER` wins | same | PostgreSQL user. |
| `PGPASSWORD`, `DATABASE_PASSWORD` | Required in discrete mode, `PGPASSWORD` wins | same | PostgreSQL password. |
| `PGDATABASE`, `DB_NAME` | Required in discrete mode, `PGDATABASE` wins | same | PostgreSQL database name. |
| `DB_TLS_SERVERNAME` | URL/host certificate name | same | Explicit SNI and hostname verification name. Required when the connect host is not the certificate identity. |
| `PG_STATEMENT_TIMEOUT_MS` | `15000`, 1000-30000 | same | Server-side statement timeout. |
| `PG_QUERY_TIMEOUT_MS` | `20000`, statement timeout to 30000 | same | Client-side query timeout. |
| `PG_POOL_MAX` | `20`, 2-100 | same | PostgreSQL pool size. |
| `PG_IDLE_TIMEOUT_MS` | `30000`, 10000-600000 | same | Idle pooled connection timeout. |
| `PG_CONNECTION_TIMEOUT_MS` | `10000`, 1000-30000 | same | Connection establishment timeout. |
| `PG_LOCK_TIMEOUT_MS` | `5000`, 500 to statement timeout | same | PostgreSQL lock wait timeout. |
| `PG_IDLE_TRANSACTION_TIMEOUT_MS` | `20000`, 1000-30000 | same | Idle-in-transaction timeout. |

## Redis and anonymous rate limits

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `REDIS_CLUSTER_NODES` | Unset | `server/session/redis-client.js` | Comma separated `host:port` seed nodes. When set, the client uses Redis Cluster with the same verified TLS policy. |
| `REDIS_USERNAME` | Unset | Redis clients | Redis ACL username. |
| `REDIS_PASSWORD` | Unset; bundled Docker requires at least 32 base64url characters | Redis clients and Docker Redis | Redis ACL password. The Docker startup helper generates a compatible value when this is missing and repairs an incompatible saved value before Redis starts. |
| `REDIS_TLS_SERVERNAME` | `redis` | Redis clients | SNI and certificate-verification name. |
| `REDIS_CA_CERT_PATH` | System roots when unset | Redis clients | Explicit Redis CA bundle. |
| `REDIS_CLIENT_CERT_PATH` | Unset | Redis clients | Client certificate for Redis mutual TLS. |
| `REDIS_CLIENT_KEY_PATH` | Unset | Redis clients | Private key for `REDIS_CLIENT_CERT_PATH`, cached key bytes are wiped on teardown. |
| `REDIS_POOL_MIN` | `4`, 1-100 and no greater than max | `server/session/redis-client.js` | Minimum pooled clients. |
| `REDIS_POOL_MAX` | `50`, 10-500 | same | Maximum pooled clients. |
| `REDIS_POOL_ACQUIRE_TIMEOUT` | `15000`, 1000-60000 | same | Pool acquisition timeout. |
| `REDIS_POOL_IDLE_TIMEOUT` | `180000`, 10000-600000 | same | Pooled client idle timeout. |
| `REDIS_POOL_EVICTION_INTERVAL` | `60000`, 10000-600000 | same | Idle client eviction interval. |
| `REDIS_CONNECT_TIMEOUT` | `15000`, 1000-60000 | same | Redis connection timeout. |
| `REDIS_COMMAND_TIMEOUT` | `10000`, 1000-30000 | same | Redis command timeout. |
| `REDIS_KEEPALIVE` | `30000`, 0-300000 | same | TCP keepalive delay. |
| `REDIS_SOCKET_TIMEOUT` | `120000`, 30000-600000 | same | Redis socket timeout. |
| `REDIS_QUIET_ERRORS` | `false`, load-balancer launcher sets `true` | same | Throttles repeated identical operational errors. It does not suppress the first error. |
| `REDIS_ERROR_THROTTLE_MS` | `5000`, 1000-60000 | same | Duplicate error throttle interval. |
| `RATE_LIMIT_REDIS_URL` | Falls back to `REDIS_URL`, must use `rediss://` | `server/rate-limiting/distributed-rate-limiter.js` | Optional dedicated Redis endpoint for the anonymous global connection limiter. |
| `RATE_LIMIT_REDIS_CONNECT_TIMEOUT` | `10000`, 1000-60000 | same | Rate-limit Redis connection timeout. |
| `RATE_LIMIT_REDIS_COMMAND_TIMEOUT` | `10000`, 1000-30000 | same | Rate-limit Redis command timeout. |

`REDISCLI_AUTH` is created internally by the launcher when invoking `redis-cli`, so
the password does not appear in command arguments. It is not an operator setting.

## Anonymous PQ HTTP transport

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `PQ_ANONYMOUS_HTTP_MAX_INFLIGHT` | `8`, 5-16 | `server/routes/pq-anonymous-http.js` | Concurrent admitted replay/KEM/decrypt/dispatch/response operations per process. |
| `PQ_ANONYMOUS_HTTP_MAX_RPS` | `100`, 1-2000 | same | Process wide token bucket for work-valid requests before KEM processing. |
| `PQ_ANONYMOUS_HTTP_MAX_FAILURE_INFLIGHT` | `16`, 1-64 | same | Concurrent fixed 64 KiB opaque failure writes, excess failures close without allocating a response. |
| `PQ_ANONYMOUS_HTTP_MAX_FAILURE_RPS` | `200`, 1-4000 | same | Process wide token bucket for opaque failure writes. |
| `PQ_ANONYMOUS_HTTP_WRITE_TIMEOUT_MS` | `180000`, 5000-300000 | same | Deadline for a success or opaque failure response write, including clients that disconnect or stop reading. |

## Authentication and cryptography
| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `AUTH_THROTTLE_WINDOW_MS` | `60000`, 5000-600000 | `server/security/auth-throttle.js` | Current/previous global failure-count window. |
| `AUTH_THROTTLE_FREE_FAILURES` | `30`, 0-1000000 | same | Work backed failures before delay begins. |
| `AUTH_THROTTLE_MS_PER_FAILURE` | `150`, 0-60000 | same | Delay added per failure above the free allowance. |
| `AUTH_THROTTLE_MAX_DELAY_MS` | `8000`, 0-120000 | same | Maximum adaptive delay. |
| `AUTH_POW_FREE_FAILURES` | `30`, 0-1000000 | same | Failures before adaptive proof-of-work activates. |
| `AUTH_POW_MIN_BITS` | `10`, 0-28 | same | Adaptive PoW difficulty when active. |
| `AUTH_POW_MAX_BITS` | `22`, 22-28 | same | Adaptive PoW ceiling. |
| `AUTH_POW_STEP_FAILURES` | `40`, 1-1000000 | same | Failures per logarithmic difficulty step. |
| `AUTH_PREFLIGHT_POW_BITS` | `20`, 18 to `AUTH_POW_MAX_BITS` | same | Baseline work before expensive registration/login processing. |
| `AUTH_FINALIZE_POW_BITS` | `22`, 22 to `AUTH_POW_MAX_BITS` | same | Baseline work before expensive authentication finalization. |
| `AUTH_PREFLIGHT_STEP_REQUESTS` | `32`, 1-1000000 | same | Paid requests per logarithmic preflight step. |
| `AUTH_OT_MAX_QUEUE` | `8`, 0-8 | same | Maximum waiters for the isolated constant-work private-auth worker. |
| `AUTH_OT_QUEUE_TIMEOUT_MS` | `90000`, 1000-120000 | same | Maximum wait for that worker. |
| `ARGON2_TIME` | `4`, 3-10 | `server/crypto/unified-crypto.js` | Argon2id time cost. |
| `ARGON2_MEMORY` | 262144 KiB, 131072-1048576 KiB | same | Argon2id memory cost. |

## Blind routing, mix relay, and cover traffic
| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `BLIND_ROUTE_WINDOW_MS` | `60000`, 1000-600000 | `server/handlers/delivery-handlers.js` | Per-connection blind-route admission window. |
| `BLIND_ROUTE_MAX_PER_WINDOW` | `30`, 1-10000 | same | Envelopes admitted in that window. |
| `BLIND_ROUTE_MAX_BYTES_PER_WINDOW` | 8 MiB, 64 KiB-512 MiB | same | Aggregate admitted bytes in that window. |
| `BLIND_ROUTE_MAX_ENVELOPE_BYTES` | 384 KiB, 16 KiB-8 MiB | same | Maximum sealed route envelope. |
| `MIXNET_DELAY_MIN_MS` | `1500`, 250-120000 | `server/routing/blind-router.js` | Minimum randomized relay delay. |
| `MIXNET_DELAY_MAX_MS` | `9000`, minimum delay to 300000 | same | Maximum randomized relay delay. |
| `MIXNET_FLUSH_MIN_MS` | `700`, 100-60000 | same | Minimum randomized relay flush interval. |
| `MIXNET_FLUSH_MAX_MS` | `2500`, minimum flush to 120000 | same | Maximum randomized relay flush interval. |
| `MIXNET_BATCH_MAX_MESSAGES` | `24`, 1-256 | same | Real messages claimed per flush. |
| `MIXNET_FLUSH_CONCURRENCY` | `8`, 1-32 | same | Concurrent claimed-message processing. |
| `MIXNET_PROCESSING_TIMEOUT_MS` | `120000`, 60000-600000 | same | Recovery age for unfinished Redis claims. |
| `MIXNET_POOL_TTL_SECONDS` | `3600`, 60-3600 | same | Maximum delay/processing recovery lifetime. The one-hour cap cannot be raised. |
| `MIXNET_PENDING_MAX_MESSAGES` | `2048`, 64-100000 | same | Global delayed/processing queue count cap. |
| `MIXNET_PENDING_MAX_BYTES` | 128 MiB, 8 MiB-2 GiB | same | Global delayed/processing queue byte cap. |
| `MIXNET_COVER_WRITES_MIN` | `1`, 0-32 | same | Minimum cover writes in a nonempty flush. |
| `MIXNET_COVER_WRITES_MAX` | `2`, minimum to 64 | same | Maximum cover writes in a nonempty flush. |
| `GLOBAL_MIX_SPOOL_TTL_SECONDS` | `86400`, 60-604800 | same | Global sealed-spool row lifetime (24-hour default, seven-day maximum). |
| `GLOBAL_MIX_SPOOL_MAX_MESSAGES` | `32768`, 64-10000000 | same | Global sealed-spool row cap held across the whole server for the full TTL. |
| `GLOBAL_MIX_SPOOL_MAX_BYTES` | 512 MiB, 1 MiB-4 GiB | same | Global sealed-spool byte cap. Only the standard 128 KiB ciphertext class is retained, base64 and envelope framing make the serialized Redis row larger. Both caps refuse writes when reached until rows age out through `GLOBAL_MIX_SPOOL_TTL_SECONDS`. |
| `GLOBAL_MIX_PUBLICATION_MAX_BYTES` | 2 MiB, 64 KiB-16 MiB | same | Maximum cross-node publication payload. |
| `GLOBAL_MIX_DELIVERY_QUEUE_MAX_MESSAGES` | `64`, 1-4096 | same | Local cross-node delivery queue count. |
| `GLOBAL_MIX_DELIVERY_QUEUE_MAX_BYTES` | 32 MiB, 1-512 MiB | same | Local cross-node delivery queue bytes. |
| `GLOBAL_MIX_PUBLICATION_QUEUE_MAX_MESSAGES` | `64`, 1-4096 | same | Local publication queue count. |
| `GLOBAL_MIX_PUBLICATION_QUEUE_MAX_BYTES` | 32 MiB, 1-512 MiB | same | Local publication queue bytes. |
| `LOCAL_BROADCAST_BUFFERED_MAX_BYTES` | 8 MiB, 1-256 MiB | same | Per-socket buffered-output threshold. |
| `LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS` | `30000`, 1000-600000 | same | Backpressure diagnostic throttle. |
| `LOCAL_BROADCAST_BACKPRESSURE_EVICT_MS` | `120000`, 10000-1800000 | same | Continuous pressure before local socket eviction. |
| `LOCAL_BROADCAST_BACKPRESSURE_SUSPEND_MS` | `120000`, 10000-1800000 | same | Local delivery suspension after pressure. |
| `LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS` | `0`, 0-300000 | same | Optional spacing between local broadcast writes. |
| `LOCAL_BROADCAST_CONCURRENCY` | `8`, 1-64 | same | Concurrent local broadcast writes. |
| `BLIND_ROUTE_MAX_LOCAL_SOCKETS` | `2048`, 64-100000 | same | Local sockets considered for one blind delivery. |
| `BLIND_DELIVERY_RETRY_MIN_MS` | `5000`, 1000-60000 | same | Minimum cross-node subscription retry. |
| `BLIND_DELIVERY_RETRY_MAX_MS` | `60000`, minimum retry to 600000 | same | Maximum cross-node subscription retry. |
| `SERVER_COVER_TRAFFIC_INTERVAL_MS` | `30000`, 5000-600000 | `server/routing/timing-protection.js` | Base idle cover-write interval. |
| `SERVER_COVER_TRAFFIC_VARIANCE_MS` | `15000`, 0-600000 | same | Random interval variance. |
| `SERVER_COVER_TRAFFIC_WRITES_MIN` | `1`, 1-32 | same | Minimum writes per cover cycle. |
| `SERVER_COVER_TRAFFIC_WRITES_MAX` | `3`, minimum to 64 | same | Maximum writes per cover cycle. |

## Discovery publication privacy

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `DISCOVERY_MAX_SOURCE_PUBLICATIONS` | `4096`, 1-100000 | `server/discovery/bucket-layout.js` | Active encrypted publications admitted to an index build. |
| `DISCOVERY_MAX_SOURCE_BYTES` | 256 MiB, 1 MiB-2 GiB | same | Cumulative source-byte budget for one index. |
| `DISCOVERY_PADDED_BUCKET_CACHE_SIZE` | `4`, 0-32 | `server/discovery/bucket-index.js` | Fully padded bucket LRU size, `0` disables the cache. |
| `DISCOVERY_PUBLISH_MAX_PER_MIN` | `12`, 1-1000 | `server/config/config.js` | Per-unlinked-connection publication admission. |
| `DISCOVERY_OPRF_HTTP_MAX_INFLIGHT` | `64`, 1-256 | `server/routes/api-routes.js` | Concurrent anonymous VOPRF evaluations per process. |
| `DISCOVERY_OPRF_HTTP_MAX_RPS` | `500`, 1-10000 | same | Per-process OPRF token bucket. |
| `DISCOVERY_MANIFEST_HTTP_MAX_RPS` | `50`, 1-2000 | same | Per-process manifest token bucket. |
| `DISCOVERY_BUCKET_MAX_INFLIGHT` | `2`, 1-8 | same | Concurrent fixed-shape bucket responses. |
| `DISCOVERY_BUCKET_HTTP_MAX_RPS` | `30`, 1-256 | same | Per-process bucket token bucket. |
| `DISCOVERY_BUCKET_RESPONSE_MAX_BYTES` | 48 MiB, 1-48 MiB | same | Serialized bucket-response ceiling. |
| `OPRF_GLOBAL_MAX_PER_MIN` | `1200`, 60-60000 | `server/crypto/oprf-discovery.js` | Anonymous global OPRF CPU ceiling. |
| `DISCOVERY_PUBLICATION_DELAY_MIN_MS` | `2000`, 1000-1800000 | `server/discovery/publication-privacy.js` | Minimum randomized publication release delay. |
| `DISCOVERY_PUBLICATION_DELAY_MAX_MS` | `10000`, minimum delay to 3600000 | same | Maximum randomized release delay. |
| `DISCOVERY_PUBLICATION_FLUSH_MIN_MS` | `1000`, 500-600000 | same | Minimum randomized relay flush interval. |
| `DISCOVERY_PUBLICATION_FLUSH_MAX_MS` | `4000`, minimum flush to 900000 | same | Maximum randomized relay flush interval. |
| `DISCOVERY_PUBLICATION_BATCH_MAX` | `32`, 1-512 | same | Real publications claimed per flush. |
| `DISCOVERY_PUBLICATION_FLUSH_CONCURRENCY` | `8`, 1-32 | same | Concurrent claimed-publication processing. |
| `DISCOVERY_PUBLICATION_PROCESSING_TIMEOUT_MS` | `120000`, 60000-600000 | same | Recovery age for unfinished claims. |
| `DISCOVERY_PUBLICATION_MAX_POOL_ENTRIES` | `512`, 100-8192 | same | Combined delayed/processing entry cap. Each entry contains one fixed 64 KiB publication. |
| `DISCOVERY_PUBLICATION_POOL_TTL_SECONDS` | `604800`, 60-2592000 | same | Redis queue-state lifetime. |
| `DISCOVERY_PUBLICATION_COVER_WRITES_MIN` | `1`, 0-64 | same | Minimum cover rows in a nonempty flush. |
| `DISCOVERY_PUBLICATION_COVER_WRITES_MAX` | `3`, minimum to 128 | same | Maximum cover rows in a nonempty flush. |
| `DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MIN` | `0`, 0-64 | same | Minimum cover rows in an idle flush. |
| `DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MAX` | `0`, minimum to 128 | same | Maximum cover rows in an idle flush. |
| `DISCOVERY_PUBLICATION_TIMESTAMP_QUANTUM_MS` | `900000`, 60000-21600000 | same | Expiry rounding quantum, exact publication time is not stored. |
| `DISCOVERY_INDEX_REFRESH_MIN_INTERVAL_MS` | `45000`, 10000-21600000 | same | Coalescing interval for index invalidation/prewarm. |

## Avatar and spool operations

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `AVATAR_GET_HTTP_MAX_RPS` | `30`, 1-2000 | `server/routes/api-routes.js` | Per-process fixed-batch avatar fetch token bucket. |
| `AVATAR_PUT_HTTP_MAX_RPS` | `20`, 1-2000 | same | Per-process anonymous avatar write token bucket. |
| `AVATAR_POOL_HTTP_MAX_RPS` | `10`, 1-2000 | same | Per-process cover-pool token bucket. |
| `AVATAR_BLOB_MAX_COUNT` | `20000`, 100-100000 | `server/config/constants.js` | Mandatory global encrypted-avatar row cap. Oldest-expiring rows are evicted, the cap cannot be disabled. |
| `AVATAR_ENFORCE_EVERY` | `100`, 1-1000 | `server/routes/api-routes.js` | Successful writes between inline cap enforcement passes. |
| `SPOOL_HTTP_MAX_RPS` | `50`, 1-2000 | same | Per-process token bucket shared by the tag-index and PIR endpoints. |

## Clustering and load balancing

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `SERVER_ID` | Launcher generates `server-<hostname>-<timestamp>` | server and cluster modules | Logical node identifier. It identifies a server process, never a user. |
| `SERVER_HOST` | Launcher detects a non-loopback address | launcher, `server/cluster/cluster-manager.js` | Backend host advertised to cluster state and HAProxy. |
| `HOST` | OS hostname | `server/cluster/cluster-manager.js` | Fallback when `SERVER_HOST` is unset. |
| `HOSTNAME` | `server` fallback | `server/cluster/cluster-integration.js` | Input to generated cluster node IDs. |
| `ENABLE_CLUSTERING` | Launcher default `true`, only exact `true` enables | `server/server.js` | Enables Redis-backed cluster registration. |
| `CLUSTER_WORKERS` | `1` | `server/bootstrap/server-bootstrap.js` | Node worker count, values greater than one use local process clustering. |
| `CLUSTER_PRIMARY` | Unset | cluster modules | Exact `true` marks the node primary. |
| `SERVER_ROLE` | Unset | `server/cluster/cluster-integration.js` | `primary` is an alternate primary marker. |
| `CLUSTER_AUTO_APPROVE` | Launcher default `true` | cluster modules | Exact `true` automatically approves new cluster nodes. |
| `NO_GUI` | `false` | launchers | Disables the interactive server/load-balancer terminal UI. |
| `HAPROXY_HTTPS_PORT` | Root auto-LB `443`, otherwise `8443` | load-balancer modules | External HAProxy HTTPS port. |
| `HAPROXY_STATS_PORT` | `8404` | load-balancer modules | HAProxy statistics listener port. |
| `HAPROXY_STATS_USERNAME` | Initialized by launcher | load-balancer modules | HAProxy statistics and command-channel credential. |
| `HAPROXY_STATS_PASSWORD` | Generated or prompted by launcher | load-balancer modules | Companion secret, launcher stores its protected form under `server/config`. |
| `HAPROXY_CERT_PATH` | Repository cert directory or `/etc/haproxy/certs` | `server/load-balancer/haproxy-config-generator.js` | HAProxy certificate directory. |
| `HAPROXY_CERT_FILE` | Auto-selected certificate | same | Specific certificate file override. |
| `HAPROXY_CONFIG_PATH` | Platform/root-dependent | cluster and load-balancer modules | Generated HAProxy configuration path. |
| `HAPROXY_PID_FILE` | Platform/root-dependent | load-balancer modules | HAProxy PID file. |
| `HAPROXY_STATS_SOCKET` | `${TMPDIR}/haproxy-admin-<uid>.sock` | load-balancer modules | Local HAProxy command socket. |
| `LOADBALANCER_LOCK_FILE` | Platform/root-dependent | `server/load-balancer/auto-loadbalancer.js` | Single-instance process lock. |
| `LB_SERVER_ACTIVE_TIMEOUT_MS` | `45000`, 10000-300000 | same | Age after which a cluster backend is no longer considered active. |
| `HAPROXY_AUTO_CONFIG` | `false` | `server/cluster/cluster-integration.js` | Exact `true` lets a primary write HAProxy configuration from cluster state. |
| `HAPROXY_AUTO_RELOAD` | `false` | same | Exact `true` validates and reloads HAProxy after an update. |
| `HAPROXY_UPDATE_INTERVAL` | `60000`, 5000-3600000 | same | Single-flight configuration refresh interval. |
| `LB_HAPROXY_CFG` | `server/config/haproxy-quantum.cfg` | load-balancer launcher | PQ-enabled HAProxy configuration. |
| `LB_OPENSSL_CONF` | Derived from `OPENSSL_CONF` | load-balancer launcher | OpenSSL provider configuration passed to HAProxy. |
| `SERVER_<server-id>_URL` | Unset | `server/load-balancer/haproxy-config-generator.js` | Optional backend URL override for a discovered server ID. |

## PQ TLS and installation tooling

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `OPENSSL_CONF` | Generated edge configuration | load-balancer modules | OpenSSL configuration that loads the bundled providers. |
| `OPENSSL_MODULES` | Fixed by the launcher | same | Internal OpenSSL provider module directory under `/opt/qor-edge`; external overrides are not accepted. |
| `OQS_PROVIDER_MODULE` | Fixed by the launcher | load-balancer image | Internal OQS provider path under `/opt/qor-edge`; external overrides are not accepted. |
| `LD_LIBRARY_PATH` | Fixed by the launcher | load-balancer image | Private-library search path under `/opt/qor-edge`; inherited paths are not used by HAProxy or Tor. |
| `OQS_SIG` | Tool-selected | `scripts/setup-quantum-haproxy.cjs` | Preferred supported PQ signature algorithm for generated PQ certificate tooling. |
| `TLS_REDIS_SERVER` | Installer-generated path | `scripts/start-server.cjs` | Repository-local TLS Redis executable override. |
| `REDIS_SERVER_BIN` | `redis-server` | same | System Redis executable fallback. |
| `REDIS_TLS_SOURCE_URL` | Redis 7.2.5 release URL | `scripts/install-deps.cjs` | Source archive used to build the local TLS Redis helper. |
| `TLS_CERT_CN` | `localhost` | `scripts/generate_tls.cjs` | Common name used by local TLS certificate generation. |

## Client and build tooling

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `VITE_WS_URL` | Unset | `src/components/setup/ConnectSetup.tsx` | Packaged web-client websocket endpoint, for example `wss://localhost:8443`. |
| `QOR_INSTANCE_ID` | `1` | `src-tauri/src/main.rs`, `scripts/start-client.cjs` | Selects a distinct native data directory and `logs/instance-<id>-logs.txt` output for multi instance testing. |
| `PROTOC` | Auto-detected | `scripts/start-client.cjs` | Explicit Protocol Buffers compiler path. |
| `QOR_PROTOC_VERSION` | `33.0` | same | Windows protoc download version. |
| `QOR_PROTOC_URL` | Version-derived official release URL | same | Explicit Windows protoc archive URL. |
| `QOR_STRAWBERRY_PERL_URL` | Pinned Strawberry Perl download URL | same | Windows native-build dependency URL. |
| `QOR_CHAT_SOFTWARE_RENDERING` | Unset | `src-tauri/src/main.rs`, `scripts/start-client.cjs` | When present on Linux, defaults `LIBGL_ALWAYS_SOFTWARE` to `1`. This is a diagnostic compatibility fallback, not the normal rendering path. |
| `WEBKIT_DMABUF_RENDERER_FORCE_SHM` | `1` on Linux | same | WebKitGTK rendering compatibility setting. An explicit inherited value is preserved. |
| `GSTREAMER_PLUGINS_DIR` | `.cache/gstreamer-plugins-<arch>` during client builds | `scripts/start-client.cjs`, Linux bundle scripts | Build-time location of the staged curated GStreamer tree. It is not required by an installed package. |
| `QOR_GSTREAMER_SYSTEM_PLUGINS_DIR` | `pkg-config` result or a standard system directory | `scripts/stage-gstreamer-plugins.cjs` | Advanced build-time override for the GStreamer plugin directory copied into the private staged runtime. |
| `QOR_GSTREAMER_LAUNCH_SOURCE` | `/usr/bin/gst-launch-1.0` or `/bin/gst-launch-1.0` | same | Advanced build-time override for the `gst-launch-1.0` executable copied into the private capture runtime. |
| `QOR_GSTREAMER_PLUGIN_SCANNER_SOURCE` | Auto-detected system scanner | same | Advanced build-time override for the GStreamer plugin scanner copied into the private capture runtime. |
| `QOR_GSTREAMER_REQUIRE_BUNDLED` | `1` for packaged Linux launches and staged development launches | native Linux startup and screen capture | Exact `1` disables automatic fallback to system capture libraries, plugins, launcher, or scanner. Normal launch paths also supply the private runtime locations automatically. |
| `QOR_GSTREAMER_LAUNCH` | Packaged or staged private launcher | native Linux screen capture | Advanced runtime override for the private GStreamer capture launcher. Normal builds set it automatically. |
| `QOR_GSTREAMER_CAPTURE_PLUGINS` | Packaged or staged capture-plugin directory | same | Advanced runtime override for the curated capture-only plugin directory. |
| `QOR_GSTREAMER_RUNTIME_LIB` | Packaged or staged private library directory | same | Advanced runtime override for the capture process dynamic-library directory. |
| `QOR_GSTREAMER_SPA_PLUGINS` | Packaged or staged `spa-0.2` directory | same | Advanced runtime override for the private PipeWire SPA root. It must contain support modules plus the video adapter used by screen capture; this replaces rather than extends the host SPA path. |
| `QOR_GSTREAMER_PLUGIN_SCANNER` | Packaged or staged private scanner | same | Advanced runtime override for the GStreamer plugin scanner. |
| `QOR_GSTREAMER_REGISTRY` | `$XDG_RUNTIME_DIR/qor-chat/gstreamer-registry-1.0.bin` | same | Advanced override for the per-session GStreamer registry file used by native screen capture. |
| `PIPEWIRE_DEBUG` | `1` for the capture child unless inherited | PipeWire library inherited by the capture child | Advanced Linux screen-capture diagnostics. Level `1` retains errors; level `4` traces SPA factory loading and stream state. Do not enable verbose levels for normal releases. |
| `GST_DEBUG` | Unset | GStreamer inherited by the capture child | Advanced GStreamer category/level diagnostics, for example `pipewiresrc:7,pipewirestream:7`. Verbose output can be large and may expose device metadata. |

## Docker interpolation

These values are consumed by Compose or container entrypoints in addition to any
server-runtime use above.

| Name | Default / required | Purpose |
| ---- | ------------------ | ------- |
| `REDIS_BIND_HOST` | `127.0.0.1` | Host interface for the published mutual-TLS Redis port. Set a private/VPN address only when another host must connect. |
| `REDIS_EXTERNAL_PORT` | `6379` | Published Redis port. |
| `POSTGRES_BIND_HOST` | `127.0.0.1` | Host interface for the published TLS PostgreSQL port. |
| `PG_ALLOWED_CIDR` | `172.16.0.0/12` | Network allowed by the generated `hostssl ... scram-sha-256` rules. Tighten it before exposing PostgreSQL to another host. |
| `POSTGRES_PASSWORD` | Required by the PostgreSQL entrypoint, Compose supplies `DATABASE_PASSWORD` | Initial PostgreSQL role password. |
| `POSTGRES_DB` | `Qor`, Compose supplies `DB_NAME` | Database initialized by the PostgreSQL entrypoint. |
| `DB_PORT` | Required by current Compose file | Host-side PostgreSQL published port. |
| `PORT` | `3000` | Host-side server published port. |
| `HAPROXY_HTTPS_PORT` | `8443` | Host-side load-balancer HTTPS port. |
| `HAPROXY_STATS_PORT` | `8404` | Host-side load-balancer statistics port. |

The PostgreSQL entrypoint regenerates network access policy on every boot and
accepts remote traffic only through TLS with SCRAM-SHA-256 authentication.

## Private Spool Retrieval

| Variable | Default | Meaning |
| --- | --- | --- |
| `BROADCAST_LANE_COVER_PERCENT` | `25` | Share of server cover traffic written to the first-contact lane. Without cover on that lane its entry count is a live readout of how fast new relationships form. |
| `QOR_PIR_WORKER_PATH` | `workers/ypir/target/release/qor-pir-worker` | Optional override. The Docker image builds the worker to the default path, so this is not normally set. **The server refuses to start without a usable worker**: small spool entries are served only by PIR, so booting without it would accept messages it can never deliver. |
| `GLOBAL_MIX_SPOOL_TTL_SECONDS` | `86400` (24h) | Spool retention. No longer tied to a paging ceiling for the tagged lane, which PIR serves directly. |
| `GLOBAL_MIX_SPOOL_MAX_MESSAGES` | `32768` | Caps retained logical records. PIR packs each retained record into nine 16 KiB rows, pads the database to a supported matrix shape, and keeps two snapshots during rotation. Memory grows at matrix size boundaries rather than one fixed amount. |
