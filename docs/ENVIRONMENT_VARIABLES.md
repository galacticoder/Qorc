# Environment variables

This is the inventory of supported Qorc runtime and deployment environment
variables. Defaults are the values used after parsing.

## Required security material

| Name | Requirement | Owner | Purpose |
| ---- | ----------- | ----- | ------- |
| `SERVER_PASSWORD` | Required: 12-512 characters | `server/authentication/auth-utils.js`, `server/authentication/server-password-monitor.js` | Password for the anonymous server entry OPAQUE gate. Startup fails on invalid input and deletes the plaintext from `process.env` after initialization. Editing the mounted `.env` rotates the gate record and password bound server entry issuer.|
| `AUTH_ROOT_SEED` | Required: exactly 32 random bytes as 64 hex characters | `server/crypto/auth-root.js` | Root seed for deriving authentication, discovery, privacy-pass, routing, decoy, and avatar privacy keys. It must remain consistent across authorized nodes and restarts. The first derivation copies it to private process memory and deletes it from `process.env`. |
| `SERVER_TRANSPORT_IDENTITY_SEED` | Required: exactly 32 random bytes as 64 hex characters | `server/server.js` | Deterministically derives the server's ML-KEM-1024, ML-DSA-87, and X25519 transport identity. Nodes behind one advertised identity must share it. Startup deletes the environment copy after derivation. Rotating it intentionally changes the client visible server fingerprint. |
| `TLS_CERT_PATH` | Required | `server/bootstrap/server-bootstrap.js`, launchers | HTTPS certificate path. Relative paths are resolved from the repository by the launchers. |
| `TLS_KEY_PATH` | Required | `server/bootstrap/server-bootstrap.js`, launchers  | Private key corresponding to `TLS_CERT_PATH`. |
| `REDIS_URL` | Required by the runtime and must use `rediss://` with an explicit host and port | `server/session/redis-client.js` | Credential-free TLS Redis endpoint used for anonymous coordination, routing, rate limits, discovery relay, and clustering.  |
| `PGSSLROOTCERT` | Required | `server/database/core.js` | Path to the explicitly trusted PostgreSQL CA bundle. The launcher validates the file but never learns a CA from the endpoint it is about to trust. |

Use independent random values for `AUTH_ROOT_SEED` and
`SERVER_TRANSPORT_IDENTITY_SEED`. Do not derive either from `SERVER_PASSWORD`.
The Docker startup helper generates independent values when either variable is
absent and saves them to `.env`. It never replaces a
present malformed value or rotates an existing value. Every authorized node
behind the same logical server identity must use the same values.

For the single-host Docker deployment, `scripts/start-docker.cjs` fills missing
container connection defaults and generates independent `DATABASE_PASSWORD`
and `REDIS_PASSWORD` values.

## Server and HTTPS

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `DISCONNECT_CLIENTS_ON_SERVER_PASSWORD_CHANGE` | `no`, enabled by `yes`, `true`, or `1` | `server/authentication/server-password-monitor.js` | When enabled at the moment `SERVER_PASSWORD` changes, synchronously removes authorization from and closes all WebSockets connected to that server process. When disabled, existing sockets remain authorized but all new connections use the new password bound issuer. |
| `PORT` | Required by the runtime, Docker supplies `3000` | `server/config/config.js`, launchers | HTTPS listen port. |
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
| `WS_BANDWIDTH_QUOTA_BYTES` | 64 MiB, 8-512 MiB | `server/config/constants.js` | Per connection inbound byte budget. |
| `WS_BANDWIDTH_WINDOW_MS` | `60000`, 5000-600000 | same | Bandwidth budget window. |
| `WS_FRAME_MAX_PER_WINDOW` | `500`, 50-100000 | same | Per connection inbound frame count. |
| `WS_FRAME_WINDOW_MS` | `60000`, 5000-600000 | same | Frame count window. |
| `WS_HEARTBEAT_MISSED_LIMIT` | `6`, 3-20 | `server/websocket/gateway.js` | Missed heartbeat limit before disconnect. |
| `WS_PENDING_MESSAGE_MAX_COUNT` | `64`, 4-4096 | same | Messages waiting behind the ordered per-socket handler. |
| `WS_PENDING_MESSAGE_MAX_BYTES` | 16 MiB, 1-256 MiB | same | Bytes waiting behind the ordered per-socket handler. |
| `WS_MAX_CONCURRENT_CONNECTIONS` | `4096`, 64-100000 | same | Per process websocket ceiling. |
| `WS_MESSAGE_HANDLER_TIMEOUT_MS` | `30000`, 1000-120000 | same | Timeout for one ordered application message handler. |
| `WS_MAX_ENCRYPTED_RESPONSE_BYTES` | 12 MiB, 1-64 MiB | `server/messaging/pq-envelope-handler.js` | Maximum serialized logical server response before fragmentation into authenticated 64 KiB binary cells. The fixed-cell protocol also caps one logical message at 24 MiB. |
| `WS_ENCRYPTED_SEND_QUEUE_MAX_COUNT` | `64`, 4-1024 | same | Per socket encrypted response queue count. |
| `WS_ENCRYPTED_SEND_QUEUE_MAX_BYTES` | 24 MiB, 4-256 MiB | same | Per socket encrypted response queue bytes. |
| `WS_DELIVERY_TIMEOUT_MS` | `30000`, 1000-120000 | same | Maximum wait for encrypted websocket delivery/drain. |
| `PQ_HANDSHAKE_MAX_PER_MIN` | `20`, 1-600 | same | Per connection PQ handshake/rehandshake ceiling. |
| `PQ_HANDSHAKE_MAX_CONCURRENCY` | `2`, 1-16 | same | Process level concurrent ML-KEM handshake work. |
| `PQ_HANDSHAKE_MAX_QUEUE` | `16`, 0-64 | same | Bounded handshake waiters. |
| `PQ_HANDSHAKE_QUEUE_TIMEOUT_MS` | `15000`, 1000-60000 | same | Maximum wait for a handshake slot. |
| `PQ_HANDSHAKE_CONFIRM_TIMEOUT_MS` | `120000`, 5000-300000 | same | Maximum time a staged session may wait for encrypted peer confirmation before the socket is closed and its pending/current transport state is wiped. Client acknowledgement and encrypted-confirmation phases have separate Tor-adjusted budgets, each capped at 180 seconds. |

## PostgreSQL

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `DATABASE_URL` | Required | `server/database/core.js` | `postgres://` or `postgresql://` URL with an explicit host, port, user, password, and database. |
| `DB_TLS_SERVERNAME` | Required | same | Explicit SNI and hostname verification name. |
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
| `REDIS_PASSWORD` | Required, at least 32 base64url characters | Redis clients and Docker Redis | The sole Redis authentication credential. It must not also be embedded in `REDIS_URL`. The Docker startup helper generates it only during initial setup when it is missing. |
| `REDIS_TLS_SERVERNAME` | Required | Redis clients | SNI and certificate-verification name. |
| `REDIS_CA_CERT_PATH` | Required | Redis clients | Explicit Redis CA bundle. |
| `REDIS_CLIENT_CERT_PATH` | Required | Redis clients | Client certificate for Redis mutual TLS. |
| `REDIS_CLIENT_KEY_PATH` | Required | Redis clients | Private key for `REDIS_CLIENT_CERT_PATH`, cached key bytes are wiped on teardown. |
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
| `RATE_LIMIT_REDIS_CONNECT_TIMEOUT` | `10000`, 1000-60000 | same | Rate-limit Redis connection timeout. |
| `RATE_LIMIT_REDIS_COMMAND_TIMEOUT` | `10000`, 1000-30000 | same | Rate-limit Redis command timeout. |

`REDISCLI_AUTH` is created internally by the launcher when invoking `redis-cli`, so
the password does not appear in command arguments. It is not an operator setting.

## Anonymous PQ HTTP transport

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `PQ_ANONYMOUS_HTTP_MAX_INFLIGHT` | `8`, 5-16 | `server/routes/pq-anonymous-http.js` | Concurrent admitted replay/KEM/decrypt/dispatch/response operations per process. |
| `PQ_ANONYMOUS_HTTP_MAX_RPS` | `100`, 1-2000 | same | Process wide token bucket for work-valid requests before KEM processing. |
| `PQ_ANONYMOUS_HTTP_BODY_MAX_INFLIGHT` | `32`, 1-256 | same | Pre-parser cap on simultaneous fixed-cell uploads, preventing unauthenticated 2 MiB PIR bodies from accumulating without bound. Excess sockets are closed before body buffering. |
| `PQ_ANONYMOUS_HTTP_MAX_FAILURE_INFLIGHT` | `16`, 1-64 | same | Concurrent fixed 64 KiB opaque failure writes, excess failures close without allocating a response. |
| `PQ_ANONYMOUS_HTTP_MAX_FAILURE_RPS` | `200`, 1-4000 | same | Process wide token bucket for opaque failure writes. |
| `PQ_ANONYMOUS_HTTP_REJECT_LOG_MAX_RPS` | `5`, 1-20 | same | Process-wide ceiling for fixed, non-attacker-controlled anonymous transport rejection diagnostics. |

Anonymous response transfers use a fixed 180-second idle limit and a size-based
deadline of 180 seconds plus one second per 16 KiB, rounded up, with a minimum
body budget of five minutes for slow but progressing transfers. An 8.5 MiB
discovery response therefore has a 724-second body budget. The response writer
uses 16 KiB chunks and applies the same idle budget to its underlying HTTPS
socket. The native client disables the HTTP library's shorter Linux TCP user
timeout, request cancellation and the explicit transfer deadlines own its
lifetime, including when Tor applies SOCKS upload backpressure. The native client
allows up to 150 seconds to establish the isolated Tor connection, within its
180-second response-header budget, separately from the body budget. These
limits are protocol policy, not environment settings. A discovery lookup fetches
four padded responses (34 MiB total) and cancels outstanding downloads when it
fails, changes account or authenticated server identity, crosses a linked/unlinked
privacy boundary, or reaches its 20-minute overall deadline. A WebSocket reconnect
does not cancel independent anonymous HTTP transfers. Their authenticated public
server keys and monotonic server-time anchor remain usable for at most 20 minutes
without a connected authenticated session, logout and explicit close revoke them.

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
| `AUTH_PIR_MAX_QUEUE` | `8`, 0-8 | same | Maximum waiters for the isolated constant-work private-auth worker. |
| `AUTH_PIR_QUEUE_TIMEOUT_MS` | `90000`, 1000-120000 | same | Maximum wait for that worker. |
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
| `GLOBAL_MIX_SPOOL_MAX_BYTES` | 512 MiB, 1 MiB-1 GiB | same | Global sealed-spool byte cap. Only the standard 128 KiB ciphertext class is retained, base64 and envelope framing make the serialized Redis row larger. The 1 GiB hard ceiling keeps the PIR tag index inside its fixed response class. Both caps refuse writes when reached until rows age out through `GLOBAL_MIX_SPOOL_TTL_SECONDS`. |
| `GLOBAL_MIX_PUBLICATION_MAX_BYTES` | 2 MiB, 64 KiB-16 MiB | same | Maximum cross-node publication payload. |
| `GLOBAL_MIX_PUBLICATION_VERIFY_MAX_RPS` | `128`, 1-2000 | same | Process-wide ML-DSA verification ceiling for signed cross-node Redis publications. |
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
| `DISCOVERY_PUBLICATION_MAX_POOL_ENTRIES` | `512`, 100-8192 | same | Combined delayed/processing entry cap. Each entry contains one fixed 128 KiB base64 character encrypted publication plus its server signature and bounded queue metadata. |
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
| `SPOOL_TAG_INDEX_HTTP_MAX_RPS` | `50`, 1-2000 | same | Per-process token bucket for fixed-cell tag-index requests. |
| `SPOOL_PIR_HTTP_MAX_RPS` | `8`, 1-128 | same | Per-process token bucket for native PIR requests. |
| `SPOOL_PIR_MAX_INFLIGHT` | `2`, 1-8 | same | Concurrent native PIR worker requests per process. |

## Clustering and load balancing

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `SERVER_ID` | Required | server and cluster modules | Logical node identifier. It identifies a server process, never a user. |
| `SERVER_HOST` | Required by the runtime, Docker supplies `server` | launcher, `server/cluster/cluster-manager.js` | Backend host advertised to cluster state and HAProxy. |
| `CLUSTER_PRIMARY` | Required | cluster modules | Must be exactly `true` for the primary node or `false` for a joining node. The role is never inferred from Redis state. |
| `CLUSTER_AUTO_APPROVE` | Required | cluster modules | Must be exactly `true` or `false`. `true` lets the primary automatically approve authenticated pending join requests. Joining nodes can never approve themselves. |
| `NO_GUI` | `false` | launchers | Disables the interactive server/load-balancer terminal UI. |
| `HAPROXY_HTTPS_PORT` | Required | load-balancer modules | External HAProxy HTTPS port. |
| `HAPROXY_STATS_PORT` | Required | load-balancer modules | HAProxy statistics listener port. |
| `HAPROXY_STATS_BIND_ADDRESS` | Required | load-balancer modules | Must be `127.0.0.1` for native deployment or `0.0.0.0` inside the Docker container. Docker publishes the statistics port only on host loopback. |
| `HAPROXY_STATS_USERNAME` | Required for the load balancer, configured through `.env` | load-balancer modules | HAProxy statistics and command channel identity. |
| `HAPROXY_STATS_PASSWORD` | Required for the load balancer, configured through `.env` | load-balancer modules | Companion secret. On first startup the launcher derives and stores its protected command channel material under `server/config`. |
| `LB_SERVER_ACTIVE_TIMEOUT_MS` | `45000`, 10000-300000 | same | Age after which a cluster backend is no longer considered active. |

## PQ TLS and installation tooling

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `OPENSSL_CONF` | Generated edge configuration | load-balancer modules | OpenSSL configuration that loads the bundled providers. |
| `OPENSSL_MODULES` | Fixed by the launcher | same | Internal OpenSSL provider module directory under `/opt/qorc-edge`, external overrides are not accepted. |
| `OQS_PROVIDER_MODULE` | Fixed by the launcher | load-balancer image | Internal OQS provider path under `/opt/qorc-edge`, external overrides are not accepted. |
| `LD_LIBRARY_PATH` | Fixed by the launcher | load-balancer image | Private-library search path under `/opt/qorc-edge`, inherited paths are not used by HAProxy or Tor. |
| `TLS_CERT_CN` | `localhost` | `scripts/generate_tls.cjs` | Common name used by local TLS certificate generation. |

## Client and build tooling

| Name | Default / range | Owner | Purpose |
| ---- | --------------- | ----- | ------- |
| `VITE_WS_URL` | Unset | `src/components/setup/ConnectSetup.tsx` | Packaged web-client websocket endpoint, for example `wss://localhost:8443`. |
| `QORC_INSTANCE_ID` | Auto-selected by the client launcher, direct app launches use `1` | `src-tauri/src/main.rs`, `scripts/start-client.cjs` | Selects a distinct native data directory and `logs/instance-<id>-logs.txt` output for multi-instance testing. Concurrent launcher runs atomically select different numeric IDs. |
| `PROTOC` | Auto-detected | `scripts/start-client.cjs` | Explicit Protocol Buffers compiler path. |
| `QORC_PROTOC_VERSION` | `33.0` | same | Windows protoc download version. |
| `QORC_PROTOC_URL` | Version-derived official release URL | same | Explicit Windows protoc archive URL. |
| `QORC_STRAWBERRY_PERL_URL` | Pinned Strawberry Perl download URL | same | Windows native-build dependency URL. |
| `WEBKIT_DMABUF_RENDERER_FORCE_SHM` | `1` on Linux | same | WebKitGTK rendering compatibility setting. An explicit inherited value is preserved. |
| `GSTREAMER_PLUGINS_DIR` | `.cache/gstreamer-plugins-<arch>` during client builds | `scripts/start-client.cjs`, Linux bundle scripts | Build-time location of the staged curated GStreamer tree. It is not required by an installed package. |
| `QORC_GSTREAMER_SYSTEM_PLUGINS_DIR` | `pkg-config` result or a standard system directory | `scripts/stage-gstreamer-plugins.cjs` | Advanced build-time override for the GStreamer plugin directory copied into the private staged runtime. |
| `QORC_GSTREAMER_LAUNCH_SOURCE` | `/usr/bin/gst-launch-1.0` or `/bin/gst-launch-1.0` | same | Advanced build-time override for the `gst-launch-1.0` executable copied into the private capture runtime. |
| `QORC_GSTREAMER_PLUGIN_SCANNER_SOURCE` | Auto-detected system scanner | same | Advanced build-time override for the GStreamer plugin scanner copied into the private capture runtime. |
| `QORC_GSTREAMER_LAUNCH` | Packaged or staged private launcher | native Linux screen capture | Advanced runtime override for the private GStreamer capture launcher. Normal builds set it automatically. |
| `QORC_GSTREAMER_CAPTURE_PLUGINS` | Packaged or staged capture-plugin directory | same | Advanced runtime override for the curated capture-only plugin directory. |
| `QORC_GSTREAMER_RUNTIME_LIB` | Packaged or staged private library directory | same | Advanced runtime override for the capture process dynamic-library directory. |
| `QORC_GSTREAMER_SPA_PLUGINS` | Packaged or staged `spa-0.2` directory | same | Advanced runtime override for the private PipeWire SPA root. It must contain support modules plus the video adapter used by screen capture, this replaces rather than extends the host SPA path. |
| `QORC_GSTREAMER_PLUGIN_SCANNER` | Packaged or staged private scanner | same | Advanced runtime override for the GStreamer plugin scanner. |
| `QORC_GSTREAMER_REGISTRY` | `$XDG_RUNTIME_DIR/qorc/gstreamer-registry-1.0.bin` | same | Advanced override for the per-session GStreamer registry file used by native screen capture. |
| `PIPEWIRE_DEBUG` | `1` for the capture child unless inherited | PipeWire library inherited by the capture child | Advanced Linux screen-capture diagnostics. Level `1` retains errors, level `4` traces SPA factory loading and stream state. Do not enable verbose levels for normal releases. |
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
| `POSTGRES_DB` | `qorc`, Compose supplies `DB_NAME` | Database initialized by the PostgreSQL entrypoint. |
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
| `QORC_PIR_WORKER_PATH` | `workers/ypir/target/release/qorc-pir-worker` locally, `/app/bin/qorc-pir-worker` in Docker | Optional override. The Docker image bundles and verifies the worker at `/app/bin/qorc-pir-worker`, so this is not normally set. **The server refuses to start without a usable worker**: small spool entries are served only by PIR, so booting without it would accept messages it can never deliver. |
| `GLOBAL_MIX_SPOOL_TTL_SECONDS` | `86400` (24h) | Spool retention. No longer tied to a paging ceiling for the tagged lane, which PIR serves directly. |
| `GLOBAL_MIX_SPOOL_MAX_MESSAGES` | `32768` | Caps retained logical records. PIR packs each retained record into nine 16 KiB rows, pads the database to a supported matrix shape, and keeps two snapshots during rotation. Memory grows at matrix size boundaries rather than one fixed amount. |
