# Offline Messaging

Offline messaging in Qor-Chat is not a per-user mailbox. The server does not store messages under usernames, inbox IDs, route IDs, buckets, or contact-specific queues.

The current design has two parts:

1. Server-routed encrypted delivery through the global mix spool.
2. A local encrypted retry queue when the sender cannot build an encrypted message yet.

## Server-Routed Delivery

When a message cannot go directly over P2P, the sender builds the normal encrypted message stack and wraps it in a sealed envelope:

1. Signal message payload.
2. Hybrid/PQ message envelope.
3. Blind-routing sealed envelope.
4. `blind-route` transport message.

The server receives only:

```json
{
  "type": "blind-route",
  "sealedEnvelope": {
    "version": "ss-v1",
    "ciphertext": "...",
    "ephemeralKey": "...",
    "nonce": "..."
  }
}
```

The active send request must not contain a destination selector. The server rejects fields such as usernames, handles, raw inbox IDs, route IDs, mailbox lookup IDs, bucket IDs, shard IDs, recipient IDs, and top-level message IDs.

Code references:

- `src/lib/transport/unified-signal-transport.ts`
- `src/lib/transport/blind-routing-client.ts`
- `server/handlers/inbox-handlers.js`
- `server/routing/destination-selector-policy.js`
- `server/routing/sealed-sender.js`

## Server Acceptance

`handleBlindRoute` validates the request, applies rate and size limits, accepts the sealed envelope into the global mix path, and returns `blind-route-ack`.

The ACK only means the opaque envelope was accepted by ingress. It does not say whether the recipient is online, offline, known, unknown, blocked, or able to decrypt.

Relevant server-side limits:

- `BLIND_ROUTE_WINDOW_MS`
- `BLIND_ROUTE_MAX_PER_WINDOW`
- `BLIND_ROUTE_MAX_BYTES_PER_WINDOW`
- `BLIND_ROUTE_MAX_ENVELOPE_BYTES`

## Global Mix Path

Server-routed envelopes enter `mixnet:delay:pool:v1` first. Each entry gets a randomized release time. A relay worker later claims due entries, shuffles the batch, adds live cover writes, and writes real envelopes to the global spool.

The global spool is one Redis sorted set:

```txt
mixnet:global:spool:v1
```

It is a rolling shared stream of sealed envelopes. It is not keyed by recipient, route, mailbox, bucket, shard, username, or account.

The server may also broadcast candidate envelopes live to connected PQ sockets. Recipients try to decrypt locally. Non-recipients receive undecryptable candidates and drop them.

Code references:

- `server/routing/blind-router.js`
- `server/websocket/gateway.js`

## Offline Catch-Up

Offline clients catch up by downloading the same global spool snapshot as every other client:

```txt
GET /api/spool/snapshot
```

The response is a uniform per-epoch encrypted snapshot. It is padded, shuffled, gzipped, digest-verified, and byte-identical for all clients in the same epoch.

Example shape:

```json
{
  "ok": true,
  "distribution": "uniform-anonymous-cdn-tor-suitable",
  "snapshot": {
    "version": "qor-spool-snapshot-gzip-v1",
    "encoding": "base64url+gzip",
    "compression": "gzip",
    "digestAlgorithm": "sha256-uncompressed-snapshot",
    "digest": "...",
    "epochId": "...",
    "epochStart": 0,
    "epochEndsAt": 0,
    "generatedAt": 0,
    "realCountHidden": true,
    "sourceCountHidden": true,
    "paddedEntryCount": 256,
    "compressed": "..."
  }
}
```

The decoded body has this shape:

```json
{
  "version": "qor-spool-snapshot-v1",
  "epochId": "...",
  "entries": [
    { "version": "ss-v1", "ciphertext": "...", "ephemeralKey": "...", "nonce": "..." }
  ],
  "realCountHidden": true,
  "sourceCountHidden": true,
  "paddingStrategy": "power-of-two-floor-with-shape-matched-decoys-v1",
  "paddedEntryCount": 256
}
```

The client verifies the digest, decompresses the snapshot, tries every entry against its local keys, and forwards successful candidates into the normal sealed-envelope receive path. Failed decrypts stay local and are not reported to the server.

Code references:

- `server/routes/api-routes.js`
- `server/routing/spool-snapshot-service.js`
- `src-tauri/src/commands/spool.rs`
- `src/lib/websocket/global-spool-pir-handler.ts`
- `src/hooks/app/useOfflineMessages.ts`
- `src/hooks/message-handling/useEncryptedMessageHandler.ts`

## Client Delivery Loop

The app-level offline hook wires the snapshot handler to the encrypted message handler.

The delivery loop starts when the app is ready and restarts after:

- WebSocket reconnect.
- PQ session establishment.

The snapshot fetch goes through Tauri via `fetch_spool_snapshot`, which requests `/api/spool/snapshot` through the configured Tor SOCKS proxy.

Client-side timing constants:

- `GLOBAL_SPOOL_PIR_CATCHUP_DELAY_MS`: first catch-up delay, currently 25 seconds.
- `GLOBAL_SPOOL_PIR_LOOP_INTERVAL_MS`: regular polling interval, currently 15 minutes.
- `GLOBAL_SPOOL_PIR_NOT_READY_RETRY_MS`: retry delay while WebSocket/PQ is not ready, currently 5 seconds.
- `GLOBAL_SPOOL_PIR_RESPONSE_TIMEOUT_MS`: snapshot response timeout, currently 10 minutes.

These constants configure the snapshot loop. The offline-message path fetches a uniform snapshot; it does not send a PIR query or recipient selector.

## Local Retry Queue

The local retry queue is only for messages the sender cannot encrypt yet, usually because recipient keys or discovery material are not available locally.

Queued messages are stored in the local encrypted database. Message content is kept in the local message vault and referenced by ID. When `USER_KEYS_AVAILABLE` fires for that recipient, the app removes valid messages from the queue and sends them through the normal send path.

Local queue limits:

- `SECURE_QUEUE_MAX_MESSAGES_PER_USER`: 50 messages per recipient.
- `SECURE_QUEUE_MESSAGE_EXPIRY_MS`: 4 hours.
- `SECURE_QUEUE_CLEANUP_INTERVAL_MS`: 5 minutes.
- `SECURE_QUEUE_MAX_PROCESSED_IDS`: 5000 processed IDs.
- `SECURE_QUEUE_SAVE_DEBOUNCE_MS`: 1 second.

Code references:

- `src/lib/database/secure-message-queue.ts`
- `src/hooks/message-sending/send.ts`
- `src/hooks/useEventHandlers.ts`
- `src/lib/database/storage-keys.ts`

## Retention And Limits

Global spool defaults:

- `GLOBAL_MIX_SPOOL_TTL_SECONDS`: 24 hours.
- `GLOBAL_MIX_SPOOL_MAX_MESSAGES`: 1024 entries.
- `GLOBAL_MIX_SPOOL_MAX_BYTES`: 16 MiB.

Mix delay defaults:

- `MIXNET_RELAY_ENABLED`: enabled by default.
- `MIXNET_DELAY_MIN_MS`: 1.5 seconds.
- `MIXNET_DELAY_MAX_MS`: 9 seconds.
- `MIXNET_FLUSH_MIN_MS`: 700 ms.
- `MIXNET_FLUSH_MAX_MS`: 2.5 seconds.
- `MIXNET_BATCH_MAX_MESSAGES`: 24.
- `MIXNET_POOL_TTL_SECONDS`: 7 days.
- `MIXNET_AVOID_SAME_WRITER`: enabled by default.
- `MIXNET_SAME_WRITER_FALLBACK_MS`: 60 seconds.

Snapshot defaults:

- `SPOOL_SNAPSHOT_EPOCH_MS`: 30 seconds.
- `SPOOL_SNAPSHOT_PADDING_FLOOR`: 256 entries.
- `SPOOL_SNAPSHOT_MAX_ROWS`: 256 rows.
- `SPOOL_SNAPSHOT_MAX_PLAINTEXT_BYTES`: 16 MiB.
- `SPOOL_SNAPSHOT_GZIP_LEVEL`: 6.
- `SPOOL_SNAPSHOT_RESPONSE_MAX_BYTES`: 8 MiB.

Code references:

- `server/routing/blind-router.js`
- `server/routing/spool-snapshot-service.js`
- `server/routes/api-routes.js`

## Privacy Properties

The server can see:

- connection timing;
- blind-route ingress timing;
- sealed-envelope size class;
- mix delay enqueue and release timing;
- snapshot request timing and response size;
- local/live broadcast attempts to connected sockets;
- coarse rate-limit and server-health information.

The server does not receive:

- plaintext message content;
- sender identity inside the sealed envelope;
- recipient username or handle;
- raw destination inbox ID;
- destination route ID;
- mailbox lookup ID;
- bucket ID;
- shard or record index;
- server-visible recipient cursor;
- decrypt success or failure.

Every client in the same snapshot epoch receives the same snapshot bytes. The server cannot tell which entries, if any, decrypted for a client.

## Calls And Files

Offline catch-up carries normal sealed-envelope messages only.

Real-time call setup state, SDP, ICE candidates, ringing state, and live media negotiation are not persisted as offline server state.

File/control messages can use this path only when they fit the normal sealed-envelope framing limits. Large file transfer state should use live transfer or local retry behavior, not the global spool as object storage.

## Implementation Index

Server:

- `server/handlers/inbox-handlers.js`
- `server/routing/destination-selector-policy.js`
- `server/routing/blind-router.js`
- `server/routing/spool-snapshot-service.js`
- `server/routes/api-routes.js`
- `server/database/schema.js`

Client:

- `src/lib/transport/unified-signal-transport.ts`
- `src/lib/transport/blind-routing-client.ts`
- `src/lib/websocket/global-spool-pir-handler.ts`
- `src/hooks/app/useOfflineMessages.ts`
- `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- `src/lib/database/secure-message-queue.ts`
- `src-tauri/src/commands/spool.rs`
