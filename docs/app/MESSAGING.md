# Qor-Chat Messaging Architecture

## Overview

The server never sees message contents or sender identity. On the server-routed path, active sends no longer submit the raw destination inbox secret, the exact destination route commitment, the destination mailbox lookup commitment, or a destination bucket. The sender submits only an opaque sealed envelope. Message delivery can use either direct P2P (QUIC) or server-routed blind routing with identical cryptographic envelopes.

Core properties:
- End-to-end encryption with LibSignal plus a post-quantum Hybrid wrapper.
- Sender identity stays inside a sealed envelope and is never visible to the server.
- Blind routing uses a global mix stream instead of usernames, raw inbox IDs, exact route IDs, mailbox lookup IDs, or buckets on active send requests.
- WebSocket transport is post-quantum encrypted and padded to a fixed size.

---

## 1. Message Layers (End-to-End)

Every message passes through multiple layers. The outer layers protect metadata, and the inner layers protect content and sender identity.

Layer order (inner to outer):
1. Application payload (text, receipts, typing, file metadata, avatar exchange).
2. LibSignal encryption (`signal.encrypt`) for per-peer E2EE.
3. Hybrid envelope (`CryptoUtils.Hybrid.encryptForClient`) which signs and wraps the LibSignal ciphertext.
4. Sealed envelope (`BlindRoutingClient.createSealedEnvelope`) which hides sender identity from the server.
5. PQ WebSocket envelope (`pq-envelope`, fixed size) for transport encryption.

Code references:
- LibSignal encryption: `src/hooks/message-sending/send.ts`, `src/hooks/app/useEncryptionProvider.ts`
- Hybrid envelope: `src/hooks/app/useEncryptionProvider.ts`
- Sealed envelope: `src/lib/transport/blind-routing-client.ts`
- PQ WebSocket encryption: `src/lib/websocket/encryption.ts`, `server/messaging/pq-envelope-handler.js`

---

## 2. Connection and Session Setup (Transport)

### 2.1 Server public keys
On connection, the server sends `server-public-key` containing the PQ hybrid public keys and blind signature public key metadata (RSABSSA-PSS).

Code references:
- Server send: `server/websocket/gateway.js`
- Client receive: `src/lib/websocket/websocket.ts`

### 2.2 PQ handshake (WebSocket)
The client establishes a post-quantum session over WebSocket:
1. Client sends `pq-handshake-init` with Kyber ciphertext, X25519 public key, ML-DSA signing public key, session id, and explicit algorithm policy.
2. Server derives a hybrid shared secret (Kyber + X25519) and responds with `pq-handshake-ack`.
3. Both sides derive `sendKey` and `recvKey` and enforce PQ-encrypted envelopes.

Required policy:
```txt
version = pq-ws-1
kem = ML-KEM-1024
signature = ML-DSA-87
classicalKeyAgreement = X25519
kdf = BLAKE3-HKDF-SHA256-DOMAIN-SEPARATED
aead = QOR-PQ-AEAD
```

The server rejects handshakes that omit or downgrade any field. Each PQ WebSocket session is bound to the exact client ML-DSA public key presented during that handshake. The client self-tests its stored ML-DSA key pair before use, overwrites corrupt or mismatched transport signing keys, keeps the active session bound locally to the exact public key from the handshake, and refuses to sign an envelope if the active session key material does not match the active signing key.

PQ WebSocket traffic keys are not persisted for background restore. A resumed app performs a fresh hybrid PQ handshake instead of replaying locally stored transport keys. This avoids stale signing-key/session-key states and preserves the rule that every encrypted envelope belongs to one freshly authenticated transport session.

Code references:
- Client handshake: `src/lib/websocket/handshake.ts`
- Server handshake: `server/messaging/pq-envelope-handler.js`

### 2.3 Server entry token (optional gatekeeper)
If the server requires an entry token, the client performs Privacy Pass gatekeeper flow and redeems a token before sending other signals.

Code references:
- Client gatekeeper flow: `src/lib/websocket/websocket.ts`
- Server token validation: `server/server.js` (`PRIVACY_PASS_REDEMPTION`)

### 2.4 Unlinkable autologin (anonymous session resume)
After the PQ session is established, the client resumes its session by redeeming a **one-time anonymous Privacy Pass token** (`resumeRedemption` in `TOKEN_VALIDATION`) rather than replaying a stored session token. The token is blind-signed (server can't link issuance to redemption) and single-use (per-token nullifier), so reconnects are unlinkable. On a valid redemption the server marks the WebSocket authenticated and optionally issues blind routing credentials. The pool of resume tokens is machine-bound (passwordless restart works) and refilled at each login. See `docs/app/AUTHENTICATION.md` §5.

Code references:
- Client: `src/lib/websocket/websocket.ts` (`attemptTokenValidationOnce`), `src/lib/signals/resume-tokens.ts`
- Server: `server/server.js` (`TOKEN_VALIDATION` → `PrivacyPassServer.redeemToken`)
- Session service: `server/authentication/anonymous-session-service.js`

---

## 3. Client Send Flow (Text, Reactions, Typing, Receipts)

### 3.1 UI and local message creation
The UI uses `useMessageSender.handleSendMessage` to validate input, create an optimistic local message, and queue retries when needed.

Code references:
- Sender: `src/hooks/message-sending/useMessageSender.ts`
- Message payload construction: `src/hooks/message-sending/send.ts`
- Local vault for message content: `src/lib/security/message-vault.ts`

### 3.2 LibSignal encryption
The payload is encrypted with LibSignal for the recipient, using `signal.encrypt`. If no session exists, the client requests a bundle and establishes a session.

Code references:
- Encryption provider: `src/hooks/app/useEncryptionProvider.ts`
- Session establishment: `src/hooks/message-sending/session.ts`
- Discovery fetch: `src/hooks/discovery/useDiscovery.ts`

### 3.3 Hybrid envelope
The LibSignal ciphertext is wrapped by `CryptoUtils.Hybrid.encryptForClient` and signed by the sender Dilithium key. The envelope includes:
- `signalCiphertext`
- `from` (sender handle)
- `fromInbox` (sender inbox id)

Code references:
- Hybrid encryption: `src/hooks/app/useEncryptionProvider.ts`

### 3.4 Transport selection
`unifiedSignalTransport.send` chooses transport:
- P2P QUIC if a peer connection is active.
- Server-routed blind routing if no P2P connection exists.

Code references:
- Transport selection: `src/lib/transport/unified-signal-transport.ts`
- P2P sender: `src/lib/transport/secure-p2p-service.ts`

---

## 4. Server Fallback Path (Blind Routing)

### 4.1 Sealed envelope creation
For server delivery, the client uses `BlindRoutingClient.createSealedEnvelope`:
- Inner payload includes sender identity.
- Envelope encrypted with Kyber KEM + AES-GCM.
- Message framing pads to a fixed size to resist length inference.

Code references:
- Sealed envelope: `src/lib/transport/blind-routing-client.ts`
- Client padding: `src/lib/transport/message-framing.ts`

### 4.2 Blind route signal
The client sends:
```json
{
  "type": "blind-route",
  "sealedEnvelope": { "...": "..." }
}
```
The message is wrapped inside a PQ WebSocket envelope on the wire.

The raw `inboxId`, exact `routeId`, mailbox lookup, and destination bucket are kept out of the active server send request. The server-visible request uses:
- `sealedEnvelope`: fixed-size sender-sealed payload addressed cryptographically to the recipient.
- no destination selector: no raw inbox, exact route, mailbox lookup, shard, bucket, username, or handle.

Security invariant:
- Active routing requests must not include `destinationInbox`, `destinationRouteId`, `destinationMailboxLookupId`, `destinationBucketId`, `routeId`, `mailboxLookupId`, `recipientUsername`, `handle`, `to`, `messageId`, `shardId`, or any other top-level destination selector.
- The server rejects `blind-route` requests that try to submit destination selectors.
- The active request is accepted into a global mixnet-style ingress delay pool before global-spool writing.
- The global writer flushes delayed entries in shuffled batches with cover writes. The sender-visible ACK is tied only to ingress acceptance.
- Each recipient attempts to open the sealed envelope locally. Non-recipients fail closed and silently drop the candidate.
- The active server no longer sees a routing bucket, so destination privacy does not depend on how many users share a bucket.
- Raw-inbox, direct-route, mailbox-targeted, and bucket-targeted active send routes are intentionally absent.

Route rotation:
0. The starting inbox itself rotates per 6h epoch. `inboxId = deriveInboxId(vaultKey, currentInboxEpoch())` folds a 6h epoch (aligned with the discovery epoch) into the derivation, so the first inbox/route claimed each login is not a permanent per-account value the server can link sessions by (it was, when the inbox was a pure function of the vault key). All derived commitments (`routeId`, `bundleLookupId`, `blockListLookupId`, `mailboxLookupId`) inherit this rotation on top of the in-session rotation below.
1. After a successful route claim, the client starts in-session route commitment rotation.
2. Rotation sends `rotate-inbox` with old and new committed IDs: `oldRouteIds`, `newRouteIds`, `oldBundleLookupIds`, `newBundleLookupIds`, and `newBlockListLookupIds`. `oldMailboxLookupIds` and `newMailboxLookupIds` are rejected.
3. The server unregisters old claimed route commitments and registers the new commitments on the same authenticated WebSocket.
4. The global candidate retrieval path advances only through the global candidate stream. It does not query mailbox-backed recipient storage.
5. The client republishes its encrypted discovery material (which carries the Signal prekey bundle inside it) for the new commitments. There is no separate server-side bundle publish.

Code references:
- Send: `src/lib/transport/unified-signal-transport.ts`
- WebSocket PQ envelope: `src/lib/websocket/encryption.ts`
- Route rotation client: `src/lib/transport/blind-routing-client.ts`

---

## 5. Server Routing and Delivery

### 5.1 Routing flow
1. `server/server.js` receives `blind-route` and calls `handleBlindRoute`.
2. `handleBlindRoute` rejects destination selectors and validates the sealed-envelope shape.
3. `routeToGlobalMix` accepts the packet into the Redis mixnet delay pool (`mixnet:delay:pool:v1`).
4. The sender receives a uniform `blind-route-ack` after ingress acceptance. The ACK does not wait for final global-spool writing and does not reveal whether the recipient is live.
5. A mixnet relay worker releases due packets after a randomized delay, claims a shuffled batch, adds cover writes, and writes the batch into the global mix spool.
6. Global writing stores the candidate envelope, tries local privacy broadcast, and publishes a global fan-out event for other server instances.
7. Every connected PQ socket may receive the candidate envelope. Only the real recipient can open it.
8. If the recipient rotated routes, peers learn the new route material only through encrypted discovery refresh.

Code references:
- WebSocket dispatch: `server/server.js`
- Blind route handler: `server/handlers/inbox-handlers.js`
- Blind router: `server/routing/blind-router.js`

### 5.2 Local vs distributed delivery
- Local: deliver to every connected PQ WebSocket as a candidate envelope.
- Distributed: publish to Redis `blind:global-mix:deliver` without any destination selector for other instances.
- Mix relay: all active sends first enter `mixnet:delay:pool:v1`. Workers flush delayed entries independently of the ingress ACK.
- Cross-server writer preference: a worker skips packets ingressed by the same `SERVER_ID` until `MIXNET_SAME_WRITER_FALLBACK_MS` expires, allowing another server instance to become the writer when the deployment has multiple instances.
- The server no longer has a direct `routeToInboxRoute` delivery helper or a receive-side bucket registration map.

Code references:
- Local registry: `server/routing/blind-router.js`
- Redis pub/sub: `server/routing/blind-router.js`

### 5.3 Global mix spool
The final writer appends each candidate envelope to one Redis sorted set: `mixnet:global:spool:v1`. Clients retrieve the recent window as a **uniform per-epoch encrypted snapshot**: every client downloads byte-identical bytes (padded to a floor with shape-matched decoys, gzipped, and digest-verified), so the request does not name or imply a recipient, route, bucket, shard, mailbox, or cursor. The client trial-decrypts every envelope and de-duplicates with a purely client-side cursor. (This replaced the spool's earlier per-record computational PIR. The discovery database is the only remaining computational-PIR surface — see `docs/app/COMPUTATIONAL_PIR.md`.)

Default global spool controls:
- TTL: 7 days (`GLOBAL_MIX_SPOOL_TTL_SECONDS`)
- Max messages: 262,144 (`GLOBAL_MIX_SPOOL_MAX_MESSAGES`)
- Snapshot epoch, padding floor, and row cap: `SPOOL_SNAPSHOT_EPOCH_MS`, `SPOOL_SNAPSHOT_PADDING_FLOOR`, `SPOOL_SNAPSHOT_MAX_ROWS`.
- Clients poll the snapshot at a fixed rate.

### 5.4 Mixnet relay and traffic shaping
The mixnet relay splits active server-routed traffic into four stages:

1. **Ingress relay**: validates and stores the opaque sealed envelope in a Redis delay pool with no destination selector.
2. **Delay pool**: releases entries only after a randomized delay window (`MIXNET_DELAY_MIN_MS` to `MIXNET_DELAY_MAX_MS`).
3. **Global writer**: claims due entries, shuffles them, injects cover writes, and writes to the global mix spool.
4. **Recipient retrieval**: clients poll at a fixed rate and download the uniform encrypted spool snapshot, then locally trial-decrypt/filter candidates.

Default mixnet controls:
- Delay window: 1.5s to 9s.
- Flush window: 0.7s to 2.5s.
- Writer batch cap: 24 delayed entries per flush.
- Cover writes: 1 to 2 full sealed-envelope-shaped writes per flush.
- Same-writer avoidance: enabled by default. Same-server writes are deferred for up to 60s to give other cluster instances a chance to write.

One-server and multi-server privacy rule:
- Destination-selector privacy is the same in one-server and multi-server deployments because the active send request contains no username, inbox, route, mailbox, shard, bucket, or other destination selector.
- A one-server deployment observes coarse ingress timing and global write timing, but randomized delay, shuffled flushes, cover writes, fixed-rate polling, fixed-size frames, and global candidate retrieval prevent that timing from being tied to a server-visible destination.
- A multi-server deployment with separate `SERVER_ID`s and shared Redis adds observer separation between ingress acceptance and global writing.

Code references:
- Global mix spool: `server/routing/blind-router.js`

---

## 6. Global Candidate Retrieval

For server-path messaging, the active send path accepts the opaque sealed envelope into the mixnet delay pool. The final global writer later appends it to the global mix spool and may then attempt opportunistic live privacy broadcast to connected PQ sockets.

There is no separate offline-only envelope format anymore:
1. the sender still produces the normal blind-routed `sealed-envelope`
2. the server accepts that envelope into the mixnet delay pool with a uniform sender-visible ACK
3. a delayed global writer writes shuffled real and cover candidates into the global mix spool
4. the server may fan candidates out live without changing the sender-visible response
5. the recipient later retrieves global candidates by downloading the fixed-rate uniform spool snapshot
6. non-recipients receive only undecryptable noise

Code references:
- Blind route acceptance: `server/handlers/inbox-handlers.js`
- Global-spool snapshot service: `server/routing/spool-snapshot-service.js`, `server/routes/api-routes.js` (`GET /api/spool/snapshot`)
- Client global-spool snapshot handler: `src/lib/websocket/global-spool-pir-handler.ts`

Route claims are keyed by committed IDs, not raw inbox IDs. A successful route claim establishes:
- `routeId` for route ownership and blind-route authorization.
- `blockListLookupId` for encrypted block-list sync.

(`bundleLookupId` is still derived/claimed for compatibility, but the server no longer stores Signal bundles — prekey bundles ride inside the encrypted discovery blob and in-band.)

`mailboxLookupId` may still exist inside encrypted peer material for local/client-side validation, but it is not accepted by `claim-inbox`, `rotate-inbox`, `blind-route`, or PIR retrieval.

Code references:
- Client derivation: `src/lib/transport/rendezvous-routing.ts`
- Inbox claim handler: `server/handlers/inbox-handlers.js`
- Route registry: `server/routing/blind-router.js`

---

## 7. Receiving and Decryption

### 7.1 PQ envelope decrypt
Incoming WebSocket data is decrypted in `WebSocketMessageHandler`. If the message is a PQ envelope, it is decrypted before dispatch.

Code references:
- Client decrypt: `src/lib/websocket/message-handler.ts`, `src/lib/websocket/encryption.ts`
- Server PQ envelope: `server/messaging/pq-envelope-handler.js`

### 7.2 Sealed envelope open
If the message is a `sealed-envelope`, the client:
1. Uses `BlindRoutingClient.openSealedEnvelope` with its Kyber secret key.
2. Extracts the Hybrid envelope.
3. Decrypts the Hybrid envelope and then the LibSignal ciphertext.

Code references:
- Sealed envelope open: `src/lib/transport/blind-routing-client.ts`
- Hybrid decrypt: `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- LibSignal decrypt: `src/hooks/message-handling/useEncryptedMessageHandler.ts`

### 7.3 P2P receives the same sealed envelope
P2P messages with type `sealed-envelope` are accepted only when the P2P transport message has a valid Dilithium signature and route proof for the certified peer channel. After that transport authorization succeeds, the sealed envelope is forwarded into the same encrypted message handler used by server-routed messages.

Security invariant:
- P2P is only a transport difference.
- P2P does not become a separate message-authentication policy.
- The outer P2P `from`/`to` fields are not copied into the decrypted app payload.
- The outer P2P signature proves transport authorization. LibSignal remains the final conversation sender authority.
- A local message object is released only after the same sealed-envelope, Hybrid/PQ, Signal identity, replay, block, and certified-identity checks that server-routed messages use.

Code references:
- P2P forwarder: `src/hooks/p2p/messaging.ts`
- P2P transport authorization: `src/lib/transport/secure-p2p-service.ts`

---

## 8. File Transfers (Chunked)

File transfers are chunked client-side and transported as sealed envelopes.

Flow:
1. File is split into chunks and compressed.
2. Each chunk is encrypted with a per-file AES key.
3. Chunk metadata is LibSignal-encrypted.
4. The chunk message is sent via `unifiedSignalTransport` with type `file-message-chunk`.
5. The receiver decrypts, validates MAC, and reassembles the file.

Code references:
- File sending: `src/components/chat/ChatInput/useFileSender.ts`
- File receive/reassembly: `src/hooks/file-handling/useFileHandler.ts`, `src/hooks/file-handling/file-assembly.ts`
- Chunk validation: `src/hooks/file-handling/chunk-validation.ts`

---

## 9. Receipts, Typing, Avatar Exchange

These are ordinary message types inside the encrypted payload:
- Typing indicators: `typing-start`, `typing-stop`.
- Delivery/read receipts: `delivery-receipt`, `read-receipt`.
- Avatar exchange: `profile-picture-request` / `profile-picture-response` (a peer requests another's current avatar directly when it is missing or stale — see `docs/app/AVATARS.md` §6). There is no `profile-update` broadcast message. Avatar and profile changes propagate passively through the republished encrypted discovery material.

Code references:
- Receipt handling: `src/hooks/message-handling/receipts.ts`
- Typing handling: `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- Avatar messaging: `src/lib/avatar/messaging.ts`

---

## 10. Cryptography and Security Details

### 10.1 PQ WebSocket envelope
`pq-envelope` fields:
- `sessionId`, `sessionFingerprint`, `messageId`, `counter`, `timestamp`
- `ciphertext`, `nonce`, `tag`, `aad`
- `signature` (ML-DSA signature over the canonical `version|sessionId|sessionFingerprint|messageId|timestamp|counter|aad` payload)

Client encrypts with `PostQuantumAEAD` and pads to fixed size (`WS_FIXED_MESSAGE_SIZE_BYTES`, currently 768 KiB). Server PQ responses use the same fixed-size target when the encrypted response fits. Very large snapshot-style responses are explicitly logged as oversize rather than silently pretending to be fixed-size.

Code references:
- Client encryption: `src/lib/websocket/encryption.ts`
- Server encryption: `server/messaging/pq-envelope-handler.js`
- Policy tests: `server/security/layer-agreement-policy.js`

### 10.2 Sealed envelope
Sealed envelopes use:
- Kyber KEM to derive a shared secret.
- BLAKE3 to derive a symmetric key.
- AES-GCM with a 24-byte nonce.
- Padding and framing to fixed sizes.

Code references:
- Sealed envelope: `src/lib/transport/blind-routing-client.ts`
- Framing: `src/lib/transport/message-framing.ts`

### 10.3 Rendezvous commitments
Server-visible routing identifiers are derived client-side with BLAKE3 and explicit domains:
- `qor-rendezvous-route-v1` -> route ownership and blind-signature verification.
- `qor-mailbox-metadata-v1` -> mailbox metadata commitment material for encrypted peer metadata and rotation state. Not an active delivery selector.
- `qor-libsignal-bundle-v1` -> historical Signal-bundle lookup id. The server no longer stores Signal bundles (prekey bundles ride inside the encrypted discovery blob and in-band), so this commitment is vestigial.
- `qor-block-list-v1` -> encrypted block-list storage.

The same raw inbox secret never has to be submitted to the server for active routing or block-list sync. Active sends reveal no destination commitment at all. Route and mailbox commitments are not active send selectors. The active send anonymity set is therefore the whole global mix stream during the timing window, not "users per bucket."

Code references:
- Client derivation: `src/lib/transport/rendezvous-routing.ts`
- Server claim validation: `server/handlers/inbox-handlers.js`
- Global mix router: `server/routing/blind-router.js`

### 10.4 Hybrid envelope
Hybrid envelope uses:
- Kyber encapsulation for PQ secrecy.
- X25519 for classical DH.
- Dilithium signatures for sender authentication.

Identity authority rule:
- LibSignal identity is the final conversation sender authority.
- Outer PQ/Hybrid/Dilithium layers authorize transport envelopes, device capabilities, route claims, and envelope integrity.
- Certified identity binds the LibSignal identity key and hybrid/P2P keys to the same account root. The LibSignal X25519 key and hybrid/P2P X25519 key are separate signed subkeys and must not be forced to equal each other.
- A message is invalid if LibSignal says Alice but an outer layer would cause the app to treat it as Bob.
- Outer signatures must not create a second competing sender identity.

Code references:
- Hybrid: `src/hooks/app/useEncryptionProvider.ts`
- Policy tests: `server/security/layer-agreement-policy.js`

### 10.5 Native Signal PQ wrapper
Native `signal.decrypt` requires the Signal ciphertext to be inside the Signal PQ envelope. A bare classical-only Signal decrypt path is rejected.

Required policy:
```txt
version = signal-pq-v1
kem = ML-KEM-1024
kdf = BLAKE3-SHA3-512-DOMAIN-SEPARATED
aead = XCHACHA20-POLY1305
mac = BLAKE3-KEYED
```

The ML-KEM ciphertext must be exactly `KYBER_CIPHERTEXT_SIZE`. No prefix stripping or compatibility header is accepted.

Code references:
- Native Signal wrapper: `src-tauri/src/signal_protocol/mod.rs`

### 10.6 Server-side controls
- Bandwidth quota and fixed-size enforcement in gateway.
- Mixnet ingress delay pool, shuffled writer batches, same-writer avoidance, and cover writes in blind routing.
- Fixed-rate recipient polling of the uniform per-epoch encrypted global-spool snapshot.
- Global mix spool retrieval instead of bucket retrieval.
- Per-message rate limiting applied at WebSocket handler using session id.

Code references:
- Gateway quotas: `server/websocket/gateway.js`
- Timing protection: `server/routing/timing-protection.js`
- Rate limiting: `server/server.js`, `server/rate-limiting/rate-limit-middleware.js`

---

## 11. Implementation Reference

### Server-Side
- `server/websocket/gateway.js`: connection lifecycle, heartbeat, bandwidth quota
- `server/server.js`: WebSocket message dispatch, signal routing
- `server/messaging/pq-envelope-handler.js`: PQ handshake, PQ envelope decrypt/encrypt
- `server/handlers/inbox-handlers.js`: route claim, blind-route, route rotation
- `server/handlers/pir-handlers.js`: discovery PIR manifest and query retrieval
- `server/routing/spool-snapshot-service.js`: uniform per-epoch global-spool snapshot (`GET /api/spool/snapshot`)
- `server/routing/blind-router.js`: mixnet ingress relay, delay pool, cover writes, global candidate stream, local/distributed fan-out
- `server/routing/sealed-sender.js`: envelope validation

### Client-Side
- `src/hooks/message-sending/useMessageSender.ts`: UI send pipeline
- `src/hooks/app/useEncryptionProvider.ts`: encryption provider, hybrid envelope
- `src/lib/transport/unified-signal-transport.ts`: P2P vs server transport
- `src/lib/transport/blind-routing-client.ts`: sealed envelopes and route claims
- `src/lib/transport/rendezvous-routing.ts`: route/mailbox/bundle/block-list commitments
- `src/lib/websocket/global-spool-pir-handler.ts`: fixed-rate global candidate polling
- `src/lib/websocket/websocket.ts`: PQ transport
- `src/hooks/message-handling/useEncryptedMessageHandler.ts`: decrypt and process
- `src/hooks/file-handling/useFileHandler.ts`: file chunk processing
