# Qor-Chat Messaging Architecture

## Overview

The server never sees message contents or sender identity and only learns the destination inbox (an ephemeral routing identifier). Message delivery can use either direct P2P (QUIC) or server fallback (blind routing) with identical cryptographic envelopes.

Core properties:
- End-to-end encryption with LibSignal plus a post-quantum Hybrid wrapper.
- Sender identity stays inside a sealed envelope and is never visible to the server.
- Blind routing uses inbox IDs instead of usernames.
- WebSocket transport is post-quantum encrypted and padded to a fixed size.

---

## 1. Message Layers (End-to-End)

Every message passes through multiple layers. The outer layers protect metadata, and the inner layers protect content and sender identity.

Layer order (inner to outer):
1. Application payload (text, receipts, typing, file metadata, profile updates).
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
1. Client sends `pq-handshake-init` with Kyber ciphertext, X25519 public key, and session id.
2. Server derives a hybrid shared secret (Kyber + X25519) and responds with `pq-handshake-ack`.
3. Both sides derive `sendKey` and `recvKey` and enforce PQ-encrypted envelopes.

Code references:
- Client handshake: `src/lib/websocket/handshake.ts`
- Server handshake: `server/messaging/pq-envelope-handler.js`

### 2.3 Server entry token (optional gatekeeper)
If the server requires an entry token, the client performs Privacy Pass gatekeeper flow and redeems a token before sending other signals.

Code references:
- Client gatekeeper flow: `src/lib/websocket/websocket.ts`
- Server token validation: `server/server.js` (`PRIVACY_PASS_REDEMPTION`)

### 2.4 Anonymous session token validation
After PQ session is established, the client validates its anonymous session token. The server marks the WebSocket as authenticated and optionally issues blind routing credentials.

Code references:
- Client: `src/lib/websocket/websocket.ts` (`TOKEN_VALIDATION`)
- Server: `server/server.js` (`TOKEN_VALIDATION`)
- Token service: `server/authentication/anonymous-session-service.js`

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
- Server fallback via blind routing if no P2P connection exists.

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
{ "type": "blind-route", "destinationInbox": "...", "sealedEnvelope": { ... } }
```
The message is wrapped inside a PQ WebSocket envelope on the wire.

Code references:
- Send: `src/lib/transport/unified-signal-transport.ts`
- WebSocket PQ envelope: `src/lib/websocket/encryption.ts`

---

## 5. Server Routing and Delivery

### 5.1 Routing flow
1. `server/server.js` receives `blind-route` and calls `handleBlindRoute`.
2. `routeToInbox` attempts local delivery, then distributed delivery, then short-term queue.
3. If delivered, an OK is sent back. If queued, OK with `queued: true` is sent back.

Code references:
- WebSocket dispatch: `server/server.js`
- Blind route handler: `server/handlers/inbox-handlers.js`
- Blind router: `server/routing/blind-router.js`

### 5.2 Local vs distributed delivery
- Local: deliver directly to the WebSocket associated with the inbox.
- Distributed: publish to Redis `blind:deliver:<serverId>` for another instance.

Code references:
- Local registry: `server/routing/blind-router.js`
- Redis pub/sub: `server/routing/blind-router.js`

### 5.3 Short-term queue
If the inbox is offline and the message is not transient, the router queues it in Redis for 5 minutes.

Code references:
- Queue storage: `server/routing/blind-router.js`

---

## 6. Long-Term Offline Storage

If delivery fails and the inbox is offline, the server returns an error:
```json
{ "type": "error", "code": "OFFLINE_LONGTERM_REQUIRED" }
```

The client then:
1. Encrypts the message into a long-term envelope (`lt-v1`) using the recipient Kyber key.
2. Sends `store-offline-message` to the server.

The server stores offline messages in Postgres by `inboxId`, and the client retrieves them with `retrieve-offline-messages`.

Code references:
- Server offline handlers: `server/handlers/offline-handlers.js`
- Server storage: `server/database/message-db.js`
- Client offline handler: `src/lib/websocket/offline-message-handler.ts`
- Error trigger: `server/handlers/message-handlers.js`

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
P2P messages with type `sealed-envelope` are forwarded directly into the same encrypted message handler.

Code references:
- P2P forwarder: `src/hooks/p2p/messaging.ts`

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

## 9. Receipts, Typing, Profile Updates

These are ordinary message types inside the encrypted payload:
- Typing indicators: `typing-start`, `typing-stop`.
- Delivery/read receipts: `delivery-receipt`, `read-receipt`.
- Profile update signal: `profile-update` (triggers discovery refresh).

Code references:
- Receipt handling: `src/hooks/message-handling/receipts.ts`
- Typing handling: `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- Profile update broadcast: `src/hooks/message-sending/useMessageSender.ts`

---

## 10. Cryptography and Security Details

### 10.1 PQ WebSocket envelope
`pq-envelope` fields:
- `sessionId`, `sessionFingerprint`, `messageId`, `counter`, `timestamp`
- `ciphertext`, `nonce`, `tag`, `aad`
- `signature` (Dilithium signature over `messageId:timestamp:counter:sessionId`)

Client encrypts with `PostQuantumAEAD` and pads to fixed size (`WS_FIXED_MESSAGE_SIZE_BYTES`).

Code references:
- Client encryption: `src/lib/websocket/encryption.ts`
- Server encryption: `server/messaging/pq-envelope-handler.js`

### 10.2 Sealed envelope
Sealed envelopes use:
- Kyber KEM to derive a shared secret.
- BLAKE3 to derive a symmetric key.
- AES-GCM with a 24-byte nonce.
- Padding and framing to fixed sizes.

Code references:
- Sealed envelope: `src/lib/transport/blind-routing-client.ts`
- Framing: `src/lib/transport/message-framing.ts`

### 10.3 Hybrid envelope
Hybrid envelope uses:
- Kyber encapsulation for PQ secrecy.
- X25519 for classical DH.
- Dilithium signatures for sender authentication.

Code references:
- Hybrid: `src/hooks/app/useEncryptionProvider.ts`

### 10.4 Server-side controls
- Bandwidth quota and fixed-size enforcement in gateway.
- Timing jitter and cover traffic in blind routing.
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
- `server/handlers/message-handlers.js`: blind delivery, offline long-term trigger
- `server/handlers/inbox-handlers.js`: claim inbox, blind-route
- `server/handlers/offline-handlers.js`: offline storage and retrieval
- `server/routing/blind-router.js`: inbox routing, local/distr/queue
- `server/routing/sealed-sender.js`: envelope validation

### Client-Side
- `src/hooks/message-sending/useMessageSender.ts`: UI send pipeline
- `src/hooks/app/useEncryptionProvider.ts`: encryption provider, hybrid envelope
- `src/lib/transport/unified-signal-transport.ts`: P2P vs server transport
- `src/lib/transport/blind-routing-client.ts`: sealed envelopes
- `src/lib/websocket/websocket.ts`: PQ transport
- `src/hooks/message-handling/useEncryptedMessageHandler.ts`: decrypt and process
- `src/hooks/file-handling/useFileHandler.ts`: file chunk processing
