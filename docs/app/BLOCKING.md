# Anonymous Blocking System

## Overview

Blocking is designed for the blind routing architecture and does not expose usernames to the server. The system has two layers:
- Encrypted block list sync for UX and cross-device state.
- Local send/receive enforcement after decrypting peer identity client-side.

The server never stores plaintext usernames and cannot reconstruct a social graph.

---

## 1. Core Guarantees

- No username-based blocking on the server.
- Encrypted block lists remain opaque to the server.
- Active blind routing does not require recipient or sender identity metadata for blocking.
- Compatible with global-mix blind routing.

---

## 2. Identifiers Used

### 2.1 BlockListLookupId
- Used to store encrypted block list blobs.
- Domain-separated commitment derived from the current inbox secret.
- Ephemeral and rotated in the routing layer.

## 3. Encrypted Block List (Client)

### 3.1 Encryption
Block lists are encrypted client-side using `PostQuantumAEAD`:
- Key derived from passphrase with argon2id or Kyber secret.
- AAD label: `block-list-v3`.
- Nonce length: 36 bytes.

Code references:
- Encryption: `src/lib/blocking/crypto.ts`

### 3.2 Local persistence
Encrypted block lists are stored in SecureDB and synced when connected.

Code references:
- Client core: `src/lib/blocking/blocking-system.ts`

---

## 4. Server Storage (Encrypted Lists)

Table: `user_block_lists`
- `inboxId` (PK column containing the committed `blockListLookupId`)
- `encryptedBlockList`
- `blockListHash`
- `salt`
- `lastUpdated`
- `version`

Code references:
- Schema: `server/database/schema.js`
- DB access: `server/database/blocking-db.js`

The active sync path uses `blockListLookupId`, a domain-separated client commitment derived from the inbox secret during `claim-inbox`. The raw inbox ID is not sent for block-list sync, and the server DB layer exposes only lookup-ID sync methods on the active code path.

---

## 5. Enforcement

Blocking is enforced entirely on the client, at two levels.

### 5.1 Content layer (display)
- Outgoing sends check the local encrypted block list before sending.
- Incoming messages are filtered after sealed-envelope, hybrid, and Signal decryption reveal the sender to the client.
- The global-mix router needs no sender or recipient identity for this.

### 5.2 Transport layer (P2P)
Blocking a peer also **severs the live direct connection and refuses to re-form it**, so a blocked peer cannot keep a channel open or reach you over P2P at all:
- `blockUser` dispatches a `USER_BLOCKED` event. The P2P service tears down the existing connection (`disconnectPeer`).
- The acceptor (`onPeerConnected`) and receive (`onMessage`) paths reject a blocked peer at the transport boundary — a re-dial is closed before a session forms, and any inbound frame is dropped — gated by an authoritative, synchronous `blockingSystem.isBlockedSync()` check (the in-memory block list, no TTL).
- Outbound `connectToPeer` to a blocked user is refused.

On unblock, `unblockUser` dispatches `USER_UNBLOCKED`. The client immediately re-dials that peer so the first message after unblock isn't stuck on a cold connection.

This preserves the blind-routing invariant — the server still needs no social-graph edge to route or drop a message — while making a block take effect immediately and completely on the direct channel.

Code references:
- Client content filter: `src/lib/blocking/blocking-system.ts`
- P2P transport gate + disconnect: `src/lib/transport/secure-p2p-service.ts`
- Instant reconnect on unblock: `src/pages/Index.tsx`

---

## 6. Protocol Signals

Signal types:
- `block-list-sync`
- `retrieve-block-list`
- `block-list-response`

### 6.1 Block list sync
Client sends:
```json
{ "type": "block-list-sync", "encryptedBlockList": "...", "blockListHash": "..." }
```
Server stores by `ws._primaryBlockListLookupId`.

Code references:
- Handler: `server/handlers/blocking-handlers.js`

### 6.2 Retrieve block list
Client sends:
```json
{ "type": "retrieve-block-list" }
```
Server responds with `block-list-response`.

Code references:
- Handler: `server/handlers/blocking-handlers.js`

---

## 7. Cryptography and Security Notes

- Block list encryption uses PQ AEAD with explicit AAD to prevent malleability.
- The server does not receive per-contact block tokens, identity hashes, or sender/recipient edges for blind-route enforcement.

Code references:
- Block list crypto: `src/lib/blocking/crypto.ts`

---

## 8. Implementation Reference

### Server-Side
- `server/database/blocking-db.js`: encrypted block-list blob storage
- `server/handlers/blocking-handlers.js`: sync/retrieve

### Client-Side
- `src/lib/blocking/blocking-system.ts`: list management and sync
- `src/lib/blocking/crypto.ts`: encryption and block-list integrity hash
