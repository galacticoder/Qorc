# Anonymous Blocking System

## Overview

Blocking is designed for the blind routing architecture and does not expose usernames to the server. The system has two layers:
- Encrypted block list sync for UX and cross-device state.
- Server-side enforcement via commitments derived from pseudonymous identity hashes.

The server never stores plaintext usernames and cannot reconstruct a social graph.

---

## 1. Core Guarantees

- No username-based blocking on the server.
- Encrypted block lists remain opaque to the server.
- Enforcement uses commitment hashes, not usernames.
- Compatible with inbox-based routing.

---

## 2. Identifiers Used

### 2.1 InboxId
- Used to store encrypted block list blobs.
- Ephemeral and rotated in the routing layer.

### 2.2 Pseudonymous identity hash
- Derived from username using `computeBlindUserId`.
- Used as a stable, non-reversible identifier in block enforcement.

Code references:
- Hash derivation: `src/lib/blocking/crypto.ts`

### 2.3 BlockCommitment
- Server commitment: `blake2b512(BLOCK_SERVER_SECRET || blockerIdentityKeyHash || blockedIdentityKeyHash)`.
- Not reversible without the server secret.

Code references:
- Commitment: `server/database/blocking-db.js` (`computeBlockCommitment`)

---

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
- `inboxId` (PK)
- `encryptedBlockList`
- `blockListHash`
- `salt`
- `lastUpdated`
- `version`

Code references:
- Schema: `server/database/schema.js`
- DB access: `server/database/blocking-db.js`

---

## 5. Server Enforcement (Commitments)

When a message includes identity hashes in metadata, the server checks:
- `BlockingDatabase.isBlocked(recipientHash, senderHash)`
- `BlockingDatabase.isBlocked(senderHash, recipientHash)`

If blocked, the server skips delivery and responds with a success placeholder.

Code references:
- Enforcement: `server/handlers/message-handlers.js`

---

## 6. Protocol Signals

Signal types:
- `block-list-sync`
- `retrieve-block-list`
- `block-list-response`
- `block-tokens-update`

### 6.1 Block list sync
Client sends:
```json
{ "type": "block-list-sync", "encryptedBlockList": "...", "blockListHash": "..." }
```
Server stores by `ws._primaryInboxId`.

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

### 6.3 Block tokens update
Client sends per-change messages:
```json
{
  "type": "block-tokens-update",
  "action": "block"|"unblock",
  "blockerIdentityKeyHash": "...",
  "blockedIdentityKeyHash": "..."
}
```

Code references:
- Client send: `src/lib/blocking/blocking-system.ts`
- Server handler: `server/handlers/blocking-handlers.js`

---

## 7. Cryptography and Security Notes

- Block list encryption uses PQ AEAD with explicit AAD to prevent malleability.
- Hashes are derived from usernames using BLAKE3 in the client auth utilities.
- Block commitments are salted with a server secret to prevent offline enumeration.

Code references:
- Block list crypto: `src/lib/blocking/crypto.ts`
- Server secret: `server/database/core.js`

---

## 8. Implementation Reference

### Server-Side
- `server/database/blocking-db.js`: commitments and tables
- `server/handlers/blocking-handlers.js`: sync/retrieve/update
- `server/handlers/message-handlers.js`: enforcement checks

### Client-Side
- `src/lib/blocking/blocking-system.ts`: list management and sync
- `src/lib/blocking/crypto.ts`: encryption and hash derivation
