# Hybrid Key Management and Signal Bundles

## Overview

This document covers:
- Hybrid public key updates (Kyber, Dilithium, X25519).
- Signal prekey bundle publishing and storage.
- How bundles are consumed to establish LibSignal sessions.

Hybrid keys are linked to `credentialId`, while bundles are indexed by `inboxId`. This separation preserves anonymity while still enabling session establishment.

---

## 1. Hybrid Key Update Flow

### 1.1 Client key generation
Clients generate:
- ML-KEM-1024 (Kyber) for encryption.
- ML-DSA-87 (Dilithium) for signatures.
- X25519 for classical DH interoperability.

Key sizes (server-validated):
- Kyber public key: 1568 bytes
- Dilithium public key: 2592 bytes
- X25519 public key: 32 bytes

Code references:
- Validation: `server/handlers/core.js`

### 1.2 Encryption for server
The client encrypts a JSON payload using the server hybrid public keys with `CryptoUtils.Hybrid.encryptForServer`. The payload includes:
- `kyberPublicBase64`
- `dilithiumPublicBase64`
- `x25519PublicBase64`
- Optional `blindedToken` for unlinked inbox claims (blind signature request)

Blind signature parameters are advertised in `server-public-key` as `blindPublicKey` metadata with `kid`, `n`, `e`, `modulusLength`, `hash`, `saltLength`, and `scheme`.

Code references:
- Client upload: `src/hooks/auth/useAuth.ts`

### 1.3 Server processing
The server:
1. Decrypts the hybrid envelope with its Kyber and X25519 secrets.
2. Validates key lengths.
3. Stores keys under the authenticated `credentialId`.
4. Returns `keys-stored`.

Code references:
- Handler: `server/handlers/key-handlers.js`
- DB: `server/database/user-db.js`

---

## 2. Hybrid Key Storage

Hybrid keys are stored in the `users` table:
- `credentialId` (primary key)
- `opaqueRecord`
- `hybridPublicKeys` (JSON)
- `shard_id`, `credential_index`

Code references:
- Schema: `server/database/schema.js`
- User DB: `server/database/user-db.js`

---

## 3. Signal Bundle Publishing

### 3.1 Client publish
The client sends:
```json
{ "type": "libsignal-publish-bundle", "bundle": { ... } }
```

The WebSocket must have a `ws._primaryInboxId` (set during inbox claim).

Code references:
- Client publish: `src/lib/websocket/websocket.ts`
- Server handler: `server/messaging/libsignal-handler.js`

### 3.2 Server validation and storage
The server:
- Validates structure only.
- Flattens the bundle for storage.
- Stores in `libsignal_bundles` by inboxId.

Code references:
- Validator/transform: `server/messaging/libsignal-handler.js`
- Bundle DB: `server/database/bundle-db.js`

---

## 4. Bundle Storage and Field Encryption

The `libsignal_bundles` table stores:
- `inboxId` (PK)
- `identityKeyHash`
- `identityKeyBase64`, `signedPreKeyPublicBase64`, `kyberPreKeyPublicBase64`, etc.
- `updatedAt`

Fields are encrypted at rest using `LibsignalFieldEncryption`, stored with prefix `pq2:`.

Code references:
- Field encryption: `server/database/core.js`
- Bundle DB: `server/database/bundle-db.js`

---

## 5. Bundle Consumption (Client)

Clients consume bundles to establish LibSignal sessions in three ways:

### 5.1 Direct delivery
A bundle can be delivered via `libsignal-deliver-bundle` and processed with `signal.processPreKeyBundle`.

### 5.2 Embedded bundle
An encrypted message may contain a `senderSignalBundle` field for opportunistic session setup.

### 5.3 Discovery-based fetch
`useDiscovery.findUser` returns `fullBundle`, which is processed when needed.

Code references:
- Session establishment: `src/hooks/message-sending/session.ts`
- Bundle processing: `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- Discovery hook: `src/hooks/discovery/useDiscovery.ts`

---

## 6. Unlinked Mode Requirements

In unlinked mode:
- The client must claim its inbox via `claim-inbox` before publishing bundles.
- `ws._primaryInboxId` is set by the claim handler.
- Bundle publish is rejected if no inboxId exists.

Code references:
- Claim inbox: `server/handlers/inbox-handlers.js`
- Bundle handler: `server/messaging/libsignal-handler.js`

---

## 7. Cryptography and Security Details

- Hybrid envelopes use Kyber encapsulation and X25519 DH to derive shared secrets.
- Dilithium signatures authenticate the sender and bind routing metadata.
- Bundle fields are encrypted at rest with PQ AEAD and per-field keys derived from `DB_FIELD_KEY`.

Code references:
- Hybrid crypto: `src/lib/utils/crypto-utils.ts`
- Field encryption: `server/database/core.js`

---

## 8. Implementation Reference

### Server-Side
- `server/handlers/key-handlers.js`: hybrid key update
- `server/database/user-db.js`: key storage
- `server/messaging/libsignal-handler.js`: bundle validation and publish
- `server/database/bundle-db.js`: bundle storage
- `server/database/core.js`: field-level encryption

### Client-Side
- `src/hooks/auth/useAuth.ts`: hybrid key upload
- `src/lib/tauri-bindings.ts`: bundle structure
- `src/hooks/message-sending/session.ts`: session establishment
- `src/hooks/discovery/useDiscovery.ts`: discovery-based bundle fetch
