# OPRF-Based Discovery System

## Overview

Discovery enables anonymous handle lookup. Clients derive a discovery token from an OPRF output and store an encrypted advertisement in a billboard database. The server cannot compute tokens for guessed handles and cannot decrypt advertisements.

Guarantees:
- Server cannot enumerate users by guessing handles.
- Encrypted discovery blobs are opaque to the server.
- Clients can discover each other only when they know the handle.

---

## 1. Cryptographic Foundation

### 1.1 RFC 9497 VOPRF
The system uses RFC 9497 VOPRF with the `ristretto255` ciphersuite.

Code references:
- Server: `server/crypto/oprf-discovery.js`
- Client: `src/lib/crypto/oprf-discovery-crypto.ts`

### 1.2 Key storage and protection
OPRF secret keys are encrypted at rest using AES-256-GCM:
- KEK derived from `KEY_ENCRYPTION_SECRET` or `DB_FIELD_KEY`.
- AAD label `oprf-discovery-v1`.

Code references:
- Key storage: `server/crypto/oprf-discovery.js`

### 1.3 Anytrust model
Separation between:
- OPRF key server (evaluates blinded points).
- Discovery blob store (Postgres table).

In this repo both components run in the same server process, but the cryptographic split is preserved in the code and data model.

---

## 2. Data Model

### 2.1 Discovery billboard
Table: `discovery_billboard`
- `token` (PK)
- `encryptedBlob`
- `expiresAt`

Code references:
- Schema: `server/database/schema.js`
- DB: `server/database/discovery-db.js`

### 2.2 Discovery material (plaintext, client-only)
`OPRFDiscoveryMaterial` contains:
- `inboxId`
- `publicKeys` (kyber, dilithium, x25519)
- `fullBundle` (Signal prekey bundle)
- `peerCertificate` (P2P cert)
- `avatar` (optional)

Code references:
- Type definition: `src/lib/crypto/oprf-discovery-crypto.ts`

---

## 3. Token Derivation

Client steps:
1. Normalize handle and compute blinded point.
2. Send blinded point to server for evaluation.
3. Verify proof and finalize OPRF output.
4. Derive:
- `token = BLAKE3("discovery-token-v1" || oprfOutput || epoch)`
- `encryptionKey = BLAKE3("discovery-encryption-key-v1" || oprfOutput)`

Code references:
- Client finalize: `src/lib/crypto/oprf-discovery-crypto.ts`
- Server helpers: `server/crypto/oprf-discovery.js`

---

## 4. Epoch Rotation

The server rotates discovery epochs every 6 hours. Clients publish to both the current and previous epoch tokens to allow a grace period.

Code references:
- Epoch manager: `server/server.js` (`DiscoveryEpochManager`)
- Client publish: `src/hooks/discovery/useDiscovery.ts`

---

## 5. Blob Encryption

Discovery blobs are encrypted client-side using `PostQuantumAEAD`:
- Key: derived from OPRF output
- Nonce: 36 bytes
- Tag: 32 bytes
- AAD: `oprf-discovery-blob-v1`

The client encodes `nonce || tag || ciphertext` as base64.

Code references:
- Client encrypt/decrypt: `src/lib/crypto/oprf-discovery-crypto.ts`

---

## 6. Protocol Signals

Signal types:
- `oprf-discovery-public-key`
- `oprf-blind-evaluate`
- `oprf-blind-evaluate-response`
- `publish-discovery`
- `query-discovery`
- `discovery-result`

### 6.1 OPRF public key
Client sends:
```json
{ "type": "oprf-discovery-public-key" }
```
Server responds with public key and epoch info.

Code references:
- Server handler: `server/server.js`

### 6.2 Blind evaluate
Client sends:
```json
{ "type": "oprf-blind-evaluate", "blindedPoint": "hex" }
```
Server responds with `evaluated`, `proof`, and `publicKey`.

### 6.3 Publish
Client sends:
```json
{ "type": "publish-discovery", "token": "hex", "encryptedBlob": "base64", "previousEpochToken": "hex" }
```
Server stores the blob with a 1-year TTL and returns `{ type: "ok", success: true }`.

### 6.4 Query
Client sends:
```json
{ "type": "query-discovery", "token": "hex", "previousEpochToken": "hex" }
```
Server returns `discovery-result` with the encrypted blob if present.

Code references:
- Server handlers: `server/server.js`
- Client hook: `src/hooks/discovery/useDiscovery.ts`

---

## 7. Client Discovery Hook

`useDiscovery`:
- Requests OPRF public key and epoch.
- Computes tokens for current and previous epochs.
- Publishes self advertisement.
- Fetches and decrypts peer advertisements.

Code references:
- Hook: `src/hooks/discovery/useDiscovery.ts`

---

## 8. Rate Limiting

The OPRF server uses an in-memory rate limiter:
- 30 requests per minute per client id.

Code references:
- `server/crypto/oprf-discovery.js`

---

## 9. Implementation Reference

### Server-Side
- `server/crypto/oprf-discovery.js`: OPRF key server and rate limiter
- `server/server.js`: discovery handlers and epoch manager
- `server/database/discovery-db.js`: billboard storage

### Client-Side
- `src/lib/crypto/oprf-discovery-crypto.ts`: OPRF client and blob crypto
- `src/hooks/discovery/useDiscovery.ts`: publish/query
- `src/lib/transport/blind-routing-client.ts`: inbox id for routing
