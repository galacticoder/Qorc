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
Table: `discovery_billboard` (k-anonymous. The server stores no exact per-user marker)
- `epochId`
- `bucketId` — the client-derived k-anonymity bucket. Narrows a handle to K users, never to one
- `publishId` — random-looking per-(epoch, bucket) upsert key, not derived from the handle, rotating each epoch (so a user's bucket trajectory cannot be fingerprinted across epochs)
- `encryptedBlob`
- `expiresAt`
- `publishedAt`
- PRIMARY KEY (`epochId`, `publishId`)

There is deliberately no exact `token` or `pirSlotKey` column: a database dump reveals only "bucket *b* holds *N* blobs", never "handle *X* is registered". See `docs/app/USERNAME_ENUMERATION_RESISTANCE.md`.

Code references:
- Schema: `server/database/schema.js`
- DB: `server/database/discovery-db.js`

### 2.2 Discovery material (plaintext, client-only)
`OPRFDiscoveryMaterial` contains:
- `inboxId`
- `routeId`
- `mailboxLookupId`
- `bundleLookupId`
- `blockListLookupId`
- `publicKeys` (kyber, dilithium, x25519)
- `fullBundle` (Signal prekey bundle)
- `peerCertificate` (P2P cert)
- `certifiedPeerBundle` (account-root/device/subkey identity chain)
- `peerCertificateFingerprint`
- `identityRootFingerprint`
- `identityBundleFingerprint`
- `avatar` (optional)

Code references:
- Type definition: `src/lib/crypto/oprf-discovery-crypto.ts`
- Rendezvous derivation: `src/lib/transport/rendezvous-routing.ts`

The server cannot decrypt these fields because they live inside the encrypted discovery blob. Peers use the encrypted `routeId` and mailbox/bundle commitments for authorization, bundle use, and local validation. Active server sends do not submit the raw `inboxId`, exact `routeId`, `mailboxLookupId`, or any destination bucket.

When route commitments rotate, the client republishes encrypted discovery material with the new `inboxId`, `routeId`, `mailboxLookupId`, `bundleLookupId`, and `blockListLookupId`. Peers learn the new destination only through the encrypted discovery path. The server only sees fresh opaque billboard writes and fresh committed claim IDs.

### 2.3 Certified identity chain
Discovery material must validate as one signed identity chain. The keys do not all have to be identical key material, but they must be bound to the same account root:
- `accountRoot` signs the device certificate.
- The device certificate attests the peer certificate and device Kyber, Dilithium, and hybrid/P2P X25519 keys.
- The device Dilithium key signs the subkey binding.
- The subkey binding carries both the hybrid/P2P X25519 key and the LibSignal identity X25519 key as separate signed fields.

The LibSignal identity X25519 key and the hybrid/P2P X25519 key are expected to be different in normal operation. Validation must not force those two keys to be equal. Instead:
- discovery `publicKeys` must match the signed hybrid keys in the subkey binding
- `fullBundle.identityKeyBase64` must match the signed `signalIdentityX25519PublicKey`
- advertised `peerCertificateFingerprint`, `identityRootFingerprint`, and `identityBundleFingerprint` must match the recomputed certified chain values
- previously pinned peer certificate/root fingerprints must not silently change.

This is a pinned/TOFU model unless an external root verification channel is added. First valid discovery pins the peer identity root. Later discovery material for that peer must remain on the same root or be treated as an identity change.

Code references:
- Build/validate chain: `src/lib/utils/certified-identity-utils.ts`
- Discovery material validation: `src/hooks/discovery/useDiscovery.ts`
- Trusted key extraction: `src/lib/utils/signal-bundle-utils.ts`

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
- `discovery-snapshot-request`
- `discovery-snapshot`
- `pir-manifest-request`
- `pir-manifest`
- `pir-query`
- `pir-response`

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
{
  "type": "publish-discovery",
  "requestId": "random",
  "bucketBatch": [ { "epochId": "...", "bucketId": 42, "publishId": "hex" }, "..." ],
  "encryptedBlob": "base64"
}
```
The client derives each `bucketId` locally from its OPRF token (`bucketId = sha256(domain || epoch || slotKey) mod bucketCount`). The server never sees the token. `publishId = sha256(dilithiumPub || epochId || bucketId)` is random-looking, server-invisible, and rotates per epoch. There is no raw `token`/`tokenBatch` on the wire.

The server does not write the blob immediately. It queues the opaque publication into the Redis delayed publication pool, acknowledges only ingress acceptance, then a relay releases shuffled batches with cover publications. Cover publications use the same server-visible shape: a `bucketBatch` of `{epochId, bucketId, publishId}` plus an opaque encrypted blob.

Client behavior:
- Publishes previous/current/forward epoch bucket batches.
- Sends fixed-rate cover publications while connected, discoverable, and PQ-ready.
- Sizes cover blobs at least as large as the most recent real discovery blob.

Server behavior:
- Delays real writes by `DISCOVERY_PUBLICATION_DELAY_MIN_MS` to `DISCOVERY_PUBLICATION_DELAY_MAX_MS`.
- Flushes random-size batches.
- Injects `DISCOVERY_PUBLICATION_COVER_WRITES_MIN` to `DISCOVERY_PUBLICATION_COVER_WRITES_MAX` cover writes.
- Stores only opaque blobs keyed by `(epochId, bucketId, random publishId)`.
- Logs only coarse publication shape classes, not exact bucket counts, exact blob lengths, exact release delays, or exact batch sizes.

### 6.4 Private snapshot retrieval
Client sends:
```json
{ "type": "discovery-snapshot-request", "requestId": "random", "snapshotMode": "full" }
```
Server returns a compressed, padded, epoch-scoped snapshot object:
```json
{
  "type": "discovery-snapshot",
  "requestId": "random",
  "snapshot": {
    "version": "qor-discovery-snapshot-gzip-v1",
    "encoding": "base64url+gzip",
    "compression": "gzip",
    "digestAlgorithm": "sha256-uncompressed-snapshot",
    "digest": "base64url",
    "epochId": "opaque",
    "epochStart": 1710000000000,
    "epochEndsAt": 1710000600000,
    "realCountHidden": true,
    "sourceCountHidden": true,
    "paddedEntryCount": 1024,
    "compressed": "base64url"
  }
}
```

The request contains no target handle, no OPRF token, no previous-epoch token, and no shard selector. The client tries to decrypt each returned blob locally with its OPRF-derived key and accepts only a blob whose certified identity material validates for the requested handle.

- The server sees only an epoch snapshot request and returns padded compressed bytes. It does not send a raw top-level `entries` list or exact active count.
- Snapshot size is rounded to a privacy floor and power-of-two padding with opaque decoys, so small deployments do not expose exact population.
- Bandwidth and client CPU scale with the padded snapshot size.

This target-free snapshot is a no-selector cover/ceiling path: the request contains no handle, token, bucket, slot, candidate index, or profile category. It must not compete with the reviewed PIR result path, and it is not an exact-query fallback.

### 6.5 Reviewed PIR worker path
Discovery has its own PIR database, separate from the volatile global message spool. Clients ask for a fixed-size PIR database manifest by kind:
```json
{ "type": "pir-manifest-request", "requestId": "random", "prepareWorker": true, "kind": "discovery" }
```

`kind: "discovery"` is the discovery database, and it is the **only** computational-PIR kind: the global message spool is no longer served by PIR (the `opaque` PIR kind was retired in favor of the uniform encrypted spool snapshot — see `docs/app/COMPUTATIONAL_PIR.md` §2.2). Discovery keeps its own independent epoch/setup, so unrelated message traffic does not churn it. The server sees query timing/volume but, within the discovery kind, never the searched handle, slot, record index, or decrypt result. The discovery query path carries cover traffic.

The server responds with a manifest containing:
- `kind` (`"discovery"` here)
- `epochId`
- `recordSize`
- `recordCount`
- `paddingFloor`
- `databaseDigest`
- `schemeId`
- `parameterId`
- `workerConfigured`
- `workerReady`

If a reviewed external PIR worker is configured and has accepted the epoch database, clients may submit the worker-specific opaque query:
```json
{ "type": "pir-query", "epochId": "...", "kind": "discovery", "query": "base64", "requestId": "random" }
```

The server does not interpret the query contents. It routes by `kind`/`epochId` to the matching PIR database (only `discovery` exists), forwards the opaque query to the isolated worker, and returns the opaque response. The server learns timing/volume, but not the handle, slot, record index, or whether a record decrypted.

In the default Docker server profile, the pinned hintless-SimplePIR worker (scheme `hintless-simplepir`, parameter id `hintless-simplepir-rlwe64-v1`) is started automatically and `PIR_REQUIRE_WORKER=true` makes server startup fail if the worker is missing or reports the wrong source commit/parameter id. This is the normal posture. There is no weaker missing-worker app mode.

The client uses this reviewed PIR path as the strict indexed lookup path (two-tier — see `COMPUTATIONAL_PIR.md` §3.1):
1. Derive the current and previous OPRF epoch tokens for the requested handle.
2. Derive `pirSlotKey = SHA-256("qor-discovery-pir-slot-key-v1" || token)` locally.
3. Derive deterministic candidate slots from the public manifest epoch and record count.
4. Read the hint-free per-epoch public params delivered inline in the manifest.
5. For a candidate slot, build an opaque request (`query-record`), send `pir-query`, and recover the tiny **handle record** (`recover-record`).
6. Fetch the encrypted **keys-blob via a k-anonymous BUCKET fetch**: the client derives its target's bucket id from the OPRF token (`bucketId = sha256(domain || epoch || slotKey) mod bucketCount`, identical on both sides), fetches that whole bucket (K=32 blobs, padded with decoys) over the dedicated Tor circuit, and **decrypt-filters locally** — the blob that decrypts with the OPRF key is the target. The server learns only the bucket id (the target is one of K users in it), never the exact user.
7. Accept only material whose certified identity validates for the requested handle. A wrong slot fails to decrypt and the client tries the next candidate.

If this reviewed PIR path fails, active lookup fails closed. The client does not ask the server for the handle, token, selected slot, bundle id, bucket, shard, or any exact lookup selector.

The per-epoch public params are tiny and ride inline in the PIR manifest. Query generation and recovery run against a persistent `qor-pir-client serve` daemon (record-major: `query-record` keeps the client secret under a handle, `recover-record` consumes it). See `docs/app/PIR_WORKER.md`.

Because HintlessPIR cost scales with record SIZE, the tier-1 discovery record is a tiny 24-byte handle, not the inlined bundle — which is what lets the discovery database grow to millions of records at sub-second query time. The full post-quantum keys-blob (about 131 KB) is then delivered by a **k-anonymous bucket fetch** rather than PIR. The bucket fetch trades full obliviousness for K-anonymity (the server learns the target's bucket = one of K=32 users, never the exact user), which is the same privacy class already used for avatars. The keys-blob content is unchanged.

Avatars are not carried inside the discovery advertisement. PIR/buckets can't carry a 1 MB avatar cheaply, so the keys-blob holds only a small `avatarRef` (opaque blobId + E2E key + hash). The avatar bytes live in a separate **unlinkable content store** as a uniform-size E2E-encrypted PURB, uploaded anonymously and fetched by opaque id with cover traffic. The server cannot link an avatar blob to a user, cannot read it, and cannot learn its size. See `docs/app/AVATARS.md` §5.

Large encrypted discovery/profile records are chunked (this primarily mattered for the old avatar-bearing blobs. The avatar-less keys-blob fits in one record). Chunk 0 is placed at the normal token-derived slot. Later chunks use:
```txt
SHA-256("qor-pir-chunk-slot-v1" || pirSlotKey || chunkIndex)
```

The client retrieves chunk 0, learns the chunk count from the encrypted-record wrapper, derives the remaining chunk slots locally, retrieves them through PIR, and verifies the encrypted blob digest before decrypting.

The discovery hook runs one light, deferring cover round against the `discovery` database while connected and PQ-ready, using the opaque `pir-query` path and discarding recovered words locally. The cover is scheduled as a **Poisson process** (a fresh exponential inter-cover delay each tick, mean `DISCOVERY_PIR_COVER_INTERVAL_MS`, clamped to `[MIN, MAX]`), **not a fixed period**. A fixed cadence is a grid an observer could fingerprint, which would let a real (off-grid) lookup be picked out by timing. A memoryless interval has no grid to break, so a real query at any moment looks like it could be the next cover tick. (Cover yields to an in-flight interactive lookup — that real query provides the round's timing cover — and the timer re-arms with a fresh randomized delay afterward, so there is no grid to "resume". The query *rate* still rises under heavy active searching, which is inherent without latency-adding query queuing. The looker stays anonymous on the dedicated Tor circuit regardless.)

Cover must stay minimal over Tor: each PIR query frame is large (about 768 KiB-class for this parameter set), so constant-rate cover floods the Tor circuit and resets the connection. (The global message spool is no longer a PIR kind, so there is no cross-kind PIR category for the server to distinguish. The spool is served by a separate uniform snapshot endpoint.) After an active PIR lookup, the client may also schedule a target-free snapshot cover request. That request contains no searched handle or token and is cover/no-selector traffic.

Code references:
- Server handlers: `server/server.js`
- Client hook: `src/hooks/discovery/useDiscovery.ts`
- Worker deployment: `docs/app/PIR_WORKER.md`

---

## 7. Client Discovery Hook

`useDiscovery`:
- Requests OPRF public key and epoch.
- Computes tokens for current and previous epochs.
- Publishes self advertisement through delayed, batched publication ingress.
- Sends cover publications with the same token-batch/blob shape as real publications.
- Uses deterministic-slot computational PIR (tier 1 HintlessPIR) for the private match-check/cover + a k-anonymous bucket fetch for the keys-blob. Avatars use the separate unlinkable content store.
- Assembles chunked encrypted blobs when records exceed one fixed PIR page.
- Sends **Poisson-scheduled** (randomized, memoryless) cover PIR queries for discovery timing privacy.
- Decodes and verifies compressed padded discovery snapshots for explicit no-selector retrieval and cover traffic.
- Uses target-free encrypted billboard snapshots as the bandwidth-heavy privacy ceiling.
- Decrypt-filters peer advertisements locally.

Code references:
- Hook: `src/hooks/discovery/useDiscovery.ts`

---

## 8. Rate Limiting

The OPRF server uses an in-memory rate limiter:
- Per client id: 30 requests per minute.
- Global (server-wide): `OPRF_GLOBAL_MAX_PER_MIN` evaluations per rolling minute (default 1200), enforced on top of the per-client limit. This bounds online username probing through the live OPRF service even by an attacker holding many anonymous tokens (a per-token limit does not bind a token-rich attacker, but a global cap does). See `docs/app/USERNAME_ENUMERATION_RESISTANCE.md`.

Code references:
- `server/crypto/oprf-discovery.js`

---

## 9. Implementation Reference

### Server-Side
- `server/crypto/oprf-discovery.js`: OPRF key server and rate limiter
- `server/server.js`: discovery handlers and epoch manager
- `server/database/discovery-db.js`: billboard storage
- `server/discovery/snapshot-service.js`: compressed padded epoch snapshots
- `server/discovery/publication-privacy.js`: delayed publication relay and cover writes

### Client-Side
- `src/lib/crypto/oprf-discovery-crypto.ts`: OPRF client and blob crypto
- `src/hooks/discovery/useDiscovery.ts`: delayed publish ingress, cover publish traffic, PIR, and compressed snapshot retrieval
- `src/lib/transport/blind-routing-client.ts`: route claims and sealed envelopes
- `docs/app/COMPUTATIONAL_PIR.md`: reviewed PIR backend policy and target-free privacy ceiling
