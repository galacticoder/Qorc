# Qorc Avatar System

## Overview

The server never receives the avatar file in plaintext. The avatar is not carried
inside the discovery blob. Instead it is encrypted into a uniform-size **PURB**
and stored in a separate content store keyed by an opaque ID, then fetched with
cover traffic. The table has no owner column, but network timing and traffic
correlation remain possible. The UI renders from local cache.

Core properties:
- Avatars stored in SecureDB on the client.
- Sharing is optional and controlled by `shareWithOthers`.
- Discovery publishes only a small `avatarRef` (opaque blobId + E2E key + hash) inside the encrypted keys-blob.
- The avatar bytes live as an E2E-encrypted, uniform-size PURB in the content store. The server cannot decrypt them or learn their true size.

---

## 1. Data Model and Local Storage

### 1.1 Types
- `AvatarData`: `{ data, mimeType, hash, updatedAt, isDefault? }`
- `CachedAvatar`: `{ data, hash, cachedAt, expiresAt }`
- `ProfileSettings`: `{ shareWithOthers, lastUpdated }`

Code references:
- Types: `src/lib/types/avatar-types.ts`

### 1.2 SecureDB keys
- Own avatar: `STORAGE_KEYS.PROFILE_AVATARS` / `own`
- Peer cache: `STORAGE_KEYS.PROFILE_AVATARS` / `cache`
- Settings: `STORAGE_KEYS.PROFILE_SETTINGS` / `profile`

Code references:
- Storage keys: `src/lib/database/storage-keys.ts`
- Initialization: `src/lib/avatar/init.ts`

---

## 2. Initialization Flow

On app startup:
1. `profilePictureSystem.setSecureDB` sets the SecureDB reference.
2. `profilePictureSystem.initialize` loads own avatar, settings, and cache.
3. If no avatar is found, a deterministic default avatar is generated from username and stored.

Code references:
- Setup: `src/hooks/app/useAppInitialization.ts`
- Initialize: `src/lib/avatar/init.ts`

---

## 3. Setting and Removing Own Avatar

### 3.1 Set avatar
`setOwnAvatar`:
1. Validates mime type, size, and magic bytes.
2. Compresses to WebP (max 512px).
3. Hashes with BLAKE3.
4. Stores in SecureDB.
5. Emits `PROFILE_PICTURE_UPDATED` event.

Code references:
- Set avatar: `src/lib/avatar/own-avatar.ts`
- Validation and compression: `src/lib/utils/avatar-utils.ts`

### 3.2 Remove avatar
`removeOwnAvatar` regenerates the default avatar for the current username and stores it.

Code references:
- Remove avatar: `src/lib/avatar/own-avatar.ts`

---

## 4. Sharing Policy

`shareWithOthers` controls what gets published in discovery:
- If `shareWithOthers` is true, the real avatar is published.
- If `shareWithOthers` is false and the avatar is default, the default is published.
- If `shareWithOthers` is false and the avatar is custom, a default avatar is generated and published instead.

Code references:
- Share toggle: `src/lib/avatar/own-avatar.ts`
- Discovery avatar selection: `src/hooks/discovery/useDiscovery.ts`

---

## 5. Distribution through the Ownerless Opaque Content Store

The avatar is delivered out of band from the discovery keys-blob because avatar bytes are too large for the discovery record. So:

What rides inside the encrypted discovery keys-blob is only an `AvatarRef`:
- `avatarRef = { blobId, keyB64, hash, mimeType }` - an opaque content ID, the E2E AEAD key, and the content hash. The reference rotates when the avatar changes or approaches expiry. The discovery blob is encrypted with the OPRF-derived key, so the server cannot read the reference.

The avatar bytes themselves go to the content store as a PURB:
- **PURB (Padded Uniform Random Blob):** the avatar (`{data, mimeType, hash}`) is padded to a fixed plaintext capacity (`AVATAR_PURB_CAPACITY`, 256 KiB) with the true length encrypted inside, then AEAD-encrypted under a fresh owner-generated key. Every stored blob is therefore byte-identical in size, so the server learns nothing from size and a "miss" can be answered with an identically-sized synthetic blob. (256 KiB fits a 512px WebP avatar with margin. The rare avatar that does not fit is not shared through the store: `publishAvatarToStore` returns null and peers continue to show a default. There is no targeted P2P avatar fallback. The cap is kept small because cover traffic fetches about ten PURBs per lookup.)
- **Ownerless upload record:** the PURB is sent as the encrypted `avatar/blob/put` operation inside `POST /api/anonymous` (never the account WebSocket), keyed only by the client-chosen random `blobId`. The outer request is always 512 KiB and uses a fresh Tor SOCKS isolation credential. The `avatar_blobs` table has no account/owner column, so there is no direct stored owner mapping. The server decrypts the operation and therefore observes the blob ID, request timing, volume, and connection carrying the upload, endpoint timing or a global observer can still attempt correlation.

Publishing (`useDiscovery` self-publish):
1. `getAvatarForDiscovery` selects the avatar to share (real or default, per `shareWithOthers`).
2. `validateAvatarCoverBlobs` (throttled, fire-and-forget) contributes this client's share of **cover PURBs** to the public pool - random-content, uniform-size, fresh-ID blobs indistinguishable from real avatars at rest. This helps populate useful decoy sets when there are few real users, but upload failures, expiry, or global caps can still leave the pool too small. Each cover upload is independently jittered.
3. `publishAvatarToStore` schedules the anonymous PUT with jitter and retries. The upload is authorized with one-time `account-auth` and `server-entry` Privacy Pass redemptions rather than a stable account credential. Cover PURBs use the same route and shape.
4. A new reference is advertised only after its upload has succeeded. The first discovery publish after a change can therefore omit it, the periodic discovery refresh advertises the confirmed reference, normally within five minutes while the app remains connected.

The avatar's `blobId` rotates when the **avatar changes** (or near its TTL), not on every publish, so its upload is a rare, jittered event rather than a per-epoch event coincident with every discovery publication. A new or changed avatar has no advertised reference until its upload succeeds and the next discovery publication carries the confirmed reference, peers show a default during that interval. An existing same-avatar reference remains usable while a near-expiry replacement is pending. There is no P2P avatar fallback.

Receiving (`useDiscovery.finalizeDiscoveryResult`):
1. After the fixed-shape discovery bucket lookup decrypts and validates the keys-blob, `cachePeerAvatarFromRef` runs in the **background** (never blocking the discovery result) and is skipped entirely if the exact hash is already cached, so most repeat lookups do not hit the network.
2. `fetchAvatarFromStore` fetches the avatar by `blobId` with **cover traffic** (`AVATAR_COVER_TOTAL_IDS`, fixed at 10): it mixes the real target with a **stable decoy set** drawn through the encrypted `avatar/pool` operation and shuffles the order, then sends the batch through `avatar/blob/get`. Both operations are inside the one `/api/anonymous` route. The request carries no target label and every ID receives an identically-sized response (real PURB or synthetic miss). The server nevertheless decrypts and sees the complete candidate set and its timing, so this is k-anonymous cover traffic, not PIR or an oblivious fetch guarantee.
3. The target PURB is decrypted with `avatarRef.keyB64`, the content hash re-verified against `avatarRef.hash`, and the avatar cached with TTL.

**Why the decoy set is *stable* per target:** if decoys were re-randomized each fetch while the target stayed the same, an observer could intersect the batches across repeated lookups of one peer and the target would fall out as the common element. Reusing the same decoy companions for a target for six hours makes repeated batches a constant set. The target blob ID rotates when the avatar changes or nears its seven-day expiry.

Privacy summary: the avatar fetch is k-anonymous, not oblivious. The opaque reference exists only inside encrypted discovery material, the bytes are E2E-encrypted and uniform-size, and the database has no owner field. Ten-ID fetches, stable decoys, cover uploads, jitter, and fresh per-call Tor isolation reduce direct linkage and repeated-set intersection. They do not eliminate timing, volume, low-population, or global-observer correlation.

Honest residuals: (a) the server sees the complete candidate ID set after decrypting the operation, (b) anonymity is bounded by the available real and cover blobs, (c) repeated requests outside the six-hour stable-decoy window can support intersection analysis, (d) every avatar fetch downloads one fixed 4 MiB outer response, and (e) anonymous global write caps permit storage churn but cannot provide fair per-user quotas without identity metadata.

### Circuit isolation

Every anonymous HTTP call gets a fresh random Tor `IsolateSOCKSAuth` username
and a connection with HTTP reuse disabled. OPRF, discovery, avatar publication,
avatar fetch, and spool retrieval all use the same external
`POST /api/anonymous` path, while their operation name and body stay inside the
hybrid-PQ envelope. This prevents deliberate circuit reuse between any two calls,
it is not proof of mutual unlinkability against endpoint timing, the visible
64 KiB/512 KiB request classes, the 64 KiB/512 KiB/4 MiB/18 MiB response
classes, or a global observer. Wiring is in
`src-tauri/src/commands/discovery.rs`.

Code references:
- Avatar PURB crypto: `src/lib/crypto/avatar-blob-crypto.ts`
- Content-store client (publish/cover-fetch/decrypt): `src/lib/avatar/avatar-store-client.ts`
- Discovery publish + background fetch: `src/hooks/discovery/useDiscovery.ts`
- Keys-blob crypto + `avatarRef`: `src/lib/crypto/oprf-discovery-crypto.ts`
- Server store + internal operations: `server/database/avatar-blob-db.js`, `server/routes/api-routes.js`
- Anonymous outer transport: `src/lib/transport/pq-anonymous-http.ts`, `server/routes/pq-anonymous-http.js`
- Cache store: `src/lib/avatar/cache.ts`

---

## 6. Avatar Retrieval

Peer avatars are retrieved only from the encrypted content store using the opaque `avatarRef` in certified discovery material. Each fetch uses a fresh isolated anonymous-transport request and bounded retries. There is no targeted peer request/response protocol, so an avatar cache miss does not notify the peer or add peer-specific messaging traffic.

---

## 7. Avatar Update Propagation

There is no peer `profile-update` broadcast message. When the local avatar or profile settings change:
1. The client updates its local cache and dispatches a local `PROFILE_PICTURE_UPDATED` (or `PROFILE_SETTINGS_UPDATED`) event so the UI refreshes.
2. The change reaches peers passively: the new `avatarRef` is carried in the republished encrypted discovery keys-blob and peers retrieve it through a fresh isolated anonymous request on their next discovery refresh.

Code references:
- Local change + events: `src/lib/avatar/own-avatar.ts`
- Discovery republish (carries `avatarRef`): `src/hooks/discovery/useDiscovery.ts`
- Avatar fetch and cache: `src/hooks/discovery/useDiscovery.ts`, `src/lib/avatar/cache.ts`

---

## 8. UI Rendering and Cache Refresh

`UserAvatar` renders from the local cache and listens for local avatar update events. Peer cache entries are replaced when a later discovery refresh validates and fetches a different avatar reference, there is no targeted avatar request message to the peer.

Code references:
- UI component: `src/components/ui/UserAvatar.tsx`
- Cache TTL: `src/lib/constants.ts` (`AVATAR_CACHE_TTL_MS`)

---

## 9. Cryptography and Validation Details

- Accepted custom input types: JPEG, PNG, and WebP. SVG is accepted only for the
  exact locally generated default-avatar template, peer-controlled SVG is
  rejected.
- Maximum size: 512KB (`MAX_AVATAR_SIZE_BYTES`).
- Compression: Canvas → WebP with quality decrement until size limit.
- Hash: BLAKE3, 32-byte output, hex encoded (64 chars).
- Validation: MIME header check and magic bytes for JPEG/PNG/WebP/SVG.

Code references:
- Validation and compression: `src/lib/utils/avatar-utils.ts`
- Limits: `src/lib/constants.ts`

---

## 10. Implementation Reference

### Client-Side
- `src/lib/avatar/profile-picture-system.ts`: high-level API
- `src/lib/avatar/init.ts`: initialization and loading
- `src/lib/avatar/own-avatar.ts`: set/remove avatar
- `src/lib/avatar/cache.ts`: cache persistence
- `src/hooks/discovery/useDiscovery.ts`: publish and receive from discovery
- `src/components/ui/UserAvatar.tsx`: rendering
