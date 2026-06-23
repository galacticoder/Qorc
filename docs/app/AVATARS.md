# Qor-Chat Avatar System

## Overview

The server never receives the actual avatar file in plaintext, and — as of the unlinkable-content-store change — it cannot link a stored avatar to any user. The avatar is **no longer carried inside the discovery blob**. Instead the avatar is encrypted into a uniform-size **PURB** and stored in a separate **unlinkable content store**, fetched by an opaque id with cover traffic. The UI always renders from local cache.

Core properties:
- Avatars stored in SecureDB on the client.
- Sharing is optional and controlled by `shareWithOthers`.
- Discovery publishes only a small `avatarRef` (opaque blobId + E2E key + hash) inside the encrypted keys-blob — never the avatar bytes.
- The avatar bytes live as an E2E-encrypted, uniform-size PURB in the unlinkable content store. The server cannot decrypt them, cannot learn their true size, and cannot link the blob to an identity.
- Direct avatar messages are end-to-end encrypted.

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

## 5. Distribution via the Unlinkable Content Store

The avatar is delivered out of band from the discovery keys-blob because avatar bytes are too large for the discovery record. So:

What rides inside the encrypted discovery keys-blob is only an `AvatarRef`:
- `avatarRef = { blobId, keyB64, hash, mimeType }` — an opaque random per-publish blobId, the E2E AEAD key, and the content hash. The keys-blob is encrypted with the OPRF-derived key, so the server cannot read the ref.

The avatar bytes themselves go to the content store as a PURB:
- **PURB (Padded Uniform Random Blob):** the avatar (`{data, mimeType, hash}`) is padded to a fixed plaintext capacity (`AVATAR_PURB_CAPACITY`, 256 KiB) with the true length encrypted inside, then AEAD-encrypted under a fresh owner-generated key. Every stored blob is therefore byte-identical in size, so the server learns nothing from size and a "miss" can be answered with an identically-sized synthetic blob. (256 KiB fits a 512px WebP avatar with margin. The rare avatar that doesn't fit is simply not shared via the store — `publishAvatarToStore` returns null, the peer shows a default and can still get the picture via the §6 P2P exchange. The cap is kept small because cover traffic fetches ~10 PURBs per lookup.)
- **Unlinkable upload:** the PURB is POSTed to `/api/avatar/blob/put` over the **dedicated anonymous Tor circuit** (never the account WebSocket), keyed only by the client-chosen random `blobId`. The `avatar_blobs` table has **no identity column**, so the server cannot link the blob to a user.

Publishing (`useDiscovery` self-publish):
1. `getAvatarForDiscovery` selects the avatar to share (real or default, per `shareWithOthers`).
2. `ensureAvatarCoverBlobs` (throttled, fire-and-forget) tops up this client's share of **cover PURBs** in the public pool — random-content, uniform-size, fresh-id blobs indistinguishable from real avatars. This guarantees the cover pool stays large enough for a full k-anonymity set even with very few real users. Each cover upload is independently jittered.
3. `publishAvatarToStore` returns the `AvatarRef` **synchronously** but **decouples the actual upload**: the anonymous PUT is scheduled at a random delay (`AVATAR_UPLOAD_JITTER_*`), not fired during the publish. This is the key timing fix — the account's discovery publish goes over the authenticated WebSocket at a known time, so doing the anonymous upload at that same instant would let the server timing-correlate the two and relink the blob to the account. An **unchanged** avatar (state persisted in `localStorage`) reuses its existing ref and uploads nothing at all, so the vast majority of publishes produce no avatar-store traffic.
4. The `AvatarRef` (not the avatar) is embedded in `OPRFDiscoveryMaterial.avatarRef` and published in the encrypted keys-blob.

The avatar's `blobId` rotates when the **avatar changes** (or near its TTL), not on every publish — so its upload is a rare, jittered event rather than a per-epoch one coincident with publishing. The brief window where a freshly-rotated blob isn't up yet (peer shows a default + can still get it via the §6 P2P exchange) only occurs right after an actual avatar change.

Receiving (`useDiscovery.finalizeDiscoveryResult` / snapshot path):
1. After the discovery lookup (tier-1 PIR match + k-anonymous bucket fetch) recovers and decrypts the keys-blob, `cachePeerAvatarFromRef` runs in the **background** (never blocking the discovery result) and is skipped entirely if we already hold this exact (hash-matching, fresh) avatar — so most repeat lookups don't hit the network at all.
2. `fetchAvatarFromStore` fetches the avatar by `blobId` with **cover traffic** (`AVATAR_COVER_TOTAL_IDS`, default 10): it mixes the real target with a **stable decoy set** drawn from the public pool (`/api/avatar/pool`) and shuffles the order, then POSTs the batch to `/api/avatar/blob/get`. All ids are real pool entries, so the server sees k equally-plausible fetches and cannot tell which the client wanted (k-anonymity). Every id returns an identically-sized response (real PURB or synthetic miss).
3. The target PURB is decrypted with `avatarRef.keyB64`, the content hash re-verified against `avatarRef.hash`, and the avatar cached with TTL.

**Why the decoy set is *stable* per target:** if decoys were re-randomized each fetch while the target stayed the same, an observer could intersect the batches across repeated lookups of one peer and the target would fall out (the only common element). Reusing the same decoy companions for a given target (cached for `DECOY_CACHE_TTL_MS`) makes repeated batches a constant set, so an intersection yields the whole set, never the target alone. The target's blobId itself also rotates each publish, bounding any analysis to one epoch.

Privacy summary: lookups are oblivious (PIR). The avatar fetch is by an opaque id the server cannot link to a peer (unlinkable upload + ref only inside ciphertext). The **upload timing is decoupled** from the account's publish (random delay + skip-if-unchanged), so the two can't be timing-correlated to relink the blob to the account. The bytes are E2E-encrypted and uniform-size. Cover traffic gives ~k-anonymity per fetch (with client-uploaded cover blobs guaranteeing the crowd even at low user counts), stable decoys defeat the intersection attack, and blobId rotation on avatar change bounds frequency analysis.

Honest residuals: (a) the fetch is **k-anonymous, not oblivious** — the server sees the candidate id set (just not which one you wanted, and none linked to a person). (b) anonymity is ultimately bounded by how many avatars/cover blobs exist. (c) cover traffic costs bandwidth — each lookup pulls ~k × ~342 KB (≈ 3.4 MB at k=10), lazy and cached, tunable via `AVATAR_COVER_TOTAL_IDS` / `AVATAR_GET_MAX_BATCH`. This is strictly stronger than the old in-blob delivery, which exposed avatar size to the server and tied avatar bytes to the (PIR-served) discovery record.

### Circuit isolation

This client's anonymous calls are split across **separate isolated Tor circuits** (Tor `IsolateSOCKSAuth`, keyed by a distinct SOCKS username per concern), so the server cannot link a client's facets to one another — even though all are already unlinkable to the account:
- `qor-discovery-pir` — discovery lookups (tier-1 PIR query, OPRF eval, manifest, keys-blob bucket fetch).
- `qor-avatar-pub` — avatar **publishing** (`/api/avatar/blob/put`, real + cover uploads).
- `qor-avatar-fetch` — avatar **lookups** (`/api/avatar/blob/get`, `/api/avatar/pool`).

So "the entity that published avatar blob B", "the entity that looks up peers' avatars X/Y/Z", and "the entity that runs the PIR lookups" land on three different circuits and are mutually unlinkable. Wiring: `isolated_tor_post(..., circuit)` in `src-tauri/src/commands/pir.rs` (the `circuit` arg is the SOCKS username).

Code references:
- Avatar PURB crypto: `src/lib/crypto/avatar-blob-crypto.ts`
- Content-store client (publish/cover-fetch/decrypt): `src/lib/avatar/avatar-store-client.ts`
- Discovery publish + background fetch: `src/hooks/discovery/useDiscovery.ts`
- Keys-blob crypto + `avatarRef`: `src/lib/crypto/oprf-discovery-crypto.ts`
- Server store + endpoints: `server/database/avatar-blob-db.js`, `server/routes/api-routes.js`
- Cache store: `src/lib/avatar/cache.ts`

---

## 6. Direct Profile Picture Messaging (Wired)

Direct avatar messages are now handled in the encrypted message pipeline:
- `profile-picture-request`
- `profile-picture-response`

Flow:
1. When a peer avatar is missing or stale, the UI triggers `profilePictureSystem.requestPeerAvatar`.
2. The system sends a `profile-picture-request` via the unified transport.
3. The payload is end-to-end encrypted (LibSignal + Hybrid wrapper).
4. The recipient handles the message via `profilePictureSystem.handleIncomingMessage` and replies with a `profile-picture-response`.

Code references:
- Messaging helpers: `src/lib/avatar/messaging.ts`
- Request trigger: `src/components/ui/UserAvatar.tsx`
- Request sender: `src/lib/avatar/peer-avatar.ts`
- Handler wiring: `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- Profile picture system: `src/lib/avatar/profile-picture-system.ts`

---

## 7. Avatar Update Propagation

There is no peer `profile-update` broadcast message. When the local avatar or profile settings change:
1. The client updates its local cache and dispatches a local `PROFILE_PICTURE_UPDATED` (or `PROFILE_SETTINGS_UPDATED`) event so the UI refreshes.
2. The change reaches peers passively: the new `avatarRef` is carried in the republished encrypted discovery keys-blob (peers pick it up on their next `findUser`), and a peer that detects a stale avatar requests the current one directly (§6).

Code references:
- Local change + events: `src/lib/avatar/own-avatar.ts`
- Discovery republish (carries `avatarRef`): `src/hooks/discovery/useDiscovery.ts`
- Receive handling: `src/hooks/message-handling/useEncryptedMessageHandler.ts`

---

## 8. UI Rendering and Cache Refresh

`UserAvatar` renders from the local cache and listens for avatar update events. For peers, it periodically checks staleness, reloads if needed, and re-requests via direct messaging when stale.

Code references:
- UI component: `src/components/ui/UserAvatar.tsx`
- Cache TTL: `src/lib/constants.ts` (`AVATAR_CACHE_TTL_MS`)

---

## 9. Cryptography and Validation Details

- Allowed mime types: JPEG, PNG, WebP, SVG.
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
