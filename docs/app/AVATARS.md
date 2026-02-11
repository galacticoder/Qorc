# Qor-Chat Avatar System

## Overview

The server never receives the actual avatar file. Distribution of the avatar happens through encrypted discovery blobs and optional direct encrypted profile-picture request/response messages. The UI always renders from local cache. The avatars are directly included in the inner payload of the discovery payload in the discovery billboard.

Core properties:
- Avatars stored in SecureDB on the client.
- Sharing is optional and controlled by `shareWithOthers`.
- Discovery publishes an encrypted avatar inside the OPRF blob.
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

## 5. Distribution via Discovery

Avatars are included inside the OPRF discovery blob:
- The avatar is part of `OPRFDiscoveryMaterial`.
- The blob is encrypted with a key derived from the OPRF output, so the server cannot read it.

Publishing:
- During self-publish, the discovery hook calls `getAvatarForDiscovery` and embeds the avatar into the encrypted blob.

Receiving:
- `useDiscovery.findUser` decrypts the blob.
- If an avatar is present and valid, it is cached with TTL.

Code references:
- Discovery publish: `src/hooks/discovery/useDiscovery.ts`
- OPRF blob crypto: `src/lib/crypto/oprf-discovery-crypto.ts`
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

## 7. Profile Update Broadcast

When the local avatar or profile settings change:
1. `useMessageSender` broadcasts a silent `profile-update` message to peers.
2. Receivers invalidate discovery cache and re-fetch via `findUser`.
3. Updated avatar is cached and UI updates.

Code references:
- Broadcast: `src/hooks/message-sending/useMessageSender.ts`
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
- `src/hooks/discovery/useDiscovery.ts`: publish and receive via discovery
- `src/components/ui/UserAvatar.tsx`: rendering
