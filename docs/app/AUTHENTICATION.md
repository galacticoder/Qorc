# Qor-Chat Authentication Architecture

## Overview

Qor-Chat implements a Total Blind Authentication system. The server never learns a plaintext username, never stores a password-equivalent, and cannot link sessions to a user identity. Authentication uses OPAQUE, post-quantum OT for oblivious lookup, and Privacy Pass for anonymous rate limiting and server entry.

Guarantees:
- Usernames never reach the server in plaintext.
- Passwords are never revealed or stored.
- Server stores only encrypted OPAQUE records indexed by a credentialId.
- Sessions are anonymous capability tokens with no user metadata.
- Unlinked routing uses blind signatures to claim inboxes without account linkage.

---

## 1. Cryptographic Primitives

### 1.1 OPAQUE
OPAQUE allows password authentication without revealing a password-equivalent to the server. The server stores an encrypted envelope and performs a blind OPRF evaluation.

Code references:
- Server OPAQUE: `server/crypto/opaque-service.js`
- Auth flows: `server/authentication/authentication.js`

### 1.2 Post-Quantum Oblivious Transfer (OT)
Credential records are stored in shards of `PRIVATE_AUTH_SHARD_SIZE` records (default 2048). Login retrieves a record via 1-out-of-2048 OT using ML-KEM-1024 public keys. The server does not learn which record is fetched. The shard is the login anonymity set: the server only ever learns that *some* member of a shard authenticated, never which one (see §4).

> **`shardId` is not a per-account identifier (`PRIVATE_AUTH_SHARD_COUNT = 1`).** All accounts live in a single shard, so the `shardId` named in every login request is the constant `0` — it carries no identity and cannot link logins. (Previously shards were assigned randomly over ~1M buckets, so each shard held ~one real account and `shardId` ≈ identity. Collapsing to one shard removed that leak. Capacity is therefore `PRIVATE_AUTH_SHARD_SIZE` accounts.) Planned next step: replace OT retrieval with **PIR**, which removes the `shardId` field entirely, drops the ~27 MB OT response, derives the record index from credentials (no stored `shard_info`), and scales past one shard — same login anonymity, better performance/scale.

Code references:
- OT login: `server/authentication/authentication.js` (`handleOTSignIn`)
- Shard size: `server/crypto/opaque-service.js` (`OPAQUE_CONFIG.PRIVATE_AUTH_SHARD_SIZE`)

### 1.3 Privacy Pass (VOPRF)
Privacy Pass is used for anonymous server entry and optional authentication rate limiting.

Code references:
- Server: `server/authentication/privacy-pass-server.js`
- Gatekeeper: `server/authentication/gatekeeper.js`

### 1.4 Blind Signatures (Unlinked Routing)
Blind signatures allow a client to prove authorization for a rendezvous route without revealing the raw inbox secret to the server when the signature is issued. The client blinds the committed `routeId`, not the `inboxId`, and the server verifies the unblinded RSABSSA-PSS signature against that route commitment during `claim-inbox`.

Code references:
- RSA blinding: `src/lib/crypto/blind-credentials.ts`
- Server signer: `server/security/blind-signatures.js`

### 1.5 ZK Device Proof (Ring Signatures)
Device proofs are LSAG ring signatures over Ed25519. Each device registers a ring public key once, then proves membership without revealing which key in the ring it controls.

Hard requirements:
- Minimum active ring size is 128.
- Proof version must be `2`.
- Key images must be valid, nonzero, and unused.
- Device proof only means "authorized device". It must not become a sender identity.

Code references:
- Client proof: `src/lib/cryptography/zk-device-proof.ts`
- Server verifier: `server/authentication/zk-verifier.js`

---

## 2. Identifier Hierarchy

| Identifier | Origin | Scope | Lifetime | Notes |
|---|---|---|---|---|
| Plaintext username | User input | Client only | Permanent | Never sent to server |
| Blind user id | BLAKE3(username) | Client only | Permanent | Used for local lookup |
| CredentialId | OPAQUE OPRF output | Account record key | Permanent | Stored server-side as a derived lookup id. Sent to the server only once at registration, NEVER at login (login is shard-anonymized — see §4). At-rest only. Not linkable to any connection or login. |
| SessionId | Random | Connection | Ephemeral | Stored in Redis |
| InboxId | `SHA-256(vault key, 6h epoch)` | Client secret / encrypted discovery | Rotates (per 6h epoch) | **Epoch-bound, not permanent.** It was previously a pure function of the vault key, so the first inbox claimed on every login was identical forever — a stable per-account value the server could link sessions by. It now folds a 6h rotation epoch (aligned with `DISCOVERY_EPOCH_DURATION_MS`) so the inbox and discovery token rotate together. Cross-session linkability via the inbox is bounded to one epoch. Still deterministic from `(vault key, epoch)`, so reconnect/recovery recompute it with no stored state. Not sent in active routing requests. |
| RouteId | BLAKE3(inboxId, route domain) | Route ownership and bundle authorization | Rotates | Server-visible during claim/rotation, not active send destination. Inherits the inbox's epoch rotation plus in-session ~5-min rotation |
| MailboxLookupId | BLAKE3(inboxId, mailbox domain) | Encrypted peer metadata / local validation | Rotates | Not accepted by active send, route claim, rotation, or global-spool PIR retrieval |
| BundleLookupId | BLAKE3(inboxId, bundle domain) | Signal bundle storage | Rotates | Server-visible bundle commitment |

Code references:
- Vault inbox derivation: `src/lib/cryptography/vault-key.ts` (`deriveInboxId(vaultKey, epoch)`, `currentInboxEpoch`, `INBOX_EPOCH_MS`). `src/lib/utils/auth-utils.ts` (`generateBlindCredential`)
- Rendezvous derivation: `src/lib/transport/rendezvous-routing.ts`
- Session state: `server/session/connection-state.js`

---

## 3. Registration Flow (OT + OPAQUE)

### Step 1: Registration request
Client sends `auth-ot-register-request` with a blinded OPRF element and optional blinded Privacy Pass tokens.

Server:
- Evaluates OPRF.
- Assigns the next shard/slot (`PRIVATE_AUTH_SHARD_SIZE` records per shard, default 2048). The slot is pre-allocated here, before `credentialId` is known, so `credentialId` is only the record key, not a placement input.
- Returns `auth-ot-register-response` with `evaluatedElement`, `serverNonce`, `shardId`, and `slotIndex`.

Code references:
- Server: `server/authentication/authentication.js` (`handleOTRegisterRequest`)

### Step 2: Registration finalize
Client derives `credentialId`, encrypts its OPAQUE envelope, and sends `auth-ot-register-finalize`.

Server:
- Stores record indexed by `credentialId`.
- Issues anonymous session token.
- Optionally issues blind routing credentials if `blindedToken` was provided.
- Optionally issues Privacy Pass tokens if `blindedTokens` were provided.

Code references:
- Server: `server/authentication/authentication.js` (`handleOTRegisterFinalize`)
- Token service: `server/authentication/anonymous-session-service.js`

---

## 4. Login Flow (OT + OPAQUE)

### Step 1: OT request
Client sends `auth-ot-request` with:
- `shardId`
- `clientPubKeys` (`PRIVATE_AUTH_SHARD_SIZE` ML-KEM-1024 public keys, default 2048: one real and the rest decoys)
- `blindedElement` (OPAQUE login OPRF input)

Server:
- Loads the shard.
- Evaluates the OPRF input.
- Encrypts all shard records (default 2048) with OT (`encryptShardForOT`).
- Generates a `serverNonce`, **binds it to this connection** (`ws._loginServerNonce`), and returns `auth-ot-response` with `otRecords`, `evaluatedElement`, and `serverNonce`.

Code references:
- Server: `server/authentication/authentication.js` (`handleOTSignIn`)

### Step 2: OPAQUE finalize (shard-anonymized, no per-account identifier)
Client decrypts its record, derives an `authProof`, and sends `auth-ot-finalize` with `shardId` and `authProof`. It does **not** send `credentialId`.

Server:
- Consumes the connection-bound `serverNonce` issued in Step 1 (**one-time**. Cleared immediately) and verifies the proof against it. A replayed finalize, or a captured `(authProof, serverNonce)` pair on a new connection, finds no nonce and is rejected. One OT request backs at most one finalize attempt (no online brute-force amplification).
- Verifies the proof against **every record in the shard** (`finishLoginAcrossShard`) with constant work and no early exit, so the response time does not leak which record matched. The server learns only that *a member of shard X* authenticated, never which account — preserving the full shard-sized (default 2048) anonymity set through finalize.
- Issues blind routing credentials if a `blindedToken` is provided.

The auth proof itself is a keyed-BLAKE3 MAC over a domain-separated transcript binding the `serverNonce`, keyed by material derived from the (password-gated) `maskedResponse` (`OPAQUE-Auth-Key-v2` / `OPAQUE-Auth-MAC-v2`). Client and server compute it byte-identically.

Code references:
- Server: `server/authentication/authentication.js` (`handleSignInFinalize`), `server/crypto/opaque-service.js` (`finishLoginAcrossShard`, `#computeAuthMac`)
- Client: `src/lib/cryptography/crypto-ops.ts` (`OPAQUEOps.finishOTLogin`)

---

## 5. Anonymous Sessions and Unlinkable Autologin

A successful registration or login establishes an anonymous capability session (BLAKE3-MAC'd, no user identifiers). What is NOT done anymore: persist a single long-lived session token and replay it on every reconnect. Replaying one stable value — even an anonymous one — let the server link all of a client's reconnects for the token's lifetime.

Unlinkable autologin instead:
- At login, the client refills a small machine-bound pool of **one-time anonymous Privacy Pass tokens** (blind-signed, so the server can't link issuance to redemption. Each carries a unique nullifier so it can't be reused).
- On reconnect/restart the client redeems a **fresh** token (`resumeRedemption` in `TOKEN_VALIDATION`). The server verifies it (`PrivacyPassServer.redeemToken`) and grants a new anonymous session for that connection only.
- The server therefore sees unlinkable, single-use proofs — never a stable session identifier — while passwordless restart still works (the pool and the vault key live in machine-bound storage). The legacy replayable token is never persisted and is cleared on logout.

Code references:
- Token service: `server/authentication/anonymous-session-service.js`
- Resume pool: `src/lib/signals/resume-tokens.ts`, `src/lib/database/token-vault.ts` (`reserveResumeTokens`)
- Validation/redemption: `server/server.js` (`TOKEN_VALIDATION`), `server/authentication/privacy-pass-server.js`
- Privacy Pass: `docs/app/AUTHENTICATION.md` §1.3, `src/lib/cryptography/privacy-pass-client.ts`

---

## 6. Gatekeeper (Server Entry Tokens)

If a server requires a global password, clients must obtain and redeem Privacy Pass entry tokens before other signals are accepted.

Flow:
1. Client requests `server-entry-request`.
2. Server returns `server-entry-challenge`.
3. Client completes challenge, requests `server-entry-token-issuance`.
4. Client redeems a token via `privacy-pass-redemption`.

Code references:
- Client flow: `src/lib/websocket/websocket.ts`
- Server validation: `server/server.js` (`PRIVACY_PASS_REDEMPTION`)

---

## 7. Blind Routing Credentials (Unlinked Mode)

Unlinked routing allows message delivery without account linkage.

Flow:
1. Client derives the current-epoch `inboxId` from its vault key and the 6h rotation epoch (`deriveInboxId(vaultKey, currentInboxEpoch())`). Because the epoch is folded in, the first inbox claimed each login is no longer a permanent per-account handle (see §2). It stays recomputable from `(vault key, epoch)` so the reconnect/recovery path needs no stored route.
2. Client derives `routeId = BLAKE3("qor-rendezvous-route-v1" || inboxId)`.
3. Client blinds the `routeId` using the server blind signature public key metadata from `server-public-key`.
4. Server signs the blinded message and returns `signedBlindedToken` plus a capability token and `blindSignatureKid`.
5. Client unblinds the signature to obtain `blindSignature`.
6. Client claims the route using `claim-inbox` with `routeId`, `bundleLookupId`, `blockListLookupId`, `capabilityToken`, `blindSignature`, and `blindSignatureKid`. `mailboxLookupId` is intentionally not accepted on this server-visible path.
7. After claim success, the client rotates in-session route commitments on a jittered interval and republishes bundle/discovery material for the new commitments.

The capability token is not an inbox ownership database. It is a short-lived, high-entropy session capability. Raw inbox IDs are not stored inside token claims, and the server has no raw-inbox registration or ownership-proof compatibility route.

Quantum-hardening note: RSABSSA-PSS blind signatures are not treated as the only route-claim authority. A route claim also requires a valid capability token from the authenticated flow, so breaking or weakening the blind-signature layer alone is not enough to claim a route.

Server public key shape:
```json
{
  "type": "server-public-key",
  "hybridKeys": {
    "kyberPublicBase64": "...",
    "dilithiumPublicBase64": "...",
    "x25519PublicBase64": "...",
    "blindPublicKey": {
      "kid": "hex",
      "n": "hex",
      "e": "hex",
      "modulusLength": 2048,
      "hash": "SHA-256",
      "saltLength": 32,
      "scheme": "RSABSSA-PSS"
    }
  }
}
```

Code references:
- Inbox id derivation: `src/lib/utils/auth-utils.ts`
- Route commitment derivation: `src/lib/transport/rendezvous-routing.ts`
- Blind signature issuance: `server/authentication/authentication.js`
- Claim inbox: `server/handlers/inbox-handlers.js`, `src/lib/transport/blind-routing-client.ts`
- Route commitment rotation: `src/lib/transport/blind-routing-client.ts`, `server/routing/blind-router.js`

---

## 8. Linked vs Unlinked Routing

Linked mode:
- Server-authenticated clients may claim a high-entropy route commitment without a blind signature when the authenticated PQ session is already authorized.
- Active sends use the global mix stream and submit no raw inbox IDs, exact route IDs, mailbox lookups, or destination buckets.

Unlinked mode:
- Client claims a derived route commitment with a blind signature over `routeId`.
- Bundle publish and block-list sync are keyed by separate committed lookup IDs without username linkage. Active message sends and global-spool PIR retrieval reveal no destination selector.

Code references:
- Login finalize: `server/authentication/authentication.js` (`handleSignInFinalize`)
- Unlinked claim: `server/handlers/inbox-handlers.js`

---

## 9. ZK Device Proof (Ring Signature)

Flow:
1. Client requests `zk-refresh-challenge`.
2. Server returns `challengeId`, `challenge`, and current ring commitments containing `ringPublicKey`.
3. If the client ring key is not registered, it sends `zk-device-register` with its `ringPublicKey`.
4. Client generates an LSAG ring signature proof over the challenge and sends `zk-device-proof`.
5. Server verifies the ring signature and marks the device as proven for this session.

If fewer than 128 active commitments are available, the server refuses to issue a challenge and clients refuse to generate a proof. This is deliberate: a tiny ring gives weak anonymity and is treated as unsafe.

Proof fields:
- `version`: `2`
- `challenge`: base64 challenge bytes
- `c0`: base64 scalar
- `s`: base64 scalar array sized to the ring
- `keyImage`: base64 key image

Code references:
- Client proof: `src/lib/cryptography/zk-device-proof.ts`, `src/lib/signals/auth-handlers.ts`
- Server verifier: `server/authentication/zk-verifier.js`

---

## 10. Cryptography and Security Details

- OPAQUE records are stored as encrypted envelopes inside the user record.
- OT uses ML-KEM-1024 to encrypt all shard entries for oblivious retrieval. The shard (default 2048) is the login anonymity set and is preserved through finalize (shard-wide verification, no `credentialId` on the wire).
- The OPAQUE auth proof is a keyed-BLAKE3 MAC over a domain-separated transcript binding the `serverNonce` (`OPAQUE-Auth-Key-v2` / `OPAQUE-Auth-MAC-v2`), and the `serverNonce` is server-authoritative, connection-bound, and one-time (replay-resistant by construction).
- The PQ WebSocket handshake uses an **ephemeral per-connection** client ML-DSA-87 signing key — it is never persisted, so the server gets no stable device fingerprint and cannot link a device's connections across time/accounts. It only authenticates messages within one session.
- Autologin uses one-time anonymous Privacy Pass tokens (see §5), not a replayable session token.
- Session/capability tokens use BLAKE3 MACs, not JWTs, to avoid metadata leakage.
- Blind signatures use RSABSSA-PSS with a persisted server key pair and a key id (`kid`) for verification.
- ZK device proofs use LSAG ring signatures over Ed25519 with a 128-device minimum anonymity set and key images to prevent double-use.

Code references:
- Ephemeral handshake signing key: `src/lib/websocket/handshake.ts` (`initializeSigningKeys`)

Code references:
- OPAQUE server: `server/crypto/opaque-service.js`
- OT login: `server/authentication/authentication.js`
- Anonymous session tokens: `server/authentication/anonymous-session-service.js`
- Blind signatures: `server/security/blind-signatures.js`
- ZK device proofs: `src/lib/cryptography/zk-device-proof.ts`, `server/authentication/zk-verifier.js`

---

## 11. Implementation Reference

### Server-Side
- `server/authentication/authentication.js`: OT registration/login, blind routing credentials
- `server/authentication/anonymous-session-service.js`: token format and verification
- `server/authentication/gatekeeper.js`: server entry flow
- `server/authentication/privacy-pass-server.js`: Privacy Pass issuance and redemption
- `server/security/blind-signatures.js`: blind signature issuance

### Client-Side
- `src/hooks/auth/handlers.ts`: auth flows and blind routing setup
- `src/lib/utils/auth-utils.ts`: inbox derivation, blind credential generation
- `src/lib/websocket/websocket.ts`: token validation, gatekeeper
