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
Credential records are stored in shards of 100 records. Login retrieves a record via 1-out-of-100 OT using ML-KEM public keys. The server does not learn which record is fetched.

Code references:
- OT login: `server/authentication/authentication.js` (`handleOTSignIn`)

### 1.3 Privacy Pass (VOPRF)
Privacy Pass is used for anonymous server entry and optional authentication rate limiting.

Code references:
- Server: `server/authentication/privacy-pass-server.js`
- Gatekeeper: `server/authentication/gatekeeper.js`

### 1.4 Blind Signatures (Unlinked Routing)
Blind signatures allow a client to prove ownership of an inboxId without revealing it to the server when the signature is issued. The system uses RSABSSA-PSS (RSA blind signatures with PSS verification).

Code references:
- RSA blinding: `src/lib/crypto/blind-credentials.ts`
- Server signer: `server/security/blind-signatures.js`

### 1.5 ZK Device Proof (Ring Signatures)
Device proofs are LSAG ring signatures over Ed25519. Each device registers a ring public key once, then proves membership without revealing which key in the ring it controls.

Code references:
- Client proof: `src/lib/cryptography/zk-device-proof.ts`
- Server verifier: `server/authentication/zk-verifier.js`

---

## 2. Identifier Hierarchy

| Identifier | Origin | Scope | Lifetime | Notes |
|---|---|---|---|---|
| Plaintext username | User input | Client only | Permanent | Never sent to server |
| Blind user id | BLAKE3(username) | Client only | Permanent | Used for local lookup |
| CredentialId | OPAQUE OPRF output | Account primary key | Permanent | Stored server-side |
| SessionId | Random | Connection | Ephemeral | Stored in Redis |
| InboxId | Derived from vault key | Routing | Rotates | Used for blind routing |

Code references:
- Vault inbox derivation: `src/lib/utils/auth-utils.ts` (`deriveInboxId`, `generateBlindCredential`)
- Session state: `server/session/connection-state.js`

---

## 3. Registration Flow (OT + OPAQUE)

### Step 1: Registration request
Client sends `auth-ot-register-request` with a blinded OPRF element and optional blinded Privacy Pass tokens.

Server:
- Evaluates OPRF.
- Assigns the next shard/slot (100 records per shard).
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
- `clientPubKeys` (100 ML-KEM public keys, one real and 99 decoys)
- `blindedElement` (OPAQUE login OPRF input)

Server:
- Loads the shard.
- Evaluates the OPRF input.
- Encrypts the 100 records with OT (`encryptShardForOT`).
- Returns `auth-ot-response` with `otRecords`, `evaluatedElement`, and `serverNonce`.

Code references:
- Server: `server/authentication/authentication.js` (`handleOTSignIn`)

### Step 2: OPAQUE finalize
Client decrypts its record, derives an `authProof`, and sends `auth-ot-finalize` with `credentialId` and `authProof`.

Server:
- Verifies the OPAQUE proof.
- Issues an anonymous session token.
- Optionally issues blind routing credentials if a `blindedToken` is provided.

Code references:
- Server: `server/authentication/authentication.js` (`handleSignInFinalize`)

---

## 5. Anonymous Session Tokens

Anonymous session tokens are capability tokens issued after registration or login.

Format:
- `version (1B) || nonce (24B) || timestamp (8B) || mac (32B)`
- MAC uses BLAKE3 keyed with a server secret derived via HKDF.
- No user identifiers are included.

Code references:
- Token service: `server/authentication/anonymous-session-service.js`
- Token validation: `server/server.js` (`TOKEN_VALIDATION`)

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
1. Client derives `inboxId` from its vault key (`deriveInboxId`).
2. Client blinds the inboxId using the server blind signature public key metadata from `server-public-key`.
3. Server signs the blinded message and returns `signedBlindedToken` plus a capability token and `blindSignatureKid`.
4. Client unblinds the signature to obtain `blindSignature`.
5. Client claims the inbox using `claim-inbox` with `capabilityToken`, `blindSignature`, and `blindSignatureKid`.

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
- Blind signature issuance: `server/authentication/authentication.js`
- Claim inbox: `server/handlers/inbox-handlers.js`, `src/lib/transport/blind-routing-client.ts`

---

## 8. Linked vs Unlinked Routing

Linked mode:
- Server may set `ws._primaryInboxId` to the credentialId after login.
- Useful for account-scoped operations but not for privacy-preserving routing.

Unlinked mode:
- Client claims a derived inboxId with blind signature.
- Routing and bundle publish are keyed by inboxId without username linkage.

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
- OT uses ML-KEM-1024 to encrypt all shard entries for oblivious retrieval.
- Session tokens use BLAKE3 MACs, not JWTs, to avoid metadata leakage.
- Blind signatures use RSABSSA-PSS with a persisted server key pair and a key id (`kid`) for verification.
- ZK device proofs use LSAG ring signatures over Ed25519 with key images to prevent double-use.

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
