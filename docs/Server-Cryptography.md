# Server-Side Cryptography Design

## Last updated November 17 2025. Updated regularly on changes.

### This document describes the cryptography implemented on the server. It focuses on the algorithms, key derivations, formats, and flows as they exist in the code.

The main goals of the server-side design are:

- Provide post-quantum (PQ) and hybrid security for all client–server traffic.
- Ensure that application data is end‑to‑end encrypted between clients; the server stores only opaque ciphertext.
- Protect long-lived secrets and key material at rest using strong KDFs and authenticated encryption.
- Use consistent, verifiable formats so that client and server cryptographic behavior match.

---

## 1. High-Level Server Crypto Stack

### 1.1 Languages and Libraries

The server is a Node.js application and uses:

- `mlkem` – ML‑KEM‑1024 (Kyber level-5 variant) key encapsulation.
- `@noble/post-quantum/ml-dsa` – ML‑DSA‑87 (Dilithium level-5 variant) signatures.
- `@noble/hashes/blake3` – BLAKE3 hash and MAC.
- `@noble/hashes/sha3` – SHA3‑512, SHAKE128, SHAKE256.
- `@noble/ciphers/aes` – AES‑GCM.
- `@noble/ciphers/chacha` – XChaCha20‑Poly1305.
- Node `crypto` – CSPRNG, HMAC-SHA512, Ed25519 verification, X25519, etc.
- `argon2` – Argon2id password hashing.
- `pg` – PostgreSQL driver (not crypto itself, but central to persistence).

### 1.2 Architectural Layers

Cryptography on the server is layered as follows:

1. **TLS termination (HAProxy + OpenSSL/OQS)** – TLS 1.3 with hybrid PQ key exchange.
2. **WebSocket PQ transport** – a ML‑KEM‑1024 + X25519 hybrid handshake derives per-session AEAD keys.
3. **Application-level hybrid envelopes** – ML‑KEM‑1024 + X25519 envelopes with Dilithium signatures, shared with the client.
4. **Token and authentication crypto** – ML‑DSA‑87–signed tokens, Argon2id-based password and KEK derivation, device proof using Ed25519, device attestation using ML-DSA-87.
5. **Database and field-level encryption** – PostQuantumAEAD (AES‑GCM + XChaCha20‑Poly1305 + BLAKE3 MAC) with keys from BLAKE3-HKDF/QuantumHKDF.
6. **Redis PQ session storage** – PQ AEAD-encrypted session keys using a dedicated `SESSION_STORE_KEY`.


### 1.3 Device Attestation

Account creation is limited to 2 accounts per device using ML-DSA-87 signatures:

1. **Device keypair**: Generated on first use with hardware entropy, stored in machine-bound secure storage.
2. **Challenge flow**: Server generates PostQuantumRandom nonce, client signs with ML-DSA-87 private key.
3. **Privacy**: Server stores only BLAKE3 hash of device public key + account count. No linkage between specific accounts and device identity.
4. **Enforcement**: Server-side verification prevents client bypass. Signature must be valid before account creation proceeds.


---

## 2. Core Cryptographic Utilities (`server/crypto/unified-crypto.js`)

All server-side crypto primitives are centralized in `CryptoUtils`, exported from `server/crypto/unified-crypto.js`.

```text
CryptoUtils = {
  Hash: QuantumHashService,
  KDF: QuantumKDFService,
  Random: QuantumRandomGenerator,
  Hybrid: HybridService,
  Kyber: QuantumKyberService,
  Dilithium: DilithiumService,
  AES: PostQuantumAESService,
  PostQuantumAEAD: PostQuantumAEAD,
  Config: CryptoConfig,
  Password: PasswordService
}
```

### 2.1 Secure Memory and Configuration

- **`SecureMemory`** – utility class with:
  - `wipe(buf)` – attempts to overwrite `Uint8Array`/`Buffer` contents using `randomFillSync` then `fill(0)`.
  - `wipeAll(...buffers)` – applies `wipe` to each argument.
- **`CryptoConfig`** – central configuration:
  - `ML_KEM_LEVEL = 1024`, `ML_DSA_LEVEL = 87`.
  - Argon2id defaults:
    - `ARGON2_TIME` – env `ARGON2_TIME`, clamped to [3, 10], default 4.
    - `ARGON2_MEMORY` – env `ARGON2_MEMORY`, clamped to [128 MiB, 1 GiB], default 256 MiB.
    - `ARGON2_PARALLELISM` – env `ARGON2_PARALLELISM`, clamped to [1, 16], default 2.
  - HKDF contexts for AES/session keys: `HKDF_INFO = "Qor-chat hybrid key v2"`, `HKDF_INFO_CLIENT_COMPATIBLE = "Qor-chat post-quantum v1"`.

These values are shared by password hashing, KEK derivation, and some session keys.

### 2.2 Randomness (`QuantumRandomGenerator`)

- **`generateRandomBytes(length)`** – synchronous CSPRNG via `crypto.randomBytes(length)`; used for nonces and salts.
- **`generateSecureRandom(length, useTimingEntropy = false)`** – async generator that:
  - Always takes `crypto.randomBytes(length)` as the primary source.
  - Optionally calls `generateTimingEntropy` to obtain additional timing-based bytes (up to 32 bytes) and mixes them with SHAKE256.
- **`generateTimingEntropy(length = 32)`** – uses `process.hrtime.bigint()` timing of mixed BLAKE3/SHA3/SHAKE operations with random iteration counts and delays, then reduces with SHAKE256.
- **`generateSalt` / `generateNonce` / `generateUUID`** – helpers for salts, nonces, and UUIDv4.

The design always relies on the OS CSPRNG and treats timing entropy as optional defense-in-depth.

### 2.3 Hashing and MACs (`QuantumHashService` and `PostQuantumHash`)

`QuantumHashService` wraps BLAKE3, SHA3, and SHAKE functions:

- **Basic utilities**:
  - Conversions to/from `Uint8Array` and base64.
  - `stringToUint8Array`, `arrayBufferToBase64`, `base64ToUint8Array`.
- **Hashing**:
  - `digestQuantumResistant(...parts)` – concatenates byte arrays and returns SHAKE256 output (64 bytes).
  - `digestSHA512(data)`, `digestSHA512Bytes(a, b)` – WebCrypto SHA‑512 wrappers.
  - `blake3(data)` – raw BLAKE3.
  - `blake3Keyed(data, key)` – BLAKE3 with a normalized 32‑byte key.
  - `sha3_512(data)` and `shake256(data, dkLen)` – SHA3 primitives.
- **MACs and HKDF**:
  - `generateBlake3Mac(message, key)` – normalizes key to 32 bytes and computes BLAKE3 MAC.
  - `generateBlake3ConcatMac(message, key)` – derives a 64‑byte key via SHAKE256 and MACs with BLAKE3.
  - `generateQuantumMAC(message, key)` – combines BLAKE3, SHA3‑512, and SHAKE256 outputs and hashes them with BLAKE3.
  - `verifyBlake3Mac` / `verifyQuantumMAC` – recompute and `safeCompare`.
  - `blake3Hkdf(ikm, salt, info, outLen)` – BLAKE3-based HKDF (Extract = BLAKE3 MAC with salt as key; Expand = iterative MAC with counter).
- **Comparison**:
  - `safeCompare(a, b)` – constant-time compare using `crypto.timingSafeEqual` with length normalization.

`PostQuantumHash` (in `server/crypto/post-quantum-hash.js`) provides a simpler HKDF wrapper:

- `deriveKey(inputKey, salt, info, length)` – HKDF-BLAKE3 used widely for hybrid envelope key derivation.

### 2.4 Key Derivation (`QuantumKDFService`)

- **`quantumHKDF(ikm, salt, info, outLen)`**:
  - Uses three parallel “extract” steps:
    - BLAKE3 MAC (key = salt, message = ikm).
    - SHA3‑512(salt || ikm).
    - SHAKE256(salt[:32] || ikm, 64 bytes).
  - Concatenates outputs and hashes with BLAKE3 to form a master PRK.
  - Expands using a loop where each iteration computes BLAKE3 MAC, SHA3‑512, and SHAKE256 over (previous block || info || counter) and feeds them into SHAKE256 to produce 64‑byte blocks.
  - Used where a multi-hash PQ KDF is required (for example `SESSION_STORE_KEY` and username+password KEK).
- **`deriveUsernamePasswordKEK(username, password, options)`**:
  - Enforces minimum lengths and derives a 64‑byte Argon2id base key from the password.
  - Hashes the username with BLAKE3 and concatenates with base key.
  - Uses SHAKE256(salt) as HKDF salt and `"username-password-kek-v1"` as info.
  - Final KEK: 32 bytes; returns `{ kek, salt }`.
- **`deriveAesKeyFromIkm(ikm, salt, context)`**:
  - Uses `QuantumHashService.blake3Hkdf` with context string `"Qor-chat hybrid key v2:<context>"` to derive a 32‑byte AES key.
- **`deriveSessionKey(ikm, salt, sessionContext)`**:
  - Uses BLAKE3-HKDF with info `"session-key-v2:<sessionContext>"` to derive 32‑byte keys.
- **`deriveKey` / `deriveMultipleKeys`** – convenience wrappers around `PostQuantumHash.deriveKey`.

### 2.5 Post-Quantum AEAD (`PostQuantumAEAD` and `PostQuantumAESService`)

`PostQuantumAEAD` implements a 32‑byte key AEAD that composes AES‑256‑GCM, XChaCha20‑Poly1305, and BLAKE3 MAC:

- Key expansion:
  - `sha3_512(key)` → 64 bytes split into `k1` and `k2`.
  - MAC key: `blake3("quantum-secure-mac-v1" || key, dkLen = 32)`.
- Nonce: 36 bytes total; first 12 bytes used for AES‑GCM IV, remaining 24 for XChaCha20 nonce.
- Encryption:
  1. AES‑256‑GCM under `k1` with AAD to produce ciphertext (including GCM tag in the tail of the buffer produced by `gcm` cipher).
  2. XChaCha20‑Poly1305 under `k2` with the same AAD over the AES output.
  3. BLAKE3 MAC over `layer2Ciphertext || aad || nonce` using `macKey[:32]`; 32‑byte tag.
- Decryption:
  - Verifies BLAKE3 MAC first, then decrypts XChaCha, then AES‑GCM.
- Static helpers:
  - `PostQuantumAEAD.encrypt(plaintext, key, aad?, explicitNonce?)` returns `{ ciphertext, nonce, tag }`.
  - `PostQuantumAEAD.decrypt(ciphertext, nonce, tag, key, aad?)` returns plaintext.

`PostQuantumAESService` builds on this:

- `encryptWithPostQuantumAead(data, key)` – returns `{ nonce, encrypted }` where `encrypted = ciphertext || tag`.
- `decryptWithPostQuantumAead(nonce, encrypted, key, aad?)` – splits `encrypted` into ciphertext and tag and decrypts.
- `encryptData(data, password)` / `decryptData(encrypted, password)` – password-based AEAD using BLAKE3-HKDF-derived key from the password and a 32‑byte salt.

### 2.6 ML‑KEM and ML‑DSA (`QuantumKyberService` and `DilithiumService`)

- **`QuantumKyberService`**:
  - `generateKeyPair()` – calls `new MlKem1024().generateKeyPair(additionalEntropy)` where `additionalEntropy` is 64 secure random bytes; returns `{ publicKey, secretKey, algorithm: 'ML-KEM-1024', securityLevel: 256, timestamp, publicKeyHash, secretKeyHash }`.
  - `encapsulate(publicKeyBytes)` – uses `MlKem1024.encap` with 32 bytes extra randomness; returns `{ ciphertext, sharedSecret, algorithm, timestamp }`.
  - `decapsulate(ciphertextBytes, secretKeyBytes)` – returns raw shared secret (Uint8Array) using `MlKem1024.decap`.
  - `deriveEnhancedSharedSecret(rawSharedSecret, publicKeyBytes)` – optional HKDF step using `QuantumKDFService.quantumHKDF` (available for higher-level protocols).
  - `validateKeyPair` – optional self-check (encap/decap plus fingerprint comparison) with a 5‑minute cache.
- **`DilithiumService`** (ML‑DSA‑87):
  - `generateKeyPair()` – promises `{ publicKey, secretKey }`.
  - `sign(message, secretKey)` / `verify(signature, message, publicKey)` – wrappers around `ml_dsa87`.

### 2.7 Password Hashing (`PasswordService`)

- `hashPassword(password)` – verifies string length between 12 and 1024 characters and runs Argon2id with:
  - Memory = `CryptoConfig.ARGON2_MEMORY`.
  - Time = `CryptoConfig.ARGON2_TIME`.
  - Parallelism = `CryptoConfig.ARGON2_PARALLELISM`.
  - Hash length = 64 bytes.
  - Returns encoded Argon2 string.
- `verifyPassword(hash, password)` – verifies an encoded Argon2 hash using `argon2.verify`, logs failures, and returns a boolean.
- `parseArgon2Hash(hash)` – parses Argon2 parameters into `{ algorithm, version, memoryCost, timeCost, parallelism, salt, hash }` for reuse.

This service is used for server password verification and for validating Argon2 parameters supplied by the client.

---

## 3. Unified Private Key Encryption (`server/crypto/unified-key-encryption.js`)

`UnifiedKeyEncryption` is responsible for encrypting ML‑DSA and ML‑KEM private keys on disk.

### 3.1 Master Key and Domain Keys

- Initialization requires a `secret` string (from `KEY_ENCRYPTION_SECRET`) and a `keyPairPath` directory.
- A 64‑byte salt is loaded from `.unified-salt` in `keyPairPath` or generated and stored with mode `0o600`.
- Argon2id is run over `secret` with parameters from `UNIFIED_KEY_CONFIG` (memory, time, parallelism, version 0x13) to obtain a 64‑byte master key.
- Domain keys are derived for `mldsa`, `mlkem`, and `audit` by SHAKE256(masterKey || salt || `"unified-key-encryption:<domain>:v1"`) → 64 bytes each.

### 3.2 QuantumResistantAEAD v3

`QuantumResistantAEAD` is a 64‑byte key AEAD used to encrypt private keys:

- Key layout:
  - `key1` = first 32 bytes (AES‑256‑GCM).
  - `key2` = last 32 bytes (XChaCha20‑Poly1305).
  - `macKey` = SHAKE256(key, dkLen = 64); first 32 bytes used for BLAKE3 MAC.
- Nonce: 36 bytes, derived via SHAKE256 over 36 random bytes.
- Encryption:
  1. AES‑GCM under `key1` with AAD → `aesResult`.
  2. XChaCha20‑Poly1305 under `key2` with same AAD over `aesResult` → `chachaResult`.
  3. BLAKE3 MAC over `chachaResult || aad || nonce` keyed with `macKey[:32]`.
  4. Ciphertext returned as `chachaResult || mac`.
- Decryption reverses the process and verifies MAC before decryption.

### 3.3 Private Key Encryption and Storage

- `encryptPrivateKey(privateKey, keyType, aad?)`:
  - Ensures `keyType` is one of `mldsa` or `mlkem`.
  - Builds AAD including domain, key type, version, and salt (`createAAD`).
  - Uses the domain key (`getDomainKey(keyType)`) with `QuantumResistantAEAD`.
  - Returns JSON containing version, keyType, base64 nonce/ciphertext, salt, algorithm metadata, and a BLAKE3 MAC over the metadata using the `audit` domain key.
- `decryptPrivateKey(encryptedKeyData, expectedKeyType)`:
  - Validates structure, version range, salt length, and key type.
  - Enforces that the salt matches the current `.unified-salt` (prevents decryption with a different master key).
  - Verifies metadata MAC if present.
  - Decrypts using the domain key and returns raw key bytes.
- `encryptAndSavePrivateKey` / `loadAndDecryptPrivateKey` are wrappers that perform atomic file writes and reads with file locks and secure permissions.

ML‑DSA and ML‑KEM private keys used by `TokenService` are managed exclusively through this component.

---

## 4. Tokens and Token Storage

### 4.1 Token Service (`server/authentication/token-service.js`)

`TokenService` manages PQ signing keys and issues/validates access, refresh, and device tokens.

#### 4.1.1 PQ Key Management

On initialization:

- A `UnifiedKeyEncryption` instance is created for `server/config`.
- A key encryption key (KEK) is derived from `KEY_ENCRYPTION_SECRET` via Argon2id (`deriveKeyEncryptionKey`).
- `UnifiedKeyEncryption.initialize(kek)` is called.
- ML‑DSA‑87 and ML‑KEM‑1024 key pairs are loaded or generated:
  - Private keys are stored encrypted via `UnifiedKeyEncryption.encryptAndSavePrivateKey('mldsa'/'mlkem', ..., keyType)`.
  - Public keys are stored as files (`mldsa-public.key`, `mlkem-public.key`).

The loaded keys are cached in `mldsaPrivateKey`, `mldsaPublicKey`, `mlkemPrivateKey`, and `mlkemPublicKey`.

#### 4.1.2 Token Format

Tokens are JWT-like but use a custom algorithm identifier `HYBRID-QR`.

- **Header**:
  - `typ: 'JWT'`.
  - `alg: 'HYBRID-QR'`.
  - `kid`: BLAKE3 fingerprint of the ML‑DSA public key.
  - `pq_alg`: describes the PQ signature and MAC algorithms (ML‑DSA‑87 and BLAKE3-HKDF).
  - `x5t`, `x5t#S256`: thumbprints derived from the ML‑DSA public key.
  - `quantum_resistant: true`, `entropy_bits: POST_QUANTUM_SECURITY_BITS`.
- **Payload**:
  - Standard claims: `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `nbf`, `nonce`.
  - `sub`: hashed user identifier via `hashUserId(userId)` – this uses `USER_ID_SALT` and a key derived from the KEK (HKDF-BLAKE3 over BLAKE3(serverSecret)).
  - Access tokens add `type: 'access'`, `scopes`, `cnf.jkt` (JWK thumbprint), and optional `tlsBinding`.
  - Refresh tokens add `type: 'refresh'`, `family`, `generation`.
  - Device tokens add `type: 'device'` and device attributes.
  - `_integrity`: version (`'3.0-pq-only'`), entropy id, security level, and a multi-hash checksum (`calculateQuantumChecksum`).
- **Signature bundle** (third JWT part):
  - JSON object containing:
    - Version `3.0-pq-only`.
    - `algorithms.ml_dsa_87`: ML‑DSA‑87 signature over `"ALG:ML-DSA-87:v2" || signingInput || keyCommitmentBytes`.
    - `algorithms.blake3_mac`: BLAKE3 MAC over the same buffer, using a key derived from public key material and a server secret (`deriveQuantumIntegrityKey` + HKDF-BLAKE3).
    - `key_commitment`: BLAKE3 hash of concatenated ML‑DSA and ML‑KEM public key prefixes.

#### 4.1.3 Token Generation and Verification

- `signTokenWithIntegrity(payload)`:
  - Populates `_integrity` with an entropy id and checksum.
  - Builds header and payload JSON, base64url encodes them.
  - Derives a key commitment and signs/MACs the augmented signing buffer.
  - Encodes the signature bundle as base64url to form the final token.
- `verifyQuantumToken(token, expectedType, skipReplayCheck)`:
  - Splits into three parts; parses header and signature bundle.
  - Enforces `alg === 'HYBRID-QR'` and `signatureBundle.version === '3.0-pq-only'`.
  - Reconstructs the augmented signing buffer and verifies:
    - ML‑DSA‑87 signature.
    - BLAKE3 MAC via `verifyBlake3MAC`.
  - Parses payload and enforces standard JWT claims.
  - Recomputes the quantum checksum and compares it with constant-time equality.

The token path uses only PQ algorithms; there is no classical RSA/ECDSA signing in the active flow.
### 4.2 Token Database and Field Encryption (`server/authentication/token-database.js`)

`TokenDatabase` handles persistent storage of refresh tokens, token families, blacklists, audit logs, and device sessions in PostgreSQL.

#### 4.2.1 Token Hashing

- A process-wide pepper `TOKEN_PEPPER` is loaded from env or `token.pepper` (mode `0o600`).
- `hashToken(token)` computes `blake3( pepper || token || 'token-hash-v1' ).toString('hex')`.
- All stored tokens are represented only by their BLAKE3 hash; raw tokens are never written to disk.
- Comparisons use fixed-size buffers and `crypto.timingSafeEqual`.

#### 4.2.2 Field-Level Encryption (`FieldEncryption`)

- Master key: `DB_FIELD_KEY` (UTF‑8) from `process.env.DB_FIELD_KEY`.
- Per-field key derivative:
  - `ikm = new Uint8Array(masterBuf)`.
  - `salt = 'db-field-key-salt-v2'`.
  - `info = 'db-field-key-v2:<fieldName>'`.
  - `keyBytes = CryptoUtils.KDF.deriveKey(ikm, salt, info, 32)`.
- Encryption format:
  - Nonce: 36 random bytes.
  - AAD: `'db-field:<fieldName>:v3'`.
  - AEAD: `CryptoUtils.PostQuantumAEAD(keyBytes)`.
  - Stored as base64(nonce || tag || ciphertext) in text columns.
- Decryption reverses the format and returns a UTF‑8 string.

This is used to encrypt user IDs and device IDs in token tables and audit logs, so those identifiers are not stored in plaintext.

#### 4.2.3 Device Sessions and Audit Log

Both device session tracking and authentication audit use the same hashing/encryption primitives described above:

- Device sessions (table `device_sessions`) record logical devices, linked to user IDs.
- `logAuthEvent` writes an audit record where userId/deviceId fields are encrypted with `FieldEncryption` and security flags are sanitized JSON.

### 4.3 Token Security Manager (`server/authentication/token-security.js`)

`TokenSecurityManager` orchestrates security policy using `TokenDatabase` and `TokenService`:

- Enforces limits on refresh token usage per user.
- Supports revocation and blacklisting with log entries.
- Detects suspicious activity (frequent refreshes, many devices, high failure rates) and can trigger actions such as logging out from all devices.

All of these operations rely on the hashed and encrypted fields described above.

---

## 5. Database and Storage Details (`server/database/database.js`)

### 5.1 Global Secrets

The server derives three long-lived secrets at startup. If environment variables are not set, they are generated and persisted to disk:

- **PASSWORD_HASH_PEPPER**:
  - Stored in `generated-pepper.txt` (or path from `PASSWORD_HASH_PEPPER_FILE`).
  - 64-byte hex string.
  - Used as HMAC key for server-side password peppering.
- **USER_ID_SALT**:
  - Stored in `generated-user-id-salt.txt` (or path from `USER_ID_SALT_FILE`).
  - 64-byte hex string.
  - Used by `TokenService.hashUserId` for pseudonymous subject identifiers.
- **DB_FIELD_KEY**:
  - Stored in `generated-db-field-key.txt` (or path from `DB_FIELD_KEY_FILE`).
  - 64-byte hex string.
  - Used by `FieldEncryption` and `LibsignalFieldEncryption` as master key for field-level encryption.

All three files are created with directory mode `0o700` and file mode `0o600`. If any of these secrets are lost, corresponding data (password hashes, token subjects, encrypted DB fields) becomes unrecoverable.

### 5.2 Password Storage Model

The server never receives a plaintext account password. The client computes an Argon2id hash and sends the encoded Argon2 string during sign-up and sign-in.

On the server:

- The raw Argon2id hash string (e.g. `$argon2id$v=19$m=65536,t=3,p=4$...`) is stored in the `users.passwordHash` column.
- A *peppered* wrapper is derived via:
  - `pepperedBase64 = HMAC_SHA512(PASSWORD_PEPPER, rawHash).toString('base64')`.
  - `rawBase64 = base64(rawHash)`.
  - Stored value: `v1:${pepperedBase64}:${rawBase64}`.
- Helper functions:
  - `encodeStoredPasswordHash(rawHash)` – creates the `v1:...` wrapper.
  - `decodeStoredPasswordHash(stored)` – recovers the raw Argon2 string if wrapper format is present.
  - `verifyPepperedHash(candidateRawHash, storedValue)` – re-computes HMAC-SHA512 and compares with `timingSafeEqual`.

`UserDatabase.saveUserRecord` and `UserDatabase.updateUserPassword` always store the peppered representation. Authentication paths compare encoded Argon2 strings using constant-time comparison, not by re-running Argon2 on the server.

### 5.3 Libsignal Field Encryption and Bundle Storage

`LibsignalFieldEncryption` provides post-quantum authenticated encryption for Signal identity and pre-key material stored in the `libsignal_bundles` table.

Key derivation and format:

- **Field Key** (`deriveFieldKey(fieldName)`):
  - Input: `DB_FIELD_KEY` (UTF-8) as input keying material (IKM).
  - Salt: `'db-libsignal-field-key-salt-v1'` (UTF-8).
  - Info: `libsignal-field:${fieldName}`.
  - KDF: `PostQuantumHash.deriveKey` (HKDF-BLAKE3) → 32‑byte key.
- **Encryption** (`encryptField`):
  - Nonce: 36 random bytes (`randomBytes(36)`), split as required by `PostQuantumAEAD` (12 bytes for AES-GCM, 24 bytes for XChaCha20-Poly1305).
  - AAD: `libsignal-field:${fieldName}:v1` (UTF-8).
  - AEAD: `CryptoUtils.PostQuantumAEAD` (double-layer AES-GCM + XChaCha20‑Poly1305 + BLAKE3 MAC).
  - Stored format: `'pq2:' + base64(nonce || tag || ciphertext)`.
- **Decryption** (`decryptField`):
  - Validates `pq2:` prefix.
  - Splits base64 payload into nonce (36 bytes), tag (32 bytes), ciphertext (rest).
  - Re-derives field key and AAD; decrypts via `PostQuantumAEAD`.

`LibsignalBundleDB.publish` and `LibsignalBundleDB.take` wrap all key material using this scheme.

`LibsignalBundleDB` itself:

- Validates bundle structure and required fields on publish.
- Encrypts identity key, pre-key public keys, signatures, and Kyber pre-key material with `LibsignalFieldEncryption`.
- Stores one row per username in `libsignal_bundles` using `INSERT ... ON CONFLICT(username) DO UPDATE`.
- On retrieval, decrypts the stored AES+XChaCha20+BLAKE3 blobs back to their original base64 fields.

Database rows store only PQ-encrypted blobs for Signal identity and pre-keys; the server reads and forwards those blobs without accessing the underlying key material.
### 5.4 Message and Offline Message Storage

`MessageDatabase` is intentionally agnostic to message content and only stores opaque encrypted payloads.

- For live messages, the server receives an object of the form:
  - `{ type: 'encrypted-message', from, to, encryptedPayload }`, where `encryptedPayload` is the client-side hybrid envelope.
- `saveMessageInDB` normalizes and stores:
  - `messageId` – from envelope or generated as `msg-${randomBytes(16).toString('hex')}`.
  - `fromUsername`, `toUsername` – validated ASCII usernames.
  - `timestamp` – validated and bounded.
  - `payload` – JSON string containing `{ messageId, fromUsername, toUsername, timestamp, encryptedContent: <stringified envelope>, messageType }`.
- The server never decrypts the inner encrypted content; it only routes and persists the opaque encrypted blob.
- Offline messages are stored in `offline_messages` as JSON strings and delivered after authentication, again without server-side decryption.

### 5.5 Blocking Database (`BlockingDatabase`)

`BlockingDatabase` manages user block lists and block tokens in a zero‑knowledge style:

- The encrypted block list (`encryptedBlockList`) is produced by the client; the server stores it as an opaque string alongside a hash and salt.
- Block tokens are short hex pseudonyms allowing the server to enforce block relationships without seeing real usernames:
  - Each token contains `tokenHash`, `blockerHash`, `blockedHash`, and `expiresAt`.
  - Hashes are 32/64/128 hex characters; they are treated as opaque and compared verbatim.
  - `isMessageBlocked` checks both “recipient blocks sender” and “sender blocks recipient” cases and uses time-based expiry.

No additional cryptography beyond secure hashing and equality checks is performed in this module; all encryption of block lists happens on the client.

---

## 6. Hybrid Application Envelopes (`HybridService` + `helpers.js`)

The server uses the same hybrid envelope format as the client. The helpers in `server/crypto/helpers.js` provide canonicalization, signing, and verification primitives; `HybridService` handles encryption and decryption.

### 6.1 Routing Header Helpers

- `buildRoutingHeader({ to, from, type, size, extras?, timestamp? })` – constructs a normalized header.
- `canonicalizeRoutingHeader(header)` – JSON-serializes a subset of fields (`to`, `from`, `type`, `timestamp`, `size`, and optional `extras`) with sorted keys.
- `computeRoutingDigest(header)` – computes BLAKE3 over the canonical header bytes.
- `signRoutingHeader(header, dilithiumSecretKey)` – ML‑DSA‑87 signature over the canonical header, base64 encoded.
- `verifyRoutingHeader(header, signatureBase64, dilithiumPublicKey)` – verifies that signature.

These functions are used by both client and server to sign and verify routing metadata for every application envelope.

### 6.2 Inner and Outer Layers

The inner and outer envelope behavior matches the description in §2.5 and the client-side document. On the server, these functions are used in two main places:

- `HybridService.encryptForClient` / `encryptForServer` – to send hybrid envelopes to clients or upstream services.
- `HybridService.decryptIncoming` – to decrypt incoming hybrid envelopes for authentication, server password, etc.

The decryption path enforces:

- Correct version (`'hybrid-envelope-v1'` and `'inner-envelope-v1'`).
- Valid Dilithium signature over the routing header, using the sender’s public key from metadata.
- Valid outer MAC (BLAKE3) and inner MAC before any plaintext is returned.

On success, the caller receives:

```text
{
  routing: <header>,
  payload: <Uint8Array>,
  payloadJson: <object|null>,
  metadata: <metadata object>,
  senderDilithiumPublicKey: <base64 string>
}
```

The same envelope formats are used on the client, so both sides can interoperate without separate specifications.

---

## 7. WebSocket PQ Transport and Session Storage

### 7.1 Server Signing Keys and PQ Handshake

`server/messaging/pq-envelope-handler.js` implements the WebSocket PQ handshake and envelope processing.

- `initializeEnvelopeHandler(serverHybridKeyPair)` caches the server’s Dilithium secret key for signing outgoing envelopes.
- `handlePQHandshake({ ws, sessionId, parsed, serverHybridKeyPair })`:
  - Validates handshake payload fields.
  - Clears any previous `_pqSessionId` on the WebSocket to ensure the handshake ack is plain.
  - Decapsulates the client’s ML‑KEM ciphertext:
    - `pqSharedSecret = CryptoUtils.Kyber.decapsulate(kemCiphertext, serverHybridKeyPair.kyber.secretKey, serverHybridKeyPair.kyber.publicKey)`.
  - Computes a classical X25519 shared secret with the client’s ephemeral public key via `HybridService.computeClassicalSharedSecret`.
  - XOR-combines the PQ and classical shared secrets to form a combined key.
  - Derives send/receive keys using `PostQuantumHash.deriveKey(combined, salt, info, 32)` with salts bound to `sessionId`, `fingerprint`, and `timestamp`.
  - Stores the session in Redis via `storePQSession`, including `recvKey` and `sendKey` and a counter.
  - Sends a plaintext `pq-handshake-ack`, followed by a redundant encrypted ack.
  - Sets `ws._pqSessionId = sessionId` to indicate a PQ session is active.

### 7.2 Envelope Decryption (`handlePQEnvelope`)

For each incoming PQ envelope:

- The server loads the session from Redis via `getPQSession(envelope.sessionId)`.
- Verifies that `envelope.sessionFingerprint` matches the stored fingerprint.
- Decodes `ciphertext`, `nonce`, `tag`, and `aad` from base64.
- Uses `new CryptoUtils.PostQuantumAEAD(session.recvKey)` to decrypt the ciphertext with the given nonce and AAD.
- Parses the decrypted JSON and normalizes it to either a stripped `{ type: 'encrypted-message', to, encryptedPayload }` or the full object.
- Forwards the inner payload to higher-level handlers.

Decryption errors result in a generic error message and do not allow partially decrypted data to propagate.

### 7.3 Envelope Encryption and Policy (`sendPQEncryptedResponse` and `sendSecureMessage`)

- `sendPQEncryptedResponse(ws, sessionOrId, payload)`:
  - Resolves an in-memory or Redis session.
  - Increments the session counter and persists it.
  - Builds AAD binding message type, message ID, timestamp, and counter.
  - Encrypts the JSON-encoded payload using `PostQuantumAEAD(session.sendKey)` and a fresh 36-byte nonce.
  - Constructs an envelope with ciphertext, nonce, tag, AAD, session identifiers, and a Dilithium signature over a string of the form `"<messageId>:<timestamp>:<counter>:<sessionId>"`.
- `sendSecureMessage(ws, payload)`:
  - If a PQ session exists (`ws._pqSessionId` is set), all messages are sent via `sendPQEncryptedResponse`.
  - If no session exists, only a fixed whitelist of message types can be sent in plaintext (handshake ack, basic error types, and server key advertisement).
  - Attempting to send any other plaintext message results in an error response and the connection being closed with code 1008.

After a PQ session is established, all traffic uses PQ AEAD and Dilithium signatures; plaintext messages outside the allowed pre-handshake types result in an error and connection close.
### 7.4 PQ Session Storage in Redis (`server/session/pq-session-storage.js`)

Session keys are stored encrypted-at-rest in Redis:

- A master key is derived from `SESSION_STORE_KEY` using `CryptoUtils.KDF.quantumHKDF` with salt `"pq-session-store-salt-v1"` and info `"pq-session-store-key-v1"`.
- Per-session, per-direction keys (`send`/`recv`) are wrapped as follows:
  - Per-key AES key derived by `quantumHKDF(masterKey, "pq-session-store:<sessionId>:<direction>", info, 32)`.
  - Encrypted with `CryptoUtils.PostQuantumAEAD` using a 36-byte random nonce and AAD `"pq-session:<sessionId>:<direction>"`.
  - Stored as base64(nonce || tag || ciphertext) embedded in the Redis value.
- Redis key prefix: `pq:session:<sessionId>`, TTL: 1 hour.

Helper functions (`storePQSession`, `getPQSession`) abstract away this storage format.

---

## 8. Authentication and Device Proof (`server/authentication/authentication.js`)

Authentication consists of an account layer (username/password/passphrase) and a server layer (server password, device proof, token issuance).

All sensitive payloads (password, passphrase, server password) are transported inside hybrid envelopes using `CryptoUtils.Hybrid.decryptIncoming`.

### 8.1 Account Authentication (`AccountAuthHandler`)

- **Sign-up (`handleSignUp`)**:
  - Decrypts `passwordData` and `userData` hybrid envelopes using the server hybrid key pair.
  - Expects `passwordPayload.content` to be a full Argon2id encoded hash string produced by the client.
  - Parses Argon2 parameters via `CryptoUtils.Password.parseArgon2Hash` and validates them with `AccountAuthHandler.validateArgon2Parameters` (minimum memory, time, salt length, algorithm `argon2id`).
  - Stores `users` row via `UserDatabase.saveUserRecord`, including both raw Argon2 hash and peppered wrapper plus parameter columns.
  - Sends `IN_ACCOUNT` success, then a `PASSPHRASE_HASH` challenge with Argon2 parameters for the passphrase.
- **Sign-in (`handleSignIn` / `handlePasswordHash`)**:
  - Loads user record via `UserDatabase.loadUser`.
  - If server has an Argon2 hash but client sent a non-Argon2 password, sends `PASSWORD_HASH_PARAMS` so the client can hash locally.
  - When the client sends a full encoded hash, the server compares it to the stored value using constant-time comparison (padded buffers and `timingSafeEqual`), without re-running Argon2.
  - If password verification succeeds, derives passphrase parameters either from stored columns or by parsing `passphraseHash`, and sends a `PASSPHRASE_HASH` challenge.

### 8.2 Passphrase Handling (`handlePassphrase`)

- For new users:
  - Expects an Argon2id encoded passphrase hash string.
  - Parses and validates parameters (algorithm, salt length, memory/time/parallelism ranges).
  - Stores the hash and parameters in the `users` row.
- For existing users:
  - Loads stored passphrase hash and the passphrase hash provided by the client.
  - Parses both using `CryptoUtils.Password.parseArgon2Hash`.
  - Compares algorithm, version, memoryCost, timeCost, parallelism.
  - Uses `crypto.timingSafeEqual` to compare salt bytes and hash bytes.

On success, `pendingPassphrase` is cleared and `pendingSignalBundle` is set, and the client is instructed to upload a Signal bundle.

### 8.3 Device Proof-of-Possession

Before issuing tokens, the server requires proof that the client controls a device-specific Ed25519 key:

- `finalizeAuth` verifies that the account login phase is complete and TLS is in use, then calls `startDeviceProof`.
- `startDeviceProof`:
  - Generates a 32-byte random nonce (base64).
  - Stores it in `ws.clientState.deviceProofNonce`, along with a timestamp.
  - Sends a `DEVICE_PROOF_CHALLENGE` message containing the nonce.
- The client responds with a `DEVICE_PROOF_RESPONSE` message containing:
  - The original nonce, device ID, Ed25519 public key (PEM), and a signature over `"device-proof:v1|<nonce>|<deviceId>"`.
- `processDeviceProofResponse`:
  - Validates type, state, nonce, and freshness.
  - Uses Node `crypto.verify` with the provided public key to verify the Ed25519 signature.
  - Records the device session in `TokenDatabase.createOrUpdateDeviceSession`, storing the public key in `securityFlags`.

On success, the server proceeds to issue PQ tokens bound to this device and TLS connection.

### 8.4 Token Issuance and TLS Binding

After successful device proof (`issueTokensAfterDeviceProof`):

- A device ID is generated or reused and stored on the WebSocket.
- An authentication context is built via `TokenMiddleware.createAuthContext`, capturing device fingerprint, IP, user-agent, etc.
- A TLS binding (fingerprint of the TLS session) is obtained via `TokenMiddleware.getTLSFingerprint`. If this is missing, token issuance fails.
- `TokenService.createTokenPair(username, deviceId, tlsBinding)` is called.
- The refresh token is stored in Postgres via `TokenDatabase.storeRefreshToken` with hashed token ID and encrypted user/device fields.
- The access token and metadata are recorded in `ws.clientState` and persisted in a Redis-backed connection state manager.

`ServerAuthHandler` later handles server password verification (also via hybrid envelopes and Argon2id) and may issue or reuse tokens for full server authentication.

---

## 9. LibSignal Bundle Handling (`server/messaging/libsignal-handler.js`)

LibSignal bundle handling is tightly coupled to `LibsignalBundleDB` and uses the PQ WebSocket transport.

- `handleBundlePublish`:
  - Requires an authenticated WebSocket with a known username.
  - Validates bundle structure and logs issues.
  - Flattens the nested bundle into the DB schema and calls `LibsignalBundleDB.publish`, which encrypts identity and pre-key material with `LibsignalFieldEncryption`.
  - If account authentication is waiting on a Signal bundle, clears `pendingSignalBundle` and calls `AccountAuthHandler.finalizeAuth` to continue the flow.
- `handleBundleRequest`:
  - Throttles bundle requests via Redis keys (`bundle:throttle:<requester>:<target>`).
  - Retrieves the bundle via `LibsignalBundleDB.take`; if present, decrypts internal fields and rebuilds the nested structure expected by the client.
  - Sends the bundle back inside a PQ envelope via a helper that uses `sendSecureMessage`.

The server never sees plaintext Signal session state; it only stores and forwards encrypted identity and pre-key material.

### 9.2 User Avatar Storage

The server acts as a blinded storage provider for user avatars, supporting the client-side privacy model:

- **Private Synchronization**: The server stores an opaque "Long-Term Envelope" (`lt-v1`) provided by the client. This payload contains the user's avatar encrypted with their own ML-KEM-1024 public key. The server cannot decrypt this file; it stores and returns it to the user's authenticated devices for synchronization.

- **Public Distribution**: If the user elects to share their avatar, the client provides a separate plaintext block (`publicData`). The server stores this alongside the encrypted envelope and serves it to other authenticated users who request that specific username's avatar.

- **Access Control**: Avatar fetch requests are authenticated using the PQ control channel. The server enforces rate limits (`SERVER_FETCH_DEBOUNCE` logic logic mirrors the client) to prevent harvesting.

---

## 10. TLS and Open Quantum Safe

TLS termination and the OQS provider configuration are handled outside the Node process but are part of the overall security posture.

### 10.1 HAProxy TLS Frontend (`server/config/haproxy-quantum.cfg`)

- Only TLS 1.3 is enabled:
  - `ssl-default-bind-options no-tlsv10 no-tlsv11 no-tlsv12 no-sslv3`.
  - `ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`.
- The HTTPS frontend listens on `*:8443` with:
  - Certificate from `server/config/certs/cert.pem`.
  - Hybrid curves: `X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024`.
- Backend traffic is forwarded to the Node.js server on `127.0.0.1:3000`.

The TLS frontend adds a hybrid PQ layer at the transport level, separate from the application-level cryptography.
### 10.2 OpenSSL OQS Provider (`server/config/openssl-oqs.cnf`)

The OpenSSL configuration enables the Open Quantum Safe provider:

- Activates the default provider and an `oqsprovider` section.
- Uses the environment variable `OQS_PROVIDER_MODULE` to locate the oqsprovider module (e.g., platform-specific shared library path).
- Leaves the exact path configurable per deployment; there is no hardcoded module location.

---

## 11. Security Properties and Assumptions

Summarizing the server-side design:

- All critical network paths (authentication, messaging, token issuance) use hybrid ML‑KEM‑1024 + X25519 key exchange with ML‑DSA‑87 signatures and BLAKE3 MACs.
- Sensitive fields in Postgres (user/device identifiers, Signal identity and pre-keys) are encrypted at rest using PostQuantumAEAD with keys derived from high-entropy, installation-specific secrets.
- Passwords and passphrases are always hashed on the client with Argon2id; the server enforces minimum parameters and never stores plaintext.
- Token verification requires both a ML‑DSA‑87 signature and a BLAKE3 MAC over a key commitment; tokens and refresh identifiers are hashed before storage.
- Redis PQ sessions store only AEAD-encrypted session keys under a master key derived via a PQ KDF.

The security of this system depends on:

- The correctness and security of the external cryptographic libraries (`mlkem`, `@noble/*`, `argon2`, OpenSSL/OQS, Node CSPRNG).
- Proper generation, protection, and backup of local secrets (`KEY_ENCRYPTION_SECRET`, `SESSION_STORE_KEY`, `PASSWORD_HASH_PEPPER`, `USER_ID_SALT`, `DB_FIELD_KEY`).
- Correct deployment of HAProxy and OpenSSL with TLS 1.3 and the OQS provider.

Under these assumptions, most application data is either end‑to‑end encrypted or encrypted at rest, and long-lived authentication artifacts are protected by post-quantum or hybrid cryptography consistent with the client-side design.
