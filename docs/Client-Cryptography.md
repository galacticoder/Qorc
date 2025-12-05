# Client-Side Cryptography Design

## Last updated November 17 2025. Updated regularly on changes.


### The client implements cryptography using the algorithms, key sizes, data formats, and flows described below, matching the current code.
---

## 1. High-level crypto stack

**Client (frontend / Electron renderer)**

- Implementation language: TypeScript / React
- Main cryptographic libraries:
  - `@noble/post-quantum@0.5.2`
    - ML‑KEM‑1024 (Kyber-class KEM, NIST PQC KEM category 5)
    - ML‑DSA‑87 (Dilithium-class signature, NIST PQC signature category 5)
  - `@noble/ciphers@2.0.0`
    - AES‑GCM
    - XChaCha20‑Poly1305 and related ARX ciphers
  - `@noble/hashes@2.0.1`
    - BLAKE3, HKDF, SHA‑3
  - `argon2-wasm@0.9.0`
    - Argon2 (used as Argon2id for password hashing / KDF)
  - WebCrypto (`crypto.subtle`, `crypto.getRandomValues`)
    - AES‑GCM, HKDF, CSPRNG
  - `@signalapp/libsignal-client@0.86.0`
    - Classical Signal double ratchet (ECDH + XEdDSA), used alongside the post‑quantum layer

At a high level, the client combines:

- Post‑quantum KEM and signatures (ML‑KEM‑1024, ML‑DSA‑87),
- Classical X25519 for hybrid key material,
- Symmetric crypto based on AES‑256‑GCM, XChaCha20‑Poly1305, and BLAKE3,
- Memory‑hard key derivation with Argon2id.

Hybrid constructions are used so that confidentiality typically requires breaking both the post‑quantum and classical assumptions.

### 1.1 Device Attestation

Client device-bound account creation limiting:

- **Keypair generation**: ML-DSA-87 keypair derived from machine entropy on first use.
- **Secure storage**: Device keys stored in Electron machine-bound secure storage (`electron-secure-storage.cjs`).
- **Challenge signing**: Client receives PostQuantumRandom nonce from server, signs with ML-DSA-87 private key.
- **Client module**: `src/lib/device-credential.ts` handles credential retrieval and challenge signing via IPC.

---

## 2. `src/lib/post-quantum-crypto.ts` — core PQ primitives

This module implements low‑level post‑quantum primitives and a layered AEAD construction used throughout the client.

### 2.1 Key encapsulation: `PostQuantumKEM`

- Algorithm: ML‑KEM‑1024 (`ml_kem1024` from `@noble/post-quantum/ml-kem.js`).
- Enforced sizes:
  - Public key: 1568 bytes
  - Secret key: 3168 bytes
  - Ciphertext: 1568 bytes
  - Shared secret: 32 bytes
- Operations:
  - `generateKeyPair()`
    - Calls `ml_kem1024.keygen()`.
    - Copies public and secret keys into new `Uint8Array`s and verifies lengths.
  - `encapsulate(publicKey)`
    - Validates that the public key is present and has the expected length.
    - Calls `kyber.encapsulate(publicKey)`.
    - Copies ciphertext and shared secret into fresh arrays.
    - Immediately zeroizes the original buffers using `PostQuantumUtils.clearMemory`.
  - `decapsulate(ciphertext, secretKey)`
    - Validates ciphertext and secret key lengths.
    - Calls `kyber.decapsulate(ciphertext, secretKey)`.
    - Copies the resulting 32‑byte shared secret into a new `Uint8Array`.
    - Zeroizes the original shared‑secret buffer.

All callers work with these validated sizes; any mismatch results in an exception.

### 2.2 Signatures: `PostQuantumSignature`

- Algorithm: ML‑DSA‑87 (`ml_dsa87` from `@noble/post-quantum/ml-dsa.js`).
- Sizes:
  - Public key: 2592 bytes
  - Secret key: 4896 bytes
  - Signature: 4627 bytes
- Operations:
  - `generateKeyPair()` (async)
    - Generates a 32‑byte random seed via `PostQuantumRandom.randomBytes`.
    - Calls `dilithium.keygen(seed)`.
    - Returns public and secret keys as `Uint8Array`s.
  - `sign(message, secretKey)`
    - Requires `message` to be a `Uint8Array`.
    - Validates that `secretKey` is a `Uint8Array` of length 4896.
    - Returns the signature as `Uint8Array`.
  - `verify(signature, message, publicKey)`
    - Validates sizes of signature and public key and the type of message.
    - Returns boolean success/failure.

These signatures are used for routing header authentication, WebSocket envelopes, P2P proofs, and call signaling.

### 2.3 Hashing and KDF: `PostQuantumHash`

- `blake3(data, options?)`
  - Thin wrapper around `blake3` from `@noble/hashes/blake3.js`.
- `deriveKey(inputKey, salt, info, length = 32)`
  - HKDF built on BLAKE3 via `hkdf(blake3, ...)`.
  - `info` is a UTF‑8 encoded string.

Derivations from ML‑KEM shared secrets (e.g., for WebSocket keys and client–server payloads) use this HKDF.

### 2.4 Layered AEAD: `PostQuantumAEAD`

`PostQuantumAEAD` is a symmetric encryption scheme combining AES‑256‑GCM, XChaCha20‑Poly1305, and BLAKE3 MAC.

- Parameters:
  - Input key length: 32 bytes (256‑bit key).
  - Nonce length: 36 bytes.
    - First 12 bytes: AES‑GCM IV.
    - Next 24 bytes: XChaCha20‑Poly1305 nonce.
  - MAC length: 32 bytes (BLAKE3 output).
- Key derivation (`deriveDoubleKey`):
  1. Input: 32‑byte key.
  2. Compute `expanded = sha3_512(inputKey)` (64 bytes).
  3. First 32 bytes → `k1` (AES‑256‑GCM key).
  4. Next 32 bytes → `k2` (XChaCha20‑Poly1305 key).
  5. MAC key: BLAKE3 over `"quantum-secure-mac-v1" || inputKey` with `dkLen = 32`.

- Encryption (`encrypt(plaintext, key, additionalData?, explicitNonce?)`):
  1. Use `explicitNonce` if provided, otherwise generate a 36‑byte random nonce.
  2. Validate key and nonce lengths.
  3. Derive `k1`, `k2`, `macKey` via `deriveDoubleKey`.
  4. AES‑GCM layer:
     - IV = first 12 nonce bytes.
     - AAD = `additionalData` (or empty).
     - `layer1 = gcm(k1, iv, aadBytes).encrypt(plaintext)`.
  5. XChaCha20‑Poly1305 layer:
     - Nonce = last 24 nonce bytes.
     - AAD = same `aadBytes`.
     - `layer2 = xchacha20poly1305(k2, xnonce, aadBytes).encrypt(layer1)`.
  6. MAC layer:
     - `macInput = layer2 || aadBytes || nonce`.
     - `tag = blake3(macInput, { key: macKey })`.
  7. Zeroize `k1`, `k2`, `macKey`.
  8. Output: `{ ciphertext: layer2, nonce, tag }`.

- Decryption (`decrypt(ciphertext, nonce, tag, key, additionalData?)`):
  1. Validate key, nonce, and tag sizes.
  2. Derive `k1`, `k2`, `macKey` via `deriveDoubleKey`.
  3. MAC verification:
     - `macInput = ciphertext || aadBytes || nonce`.
     - `expectedMac = blake3(macInput, { key: macKey })`.
     - Compare `tag` to `expectedMac` using `PostQuantumUtils.timingSafeEqual`. On mismatch, throw.
  4. XChaCha20‑Poly1305 decryption:
     - Nonce = last 24 bytes of `nonce`.
     - `layer1 = xchacha20poly1305(k2, xnonce, aadBytes).decrypt(ciphertext)`.
  5. AES‑GCM decryption:
     - IV = first 12 bytes of `nonce`.
     - `plaintext = gcm(k1, iv, aadBytes).decrypt(layer1)`.
  6. Zeroize `k1`, `k2`, `macKey`.

Every use of `PostQuantumAEAD` in the client enforces key and nonce lengths and treats MAC failure as a hard error.

### 2.5 Randomness: `PostQuantumRandom`

- Entropy source:
  - Strictly requires `globalThis.crypto.getRandomValues`.
  - If unavailable, throws an error; there is no fallback to `Math.random`.
- Limits:
  - `maxRandomBytes` is configurable (default 1 MiB) with an absolute cap of 100 MiB per call.
- `randomBytes(length)`:
  - Validates that `length` is a positive integer and ≤ `maxRandomBytes`.
  - Fills a `Uint8Array` using `getRandomValues`.
- `randomUUID()`:
  - Uses `crypto.randomUUID()` when available.
  - Else, generates 32 random bytes, hashes them with BLAKE3 (`dkLen=16`), sets RFC 4122 version/variant bits, and formats as a standard UUID string.

### 2.6 Utilities: `PostQuantumUtils`

Key functionality:

- `timingSafeEqual(a, b)` — constant‑time comparison over the maximum length of the two buffers.
- `asUint8Array` — converts various byte‑like values (ArrayBuffer views, Buffer, arrays) to `Uint8Array`.
- `clearMemory(data)` — fills a `Uint8Array` with zeros.
- `deepClearSensitiveData(root)` — recursively walks objects, arrays, maps, sets and zeroizes any underlying `Uint8Array`/`ArrayBuffer` it finds; invokes a `zeroize()` method on objects if present.
- String/byte conversions (UTF‑8), hex and base64 encode/decode with size checks (`MAX_DATA_SIZE = 10 MiB`).

All higher‑level modules rely on these helpers for conversions and best‑effort zeroization.

### 2.7 Sessions: `PostQuantumSession`

`PostQuantumSession` maintains process‑local session state with time‑bounded lifetimes.

- Internal state:
  - `Map<string, { keys: unknown; created: number; lastUsed: number }>`.
  - Default timeout: 30 minutes.
- `createSession(sessionId, keys, timeoutMs?)`:
  - Validates `sessionId`.
  - Stores the record and triggers cleanup of expired sessions.
- `getSession(sessionId, timeoutMs?)`:
  - Returns `keys` if the session is still within its timeout.
  - If expired, destroys the session first and returns `null`.
- `destroySession(sessionId)`:
  - Looks up the record and calls `securelyEraseKeys(record.keys)`.
  - `securelyEraseKeys` uses `PostQuantumUtils.deepClearSensitiveData` and ignores errors.
- `setSessionTimeout(timeoutMs)`/`getSessionTimeout()` allow configuration.

All secrets reachable from `keys` are subject to recursive best‑effort zeroization when sessions are destroyed or expire.

### 2.8 Worker offload: `PostQuantumWorker`

`PostQuantumWorker` optionally uses a Web Worker to generate ML‑KEM keypairs off the main thread.

- Worker script: `post-quantum-worker.ts` (module worker).
- Authentication:
  - The worker sends an initial `auth-token-init` with a hex token.
  - The main thread stores this as a 32‑byte array; every request to the worker includes this token.
  - The worker can rotate the token (`auth-token-rotated`).
- Operations:
  - `generateKemKeyPair()`:
    - If workers are unsupported or initialization fails, falls back to `PostQuantumKEM.generateKeyPair()`.
    - Otherwise, sends a `kem.generateKeyPair` request and resolves with `{ publicKey, secretKey }`.
  - `destroyKey(keyId)`:
    - Sends `kem.destroyKey` to the worker and removes tracking state locally, with a timeout.

If the worker is unavailable or fails, key generation falls back to running on the main thread.

### 2.9 Client–server KEM+AEAD protocol: `ClientServerProtocol`

`ClientServerProtocol` provides a simple KEM+AEAD wrapper for client ↔ server messages when they are not inside the more complex hybrid envelope.

- Payload type: `EncryptedMessagePayload`:
  - `version: 1`
  - `kemCiphertext: Uint8Array`
  - `aeadCiphertext: Uint8Array`
  - `aeadNonce: Uint8Array`
  - `aeadTag: Uint8Array`
  - `timestamp: number` (ms since epoch)
- Shared secret salt:
  - A fixed 32‑byte constant corresponding to the ASCII string `"Qor-Chat-PQ-Hybrid-KEM-Key-1"`.

Encryption (`encryptForServer`):

1. Require `message` to be `Uint8Array`.
2. Call `PostQuantumKEM.encapsulate(serverPublicKey)` to obtain `kemCiphertext` and `sharedSecret`.
3. Build a context string `"client-to-server-v1:length:<len>:ts:<now>"`.
4. Derive a 32‑byte encryption key via `PostQuantumHash.deriveKey(sharedSecret, salt, contextInfo, 32)`.
5. Call `PostQuantumAEAD.encrypt(message, encryptionKey, additionalData)`.
6. Return an `EncryptedMessagePayload` with current timestamp.
7. Zeroize the shared secret.

Decryption (`decryptFromServer`):

1. Validate that `encryptedMessage.version === 1`.
2. Compute age and reject if older than `MAX_MESSAGE_AGE_MS` (default 5 minutes).
3. Call `PostQuantumKEM.decapsulate(encryptedMessage.kemCiphertext, mySecretKey)`.
4. Record the `kemCiphertext` in a bounded map using a BLAKE3 hash to detect replays.
5. Build context string `"server-to-client-v1:length:<ciphertextLen>:ts:<timestamp>"` and derive the decryption key with the same salt.
6. Call `PostQuantumAEAD.decrypt(...)`.
7. Zeroize the shared secret.

Replay protection relies on timestamp and a map of seen ciphertext hashes.

---

## 3. `src/lib/unified-crypto.ts` — hybrid orchestration layer

This module composes PQ and classical primitives into higher‑level functions: hybrid envelopes, Argon2‑based hashing, AES utilities, and a single exported `CryptoUtils` namespace.

### 3.1 Argon2, hashing, and MACs

#### Hashing and Argon2: `HashingService`

- General Argon2 hashing (`hashData`):
  - Uses `argon2.hash` with:
    - Random 32‑byte salt from `crypto.getRandomValues`.
    - Type: Argon2id (`type: 2`).
    - Default parameters: time=5, mem=2^17, parallelism=4, version=0x13, hashLen=32.
  - Enforces maximum input size (1 MiB) and timeout bounds.
- Argon2 encoded hash parsing (`parseArgon2Hash`):
  - Validates algorithm (`argon2i`, `argon2d`, `argon2id`), version, parameters `m`, `t`, `p`, and hash length.
- `hashDataUsingInfo(data, args)`:
  - Takes a base64 salt and optional Argon2 parameters; returns encoded Argon2 hash string.
- `deriveKeyFromPassphrase`:
  - Derives a raw key from a passphrase and salt using Argon2id with configurable parameters, returning the raw hash bytes.

#### BLAKE3 MAC: `HashingService.generateBlake3Mac`

- Accepts `message: Uint8Array` and `key: Uint8Array`.
- If the key length is not 32 bytes, it is first compressed to 32 bytes via BLAKE3.
- Uses BLAKE3 keyed mode to compute a MAC; any temporary key buffers are zeroized via `SecureMemory.zeroBuffer`.
- `verifyBlake3Mac` recomputes the MAC and compares with `SecureMemory.constantTimeCompare`.

### 3.2 AES utilities and key services

#### WebCrypto AES: `KeyService` and `AES`

- `KeyService.generateAESKey()` generates a 256‑bit AES‑GCM key via WebCrypto.
- `importAESKey`/`exportAESKey` import/export raw AES keys.
- `deriveAESKeyFromPassphrase` uses Argon2id to derive a 32‑byte key and imports it as AES‑GCM, returning both the key and encoded Argon2 hash.

`AES` provides:

- `encryptBinaryWithAES(data, aesKey, aad?)`:
  - Uses AES‑GCM with 96‑bit random IV, optional AAD.
  - Returns `{ iv, authTag, encrypted }`, splitting out the last 16 bytes as the GCM authentication tag.
- `decryptBinaryWithAES` performs the inverse operation.
- `serializeEncryptedData` encodes version, IV, tag, and ciphertext into a compact binary format, then base64‑encodes it.

`EncryptService` and `DecryptService` are higher‑level wrappers for string payloads and for parsing/serializing AES‑GCM formats.

### 3.3 Hybrid envelopes: `Hybrid`

Hybrid envelopes, routing headers, and key derivation in `unified-crypto.ts` use the following construction:

- ML‑KEM‑1024 for outer layer shared secrets.
- X25519 for inner layer hybridization.
- BLAKE3‑based HKDF and MACs.
- Dilithium signatures for routing headers.
- `PostQuantumAEAD` for inner payload encryption.
- AES‑256‑GCM + BLAKE3 MAC for outer envelope.

`Hybrid.encryptForClient`, `Hybrid.encryptForServer`, and `Hybrid.decryptIncoming` are the main entry points used by higher‑level components.

### 3.4 Post‑quantum helper: `PostQuantumHybridService`

`PostQuantumHybridService` is a thin wrapper:

- `generateHybridKeyPair()` delegates to `Hybrid.generateHybridKeyPair()`.
- `exportPublicKeys(hybridKeyPair)` returns `kyberPublicBase64` and `dilithiumPublicBase64` for server‑side lookups.
- `signMessage`/`verifySignature` expose Dilithium for generic use.

### 3.5 Exported namespace: `CryptoUtils`

`CryptoUtils` is the main public API for other modules:

- `Config`, `Base64`, `Hash`, `Keys`, `Encrypt`, `Decrypt`, `Hybrid`, `Kyber`, `Dilithium`, `PostQuantum`, `PostQuantumAEAD`, `AES`, `KDF`, `SecureMemory`.

All client code that needs cryptography goes through these utilities rather than accessing low‑level primitives directly.

---

## 4. Device‑local key management and encrypted storage

### 4.1 `src/lib/secure-key-manager.ts` — master key and hybrid key bundle

This module manages a per‑user master key and the encrypted storage of the user’s hybrid key bundle (Kyber, Dilithium, X25519).

#### 4.1.1 Master key derivation from passphrase

- Entropy:
  - User passphrase (UTF‑8 string).
  - Salt:
    - If metadata exists: 32‑byte base64 salt from previous runs.
    - Else: 32 random bytes from WebCrypto `getRandomValues`.
- KDF: `argon2-wasm` Argon2id with parameters (defaults if no metadata is present):
  - `version = 0x13` (Argon2 v1.3).
  - `algorithm = "argon2id"`.
  - `memoryCost = 524288` (512 MiB).
  - `timeCost = 6` iterations.
  - `parallelism = 4`.
  - `hashLen = 32`.
- Runtime hardening:
  - The code measures Argon2 runtime and enforces a minimum of 200 ms by sleeping if necessary.
- Master key representation:
  - The 32‑byte Argon2 output is imported as a WebCrypto AES‑GCM `CryptoKey`:
    - Algorithm `{ name: 'AES-GCM', length: 256 }`.
    - `extractable = true` so it can be exported as 32 raw bytes for use with `PostQuantumAEAD`.
  - Metadata stored in per‑user `SQLiteKV` under `metadata`:
    - `salt` (base64),
    - `iv` (base64, reserved for legacy schemes),
    - `argon2Params` (version, algorithm, memoryCost, timeCost, parallelism).

`getEncodedPassphraseHash(passphrase)` reuses the stored salt and Argon2 parameters to recompute and return the encoded Argon2 hash string for use in authentication flows, without storing the raw passphrase.

#### 4.1.2 Hybrid key bundle encryption (PQ AEAD)

- Cleartext structure (`DecryptedKeys`):
  - `kyber`: `{ publicKeyBase64, secretKey: Uint8Array }`.
  - `dilithium`: `{ publicKeyBase64, secretKey: Uint8Array }`.
  - `x25519`: `{ publicKeyBase64, private: Uint8Array }`.
- When `storeKeys` is called:
  1. The master `CryptoKey` is exported to a 32‑byte raw key via WebCrypto.
  2. The three secret keys are serialized as JSON arrays and encoded as base64 strings inside a JSON payload.
  3. The payload JSON is UTF‑8 encoded to `payloadBytes`.
  4. A 36‑byte nonce `pqNonce` is generated via WebCrypto.
  5. AAD is `"secure-key-manager-pq:<username>"` in UTF‑8.
  6. `PostQuantumAEAD.encrypt(payloadBytes, key, pqAad, pqNonce)` is called,
     returning `{ ciphertext, tag }`:
     - This uses the double‑AEAD + BLAKE3 construction described in §2.
  7. A BLAKE3 MAC over `ciphertext || tag || aad` is computed with `key` as the MAC key.
  8. An `EncryptedKeyData` record is written to `SQLiteKV` under `keys`:
     - `bundleCiphertext`, `bundleNonce`, `bundleTag`, `bundleAad`, `bundleMac` (base64),
     - `kyberPublicBase64`, `dilithiumPublicBase64`, `x25519PublicBase64`,
     - `salt` and `argon2Params` (for future derivations),
     - timestamps, expiry, sequence, payload size,
     - `version: 4` (current schema version).
  9. The exported key buffer is zeroized.

- When `getKeys` is called:
  1. The master `CryptoKey` is exported again as 32 bytes.
  2. The ciphertext, nonce, tag, AAD, and stored MAC are base64‑decoded.
  3. A separate BLAKE3 MAC over `ciphertext || tag || aad` is recomputed with the key.
  4. MAC equality is checked using the constant‑time helper in `PostQuantumUtils`.
  5. If MACs match, `PostQuantumAEAD.decrypt(ciphertext, nonce, tag, key, aad)` is called.
  6. The decrypted JSON payload is parsed and converted back into `Uint8Array` secret keys, with strict length checks:
     - Kyber secret key: 3168 bytes.
     - Dilithium secret key: 4896 bytes.
     - X25519 private key: 32 bytes.
  7. The exported key buffer is zeroized; a `DecryptedKeys` object is returned.

At rest, all hybrid key material is stored only under `PostQuantumAEAD` encryption, with an additional BLAKE3 MAC keyed by the master key.

### 4.2 `src/lib/secureDB.ts` — encrypted per‑user database

`SecureDB` implements a per‑user encrypted store (backed by `SQLiteKV`) that is used for messages, user metadata, and ephemeral values.

- Key material:
  - `initializeWithKey` receives the same master AES‑GCM `CryptoKey` produced by `SecureKeyManager`.
  - Only 256‑bit AES keys are accepted (AES‑GCM or AES‑CBC).
- Encryption (`encryptData`):
  1. The AES key is exported to raw 32‑byte `Uint8Array`.
  2. The value is serialized as JSON and UTF‑8 to bytes, enforcing a 10 MiB maximum.
  3. AAD is `"securedb-aead-v2:<username>"` in UTF‑8.
  4. `PostQuantumAEAD.encrypt(plaintext, keyBytes, aad)` is called, letting the AEAD generate a 36‑byte nonce.
  5. The stored format is:
     - 2‑byte big‑endian AAD length.
     - Raw AAD bytes.
     - 36‑byte nonce.
     - Ciphertext.
     - 32‑byte BLAKE3 tag.
- Decryption (`decryptData`):
  1. The AES key is exported again to 32‑byte raw key.
  2. AAD length, AAD, nonce, ciphertext, and tag are parsed from the stored blob.
  3. `PostQuantumAEAD.decrypt(ciphertext, nonce, tag, keyBytes, aad)` is called.
  4. The plaintext is decoded as UTF‑8 and parsed as JSON.

All structured data stored by `SecureDB` (messages, users, ephemerals, arbitrary KV) goes through this PQ AEAD scheme. If decryption fails (MAC/BLAKE3 error or key mismatch), the code returns empty data and may trigger a store reset; plaintext storage or retrieval is not used in this path.

### 4.3 `src/lib/encrypted-storage.ts` — application‑wide key–value store

`EncryptedStorageManager` and `SyncEncryptedStorageAdapter` provide a higher‑level API on top of `SecureDB`.

- Every `setItem` call stores values through `SecureDB.store('encrypted_storage', key, value)`, so disk storage is always protected by `PostQuantumAEAD`.
- `getItem` retrieves and decrypts via `SecureDB.retrieve(...)`.
- Keys are validated to avoid control characters and prototype pollution.
- Operations are lightly rate‑limited (window 1 second, maximum 100 operations) to reduce abuse.
- `SyncEncryptedStorageAdapter` caches a small in‑memory subset of keys for fast access (for example, the last authenticated username and pinned server keys); all disk copies remain PQ‑encrypted.

### 4.4 `src/lib/vault-key.ts` — Electron vault wrapping

On Electron, the master key can be wrapped under a device‑bound vault key stored in `safeStorage`.

- Vault key lifecycle:
  - `ensureVaultKeyCryptoKey(username)` loads a raw 32‑byte vault key from OS secure storage, or generates one via WebCrypto if missing.
  - The vault key is imported as an AES `CryptoKey` and later exported as 32 raw bytes when needed.
- Wrapping the master key:
  - `saveWrappedMasterKey(username, masterKeyBytes, vaultKey)`:
    1. Exports the vault `CryptoKey` to a 32‑byte key.
    2. AAD = `"vault-wrapped-master-v2:<username>"` in UTF‑8.
    3. Calls `PostQuantumAEAD.encrypt(masterKeyBytes, rawVaultKey, aad)`.
    4. Stores `{ v:2, nonce, tag, ct }` as base64 JSON in the Electron secure store.
  - `loadWrappedMasterKey(username, vaultKey)` reverses this, using `PostQuantumAEAD.decrypt`.

The vault layer uses the same PQ AEAD construction for wrapping the master key; any AES‑GCM at this layer is internal to the OS secure store and the AEAD construction.

### 4.5 `src/lib/username-hash.ts` — deterministic pseudonymization

Usernames are pseudonymized into 32‑character lowercase hex identifiers.

- Primary method:
  - Argon2id via `CryptoUtils.Hash.hashDataUsingInfo` with a global, non‑secret base64 salt `"pseudonym-v1-global-salt"`.
  - Time cost 3, memoryCost between 2^12 and 2^20 (from config), parallelism 1, version 0x13.
  - The raw Argon2 hash bytes are converted to hex and truncated to the first 32 characters.
- Fallbacks:
  - BLAKE3 MAC with the same global salt as the key; hex‑encoded and truncated.
  - SHA‑512 via WebCrypto, also hex‑encoded and truncated.
- Input validation:
  - Usernames must match `VALID_USERNAME_PATTERN` and be ≤ 200 characters.

The scheme provides deterministic pseudonymization across devices. Because the salt is intentionally public, it does not prevent a global offline enumeration attack against the username space.

### 4.6 `src/lib/secure-memory.ts` — random bytes and zeroization

`SecureMemory` centralizes buffer handling where explicit zeroization matters.

- Randomness:
  - Prefers `globalThis.crypto.getRandomValues`.
  - Falls back to `require('crypto').webcrypto` under Node/Electron.
  - Refuses to operate without a CSPRNG.
- `zeroBuffer(buffer)`:
  - Overwrites the buffer with random bytes, touches a random index, XORs some extra entropy into the first 64 bytes, then fills with zeros.
- `constantTimeCompare(a, b)`:
  - XOR‑based comparison that always scans up to the maximum input length.

This is used throughout the codebase (e.g. for MAC comparison and key cleanup) to reduce side‑channel leakage.

### 4.7 `src/lib/secure-message-queue.ts` and `src/lib/offline-message-queue.ts`

These modules define how encrypted messages are queued and retried; they do not define new cryptographic constructions.

- `secure-message-queue.ts`:
  - Stores queued messages in `SecureDB`, so payloads are PQ‑encrypted at rest via `PostQuantumAEAD`.
  - Validates usernames and content, enforces length bounds, and guards against prototype pollution.
  - Uses no `Math.random`; IDs come from `crypto.randomUUID` or higher‑level PQ random utilities.

- `offline-message-queue.ts`:
  - Treats `EncryptedPayload` objects as opaque (`{ content, nonce, tag, mac, aad, kemCiphertext, ... }`).
  - Sanitizes these fields for logging/UI (e.g. removing `javascript:` or `<script>` substrings) without decrypting.
  - Device IDs used for queueing are generated via `PostQuantumRandom.randomUUID()` and stored via encrypted storage.
  - Retry backoff jitter is derived from `PostQuantumRandom.randomBytes`, not `Math.random`.

---

## 5. WebSocket transport and PQ session

### 5.1 `src/lib/websocket.ts` — hybrid PQ WebSocket session

The WebSocket client establishes a hybrid ML‑KEM‑1024 ⊕ X25519 transport with PQ AEAD and Dilithium signatures.

#### 5.1.1 Server key material and pinning

- `setServerKeyMaterial(hybridKeys, serverId)` accepts:
  - `kyberPublicBase64` (required ML‑KEM key).
  - `x25519PublicBase64` (required X25519 key).
  - `dilithiumPublicBase64` (optional but used when present for signatures).
- The function decodes these keys and computes a BLAKE3 fingerprint over the JSON triple `{ kyber, dilithium, x25519 }`, stored as hex.
- This fingerprint is later used to bind the session to a specific server identity (full hybrid triple), and is also stored in `serverKeyMaterial` for pinning via the auth layer.

#### 5.1.2 Handshake and key derivation

- On connection (`establishConnection`), `performHandshake` runs:
  - If server public keys are unknown, the client sends a single plaintext JSON message `{ "type": "request-server-public-key" }` to fetch them. This message contains no secrets.
  - Once keys are known, the client:
    1. Generates `sessionId = hex(PostQuantumRandom.randomBytes(16))`.
    2. Generates a random `clientNonce` and `timestamp = Date.now()`.
    3. Performs ML‑KEM encapsulation with the server’s Kyber public key:
       - `{ ciphertext: kemCiphertext, pqSharedSecret } = PostQuantumKEM.encapsulate(serverKyberPublicKey)`.
    4. Generates an ephemeral X25519 keypair and computes a classical shared secret with the server’s X25519 public key.
    5. Combines PQ and classical secrets bytewise via XOR into `combined`.
    6. Derives two independent 32‑byte session keys with HKDF(BLAKE3):
       - `sendKey` with salt = `"<fingerprint>:<sessionId>:send-<timestamp>"` (UTF‑8), info = `"ws-pq-hybrid-send"`.
       - `recvKey` with salt = `"<fingerprint>:<sessionId>:recv-<timestamp>"` (UTF‑8), info = `"ws-pq-hybrid-recv"`.
    7. Zeroizes `pqSharedSecret` and `combined`.
- A `pq-handshake-init` message is sent containing the sessionId, timestamp, ML‑KEM ciphertext, fingerprint, and capabilities. On `pq-handshake-ack` from the server with the same sessionId, the keys are promoted to active.

Transport keys are hybrid (ML‑KEM ⊕ X25519) and unique per session; there is no classical‑only fallback.

#### 5.1.3 Message encryption and integrity

All non‑handshake, non‑error messages are wrapped in a `pq-envelope` once a session is established.

- For each outgoing message:
  1. A logical payload is built and normalized (e.g. for `type === 'encrypted-message'`, only `{ to, encryptedPayload }` is included inside the envelope so inner hybrid payloads stay opaque).
  2. `messageId = hex(PostQuantumRandom.randomBytes(16))`.
  3. `timestamp = Date.now()`, `counter = ++sessionNonceCounter`.
  4. `aadBytes = buildEnvelopeAAD(type, messageId, timestamp, counter)` (bounded length).
  5. `nonce = PostQuantumRandom.randomBytes(36)`.
  6. `PostQuantumAEAD.encrypt(payloadBytes, sendKey, aadBytes, nonce)` produces `{ ciphertext, tag }`.
  7. The outer envelope includes `sessionId`, `sessionFingerprint`, message metadata, and base64‑encoded `nonce`, `ciphertext`, `tag`, `aad`.
  8. A Dilithium signature is created over `"messageId:timestamp:counter:sessionId"` using a persistent client keypair and attached to the envelope.

`sendSecureControlMessage` ensures that even control frames (session resets, offline message requests) are sent inside this PQ envelope.

#### 5.1.4 Decryption and replay protection

Incoming `pq-envelope` messages are processed as follows:

1. The current session fingerprint is checked against `envelope.sessionFingerprint`. A short grace period can allow for server failover, but mismatched sessions are not accepted for decryption.
2. Timestamp and counter are validated against windows (`MAX_REPLAY_WINDOW_MS`) and tracked counters.
3. The server’s Dilithium public key is used to verify the signature over `messageId:timestamp:counter:sessionId`.
4. `messageId` is checked against a cache (`seenMessageFingerprints`) to prevent replays.
5. Base64 `nonce`, `ciphertext`, `tag`, and `aad` are decoded.
6. `PostQuantumAEAD.decrypt(ciphertext, nonce, tag, recvKey, aad)` is called.
7. The inner JSON is parsed and forwarded to the rest of the application.

Randomized reconnection backoff uses `PostQuantumRandom.randomBytes` and does not reuse any cryptographic keys or nonces.

### 5.2 `src/hooks/useWebsocket.ts` — plaintext enforcement

The `useWebSocket` hook enforces that, once a PQ session is established:

- Only `pq-envelope`, `pq-heartbeat-pong`, handshake/control, and a small set of explicitly allowed system messages are processed.
- Any unexpected plaintext application message is treated as a security violation and dropped.
- For `pq-envelope` messages, the hook calls `websocketClient.decryptIncomingEnvelope`, then re‑sanitizes and dispatches the decrypted payload.

After the initial key exchange, application traffic is transported inside post‑quantum envelopes under this policy.

---

## 6. WebRTC P2P and calling

### 6.1 `src/lib/webrtc-p2p.ts` — P2P transport with PQ authentication

The WebRTC P2P layer builds PQ authentication and channel binding on top of WebRTC’s DTLS/SRTP.

- Each peer has:
  - Local Dilithium signing keys and cached peer Dilithium public keys.
  - A PQ session record per peer (Kyber keypair, shared secret, send/receive keys, role, replay windows).
- Route proofs and message identifiers use:
  - WebCrypto RNG (`getRandomValues`) for nonces and MAC keys.
  - BLAKE3 MAC via `CryptoUtils.Hash.generateBlake3Mac` over canonicalized proof payloads.
  - Dilithium signatures (`CryptoUtils.Dilithium`) for signing and verifying proofs.

P2P messages are authenticated by PQ signatures and MACs; WebRTC’s classical crypto remains as the underlying transport and is not the only security layer.

### 6.2 `src/lib/webrtc-calling.ts` — media sessions, device IDs, and call signals

This module implements end‑to‑end protections for call setup, media streams (audio, camera, screen), and device identifiers on top of WebRTC. It uses:

- ML‑KEM‑1024 for device keys and PQ audit envelopes.
- Dilithium signatures for call signaling.
- `PostQuantumAEAD` for encrypting IDs and audit payloads.
- A P2P PQ session (from `webrtc-p2p.ts`) plus WebRTC insertable streams to encrypt media frames.

#### 6.2.1 Device-level PQ keys and preferences

- **Device keypair (`pqDeviceKeyPair`)**
  - Type: ML‑KEM‑1024 keypair `{ publicKey: Uint8Array; privateKey: Uint8Array }`.
  - Storage:
    - On startup, attempts to load from encrypted storage key `pq_calling_device_keys`.
    - The value is JSON `{ publicKey: <hex>, privateKey: <hex> }`.
    - If lengths do not match `PostQuantumKEM.SIZES.publicKey` (1568) and `PostQuantumKEM.SIZES.secretKey` (3168), the keys are discarded.
  - If no valid keys are found, `generatePQDeviceKey()` calls `PostQuantumKEM.generateKeyPair()` and persists the result under `pq_calling_device_keys` as hex strings.

- **Preferred camera device ID (`preferredCameraDeviceId`)**
  - When set via `setPreferredCameraDeviceId(deviceId)`:
    1. The value is encrypted with `encryptDeviceIdPQ(deviceId, pqDeviceKeyPair.publicKey)` (see below).
    2. The encrypted string is stored under `preferred_camera_deviceId_v1_pq` in encrypted storage.
  - On startup, if `preferred_camera_deviceId_v1_pq` exists and `pqDeviceKeyPair.privateKey` is available, `decryptDeviceIdPQ` is used to recover the plain camera `deviceId`.

#### 6.2.2 Device ID encryption (`encryptDeviceIdPQ` / `decryptDeviceIdPQ`)

**Encryption (v2 format):**

- Function: `encryptDeviceIdPQ(deviceId, publicKey)`
- Preconditions:
  - `deviceId` is a string; empty string returns `""` directly (no payload).
  - `publicKey` must be an ML‑KEM‑1024 public key of exact length `PostQuantumKEM.SIZES.publicKey`.
- Steps:
  1. `plaintext = UTF8(deviceId)`.
  2. `aad = UTF8("device-id-pq-v2")`.
  3. `salt = UTF8("device-id-pq-kem-v1")`.
  4. `PostQuantumKEM.encapsulate(publicKey)` → `{ kemCiphertext, sharedSecret }`.
  5. `aeadKey = PostQuantumHash.deriveKey(sharedSecret, salt, "device-id-pq-v2", 32)`.
  6. `nonce = PostQuantumRandom.randomBytes(36)`.
  7. `PostQuantumAEAD.encrypt(plaintext, aeadKey, aad, nonce)` → `{ ciphertext, tag }`.
  8. Zeroize `aeadKey` and `sharedSecret`.
  9. Serialize as:
     - `"v2." + base64(kemCiphertext) + "." + base64(nonce) + "." + base64(ciphertext) + "." + base64(tag)`.

**Decryption:**

- Function: `decryptDeviceIdPQ(encryptedData, privateKey)`
- Inputs:
  - `encryptedData` is a string; empty string returns `""`.
  - For v2, `privateKey` must be an ML‑KEM‑1024 secret key of length `PostQuantumKEM.SIZES.secretKey`.
- Steps (v2 path):
  1. Split on `"."` into `[version, kemB64, nonceB64, ctB64, tagB64]`.
  2. If `version === "v2"` and exactly five parts, decode:
     - `kemCiphertext`, `nonce`, `ciphertext`, `tag` using `PostQuantumUtils.base64ToUint8Array`.
  3. `salt = UTF8("device-id-pq-kem-v1")` and `aad = UTF8("device-id-pq-v2")`.
  4. `sharedSecret = PostQuantumKEM.decapsulate(kemCiphertext, privateKey)`.
  5. `aeadKey = PostQuantumHash.deriveKey(sharedSecret, salt, "device-id-pq-v2", 32)`.
  6. `plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, aeadKey, aad)`.
  7. Zeroize `aeadKey` and `sharedSecret` and return `UTF8(plaintext)`.
- Any malformed input or unexpected format results in an empty string; legacy ad‑hoc formats are treated as “no preference set”.

#### 6.2.3 Call-level PQ keys

- **Media session keypair (`pqMediaSessionKeyPair`)**
  - A short‑lived ML‑KEM‑1024 keypair used for deriving media session keys per call.
  - `getOrGenerateSessionKeyPair()`:
    - If a cached keypair is newer than `MEDIA_SESSION_KEY_TTL_MS` (5 minutes), returns it.
    - Otherwise, calls `PostQuantumKEM.generateKeyPair()` and caches `{ keyPair, generatedAt }`.
  - This pair is attached to local and remote media streams via a `_pqSessionKey` property (used for key derivation and later zeroization).

- **Per-call session keys (`pqSessionKeys`)**
  - Structure: `{ send: Uint8Array; receive: Uint8Array } | null`.
  - `updateSessionKeys({ send?, receive? })`:
    - If `pqSessionKeys` is null, initializes `send` and `receive` from arguments or fresh `PostQuantumRandom.randomBytes(32)`.
    - Otherwise, selectively updates `send` and/or `receive`.

- **Media key derivation from P2P PQ session**
  - `deriveMediaKeyFromSession(baseKey, peer, context)`:
    - `salt = UTF8("pq-media-salt-v1:" + peer)`.
    - `info = "pq-media-" + context + ":" + (currentCall.id or "unknown")`.
    - Returns `PostQuantumHash.deriveKey(baseKey, salt, info, 32)`.
  - `ensurePqSecureMediaReady(peer)` ensures that:
    - Insertable streams API is available on `RTCRtpSender`/`RTCRtpReceiver`.
    - A P2P PQ session exists for `peer` (via `window.p2pService.getSessionStatus`); if needed, it triggers `connectToPeer` and waits for a `p2p-pq-established` event.

#### 6.2.4 Media frame encryption using insertable streams

The module uses WebRTC insertable streams (`createEncodedStreams`) to wrap outgoing and incoming RTP frames in `PostQuantumAEAD` using keys derived from the P2P PQ session.

- Preconditions: `hasInsertableStreamsSupport()` must detect `RTCRtpSender.prototype.createEncodedStreams` and `RTCRtpReceiver.prototype.createEncodedStreams`.

**Key rotation and padding helpers:**

- `KEY_ROTATION_INTERVAL_MS = 10_000` (10 seconds): key epoch length.
- `epochKey(baseKey, epoch)`:
  - `epochBytes = UTF8("epoch:" + epoch)`.
  - Concatenate `baseKey || epochBytes` and hash with BLAKE3 (`dkLen = 32`).
- For audio, frames are padded:
  - `AUDIO_PADDING_STEP = 128`, `AUDIO_PADDING_MAX = 4096`.
  - `nextAudioPaddedSize(len)` computes the smallest multiple of 128 ≥ `len + 2`, capped at 4096.

**Outgoing encryption (`enablePqE2eeForSender`)**

- Inputs: `sender: RTCRtpSender`, `context: 'audio' | 'camera' | 'screen'`, `peer: string`.
- Steps:
  1. Get PQ session status from `window.p2pService.getSessionStatus(peer)`.
  2. If the session is established and has `sendKey`, derive `baseMediaKey = deriveMediaKeyFromSession(sendKey, peer, context)`.
  3. Call `sender.createEncodedStreams()` to obtain `{ readable, writable }`.
  4. Define `aad = UTF8("pq-media-" + context + "-v1")`.
  5. Create a `TransformStream` that, for each `chunk`:
     - Compute `epoch = floor(Date.now() / KEY_ROTATION_INTERVAL_MS)`.
     - `mediaKey = epochKey(baseMediaKey, epoch)`.
     - `data = new Uint8Array(chunk.data)`.
     - `nonce = PostQuantumRandom.randomBytes(36)`.
     - `PostQuantumAEAD.encrypt(data, mediaKey, aad, nonce)` → `{ ciphertext, tag }`.
     - For `audio`:
       - `sealedLen = 36 + ciphertext.length + 32`.
       - `paddedLen = nextAudioPaddedSize(sealedLen)`.
       - Allocate `outBuf[paddedLen]`, write `sealedLen` as 2‑byte big‑endian at offset 0.
       - Write `nonce`, `ciphertext`, `tag` sequentially after the header.
     - For `camera`/`screen`:
       - Concatenate `nonce || ciphertext || tag` to `outBuf`.
     - Replace `chunk.data` with `outBuf.buffer` and enqueue.
  6. Pipe `readable.pipeThrough(transformer).pipeTo(writable)`.
  7. For `audio` senders, also clamp bitrate by calling `sender.getParameters()` / `sender.setParameters()` and setting `encodings[0].maxBitrate = 40_000`.

**Incoming decryption (`enablePqE2eeForReceiver`)**

- Inputs: `receiver: RTCRtpReceiver`, `context`, `peer`.
- Steps:
  1. Obtain PQ session status and require `receiveKey` to be present.
  2. `baseMediaKey = deriveMediaKeyFromSession(receiveKey, peer, context)`.
  3. `streams = receiver.createEncodedStreams()` → `{ readable, writable }`.
  4. `aad = UTF8("pq-media-" + context + "-v1")`.
  5. `intervalMs = KEY_ROTATION_INTERVAL_MS`.
  6. Create a `TransformStream` that, for each `chunk`:
     - Compute `epochNow = floor(Date.now() / intervalMs)`.
     - `currKey = epochKey(baseMediaKey, epochNow)`.
     - `prevKey = epochKey(baseMediaKey, epochNow - 1)`.
     - Parse `buf = new Uint8Array(chunk.data)`.
     - For `audio`:
       - Read `sealedLen` from the first 2 bytes.
       - Ensure `sealedLen >= 36 + 32` and within bounds, then `sealed = buf[2 .. 2+sealedLen)`.
       - `nonce = sealed[0..36)`, `tag = sealed[last 32 bytes]`, `ciphertext = sealed[36 .. len-32)`.
     - For `camera`/`screen`:
       - `nonce = buf[0..36)`, `tag = buf[last 32 bytes]`, `ciphertext = buf[36 .. len-32)`.
     - Try to decrypt with `currKey`; if it fails, try `prevKey`.
     - On success, set `chunk.data = plaintext.buffer` and enqueue; otherwise drop the frame.
  7. Pipe `readable.pipeThrough(transformer).pipeTo(writable)`.

The media encryption mechanism has the following properties:

- End‑to‑end media encryption between peers using keys derived from a PQ P2P session.
- Frequent key rotation (every 10s), with a one‑epoch overlap for robustness.
- Audio padding to reduce correlation between ciphertext length and content.

#### 6.2.5 PQ audit envelopes for call events

- `pqAuditPublicKey` (optional):
  - If present and of correct ML‑KEM public key length, audit events can be wrapped in a PQ envelope.
  - Loaded from encrypted storage key `pq_calling_audit_pubkey` as hex.

- `buildPqAuditEnvelope(data)`:
  1. Require `pqAuditPublicKey` with ML‑KEM key length; otherwise return `null`.
  2. `payloadBytes = UTF8(JSON.stringify(data))`.
  3. `aad = UTF8("call-audit-pq-v1")`.
  4. `salt = UTF8("call-audit-pq-kem-v1")`.
  5. `PostQuantumKEM.encapsulate(pqAuditPublicKey)` → `{ kemCiphertext, sharedSecret }`.
  6. `aeadKey = PostQuantumHash.deriveKey(sharedSecret, salt, "call-audit-pq-v1", 32)`.
  7. `nonce = PostQuantumRandom.randomBytes(36)`.
  8. `PostQuantumAEAD.encrypt(payloadBytes, aeadKey, aad, nonce)` → `{ ciphertext, tag }`.
  9. Zeroize `aeadKey` and `sharedSecret`.
  10. Serialize as `"v1." + base64(kemCiphertext) + "." + base64(nonce) + "." + base64(ciphertext) + "." + base64(tag)`.

- `logAuditEvent(event, callId, peer, details)`:
  - Builds a base object `{ callId, peer, ...details }`.
  - Calls `buildPqAuditEnvelope` and, if successful, includes `{ auditPayload }` in the log entry sent to `SecurityAuditLogger.log('info', event, ...)`.

Audit data has an optional PQ‑encrypted layer in addition to being logged locally.

#### 6.2.6 Call signaling with Dilithium and hybrid transport

Call control messages (offer/answer/ICE/end/decline/connected) are represented as `CallSignal` objects:

- Fields:
  - `type: 'offer' | 'answer' | 'ice-candidate' | 'end-call' | 'decline-call' | 'connected'`.
  - `callId`, `from`, `to`, `timestamp`, optional `data` and `isRenegotiation`.
  - `pqSignature?: { signature: string; publicKey: string }`.

**Signing (`attachSignalSignature`)**

- If `pqCallSigningKey` is not initialized, `PostQuantumSignature.generateKeyPair()` is called and the resulting Dilithium keypair is stored and persisted in encrypted storage key `pq_call_signing_key_v1` (public and private keys base64‑encoded).
- For a given `signal`:
  1. Build `payload = callId:type:timestamp:from:to`.
  2. `message = UTF8(payload)`.
  3. `signature = PostQuantumSignature.sign(message, privateKey)`.
  4. Set `signal.pqSignature = { signature: base64(signature), publicKey: base64(publicKey) }`.

**Verification (`verifySignalSignature`)**

- On receiving a `CallSignal`:
  1. If `signal.pqSignature` is missing, return `false`.
  2. Rebuild `payload = callId:type:timestamp:from:to` and encode.
  3. Decode `signature` and `publicKey` from base64.
  4. Cache `publicKey` per username in `peerSignatureKeys`.
  5. Call `PostQuantumSignature.verify(signature, message, publicKey)`.

Only signals with valid Dilithium signatures are processed; others are discarded.

**Transport path for call signals (`sendCallSignal`)**

1. `attachSignalSignature(signal)` is called and an audit entry is logged.
2. **P2P‑first signaling:** a `p2p-call-signal-send` event is dispatched with a `requestId`; the service waits ~700 ms for a `p2p-call-signal-result` event indicating success. If successful, the call signal is delivered directly over the P2P channel.
3. If P2P fails or is unavailable, the signal is sent via the existing encrypted messaging stack:
   - A `signalData` object (including `messageId`, `from`, `to`, `content`, etc.) is serialized.
   - The code ensures a libsignal session with the peer exists, requesting a Signal bundle and waiting for a `libsignal-session-ready` event if necessary.
   - Recipient hybrid keys (including Kyber) are resolved via `resolveRecipientHybridKeys(peer)`, which coordinates with the server and caches results.
   - `(window as any).edgeApi.encrypt(...)` is called to produce an `encryptedPayload`, using the resolved Kyber and hybrid keys. If there are session errors, it can request a new Signal bundle and retry.
   - The final payload is sent as a `SignalType.ENCRYPTED_MESSAGE` with the encrypted call signal as `encryptedPayload` through the regular PQ+Signal messaging pipeline.

Call control information is:

- Authenticated with Dilithium at the application level.
- Transported either over P2P channels or over the existing hybrid PQ+Signal message transport.

#### 6.2.7 Zeroization and cleanup

When a call ends or the service is destroyed:

- `cleanup()`:
  - Clears timeouts and closes the `RTCPeerConnection`.
  - Stops all tracks on `localStream`, `screenStream`, `remoteStream`, and `remoteScreenStream`.
  - For each stream, if a `_pqSessionKey` property exists, `secretKey` and `publicKey` are zeroized via `PostQuantumUtils.clearMemory` and the property is deleted.
  - Resets `pqSessionKeys`, `currentCall`, `ringStartAt`, `connectedDetectedAtLocal`, and screen‑sharing state flags.

Media‑related PQ keys are kept in memory only for the duration of the call or screen‑sharing session and are explicitly wiped afterwards.

In this module, voice/video and screen‑sharing are anchored in the P2P PQ session, use frequent key rotation and padding on media frames, and rely on ML‑KEM, Dilithium, and `PostQuantumAEAD` for protecting device IDs, call signals, and audit data.

### 6.3 `src/hooks/useP2PMessaging.ts` — P2P integration

`useP2PMessaging` wires the WebRTC P2P utilities into the React app:

- Peer hybrid keys are deserialized via `CryptoUtils.Base64.base64ToUint8Array`.
- Route proofs and message IDs are derived from WebCrypto RNG plus BLAKE3 and Dilithium signatures.
- P2P route proofs and identifiers are MACed or signed with PQ primitives; no ECDSA or RSA algorithms are used on this path.

---

## 7. Authentication and SecureDB integration

### 7.1 `src/hooks/useAuth.ts` — server pinning and hybrid keys

The auth hook ties together server identity and the user’s hybrid key material.

- Server pinning:
  - `PinnedServer` stores `x25519PublicBase64`, `kyberPublicBase64`, `dilithiumPublicBase64` in encrypted storage (`syncEncryptedStorage`).
- `validateServerKeys` checks that decoded lengths are exactly 32, 1568, and 2592 bytes, respectively.
- Server pins always include ML‑KEM and Dilithium keys, not just classical ones.
- Hybrid key management:
  - Uses `SecureKeyManager` to derive/load the per‑user master key and hybrid key bundle.
  - When Kyber keys are available, they are communicated to the Signal layer via `edgeApi.setStaticMlkemKeys`, allowing classical libsignal sessions to be anchored to PQ keys.
- Tokens and other auth artifacts are stored via encrypted storage, which ultimately uses `PostQuantumAEAD` and Argon2id‑derived keys.

### 7.2 `src/hooks/useSecureDB.ts` — binding auth to encrypted storage

- After login, once `Authentication.loginUsernameRef` and `Authentication.aesKeyRef` are populated, `SecureDB` is initialized with the user’s master AES key.
- `encryptedStorage` and `syncEncryptedStorage` are then wired to that `SecureDB` instance.
- On decryption failures (MAC / BLAKE3 / passphrase mismatch), only the affected store is cleared and re‑initialized; plaintext storage or retrieval is not used in this flow.

---

## 8. Security properties and assumptions

The client‑side cryptography provides the following properties under standard assumptions about the underlying primitives.

### 8.1 Confidentiality

- Message contents between clients and server are encrypted under a hybrid scheme:
  - Outer layer: ML‑KEM‑1024 + AES‑GCM with BLAKE3 MAC.
  - Inner layer: ML‑KEM‑1024 ⊕ X25519 combined into keys for `PostQuantumAEAD`.
- WebSocket transport uses hybrid ML‑KEM‑1024 ⊕ X25519 session keys with `PostQuantumAEAD`.
- Local data (SecureDB, encrypted storage, Electron vault‑wrapped keys) is always encrypted with `PostQuantumAEAD` under keys ultimately derived from Argon2id and ML‑KEM.

### 8.2 Integrity and authentication

- BLAKE3 MACs are used at multiple layers (inner and outer envelopes, key bundles, SecureDB values) with constant‑time comparisons.
- ML‑DSA‑87 (Dilithium) signatures authenticate:
  - Routing headers in hybrid envelopes.
  - WebSocket envelopes (client/server signatures).
  - WebRTC route proofs and call signals.
- Replay protection is implemented using bounded maps of seen ciphertexts or message IDs and strict timestamp windows.

### 8.3 Post‑quantum resilience

- As implemented:
  - ML‑KEM‑1024 and ML‑DSA‑87 are NIST‑selected post‑quantum algorithms with security close to category 5.
  - Symmetric primitives (AES‑256, XChaCha20, BLAKE3, SHA‑3) are believed to offer strong post‑quantum security, with AES‑256 providing ~128‑bit security against a generic quantum adversary.
  - Argon2id is a memory‑hard KDF; no known quantum attack fundamentally breaks its design.
- Hybrid constructions (ML‑KEM ⊕ X25519) ensure that breaking confidentiality typically requires breaking both the PQ and classical assumptions simultaneously.

### 8.4 Key handling and zeroization

- All long‑term secret keys (Kyber, Dilithium, X25519) are stored only in PQ‑encrypted form at rest.
- In memory:
  - Secret keys and derived keys are passed as `Uint8Array`s.
  - After use, the code attempts to zeroize sensitive buffers using either `PostQuantumUtils.clearMemory`, `PostQuantumUtils.deepClearSensitiveData`, or `SecureMemory.zeroBuffer`.
- Because of JavaScript’s runtime model and garbage collection, zeroization is best‑effort but applied consistently at the application level.

### 8.5 Non‑goals and constraints

- The system does not claim absolute security; it is designed to be robust against known practical attacks under the assumptions above.
- BLAKE3 is not yet a NIST‑standard primitive. Deployments requiring “NIST only” cryptography should take this into account when evaluating the design.
- Some underlying transports (WebRTC DTLS/SRTP, OS keychains) use classical cryptography internally. The client adds PQ layers on top of those transports but does not modify their internals.

---