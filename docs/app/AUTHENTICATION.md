# Authentication

qorc keeps account names and passwords on the client. The server stores a
fixed-size set of opaque credential records and verifies a login across the full
set. Successful connections authorize delivery with single-use anonymous tokens.
Separately, a private append-only transparency
map binds the human handle's OPRF-derived label to the account identity root.

This design reduces account and reconnect linkability. It does not make the
server metadata-free: the server still sees connection timing, registration and
login protocol timing, traffic volume, a stable opaque account record, and the
current rounded size of the authentication set.

## Primitives

- OPAQUE-style password envelope and OPRF evaluation:
  `server/crypto/opaque-service.js` and
  `src/lib/cryptography/opaque-client.ts`.
- ML-KEM-1024 oblivious record transfer for login.
- Privacy Pass VOPRF tokens with separate `account-auth` and `server-entry`
  issuer keys.
- `pq-ws-8` WebSocket handshake with initiator and responder ML-KEM-1024
  contributions, X25519, an ML-DSA-87-signed server acknowledgement, and
  encrypted bidirectional key confirmation. The client creates fresh KEM and
  X25519 handshake keys but no transport signing identity.
- TLS 1.3 client/server key exchange restricted to the hybrid
  `X25519MLKEM768` group, with resumption and early data disabled.
- SHA3-512 Merkle map/log proofs and ML-DSA-87-signed transparency heads for the
  account root, with a seven-day recovery activation delay. The recovery signing
  seed is random persistent account material wrapped by the native local vault,
  it is not derived in the renderer from the OPAQUE export key.

OPAQUE, the Ristretto255 VOPRF operations, and Privacy Pass issuance are
classical primitives. ML-KEM protects the fixed-set record transfer, the
WebSocket and client-facing TLS handshakes are hybrid, and anonymous VOPRF HTTP
requests are carried inside the hybrid-PQ anonymous tunnel. Those transport
layers protect captured plaintext protocol traffic, but they do not remove the
classical discrete-log assumptions inside OPAQUE/VOPRF/Privacy Pass or make the
complete authentication construction post-quantum.

## Registration

1. The client derives a composite secret from the normalized local username,
   password, and local encryption passphrase.
2. `AUTH_OT_REGISTER_REQUEST` sends only a blinded OPRF element and a proof-of-work
   preflight response when required. It sends no username.
3. The server returns an evaluated OPRF element and a connection-bound nonce.
4. The client creates the OPAQUE envelope and authentication public key.
   `AUTH_OT_REGISTER_FINALIZE` carries those values and a bounded random
   registration-attempt receipt, but no username or token batch.
5. The server stages the opaque record in one slot of the fixed anonymity set and
   returns the slot index, or reports that the account was already committed.
6. Only after a new registration is staged does the client create or unlock its
   native local account, open the account-master-bound token vault, and prepare
   exactly 250 blinded `account-auth` tokens. This ordering prevents an attempted
   registration of an already-taken name from creating a conflicting local
   account vault.
7. The client verifies local persistence of the slot index, then sends
   `AUTH_OT_REGISTER_CONFIRM` with the blinded batch. The server atomically
   commits the staged account before issuing those tokens. The slot index is not
   sent during later login.

The current set size is 2,048 records and therefore also the current account
capacity. There are no shards and no shard identifier on the wire.

## Login

1. The client loads its slot index from local protected storage.
2. It creates 2,048 ML-KEM public keys, retaining the secret key for its local
   slot, and sends the public-key set, blinded OPRF element, and a transcript
   commitment in `AUTH_OT_REQUEST`.
3. The server returns exactly 2,048 fixed-size encrypted records plus a
   connection-bound nonce and OPRF evaluation. It performs the same record work
   for every slot.
4. The client decrypts its slot and opens the OPAQUE envelope. After that local
   credential check succeeds, it unlocks the native account before opening the
   account-bound token vault and preparing the replacement token batch.
5. The client sends a proof bound to the one-time server nonce in
   `AUTH_OT_FINALIZE`. The server consumes the nonce and checks the proof against
   every record with no early successful exit. The finalize request carries no
   credential ID, username, or slot index.
6. A successful login blind-issues exactly 250 `account-auth` Privacy Pass
   tokens. The client atomically replaces its prior local batch instead of
   appending another batch.

The implemented transfer protects the selected slot from an honest current
client and from the server. It is not a malicious-client-secure 1-out-of-N OT:
a modified client could retain more than one generated ML-KEM secret key and try
to decrypt additional opaque records. Those records remain password protected,
but a true malicious-receiver OT or PIR construction is required to remove this
limitation.

It is also not malicious-sender-secure or verifiable retrieval. A malicious
server can corrupt or permute selected subsets of the 2,048 returned records
across attempts and observe whether the connection later authenticates. That
adaptive selective-failure channel can help it learn the client's stable slot.
Fixed work and absent selectors protect against the honest implementation and
passive observation, removing this active attack requires a reviewed
malicious-sender-secure OT/PIR protocol or a client-verifiable committed
credential database.

## Authentication Channel Binding

Private account login and server-entry OPAQUE requests include a 64-byte
SHA3-512 binding over the exact `pq-ws-8` session ID, authenticated server
fingerprint, and request UUID. The PQ envelope layer verifies the value before
the authentication handler can consume it. The same binding is included in the
OPAQUE transcript and retained with the one-time server nonce through finalize.

This prevents a valid encrypted request or response from being transplanted to
another PQ WebSocket generation, even if the attacker can replay application
objects inside a different encrypted connection. The binding is not a stable
client identifier, it changes with the fresh PQ session and request.

Code references:

- `shared/auth-channel-binding.js`
- `src/lib/websocket/encryption.ts`
- `server/messaging/pq-envelope-handler.js`
- `server/authentication/authentication.js`
- `server/authentication/gatekeeper.js`

## Account-Root Transparency

After password authentication, the client proves that its local ML-DSA-87
account root matches the append-only state for the handle's OPRF-derived label.
Initial registration is authorized by the new root and the independent recovery
key stored in the native account vault. Normal root rotation requires both old
and new roots. Root recovery is announced for at least seven days and can be
cancelled by the old root. This is not a cross-device or lost-disk recovery
mechanism: the native vault and its two unlock credentials must still be
available.

The transparency update is not part of the opaque-record database transaction.
The client queries after an ambiguous update and does not enter normal identity
operation until the current root is verified. A label can be registered only
once, so the first valid claimant controls the qorc handle on that server.

See `docs/app/KEY_TRANSPARENCY.md` for proofs, monitoring, gossip, recovery, and
the exact first-contact trust boundary.

## Anonymous Resume

One full account authentication creates a finite pool of 250 `account-auth`
tokens. The native account vault retains most of that pool and a separate native
restart pool holds up to 32 completed tokens. The two pools have independent
account-master-derived encryption keys and storage identifiers bound to the
authenticated server scope. The renderer never receives either persistent
vault key. Tokens are purpose-bound, epoch-bound, and single use. A token is
removed locally before it is sent, an ambiguous network result burns it rather
than replaying a value that the server may already have accepted.

Resume is deliberately split from account authentication:

1. The account/setup socket is closed.
2. The client requests a fresh Tor circuit and waits randomized jitter.
3. A new WebSocket performs a new `pq-ws-8` handshake with fresh client ML-KEM
   and X25519 material, then completes encrypted key confirmation.
4. `TOKEN_VALIDATION` redeems one `account-auth` token on that unlinked socket.
5. The client activates global-mix delivery.
6. Only after token redemption and delivery activation succeed does the app
   enter its logged-in state or publish discovery material.

After a token-authorized socket becomes ready, it may request exactly one blinded
replacement. The server permits that operation only when the same live socket
successfully spent an `account-auth` token, marks the replacement as issued before
signing, and accepts a batch of exactly one. The client also attempts it only once
per native connection and moves the completed replacement into the restart cache.
This conserves the login-issued total (`one spent -> one replacement`) without a
user identifier or per-user server table, it cannot amplify one token into a
larger batch.

A successful full login can still create a new 250-token batch because the server
deliberately has no stable issuance identifier with which to recognize that the
same person logged in earlier. A hard lifetime/per-person issuance quota is
cryptographically incompatible with that constraint: enforcing one would require
a stable pseudonymous quota handle, account-linked state, or a trusted-device
credential. The implementation instead fixes every batch size, replaces the
honest client's local pool, limits authentication attempts per connection, and
requires a fresh password proof and expensive authentication work for each new
full batch.

Account registration and login messages are rejected on an unlinked socket.
Conversely, resume redemption is rejected on a linked socket. The server also
rejects resume redemption on a connection that already completed account
authentication.

A renderer reload may resume immediately while the native Tauri process still
owns the unlocked account session. A complete application/native-process restart
does not automatically reconstruct the account master from disk. The client
shows the standard **Sign in** form in local-unlock mode and requires the account
password plus the local encryption passphrase. Rust unlocks the local account
vault before the client reads the native restart pool. If that pool is empty,
the same submit continues into normal private account authentication without
deriving the local vault a second time.

This prompt is required by the no-keychain, no-second-device design. Persisting
an unattended recovery secret beside the copied files would make those files
self-unlocking and would defeat the local theft boundary.

If an unlinked resume needs the server password, the client closes it, rotates
the Tor circuit again, and reconnects in linked authentication mode before it
shows the password prompt.

Code references:

- `src/hooks/auth/recovery.ts`
- `src/lib/signals/resume-tokens.ts`
- `src/lib/database/token-vault.ts`
- `src/lib/websocket/websocket.ts`
- `server/server.js`

## Server Entry

An optional server-wide password is separate from account authentication. Its
gatekeeper uses OPAQUE and blind-issues exactly 1,000 `server-entry` Privacy Pass
tokens. The purpose-specific issuer key prevents an account token from being
accepted as a server-entry token or vice versa.

On each new connection, a completed server-entry token is redeemed first when
the server requires one. The client marks a token pending before transmission,
after an ambiguous send it is burned. Pending token state is persisted before
network use. There is no server-entry replenishment signal: when the finite pool
is exhausted or expires, the client must prove the shared server password again
to replace it with a new 1,000-token pool.

Code references:

- `src/lib/cryptography/gatekeeper-client.ts`
- `server/authentication/gatekeeper.js`
- `server/authentication/privacy-pass-server.js`

## Connection State

Authorization is held only on the live WebSocket object. It is not copied into a
cross-worker Redis session record. A reconnect must present fresh one-time
proofs. Ordinary reconnects preserve the client application's registered message
handlers, logout kills the PQ session, clears handlers and queues, wipes local
account singletons, clears token pools, and returns the connection manager to
linked mode.

## Operation And Secret Lifecycle

Authentication, registration, resume, and account-key commits each have an exact
operation owner and account generation. Results are checked again after every
native, storage, worker, WebCrypto, Tor, and network await before they may update
state. Starting logout invalidates transport work synchronously, token-pool
deletion, native account locking, and other secret cleanup then run behind that
invalidation boundary. Ordinary logout retains the credential-wrapped native
account vault and encrypted database so a later login can recover the same local
identity and history.

Expensive private-auth work runs in bounded worker threads with a bounded,
disconnect-aware queue. Worker requests and outputs have exact schemas and byte
limits, and copied secret buffers are wiped on success, error, unsolicited
output, cancellation, and teardown. Token-vault and native-account mutations
are serialized, generation-bound, and verified after persistence so a stale
write cannot recreate credentials after logout or lock. Persistent account
private keys, database keys, and Signal state never pass through renderer IPC.

These controls prevent one renderer lifetime or reused username from inheriting
the prior account instance's keys, tokens, handlers, socket state, or delayed
completion. They do not prevent a compromised device from reading secrets while
that account is actively unlocked.

The complete local key hierarchy, restart behavior, IPC operation allowlist, and
copied-file threat boundary are documented in
`docs/app/LOCAL_DATA_SECURITY.md`.

## Discovery And Messaging

Authentication does not allocate a user mailbox or a destination route. After
an unlinked session is ready, the client publishes encrypted discovery material
through the delayed discovery relay. Server-routed messages contain only an
`ss-v2` sealed envelope and enter the shared global mix spool. There is no
per-account inbox claim, mailbox lookup, blind routing signature, or stable
delivery identifier.

See `docs/app/DISCOVERY.md`, `docs/app/MESSAGING.md`, and
`docs/app/OFFLINE_MESSAGING.md`.

## Post-Quantum Combiner Status

The authentication path combines password-derived OPAQUE material, a fixed-set
ML-KEM-1024 transfer, the hybrid PQ WebSocket/TLS channels, transcript signing,
and one-use anonymous tokens. These are independent defenses, but this
composition is not a proven 2026 post-quantum OPRF combiner. In particular, the
Ristretto255 OPRF/VOPRF remains computationally secure under a classical
discrete-log assumption, and an outer ML-KEM channel does not transform that
primitive into a statistically client-secure PQ OPRF.
