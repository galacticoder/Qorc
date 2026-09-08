# Messaging Cryptography

This document lists the cryptographic layers used by the current messaging and
P2P protocols. `docs/app/MESSAGING.md` describes delivery and durability.

## Current Protocols

| Boundary | Current wire form | Main primitives |
|---|---|---|
| Signal storage and ratchet | libsignal PQXDH/SPQR v1 plus `signal-pq` | Double Ratchet, X25519, ML-KEM-1024, SPQR, XChaCha20-Poly1305 |
| End-to-end outer envelope | `hybrid-envelope` | ML-KEM-1024 + X25519, HKDF, AEAD, ML-DSA-87 |
| Server sealed sender | `sealed-sender` | ML-KEM-1024, BLAKE3 KDF, AES-256-GCM |
| Direct P2P session | `hybrid-mlkem1024-mldsa87-session` | ML-KEM-1024 + X25519, ML-DSA-87, directional AEAD and call-stream subkeys |
| WebSocket session | `pq-ws` | two ML-KEM-1024 contributions + X25519, ML-DSA-87 server authentication, directional AEAD in authenticated 64 KiB binary cells |
| Anonymous HTTP tunnel | `qorc-pq-anonymous-http` | ML-KEM-1024 + X25519 request KEX, responder ML-KEM, ML-DSA-87, padded AEAD |
| Account-root transparency | `qorc-key-transparency` | SHA3-512 rolling hash chain, ML-DSA-87 heads and root/recovery authorization, XChaCha20-Poly1305 events |

| Client-facing TLS KEX | TLS 1.3 with `X25519MLKEM768` only | hybrid ML-KEM-768 + X25519 key establishment, no classical KEX fallback |

These wire forms and algorithm bindings are required. Classical-only message
decryption is not accepted.

## Signal Core

The native Signal store supplies identity keys, signed prekeys, one-time prekeys,
and ML-KEM prekeys. Session establishment combines the Signal/X25519 agreements
with the advertised ML-KEM prekey. Every session must negotiate or use SPQR
version 1, and non-PQ ratchet state is rejected. Each encrypted message is then
placed inside the required `signal-pq` envelope.
Native decryption checks exact algorithm bindings and atomically commits ratchet
state with staged plaintext.

The Double Ratchet supplies forward secrecy and post-compromise recovery. The
additional ML-KEM envelope supplies a mandatory post-quantum confidentiality
layer to every current Signal ciphertext, including established-session
messages. That outer KEM uses an account static ML-KEM key, SPQR is the component
that provides ongoing post-quantum ratchet evolution rather than treating that
static envelope as post-quantum forward secrecy by itself.

Code:

- `src-tauri/src/signal_protocol/mod.rs`
- `src-tauri/src/signal_protocol/store.rs`
- `src/hooks/app/useEncryptionProvider.ts`

## Hybrid Envelope

`hybrid-envelope` encapsulates to the recipient's certified ML-KEM-1024 key
and performs X25519 with the recipient's certified Hybrid key. The two secrets
are domain-separated into the AEAD key. The sender signs the current routing
header with ML-DSA-87. The recipient requires agreement between the certificate,
outer sender hint, Hybrid signature, and final libsignal sender.

The Signal identity X25519 key and the Hybrid/P2P X25519 key are distinct signed
subkeys. They are not required to have the same bytes.

Before accepting those certified subkeys, the client verifies that their account
root matches the current append-only transparency commitment for the handle.
This authorizes continuity of the Qorc cryptographic identity, it does not prove
who owns the handle in the real world.

Persistent receive keys are native-only. Rust verifies the canonical signed
public header, decapsulates ML-KEM, performs the static X25519 agreement, derives
both encryption layers, verifies the BLAKE3 MACs, authenticates both AEAD layers,
checks the declared payload size and type, and returns only the one bounded
plaintext requested by the caller. The JavaScript Hybrid module constructs
outgoing envelopes from public recipient material and obtains the sender
signature through a purpose-bound native operation. It has no receive private
key fields or local decryption capability.

Code:

- `src/lib/cryptography/hybrid.ts`
- `src/lib/key-transparency/client.ts`
- `src/lib/utils/certified-identity-utils.ts`

## Server Sealed Sender

For server delivery, the client wraps the Hybrid payload in `sealed-sender`. A fresh
ML-KEM encapsulation derives an AES-256-GCM key, and the KEM ciphertext is bound
as additional authenticated data. The plaintext contains the sender identity but
is padded to a 128 KiB or 256 KiB frame before encryption. The server sees only
the fixed envelope fields and cannot select a recipient from the request. The
128 KiB class is eligible for offline catch-up. The 256 KiB class carries file
chunks and is delivered live or over P2P only.

Live delivery broadcasts every candidate to every activated socket, so a client
that is connected receives entries it cannot open and discards them. Only the
recipient can decapsulate the sealed envelope, failed trials remain local and are
memoized so the same envelope is never decapsulated twice. Catch-up for entries
missed while disconnected is not broadcast — it is retrieved by PIR over the tag
index, described in `docs/app/OFFLINE_MESSAGING.md`.

Sealed-envelope opening is native. The renderer submits one exact `sealed-sender`
envelope, Rust performs ML-KEM decapsulation, fixed-frame authentication and
parsing, exact JSON validation, and canonical sender-handle validation. The
account ML-KEM secret remains inside the native account boundary.

Code:

- `src/lib/transport/blind-routing-client.ts`
- `src/lib/transport/message-framing.ts`
- `server/routing/sealed-sender.js`

## P2P Session

`hybrid-mlkem1024-mldsa87-session` combines both endpoints' ML-KEM-1024 and
X25519 shared-secret contributions with the authenticated handshake transcript.
HKDF-BLAKE3 produces 64 bytes and assigns independent 32-byte send and receive
keys according to the initiator or responder role. ML-DSA-87 signatures
authenticate the complete handshake against certified peer keys, and both sides
verify encrypted key-confirmation frames before marking the connection ready.

The enclosing network transport is a Tor onion-service stream. Tor's circuit
cryptography is classical and contributes no post-quantum key exchange. The
required `hybrid-mlkem1024-mldsa87-session` application P2P session is the
source of PQ confidentiality and peer authentication on this path. There is no
application relay, ambient discovery, port mapping, or gateway probing. Every
peer connection is dialled through Tor.

Application messages receive another ML-DSA signature and a monotonic route
proof bound to the active session and peer certificates. These prove transport
authorization, the inner libsignal identity remains the conversation identity.

The P2P renderer and transport retain only the three certified public identity
keys. Device ML-DSA transcript signatures and the static responder ML-KEM/X25519
operations run in Rust. The native P2P operation returns only two 32-byte
handshake-scoped shared secrets. The short-lived Noise session runs in
JavaScript, and those secrets are zeroed after directional session keys are
derived. Persistent private keys are never copied into the P2P hook, service,
connection, or transport objects.

Message streams use the directional session key. Each call stream derives a
32-byte subkey with HKDF-BLAKE3, the salt
`qorc-call-stream-key-salt`, and the info value
`qorc-call-stream-key:<completeStreamId>`. Accepted contexts are
`call-audio`, `call-video`, `call-telemetry`, and `call-screen` followed by a
16–64 character lowercase hexadecimal identifier. The complete stream ID is
also AEAD additional data, so changing the media kind, call ID, or screen stream
causes authentication failure. At most 128 call-stream contexts are cached,
retired and session-owned keys are wiped.

P2P data uses the 32-byte selected directional key in this composed symmetric
construction:

1. SHA3-512 expands it into independent 32-byte AES and XChaCha keys.
2. AES-256-GCM encrypts the plaintext with the first 12 bytes of a 36-byte
   nonce and the stream ID as additional data.
3. XChaCha20-Poly1305 encrypts that result with the remaining 24 nonce bytes and
   the same additional data.
4. A domain-separated 32-byte keyed BLAKE3 tag authenticates the final
   ciphertext, additional data, and full nonce.

The transmitted encrypted frame is a big-endian 32-bit total length, a
big-endian 64-bit session sequence, the composed ciphertext, and the 32-byte
BLAKE3 tag. The two AEAD tags add 32 ciphertext bytes, producing 76 bytes of
authenticated-frame overhead in total. The nonce is derived from the session
sequence rather than transmitted. A 32,768-slot session replay window permits
bounded reordering between the primary and four media Tor TCP lanes, it records a
sequence only after complete authentication. Sessions expire after 24 hours or
sequence exhaustion.

Call payloads use the selected stream key at this P2P boundary. The calling
service submits an audio batch containing one to four ordered 20 ms Opus packets,
a visual batch containing one to two exact raw VP8 frames with 32-byte visual
headers, or a telemetry probe or keyframe request directly to
the P2P frame operation. The media lanes change scheduling and TCP head-of-line
behavior without changing the cryptographic frame. `docs/app/CALLING.md`
specifies the media formats, queue bounds, and transport layout.

Code:

- `src/lib/cryptography/noise-protocol.ts`
- `src/lib/transport/pq-noise-session.ts`
- `src/lib/transport/p2p-transport.ts`
- `src/lib/transport/secure-p2p-service.ts`

## WebSocket Session

`pq-ws` derives each connection from an initiator encapsulation to the server's
ML-KEM-1024 key, an ephemeral-client/static-server X25519 agreement, and a second
server encapsulation to the client's fresh ML-KEM-1024 key. The server's
ML-DSA-87-signed acknowledgement binds the request digest and responder KEM
ciphertext. Both sides then exchange encrypted key-confirmation messages before
application traffic is released.

There is no client transport signing identity. After the authenticated server
handshake, ordinary frames use directional symmetric keys so they do not add a
transferable client signature. After confirmation, application traffic is sent
only in exact 65,536-byte binary cells. Each cell binds the session ID,
fingerprint, logical message ID, timestamp, counter, fragment position,
ciphertext, and random remainder padding under AEAD. Large logical messages are
reassembled only after every cell authenticates. The receive counter is
committed only after authentication, preventing corrupted cells from burning
valid sequence numbers. Rekeying is staged: the active session remains current
until encrypted confirmation succeeds, queued sends are bounded, and abandoned
candidate keys are wiped on every terminal path.

Server-bound WebSocket traffic is carried over Tor. Tor provides network-path
separation, the post-quantum handshake provides application server identity.

Code:

- `src/lib/websocket/handshake.ts`
- `src/lib/websocket/encryption.ts`
- `server/messaging/pq-envelope-handler.js`

## Anonymous HTTP Tunnel

Discovery lookup, VOPRF evaluation, avatar storage/fetch, and tagged-spool
index/PIR retrieval use one outer `POST /api/anonymous` route. The operation and
JSON body are inside a padded authenticated-encryption envelope. Requests derive
their key from an encapsulation to the authenticated server ML-KEM-1024 key plus
X25519. Responses add a fresh server encapsulation to the request's ephemeral
client ML-KEM key and are signed by the pinned server ML-DSA-87 key before the
client decapsulates them.

The wire has three request classes—64 KiB, 512 KiB, and 2 MiB—and four response
classes: 64 KiB, 512 KiB, 4 MiB, and 8.5 MiB. Ten operations share this route,
including key-transparency sync and append. Tag-index and PIR retrieval use a
dedicated Tor daemon, SOCKS listener, circuit pool, and single-request queue,
the remaining anonymous operations use the primary Tor daemon. A fresh Tor SOCKS isolation credential and
HTTP/1.1 connection are used per request. Intermediaries do not see the operation
name, but they can see the outer size class and timing. The destination server
must decrypt the operation to execute it, so this tunnel does not hide the
operation from the server itself. Trust material and response completion are
also bound to the exact authenticated native WebSocket generation, reconnecting
to the same server cannot start an operation queued by another generation or
release its anonymous response into the active connection lifetime.

Code:

- `src/lib/transport/pq-anonymous-http.ts`
- `src-tauri/src/commands/discovery.rs`
- `server/routes/pq-anonymous-http.js`

## Quantum Resistance Boundary

For message content, current protocols require both classical and post-quantum
contributions. An attacker must defeat the enforced ML-KEM layer to recover the
application plaintext from a recorded Hybrid, Signal, sealed-sender, P2P, or
WebSocket envelope, assuming the keys and composition are implemented correctly.
ML-DSA authenticates the current Hybrid, P2P, and WebSocket transcripts and
headers. Classical X25519 is retained as an independent hybrid contribution.

ML-KEM-1024 and ML-DSA-87 target NIST security category 5. The mandatory
`X25519MLKEM768` TLS group uses ML-KEM-768, which targets category 3. These
are NIST comparison categories, not literal measured bit-security scores for the
complete composed application. AES-256 and 256-bit hashes retain a substantial
generic quantum-search margin, but Grover-style analysis is still why symmetric
key/output sizes must not be described as unchanged 256-bit quantum security.

This does not make the entire app or network path post-quantum:

- Signal identity signatures and parts of the Double Ratchet remain classical,
  PQXDH, SPQR v1, and the required outer ML-KEM envelope supplement them.
- Qorc-controlled client-facing TLS permits only `X25519MLKEM768`, a hybrid
  ML-KEM-768 + X25519 group. TLS certificate signatures remain classical, while
  the pinned application ML-DSA/P2P transcript authentication supplies the
  additional PQ identity layer. The P2P transport is a Tor onion stream whose
  circuit cryptography is classical and contributes no PQ key exchange, the
  application session covers that path. Other infrastructure TLS is not covered
  by this claim.
- Tor circuit establishment remains classical. The hybrid application and TLS
  layers protect recorded content against passive harvest-now/decrypt-later
  attacks, but they do not make Tor routing, availability, or traffic analysis
  post-quantum.
- OPAQUE, discovery VOPRF, and Privacy Pass use classical Ristretto255-based
  operations. Hashes used inside those protocols do not remove their
  discrete-log assumptions.
- Key-transparency rolling-chain hashing and ML-DSA signatures are
  post-quantum-oriented, but the epoch label is derived through the classical
  discovery VOPRF. A
  malicious VOPRF operator can enumerate candidate labels, and a fresh install
  still trusts its first pinned server signer.
- Symmetric AEAD and hash functions are not public-key post-quantum primitives,
  their key and output sizes are selected with quantum search margins in mind.
- A later compromise of a recipient's static ML-KEM secret can expose envelopes
  addressed to that key. Signal's ratchets and SPQR provide separate forward and
  post-compromise properties, subject to their update schedule and endpoint
  security.

No internal test suite proves the cryptographic constructions or their
composition. Independent protocol review, implementation audit, test vectors,
and interoperability analysis remain required before making a formal
post-quantum security claim.

## Key And Metadata Limits

The cryptographic layers protect content and sender/recipient fields carried
inside them. They do not erase timing, volume, endpoint availability, or Tor
connection metadata. The server path uses Tor, fixed sealed-sender size classes,
delayed mixing, cover entries, and a tag index identical for every client to reduce
those signals. A global observer or a peer participating through Tor still has
correlation information, but peers do not learn each other's IP addresses.

Local message plaintext is also bounded. Durable history is encrypted by the
native SQLCipher and authenticated row-encryption layers. Conversation database
segments, IPC pages, and per-conversation renderer state are capped at 50
messages. Loading another page replaces the renderer's bounded metadata window,
stored private text remains in native content records rather than accumulating
in JavaScript. See `docs/app/LOCAL_DATA_SECURITY.md` for the account master,
database key hierarchy, Signal storage, token pools, and threat boundaries.
