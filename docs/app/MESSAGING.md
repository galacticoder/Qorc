# Messaging

Qor-Chat uses one end-to-end message pipeline with two delivery transports:
direct P2P through authenticated Tor onion connections or a server-routed global
mix spool.

## End-To-End Layers

Application payloads include text messages, edits, deletes, receipts, typing
state, Signal session control, and file chunks. The sender applies these layers:

1. Native libsignal encryption and ratchet state update.
2. The required `signal-pq-v2` ML-KEM-1024 envelope around the Signal
   ciphertext.
3. `hybrid-envelope-v2`: ML-KEM-1024 plus X25519 key agreement, AEAD, and an
   ML-DSA-87 signature bound to the certified sender keys.
4. Either the authenticated P2P transport or an `ss-v2` sealed-sender envelope
   for the server path.

The recipient validates the certified key binding, outer signature, replay
state, key-transparency authorization, Hybrid envelope, native Signal PQ
envelope, libsignal identity, and libsignal ratchet before releasing plaintext.
Libsignal is the final conversation-sender authority. Transport sender hints
must agree with it but do not replace it.

Code references:

- `src/hooks/app/useEncryptionProvider.ts`
- `src/lib/cryptography/hybrid.ts`
- `src-tauri/src/signal_protocol/mod.rs`
- `src/hooks/message-handling/useEncryptedMessageHandler.ts`

## Signal And Prekeys

Discovery carries the current certified Signal bundle inside its encrypted
record. A new session consumes the advertised one-time prekey and ML-KEM prekey.
The bundle's account root must match the verified append-only transparency log
before native identity installation or session construction.
The native store atomically commits ratchet changes and staged inbound
plaintext; if durable storage fails, the previous ratchet snapshot remains
retryable.

Signal ciphertexts must use the `signal-pq-v2` wire form. Bare classical Signal
ciphertexts are rejected, and session reset or replacement does not negotiate
an alternate envelope form.

Signed transparency heads are carried inside ordinary authenticated Signal
plaintext. Peers anonymously audit received heads for append-only consistency.
A conflicting global head quarantines identity-dependent messaging, a changed
contact root revokes its Signal sessions and peer ML-KEM state before the local
monitor checkpoint advances. See `docs/app/KEY_TRANSPARENCY.md`.

## Peer-to-peer over Tor onion services

Each client publishes an **ephemeral v3 onion service** and dials peers at their
onion address through Tor's SOCKS proxy. Inbound arrives through Tor introduction
points, so peers reach each other with no routable address and no port
forwarding, including behind NAT, double NAT, and carrier-grade NAT.

Transport properties:

- The onion key is created with `Flags=DiscardPK` and without `Detach`, so the
  address is fresh per session, is never written to disk, and the service dies
  with the controller rather than outliving it.
- An endpoint URL is `onion://<56-char-id>.onion`. There is no address list and
  no "is this address routable" test, because an onion host always is.
- Identity rotation replaces the onion service and removes the superseded
  service, so its address stops resolving.
- Neither peer learns the other's IP address.
- Tor carries TCP. Logical application streams are multiplexed over a primary
  connection, and active call media uses four capability-bound, circuit-isolated
  TCP lanes on the same onion service. Audio and visual traffic prefer distinct
  selected lanes. Until an eligible dedicated lane is ready, either can use its
  bounded primary-connection queue. Length framing is exact; a framing error
  that loses byte synchronization closes its TCP connection.
- Tor reveals nothing about who connected, so an inbound connection has no
  transport-level identity. It is keyed synthetically until the handshake below
  binds the peer's alias. Inbound remains fail-closed until the peer's discovery
  certificate verifies.
- After account and database readiness, persisted transparency-authorized
  certificates and authenticated onion endpoints for known peers are restored
  into the P2P transport without dialing them. This lets a known peer's first
  inbound handshake authenticate immediately after startup.

Latency is that of a Tor rendezvous, roughly six hops. Calls use bounded lossy
media streams and four ranked media lanes to keep video or screen writes off the
selected audio circuit and to route around a delayed circuit. A bounded primary
fallback keeps media setup from depending on a dedicated lane becoming ready,
but media still has Tor rendezvous latency. See `docs/app/CALLING.md`.

Before application data is accepted, peers complete
`hybrid-mlkem1024-mldsa87-session-v5`:

- ML-KEM-1024 and X25519 both contribute to directional session keys.
- ML-DSA-87 authenticates the transcript against certified peer keys.
- The certified peer account root must match the locally retained
  key-transparency authorization. That authorization remains usable across
  freshness-check failures and is removed on a verified root change, explicit
  revocation, or a server-scoped transparency incident.
- Both peers exchange key-confirmation frames.
- Session IDs, counters, replay windows, frame sizes, queue sizes, streams, and
  handshake timing are bounded.

The enclosing transport is a Tor TCP stream. The authenticated hybrid
application session above is the peer-identity and transport-key boundary. Tor
supplies reachability and network-address hiding.

Every call stream derives its own directional 32-byte key from the established
P2P directional key and complete stream ID. The same ID is authenticated as
additional data, separating audio, video, telemetry, calls, and screen shares.
Call audio uses 20 ms Opus packets, batches up to four packets per encrypted
write under pressure, retains at most five captures, applies an RTT-aware
160–320 ms deadline, and uses an adaptive 60–100 ms receiver jitter buffer.
Camera and screen media use persistent raw VP8 WebCodecs streams. The encoder's
ceiling is 1280x720 at 2.5 Mbit/s and 60 FPS; the actual capture source can lower
the frame target, and the encoder adapts dimensions and bitrate below that
ceiling under capture, codec, or send pressure. At most two consecutive encoded
frames share one write. Visual traffic prefers an RTT-qualified lane separate
from audio and otherwise enters the bounded primary queue with the same
RTT-aware 400–1,500 ms freshness admission deadline. Once a primary media frame
starts writing, a longer health deadline prevents cancellation in the middle of
its length-prefixed TCP frame. Sequence discontinuities trigger an authenticated
keyframe request. The sender forces its next accepted codec input to be a
keyframe, and the receiver replaces its bounded decoder and renders only fresh,
newest frames without creating a playback buffer or container timeline. The
dedicated lanes and primary fallback carry the same authenticated application
frames.
`docs/app/CALLING.md` defines the complete call frame and queue behavior.

Each direct application message is also signed with the certified ML-DSA key and
contains a monotonically increasing, session-bound route proof. The P2P outer
`from` and `to` values are transport authorization only. The inner Hybrid and
Signal layers are unchanged from the server path.

A successful native write does not prove application delivery. Persistent
messages wait for an authenticated delivery receipt, if it does not arrive, the
same already-encrypted payload is sealed and submitted to the server path. The
native send deadline is authoritative so a JavaScript timeout cannot start a
duplicate server send while a late P2P write is still active.

The onion transport avoids the application server delivery path without
revealing either peer's IP address to the other. It does not eliminate timing and
volume observations by the endpoints or a sufficiently capable Tor observer.

Code references:

- `src/lib/transport/p2p-transport.ts`
- `src/lib/transport/pq-noise-session.ts`
- `src/lib/transport/secure-p2p-service.ts`
- `src/hooks/p2p/messaging.ts`

## Server Path

When P2P is unavailable or unconfirmed, the client creates an `ss-v2` envelope:

```json
{
  "version": "ss-v2",
  "ciphertext": "...",
  "ephemeralKey": "...",
  "nonce": "...",
  "tag": "16 hex chars",
  "probe": "64 hex chars"
}
```

All six fields are required and no others are permitted, the count is checked
exactly, so an envelope missing `tag` or `probe` is rejected as
`invalid_field_count`. The detection tag and probe are present on every envelope
including cover; see the Detection Tags section of
`docs/app/OFFLINE_MESSAGING.md`.

The envelope uses ML-KEM-1024 and AES-256-GCM. Its plaintext contains the local
sender identity and the already encrypted Hybrid payload, padded into exactly a
128 KiB or 256 KiB frame. Those values are invisible to the server.

The active request has this exact shape:

```json
{
  "type": "blind-route",
  "requestId": "random request UUID",
  "sealedEnvelope": { "version": "ss-v2", "ciphertext": "...", "ephemeralKey": "...", "nonce": "...", "tag": "...", "probe": "..." }
}
```

One optional field may be added: `deliveryPolicy`, whose only accepted value is
`"live-only"`. It marks traffic that must reach a live socket or not arrive at
all—call signaling, typing state, and file chunks—which bypasses both the
delay pool and the durable spool. Any other key set is rejected.

The request contains no username, recipient, inbox, route, mailbox, bucket,
shard, or message identifier. The server validates the fixed envelope shape and
resource budgets, delays and shuffles accepted entries, adds shape-matched cover,
and writes them to one shared global spool.

`BLIND_ROUTE_ACK` confirms only that the opaque envelope was accepted into the
mix path. It reveals no recipient state. The client does not mark the message
delivered until an end-to-end receipt arrives.

Code references:

- `src/lib/transport/blind-routing-client.ts`
- `src/lib/transport/unified-signal-transport.ts`
- `server/routing/blind-route-schema.js`
- `server/routing/blind-router.js`
- `server/routing/sealed-sender.js`

## Live And Offline Receive

An authorized unlinked socket explicitly activates global delivery. Live clients
receive broadcast sealed-envelope candidates. Offline clients retrieve through
the tagged lane: they fetch the whole tag index, test each entry's probe against
their own detection key, and issue one batched PIR request per match. Both requests carry
no recipient selector and travel as the encrypted `spool/tag-index` and
`spool/pir` operations inside the fixed `/api/anonymous` hybrid-PQ tunnel. The
index is byte-identical for every caller and the PIR query hides which entry was
selected. Failed decapsulation is not reported.

The server spool has global message and byte caps. Redis byte accounting is
reconstructed from stored envelopes if its counter key is missing, so the byte
limit cannot silently degrade into only a message-count limit.

See `docs/app/OFFLINE_MESSAGING.md` for the tagged PIR format and retention.

## Durability And Deduplication

- Outgoing text and file messages are stored in the encrypted local database
  before their first network send.
- Transport acceptance and application delivery are separate states.
- Durable P2P receipt timers survive transient transport failure and can spool
  the already encrypted envelope to the server.
- Signal ciphertext, prekey, envelope, message-ID, and application replay caches
  are bounded and expire.
- Receipt batching is per peer and bounded. Only an authenticated matching peer
  can cancel a pending delivery retry.
- Native staged plaintext is acknowledged only after application handling and
  any required durable database write succeed. Once native Signal has atomically
  persisted ratchet state and staged plaintext, the shared server spool may
  advance even if a later UI/database step fails, the native pending record then
  owns local recovery and is not acknowledged until replay succeeds.
- Expired deferred controls and first-contact entries become terminal instead of
  renewing their lifetime on every retry. Replay, tombstone, and deferred maps
  remain bounded.

## Account And Operation Isolation

Every long-lived messaging object is bound to the current local account owner,
account generation, transport generation, or a combination of them. Logout
invalidates WebSocket, P2P, Signal, discovery, receipt, retry, file-transfer,
call, database, and vault work before awaiting slower cleanup. Completion after
an account transition is rejected rather than applied to a newly opened account,
even when the normalized username is reused.

Native WebSocket and P2P events carry connection-generation tokens. Sends,
disconnects, queue reservations, handshake promotion, endpoint updates, and
renderer callbacks must match the exact current token. Durable retry and receipt
records are peer-scoped and account-scoped, an acknowledgement from one peer
cannot cancel another peer's recovery record.

Sensitive copied keys and plaintext buffers are wiped on normal completion and
terminal failure paths. JavaScript cannot guarantee physical erasure of every
engine copy, so this is defense in depth rather than a secure-memory guarantee.

A server-scoped key-transparency incident clears live peer authorization and
blocks further identity-dependent work. Corrupt or rolled-back local trust state
cannot silently become a new in-memory authorization. Complete local snapshot
rollback remains outside a file-only defense and is documented in
`docs/app/KEY_TRANSPARENCY.md`.

## Files

Files are capped at 70 MiB and stored locally before transmission. The sender:

1. Generates a fresh per-file AES key and MAC key.
2. Encrypts the file-key envelope to the recipient.
3. Reads fixed 32 KiB chunks and optionally compresses only when beneficial.
4. Encrypts each chunk with AES and authenticates its encrypted bytes plus file
   ID, filename, chunk index, and total count.
5. Sends the complete chunk object through the normal single Signal, Hybrid, and
   transport pipeline.

There is no nested second Signal ciphertext for file metadata. The receiver
accepts one exact current chunk schema, validates canonical base64 and all size
relationships, bounds concurrent and aggregate memory, rejects conflicting
duplicates, and writes the completed file and message atomically. The final
transport ACK and delivery receipt are sent only after that durable write.

Missing chunks are requested with bounded authenticated NACKs. The sender retains
a bounded encrypted transfer context for retransmission and uses the same rate
budget as the primary send. The sender runs at five chunks per second, below the
receiver's per-peer Signal-decryption budget, so normal transfers do not trigger
abuse backpressure.

Images are metadata-stripped by decoding pixels and producing a static WebP,
failure is terminal rather than falling back to the source file. Received image
previews parse the complete RIFF/WebP container, reject trailing bytes,
conflicting image chunks, animation, metadata chunks, invalid padding, oversized
dimensions, and excessive pixel counts before the browser decoder is used.
Audio/video previews require a bounded recognized container header, but their
platform decoders remain third-party attack surface.

Code references:

- `src/components/chat/ChatInput/useFileSender.ts`
- `src/hooks/file-handling/chunk-validation.ts`
- `src/hooks/file-handling/useFileHandler.ts`
- `src/hooks/file-handling/file-assembly.ts`

## WebSocket Transport

Server traffic runs through Tor and a pinned TLS endpoint. After bootstrap, the
WebSocket uses `pq-ws-8`. Session establishment combines an initiator
ML-KEM-1024 secret, X25519, and a responder ML-KEM-1024 secret. An
ML-DSA-87-signed server acknowledgement binds the complete exchange, followed by
encrypted confirmation in both directions. Rekeys remain staged until that
confirmation completes, and activation queues are count/byte bounded. Ordinary
traffic then uses deniable keyed AEAD rather than a fresh client signature on
every frame. Every protected application frame is an exact 65,536-byte binary
cell, including `SECURE_CHUNK` traffic; larger logical messages use multiple
authenticated cells. Replay counters are committed only after authenticated
decryption. The cell count still exposes coarse traffic volume even though each
protected frame has a constant size.

The client-facing TLS 1.3 layer also permits only `X25519MLKEM768`, with session
resumption and early data disabled. The hybrid TLS KEX protects transport keys,
the pinned application ML-DSA identity remains the authoritative server
authentication layer for onion connections.

Browser-origin WebSocket upgrades are restricted to configured first-party
origins. Originless native/Tor clients remain supported.

## Metadata Limits

The server can still observe:

- connection, authentication, publish, send, tag-index, and PIR-query timing,
- traffic volume and encrypted frame size classes,
- which control protocol operation it is processing,
- live socket duration and global-spool retention events.

For direct P2P, the server can observe signaling/discovery timing but not the
direct message bytes. Peers do not learn each other's IP addresses, but each
endpoint can observe the timing and traffic volume of its own Tor connection.
Tor, jitter, cover traffic, fixed message frames, a global spool, and fresh
unlinked connections reduce these signals but do not eliminate global timing
correlation.
