# Calling

Qor-Chat calling has two separate encrypted planes. The signaling plane carries
offers, answers, declines, hangups, and screen-share authorization through the
same Signal and hybrid post-quantum application-encryption pipeline used by
messaging. The media plane carries live audio, camera video, and screen frames
over dedicated streams inside the authenticated P2P onion connection.

The application server can relay a live signaling envelope, but it never relays
call media. Call signaling is intentionally ephemeral: it can reach a currently
connected peer and can make bounded retries while the current action is alive,
but it cannot become an offline message that rings later.

## Components And Ownership

The calling stack is divided into five responsibilities:

1. `useCalling` owns one `SecureCallingService` for the currently authenticated
   local account. It connects service callbacks to React state and destroys the
   service across logout, account replacement, or unmount.
2. Calling actions validate UI requests, record deliberate-contact state, obtain
   certified peer material, and ensure a Signal session exists.
3. `SecureCallingService` owns the single active call, capture devices, media
   streams, timers, call signaling, media key state, and cleanup.
4. `unifiedSignalTransport` encrypts and sends call-control payloads over an
   existing P2P message route when available or through a sealed live-only
   server route otherwise.
5. `p2pTransport` carries the media streams through the peer's ephemeral Tor v3
   onion service after its authenticated hybrid session has completed.

The UI receives snapshots of call state and browser `MediaStream` objects. It
does not own cryptographic call state or transport streams. The calling service
remains the authority for whether a signal belongs to the active account, peer,
call ID, direction, and state.

The service exists only while the account is fully authenticated.
Initialization loads the account's preferred camera and installs call, block,
unload, and key-transparency listeners. A transient initialization failure
receives one initial attempt plus three bounded exponential-backoff retries with
random jitter; a final failure destroys the partial service instead of leaving
a half-initialized calling surface.

Code references:

- `src/hooks/calling/useCalling.ts`
- `src/hooks/calling/actions.ts`
- `src/hooks/calling/callbacks.ts`
- `src/lib/transport/secure-calling-service.ts`

## Identity And Transport Prerequisites

Calling does not trust a username, onion address, or call ID by itself. Before
outbound call setup can proceed, the application obtains the peer's certified
discovery material, verifies its account-root and key bindings through key
transparency, registers the peer with the P2P transport, and ensures that native
Signal has a session for that peer.

The P2P connection then completes
`hybrid-mlkem1024-mldsa87-session-v5`. ML-KEM-1024 and X25519 contribute to
directional session keys; ML-DSA-87 authenticates the transcript against the
peer's certified keys; key confirmation completes before application streams
are accepted. The direct route is a Tor onion connection, so neither endpoint
needs a public address or port forwarding and the peers do not learn each
other's IP address from this transport.

Blocking enforcement must be initialized and the peer must be unblocked before
an outgoing call, an answer, or a call signal can proceed. A server-scoped
key-transparency incident quarantines identity-dependent calling. A
contact-root change revokes the old peer material through the shared
transparency and messaging machinery.

These controls serve different purposes:

- key transparency authorizes the cryptographic identity currently bound to a
  Qor handle;
- Signal authenticates and ratchets the call-control conversation;
- the P2P handshake authenticates the direct onion session and derives media
  transport keys;
- the local deliberate-contact marker decides whether an otherwise valid
  incoming offer is allowed to ring;
- blocking is a local deny policy applied at every relevant boundary.

See `docs/app/KEY_TRANSPARENCY.md`, `docs/app/MESSAGING.md`, and
`docs/app/BLOCKING.md` for those shared subsystems.

Code references:

- `src/hooks/calling/actions.ts`
- `src/hooks/discovery/useDiscovery.ts`
- `src/lib/transport/p2p-transport.ts`
- `src/lib/transport/pq-noise-session.ts`

## Call State Model

Only one call may be active in a `SecureCallingService`. A call has a random
128-bit ID encoded as exactly 32 lowercase hexadecimal characters, a peer, an
audio or video type, incoming or outgoing direction, and one of these states:

- `connecting`: secure signaling, capture, or direct media setup is in progress;
- `ringing`: an outbound offer was sent or an admitted inbound offer is waiting
  for the local user;
- `connected`: both sides accepted and media processing started;
- `ended`: the user, peer, timeout, block, failure, shutdown, or security event
  ended the operation;
- `declined`: either side rejected the ringing call;
- `missed`: an admitted incoming call rang for 60 seconds without an answer.

The connected duration begins when the state changes to `connected`, not when
device capture or dialing begins. Both outgoing and incoming ringing windows are
60 seconds. All control signals must be within five minutes of the receiver's
clock.

Lifecycle, media, screen-share, camera-switch, and microphone-switch generations
invalidate asynchronous completions from an old operation. A permission prompt,
connection attempt, decoder, or device switch that completes after the call or
account changed cannot install its resources into the replacement call.

Code references:

- `src/lib/types/calling-types.ts`
- `src/lib/utils/calling-utils.ts`
- `src/lib/constants.ts`
- `src/lib/transport/secure-calling-service.ts`

## Signaling Format And Encryption

The exact inner call-signal variants are:

- `offer`, with `{ callType: "audio" | "video" }`;
- `answer`;
- `decline-call`;
- `end-call`;
- `screen-share-start`, with an authenticated stream ID;
- `screen-share-ready`, with the same stream ID;
- `screen-share-stop`, with the same stream ID.

Every variant also carries the call ID, lowercase `from` and `to` usernames, and
an integer timestamp. The parser rejects missing fields, extra fields, invalid
identifiers, malformed nested data, noncanonical usernames, prototype-pollution
keys, the wrong recipient, or a stale timestamp. The serialized inner object is
bounded to 16 KiB before JSON parsing.

The inner object is serialized into the `content` of a `CALL_SIGNAL` application
payload. It then receives the same native libsignal encryption, required
`signal-pq-v2` wrapper, signed `hybrid-envelope-v2`, and P2P or `ss-v2` transport
protection described in `docs/app/MESSAGING.md` and
`docs/app/MESSAGING_CRYPTOGRAPHY.md`. A call signal is not plaintext WebSocket
control traffic.

On receive, the encrypted-message handler finishes Hybrid and Signal
authentication before parsing the call object. The authenticated outer Signal
sender must equal the inner `from`; the inner `to` must equal the current local
account. After that binding, the handler freezes and dispatches the exact signal
to the calling service. A guessed call ID is insufficient: non-offer signals
must match both the current call ID and the authenticated current peer.

Signaling and media therefore use related identity material but different keys
and lifecycles. Signal protects call intent and control. It does not encrypt
every audio or video frame. Live frames use the call-media construction below.

Code references:

- `src/lib/types/message-handler-types.ts`
- `src/hooks/app/useEncryptionProvider.ts`
- `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- `src/lib/transport/unified-signal-transport.ts`

## Outgoing Call Lifecycle

Starting a call performs these operations in order:

1. Validate the secure browser context, active account, canonical peer, call
   type, self-call rule, and blocking state.
2. Persist the local deliberate-contact marker. Pressing the call button counts
   even if later certificate, permission, network, or remote-answer work fails.
3. Obtain the current certified peer bundle, register it with P2P, and ensure the
   native Signal session.
4. Create the call ID and enter `connecting`.
5. Confirm Signal signaling is available before activating privacy-sensitive
   microphone or camera capture or opening a media route.
6. Capture audio and, for a requested video call, the preferred or default
   camera. A missing or overconstrained camera can downgrade the call to audio;
   permission denial and audio failure remain terminal.
7. Reuse or establish the authenticated P2P onion connection, with a 90-second
   connection timeout. Open deterministic lossy audio and optional video
   streams and derive call-specific media keys.
8. Enter local `ringing` before sending the offer. This ordering prevents an
   immediate answer from racing ahead of the caller's state transition.
9. Send the encrypted live-only offer and arm the 60-second outgoing timeout.

The caller establishes its direct media route before sending the offer, but it
does not start sending media frames until an authenticated answer arrives. If
any setup step fails, the call becomes `ended` with a failure reason and all
call-owned resources are released.

## Incoming Authentication And Ringing Admission

An incoming `offer` passes through more gates than an ordinary call-control
signal because merely receiving valid encrypted traffic must not let a stranger
ring the device.

The encrypted-message handler first requires current key-transparency
authorization for the exact sender and peer keys that authenticated the offer.
Without it, the offer is consumed and discarded without a response. It cannot
remain in native pending-message recovery and become a future ring after trust
state changes.

The handler then opens the current account's secure database and checks for an
encrypted deliberate-contact marker. If the database is unavailable, replaced,
or fails integrity checks, admission fails closed and the offer is terminal.
An incoming offer never creates its own permission to ring.

If key transparency is current but deliberate contact is absent, the client:

- records a declined entry only in encrypted call history;
- does not open calling UI;
- does not activate microphone, camera, audio playback, or a notification;
- does not create a call-system row in the conversation;
- sends one best-effort, live-only decline so the caller can stop immediately.

After those gates, the calling service again validates the exact schema,
recipient, timestamp, blocking state, and current call state. It accepts at most
four offers from one peer and sixteen offers globally per rolling minute, with a
bounded 128-peer rate map. Only then does it create an incoming `ringing` call,
notify the UI, and arm the 60-second missed-call timeout.

Code references:

- `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- `src/lib/database/secureDB.ts`
- `src/lib/transport/secure-calling-service.ts`
- `src/hooks/calling/callbacks.ts`

## Deliberate-Contact Policy

The following local user actions grant future incoming ringing permission for
that peer:

- submitting a new text message, including a reply;
- selecting and sending a file;
- sending a voice note, which uses the file pipeline;
- adding or removing a reaction;
- starting an outbound audio or video call.

The local action is authoritative; server acceptance, recipient delivery, and a
remote answer are not required. Texts, replies, files, and voice notes carry an
`isDeliberateUserAction` provenance bit and atomically write the marker with the
local conversation update. A reaction writes the marker in the same transaction
as its local reaction change. An outbound call has no conversation row, so its
action writes the marker directly before certificate, session, media, or network
work.

Typing indicators, delivery receipts, discovery and session setup, retry replay,
incoming messages, incoming files, incoming calls, call-history records, and
other background traffic do not grant permission. Edits and deletes do not
create a new grant; a locally authored message already granted it when first
submitted.

The marker is encrypted, account-scoped local state. It is not sent to the peer
or server. Deleting or trimming visible conversation history does not revoke it.
If the marker is missing but a retained outgoing text/file row has valid local
provenance, the database can reconstruct it. Incoming rows and malformed sender
or type combinations cannot manufacture that provenance.

This is an anti-harassment policy, not identity proof. It never substitutes for
current key-transparency authorization.

## Answering, Declining, And Call Collision

Answering is allowed only for the exact active incoming ringing call. The client
rechecks quarantine and blocking, enters `connecting`, waits for a Signal
session, and then captures local media. It reuses the caller-established P2P
connection when available or establishes it itself, opens the deterministic call
streams, sends the encrypted answer, starts media processing, and enters
`connected`.

The outgoing peer accepts an answer only from the current peer for the current
outgoing ringing call. It then starts send and receive processing on the streams
it prepared before the offer and enters `connected`.

Decline and end operations update local state and release privacy-sensitive
resources before waiting on the network. Their final control signal is best
effort. A peer going offline can therefore leave the other endpoint to resolve
the call through its own timeout or transport failure rather than a durable
hangup delivered later.

If both peers call one another at the same time, lexicographic username order
breaks the symmetry: the lower username remains the initiator. The other
outgoing call is locally superseded and its incoming offer becomes the single
active call. An offer from a different peer while any call is active is declined.
Duplicate offers for the already active incoming peer and call ID are ignored.

## Live-Only Delivery And Bounded Retries

Call signals use the latency-priority side of the per-peer in-memory encryption
lane. A call signal expires if it spends five seconds waiting in that lane or
for a global send permit. This prevents it from emerging behind a message/file
backlog as though the caller had just acted.

One call action makes one initial live send. An actual retryable send error may
cause at most three more attempts during the same active operation, with 250 ms,
500 ms, and 1 second delays. Every attempt rechecks the service generation,
security quarantine, blocking policy, timestamp, peer, call ID, direction, and
state. Invalid recipients, policy/account changes, missing encryption, or an
invalid encrypted envelope are terminal instead of retryable.

Call signals never enter:

- the WebSocket reconnect queue;
- the durable outbound message retry queue;
- the delivery-ACK journal or ACK-timeout spool fallback;
- P2P reconnect/recovery redelivery;
- the server Redis delayed-mix recovery pool;
- the global offline spool.

When the direct signaling write is unavailable, the existing encrypted payload
may use the server path. Its outer blind-route request carries
`deliveryPolicy: "live-only"`; the WebSocket send uses `queueOnFailure: false`.
The server publishes the sealed envelope only to currently authorized delivery
sockets and excludes it from delayed recovery and storage. Server acceptance is
not proof that the intended peer was online or decrypted it.

Live-only does not mean that every function call is literally bufferless. The
server uses bounded in-memory local-delivery and cross-node publication handoff
queues; a cross-node publication expires after 30 seconds. Those queues exist
only to finish current live fanout and are not a reconnect queue, recipient
mailbox, Redis delay-pool entry, or tagged PIR spool entry.

Code references:

- `src/lib/transport/secure-calling-service.ts`
- `src/lib/transport/unified-signal-transport.ts`
- `src/lib/websocket/websocket.ts`
- `server/routing/blind-router.js`

## Direct Media Connection And Streams

Media is not WebRTC and is not routed through a media server. It uses the
authenticated application P2P connection carried through Tor. A connected P2P
session is reused; otherwise the caller dials the peer's current ephemeral onion
endpoint. The same underlying P2P connection can also carry messaging and stays
open after call cleanup.

Each call opens these logical streams as needed:

- `call-audio:<callId>` for bidirectional audio;
- `call-video:<callId>` for bidirectional camera frames;
- a random `call-screen:<randomHex>` for each screen-share operation.

Audio and video use deterministic IDs so both endpoints open the same logical
stream. Screen streams are random and require a separate authenticated
announcement. Call frames are bounded to 2 MiB including their transport
overhead.

Tor supplies an ordered TCP byte stream. Calling's `lossy` option does not turn
that path into UDP and cannot remove TCP head-of-line blocking. It changes local
backpressure behavior: bounded real-time queues may drop frames when consumers
fall behind instead of treating queue pressure as a fatal reliable-stream error.
At the application stream layer, receive queues are capped at 256 frames and
4 MiB; audio and image renderers add smaller media-specific queues described
below.

Code references:

- `src/lib/transport/secure-transport.ts`
- `src/lib/transport/p2p-transport.ts`
- `src/lib/transport/secure-calling-service.ts`
- `src-tauri/src/network/p2p.rs`

## Media Key Schedule And Frame Protection

After the authenticated P2P handshake, the calling service exports copies of its
directional session key material. It derives separate send and receive families
using the call ID and explicit `i2r` or `r2i` flow direction. Each family is then
domain-separated again into audio, video, and screen keys. This prevents two
peers, two calls, two directions, or two media kinds from accidentally sharing
the same media key and nonce space.

Every media plaintext receives an additional call-media encryption layer before
the P2P stream's own authenticated encryption. Its frame is:

```text
12-byte authenticated header || nonce || ciphertext || authentication tag
```

The header contains an unsigned 64-bit global outbound frame counter followed by
a 32-bit key epoch. It is authenticated as additional data. The media layer uses
the project's `PostQuantumAEAD` composition: AES-256-GCM, then
XChaCha20-Poly1305, plus a keyed BLAKE3 MAC. Its post-quantum key-establishment
property comes from the hybrid ML-KEM/X25519 P2P session that supplied the key
material; the symmetric ciphers themselves are not public-key KEMs.

Send key families rotate every 10 seconds through a one-way labeled derivation
and increment the send epoch. A receiver may authenticate the current epoch, the
immediately previous epoch, or derive forward by at most 64 epochs. A proposed
future epoch becomes current only after a frame authenticates successfully, so
forged epoch numbers cannot commit receiver key state.

Replay tracking is separate by epoch and media kind, uses exact 64-bit frame
numbers, and retains a 4,096-frame window. Freshness is checked before expensive
decryption and committed only after authentication. Old, duplicate, malformed,
oversized, or excessively future frames are discarded.

Short-lived derived keys, copied directional material, plaintext byte arrays,
and encrypted frame scratch buffers are wiped on normal and failure paths where
JavaScript permits. That is defense in depth, not a guarantee that a browser
engine, operating system, driver, or compromised process retained no copy.

Code references:

- `src/lib/transport/pq-noise-session.ts`
- `src/lib/transport/secure-calling-service.ts`
- `src/lib/cryptography/aead.ts`
- `src/lib/cryptography/hash.ts`

## Audio Pipeline

The microphone enters a shared 48 kHz `AudioContext`. An audio worklet collects
2,048 mono `Float32` samples per frame. Only one encrypted stream write may be in
flight; if the transport is still writing, the newer worklet frame is dropped
and zeroed instead of building an unbounded latency queue.

Each audio byte frame is padded to a 128-byte boundary, bounded to 64 KiB,
encrypted with the audio media key, and written to the call-audio stream. On
receive, the client authenticates and decrypts it, validates finite samples,
clamps values to the `[-1, 1]` range, and transfers the sample buffer to a
playback worklet.

The playback worklet retains at most twelve decoded frames. It drops and wipes
the oldest frame under pressure and emits silence on underrun. Played, dropped,
and destroyed sample buffers are wiped on a best-effort basis. The capture and
playback audio contexts are reused across calls to avoid repeated device setup;
they are suspended on call cleanup and closed when the account's calling service
is destroyed.

Code references:

- `public/audio-worklet-processor.js`
- `src/lib/transport/secure-calling-service.ts`

## Camera Video Pipeline

A video call requests microphone plus the account's preferred camera when one
is stored, then tries the default camera. Only missing-device and constraint
errors permit an audio-only fallback. Denied permissions or an unusable audio
device fail the call.

Camera frames are drawn to a private canvas and encoded as JPEG. Resolution,
frame-rate, and quality settings are validated against fixed presets. Capture is
bounded to 3,840 by 2,160 and 8,294,400 pixels. If a JPEG exceeds the media-frame
budget, the encoder makes at most four attempts while reducing scale and
quality; a frame that still does not fit is dropped.

The receiver authenticates and decrypts each frame, validates the complete JPEG
container and declared dimensions before invoking the browser decoder, and
checks that the decoder returned those same dimensions. At most two decoded
`ImageBitmap` frames wait for rendering. Older frames are closed and dropped
under pressure. The rendered canvas exposes a capture-stream track to the call
UI.

Muting changes the microphone track's enabled state. Video toggling changes the
camera track's enabled state; if no live camera track exists, it obtains a new
one and starts its stream only if the same call is still active. Camera and
microphone switches acquire and install a replacement first, verify their
generation and call ownership, and only then remove and stop the previous
track. Camera releases have an 800 ms settle period before reacquisition to
reduce device-driver races.

Code references:

- `src/lib/transport/secure-calling-service.ts`
- `src/lib/database/screen-sharing-settings.ts`
- `src/components/chat/calls/CallModal.tsx`

## Screen Sharing

Screen sharing is allowed only in a connected call with an active media
encryption context. Native source enumeration accepts at most 128 exact screen
or window entries, validates source IDs and names, removes duplicates, and never
accepts an arbitrary source string from the UI.

Starting a share performs an authorization handshake before screen capture:

1. The sender creates a random lossy `call-screen` stream.
2. It installs a ready waiter before sending `screen-share-start`, preventing an
   immediate response from racing past local state.
3. The recipient accepts only an exact signal for the connected call and peer,
   records the announced stream ID, and sends `screen-share-ready`.
4. Unannounced or mismatched incoming screen streams are aborted.
5. Only after the exact ready response arrives does the sender request native or
   browser screen capture and begin transmitting. The ready wait expires after
   10 seconds.

The recipient remembers at most 128 remote screen stream IDs per call, rejects
duplicates, and replaces prior remote-share state in a bounded way. Stopping a
share, ending the source track, or failing setup stops capture and closes the
logical stream before sending a best-effort `screen-share-stop`.

Screen frames use the same bounded JPEG encoder, decoder validation, two-frame
render queue, and dimension limits as camera video, but use a distinct screen
key. Screen settings allow native, 720p, 1080p, 1440p, or 4K resolution and 15,
30, or 60 frames per second. Persistent non-Tor settings are exact-schema,
encrypted, authenticated, account-bound, rate-limited, and expire after 24
hours; Tor-mode settings remain transient.

Code references:

- `src/lib/transport/secure-calling-service.ts`
- `src/lib/database/screen-sharing-settings.ts`
- `src/lib/types/screen-sharing-types.ts`
- `src/components/chat/calls/ScreenSourceSelector.tsx`

## Termination And Cleanup

Cleanup first invalidates outstanding media and device generations. It then:

- cancels pending Signal-session and screen-ready waits;
- removes stream listeners and detaches capture/render media elements;
- stops local microphone, camera, screen, remote video, and remote screen tracks;
- destroys call audio worklet nodes and suspends shared audio contexts;
- closes or aborts audio, video, and screen logical streams;
- wipes media key families, previous receive keys, replay state, and scratch
  ownership;
- cancels key-rotation and ring timers;
- clears the active call and per-call screen identifiers.

The shared authenticated P2P connection is deliberately not closed because
messaging may own or reuse it. A later block event is broader: shared P2P policy
also disconnects the blocked peer. Destroying the calling service removes all
event listeners, closes shared audio contexts, clears callbacks and rate maps,
and prevents retired-account work from reattaching.

Blocking the active peer marks the call ended and releases media before any
network wait. A global key-transparency incident also ends and cleans the call,
but sends no end signal through the transport whose authorization was just
revoked. Window unload, logout, and authenticated-account replacement follow the
same local-first privacy rule.

## UI, Notifications, And Local History

An admitted incoming call updates React state immediately. A native notification
and tray unread increment occur only when the document is hidden or unfocused.
Call status events are exact-schema, account-bound, timestamp-bounded, and
locally limited to 120 accepted events per 10-second window before they can
affect conversation UI or call history. The app asks the operating system to
inhibit sleep while a call is connecting or connected and releases that
inhibitor at every terminal state or service teardown.

Terminal calls produce an encrypted, account-scoped history row with peer,
audio/video type, direction, completed/missed/declined status, start time, and
optional connected duration. History is capped at 500 entries and reloads or
clears when encrypted storage binds to a different account.

Normal call lifecycle events can also create local system rows in the relevant
conversation. A stranger offer rejected by deliberate-contact admission uses
`historyOnly`; it creates the declined history entry but intentionally creates
no system row and no visible ringing UI. Call-history rows never grant
deliberate-contact admission.

Code references:

- `src/hooks/calling/callbacks.ts`
- `src/hooks/app/useCallEventHandlers.ts`
- `src/contexts/CallHistoryContext.tsx`
- `src/components/chat/calls/CallLogs.tsx`

## Memory And Security Boundaries

Readable live media necessarily exists while a call is active. Microphone audio
appears as `Float32Array` samples; camera and screen frames pass through canvas,
JPEG `Blob`, `ImageBitmap`, and `MediaStream` objects; decrypted output reaches
browser audio/video APIs. Scratch arrays are bounded and wiped where possible,
but canvas backing stores, decoder allocations, transferred buffers, operating-
system capture buffers, and driver memory are not under JavaScript's complete
control.

This means call media has strong cryptographic protection in transit and bounded
application queues, but calling is not an isolation boundary against malware in
the same unlocked process or a compromised operating system. Native message-
render isolation described in `docs/app/LOCAL_DATA_SECURITY.md` does not make
live browser media unreadable to that process.

## Metadata And Availability Limits

The application server can observe connection and blind-route timing, encrypted
size classes, and that an outer route selected the live-only delivery policy. It
cannot read the Signal-protected call subtype, call ID, participants, or call
contents from the sealed envelope. A successful server ACK confirms only that
the opaque envelope was accepted for live publication, not that a particular
peer was online or received it.

Call media bypasses the application server, but a peer observes the timing,
duration, and volume of its own direct encrypted media connection. Tor relays
observe their local network edges. Fixed audio padding, encrypted framing,
ephemeral onion services, and Tor reduce metadata exposure; variable JPEG sizes
and real-time traffic patterns still leak coarse activity to a capable traffic
observer.

Calling prioritizes freshness over delivery. Tor latency, TCP head-of-line
blocking, peer availability, capture permissions, decoder behavior, and local
resource pressure can delay or drop live frames. There is no offline call setup,
store-and-forward media, delivery guarantee, or promise that a lost decline or
hangup reaches the peer.
