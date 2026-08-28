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
2. Calling actions validate UI requests, resolve current certified peer
   material, restore a saved authenticated endpoint when needed, and check
   a Signal session exists.
3. `SecureCallingService` owns the single active call, capture devices, media
   streams, timers, call signaling, bounded media queues, and cleanup.
4. `unifiedSignalTransport` encrypts and sends call-control payloads over an
   existing P2P message route when available or through a sealed live-only
   server route otherwise.
5. `p2pTransport` carries the media streams through the peer's ephemeral Tor v3
   onion service after its authenticated hybrid session has completed.

The UI receives snapshots of call state, a local-media lifecycle sentinel, and
the canvases used for local previews and authenticated remote camera and screen
frames. It does not own capture sessions, cryptographic call state, or transport
streams. The calling service remains the authority for whether a signal belongs
to the active account, peer, call ID, direction, and state.

The service exists only while the account is fully authenticated.
Initialization loads the account's preferred camera and installs call, block,
unload, and key-transparency listeners. A transient initialization failure
receives one initial attempt plus three bounded exponential-backoff retries with
random jitter, a final failure destroys the partial service instead of leaving
a half-initialized calling surface.

Code references:

- `src/hooks/calling/useCalling.ts`
- `src/hooks/calling/actions.ts`
- `src/hooks/calling/callbacks.ts`
- `src/lib/transport/secure-calling-service.ts`

## Identity And Transport Prerequisites

Calling does not trust a username, onion address, or call ID by itself. Before
outbound call setup can proceed, the application resolves the peer's certified
discovery material, verifies its account-root and key bindings through key
transparency, registers the peer with the P2P transport, and checks that native
Signal has a session for that peer.

Resolution is cache-first. An in-memory certificate may be reused for up to five
minutes, and an account-bound saved certificate or onion endpoint may be
restored after restart when its signed identity, complete key set, and
fingerprints still match the locally retained key-transparency authorization.
Certificate expiry is a refresh deadline for an already-authorized identity,
not a reason to discard that identity or close an active P2P session. A newly
discovered identity must still carry a currently valid certificate. A network
discovery lookup runs in the background when no acceptable cached or saved
certificate exists. Call initiation never waits for that lookup and never
places a delayed call after it completes. The current click either uses trusted
local material immediately or fails immediately while the background refresh
continues. Known-peer transparency state is refreshed after 18 hours without a
successful check, certificates refresh during their final six hours, and each
client publishes its replacement certificate eight hours before expiry. A
failed refresh does not interrupt the retained identity, an observed root
change, explicit revocation, or security incident does. If no Signal session
exists, session prefetch establishes one before call signaling, the calling
service itself waits at most ten seconds for that session to become available.

The P2P connection then completes
`hybrid-mlkem1024-mldsa87-session-v5`. ML-KEM-1024 and X25519 contribute to
directional session keys, ML-DSA-87 authenticates the transcript against the
peer's certified keys, key confirmation completes before application streams
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
  Qor handle,
- Signal authenticates and ratchets the call-control conversation,
- the P2P handshake authenticates the direct onion session and derives media
  transport keys,
- blocking is a local deny policy applied at every relevant boundary.

See `docs/app/KEY_TRANSPARENCY.md`, `docs/app/MESSAGING.md`, and
`docs/app/BLOCKING.md` for those shared subsystems.

Code references:

- `src/hooks/calling/actions.ts`
- `src/hooks/discovery/useDiscovery.ts`
- `src/lib/transport/p2p-transport.ts`
- `src/lib/transport/pq-noise-session.ts`

## Runtime And Device Permissions

Calling runs only in the packaged Tauri desktop client. The distributed client
supports x86_64 Linux and x86_64 Windows, a browser-only session cannot start
the required native Opus codec or native P2P transport. The renderer must also
be a secure context before the start or answer action can request media.

An incoming offer can ring without activating any capture device. The client
asks for media access only after the local user starts or answers a call,
explicitly switches a device, or begins screen sharing. The native media-access
gate runs before microphone and camera startup. Linux captures microphones and
plays speakers through PulseAudio, and captures cameras through Video4Linux.
Windows uses CPAL for microphone and speaker I/O and Media Foundation for camera
capture. Microphone and camera frames therefore do not traverse WebKit.

Linux screen sharing is a separate native path. The xdg-desktop-portal chooser
authorizes one monitor or window and returns a restricted PipeWire connection,
the app-private GStreamer runtime consumes that PipeWire stream and requests up
to 60 frames per second. A lower-rate desktop source remains at its actual rate, the capture pipeline does not synthesize duplicate frames. Other supported
runtimes use `getDisplayMedia()` as the fallback. Denial, cancellation, stale
call ownership, a failed native session, or a capture source that does not
produce its first frame within eight seconds of starting the capture child
aborts setup and releases resources already acquired. Time spent choosing a
source in the portal is outside that first-frame deadline.

Listing microphone, speaker, and camera devices from settings is a separately
confirmed action. In-call pickers enumerate only after the corresponding native
capture or playback session exists. On Linux the portal chooser, rather than a
renderer-provided source identifier, is authoritative for the screen or window
that is captured.

Code references:

- `src/main.tsx`
- `src/lib/tauri-bindings.ts`
- `src-tauri/src/commands/system.rs`
- `src/lib/transport/secure-calling-service.ts`

## Call State Model

Only one call may be active in a `SecureCallingService`. A call has a random
128-bit ID encoded as exactly 32 lowercase hexadecimal characters, a peer, an
audio or video type, incoming or outgoing direction, and one of these states:

- `connecting`: secure signaling, capture, or direct media setup is in progress,
- `ringing`: an outbound offer was sent or an admitted inbound offer is waiting
  for the local user,
- `connected`: both sides accepted and media processing started,
- `ended`: the user, peer, timeout, block, failure, shutdown, or security event
  ended the operation,
- `declined`: either side rejected the ringing call,
- `missed`: an admitted incoming call rang for 60 seconds without an answer.

The connected duration begins when the state changes to `connected`, not when
device capture or dialing begins. Each endpoint records that transition from its
own clock, there is no duration-synchronization message or peer-clock adjustment,
so the two displayed durations can differ slightly. Both outgoing and incoming
ringing windows are 60 seconds. All control signals must be within five minutes
of the receiver's clock.

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

- `offer`, with `{ callType: "audio" | "video" }`,
- `answer`,
- `decline-call`,
- `end-call`,
- `screen-share-start`, with an authenticated stream ID,
- `screen-share-ready`, with the same stream ID,
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
sender must equal the inner `from`, the inner `to` must equal the current local
account. After that binding, the handler freezes and dispatches the exact signal
to the calling service. A guessed call ID is insufficient: non-offer signals
must match both the current call ID and the authenticated current peer.

Signaling and media therefore use related identity material but different keys
and lifecycles. Signal protects call intent and control. Live audio, video,
screen, and telemetry payloads use stream-specific keys derived from the
authenticated P2P session.

Code references:

- `src/lib/types/message-handler-types.ts`
- `src/hooks/app/useEncryptionProvider.ts`
- `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- `src/lib/transport/unified-signal-transport.ts`

## Outgoing Call Lifecycle

Starting a call performs these operations in order:

1. Validate the secure browser context, active account, canonical peer, call
   type, self-call rule, and blocking state.
2. Reuse or resolve the current certified peer bundle, register it with P2P,
   restore its authenticated saved endpoint when the runtime has none, and
   check the native Signal session.
3. Create the call ID and enter `connecting`.
4. Confirm Signal signaling is available before activating privacy-sensitive
   microphone or camera capture or opening a media route.
5. Capture audio and, for a requested video call, the preferred or default
   camera. Audio calls require a live audio track, video calls require that track
   plus a native camera session. Permission denial or a missing required source
   fails setup instead of silently changing the call type.
6. Reuse or attempt to establish the authenticated P2P onion connection, with a
   90-second connection timeout. A connected route opens deterministic lossy
   audio and optional video streams, each with a distinct derived key. A missing
   endpoint or recoverable onion-dial failure does not prevent the live offer,
   either endpoint can establish the media route after the answer.
7. Enter local `ringing` before sending the offer. This ordering prevents an
   immediate answer from racing ahead of the caller's state transition.
8. Send the encrypted live-only offer and arm the 60-second outgoing timeout.
   Camera and screen media use the fixed raw VP8 WebCodecs stream format.

When the pre-offer route attempt succeeds, the caller prepares its media streams
before signaling. When it fails for a recoverable reachability reason, the
answerer sends the answer first and retries the direct connection, allowing the
caller to accept the resulting authenticated inbound route. Neither side starts
media processing until an authenticated answer exists and a direct connection
with the required streams is ready. If setup ultimately fails, the call becomes
`ended` with a failure reason and all call-owned resources are released.

## Incoming Authentication And Ringing Admission

An incoming `offer` is admitted only after the complete messaging identity path
has authenticated it. A syntactically valid object, known username, onion
endpoint, or guessed call ID is not enough to ring the device.

The encrypted-message handler requires current key-transparency authorization
for the exact sender and peer keys that authenticated the offer. Without it, the
offer is consumed and discarded without a response. It cannot remain in native
pending-message recovery and become a future ring after trust state changes.
An authenticated and transparency-authorized peer may ring even when no local
conversation row exists.

The calling service then independently validates the exact schema, recipient,
timestamp, blocking state, and current call state. It accepts at most four
offers from one peer and sixteen offers globally per rolling minute, with a
bounded 128-peer rate map. Only then does it create an incoming `ringing` call,
notify the UI, and arm the 60-second missed-call timeout. Microphone and camera
capture still do not begin until the local user answers.

Code references:

- `src/hooks/message-handling/useEncryptedMessageHandler.ts`
- `src/lib/transport/secure-calling-service.ts`
- `src/hooks/calling/callbacks.ts`

## Answering, Declining, And Call Collision

Answering is allowed only for the exact active incoming ringing call. The client
rechecks quarantine and blocking, enters `connecting`, waits for a Signal
session, and then captures local media. It reuses the caller-established P2P
connection when available or establishes it itself and opens the deterministic
call streams. If the first route attempt fails for a recoverable reachability
reason, it sends the encrypted answer before retrying so the caller can provide
the authenticated inbound connection. Once signaling and direct media are both
ready, it starts media processing and enters `connected`.

The outgoing peer accepts an answer only from the current peer for the current
outgoing ringing call. It uses streams prepared before the offer when available
or establishes them after the answer, then starts send and receive processing
and enters `connected`.

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

- the WebSocket reconnect queue,
- the durable outbound message retry queue,
- the delivery-ACK journal or ACK-timeout spool fallback,
- P2P reconnect/recovery redelivery,
- the server Redis delayed-mix recovery pool,
- the global offline spool.

When the direct signaling write is unavailable, the existing encrypted payload
may use the server path. Its outer blind-route request carries
`deliveryPolicy: "live-only"`, the WebSocket send uses `queueOnFailure: false`.
The server publishes the sealed envelope only to currently authorized delivery
sockets and excludes it from delayed recovery and storage. Server acceptance is
not proof that the intended peer was online or decrypted it.

Live-only does not mean that every function call is literally bufferless. The
server uses bounded in-memory local-delivery and cross-node publication handoff
queues, a cross-node publication expires after 30 seconds. Those queues exist
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
session is reused, otherwise the caller dials the peer's current ephemeral onion
endpoint. The authenticated session remains available for messaging after call
cleanup. There is no ICE candidate exchange, STUN/TURN service, DTLS-SRTP, or
UDP media path.

Each call opens these logical streams as needed:

- `call-audio:<callId>` for bidirectional audio,
- `call-video:<callId>` for bidirectional camera frames,
- `call-telemetry:<callId>` for bidirectional RTT probes,
- a random `call-screen:<randomHex>` for each screen-share operation.

Audio, video, and telemetry IDs are deterministic so both endpoints select the
same logical stream. Screen IDs are random and become valid only after the
authenticated screen-share authorization exchange. Every complete stream ID is
validated as a lowercase hexadecimal suffix between 16 and 64 characters and
is used both for routing and cryptographic domain separation. A call frame is
bounded to 2 MiB including authenticated transport overhead.

The onion service exposes a primary TCP port and a dedicated realtime-media TCP
port. The primary connection carries the P2P handshake, messages, telemetry,
and media while dedicated paths are unavailable or not yet preferable.
Realtime traffic causes each sender to establish up to four media TCP lanes,
each with unique Tor SOCKS isolation credentials. Every lane has its own 32-byte
random capability, offered over the authenticated primary connection and
presented as the media-lane preamble, which binds it to the same connection
generation. The payload remains protected by the authenticated P2P session,
the capability does not replace media encryption. Pending lane offers and
connections are capped at 64 and expire after ten seconds.

The DONAR-lite scheduler measures same-lane RTT with a two-second ping, smooths
the result, and ranks the four lanes. It changes the selected media lane only
after a candidate is at least 75 ms and 10 percent faster for three samples.
The renderer also requires three samples and at least a 50 ms and 10 percent
advantage before moving audio between the primary connection and the media-lane
set. This hysteresis prevents small RTT changes from moving consecutive audio
batches back and forth. The remaining lanes stay warm for immediate send
failure. A distinct ready lane is reserved for camera and screen traffic, so a
large visual write cannot occupy the selected audio circuit.

Three missed six-second probe deadlines remove a lane. A lane whose RTT is both
more than twice and more than 750 ms above the fastest alternative for three
samples is also replaced. Lane setup retry starts at five seconds, backs off to
at most 60 seconds after complete setup failures, and returns to the five-second
repair interval when at least one lane remains usable.

Audio capture has an RTT-aware absolute deadline between 160 and 320 ms. Under
send pressure, up to four consecutive 20 ms Opus packets share one encrypted
native write, reducing encryption, IPC, framing, and socket-flush operations
without retaining more than the existing five captured packets. A selected lane
receives 40 ms to accept a batch before the same batch is attempted on the next
ranked lane. A native 64-bit audio frame ID removes an ambiguous duplicate before
it reaches the encrypted logical stream and permits bounded cross-lane
reordering. While the media lanes are opening, the primary writer selects a
five-entry realtime queue before its normal 64-entry queue. Full or expired
realtime writes fail instead of waiting behind stale media. Visual batches
prefer a separately reserved lane whose measured RTT is meaningfully below the
primary path. If none is eligible, they use the bounded primary normal queue,
they never occupy the selected audio lane. Visual sends use an RTT-aware
400-to-1,500 ms freshness deadline for queue admission and dedicated-lane
attempts.

Once a primary TCP write has been admitted, audio and visual frames receive the
normal ten-second connection-health write deadline. This distinction prevents
an expired media timestamp from cancelling a partially written authenticated
TCP frame and corrupting the shared connection. Queue admission still rejects
media that is already too old.

Logical stream framing is binary. The renderer prefixes each authenticated frame
with a big-endian 16-bit stream-ID length and the UTF-8 stream ID. Native TCP
framing adds a little-endian 32-bit body length. The native side validates the
stream ID and size before forwarding the frame. The native P2P worker never
parses media plaintext.

Native ingress owns one bounded event receiver with global limits of 1,024
frames and 16 MiB. The renderer issues one long-lived `p2p_receive`
request at a time and asks for the next item only after processing the previous
response. Unsubscribe wakes the outstanding pull immediately. No Tauri channel
push or ordered renderer-side IPC cache sits between the native bound and the
application queues.

Audio encrypted and decrypted stream queues are each limited to five frames and
64 KiB. The SecureStream camera and screen queues retain at most six encrypted or
decrypted visual batches and 4 MiB at each stage. Each batch contains at most
two consecutive VP8 stream chunks. Telemetry queues retain at most 16 frames and
64 KiB, and message streams retain at most 256 frames and 4 MiB. These transport
bounds are separate from the four-entry compressed visual sender queue. Lossy
streams discard the oldest backlog under receive pressure, reliable
message-stream overflow closes the connection.

Code references:

- `src/lib/transport/secure-transport.ts`
- `src/lib/transport/p2p-transport.ts`
- `src/lib/transport/secure-calling-service.ts`
- `src-tauri/src/network/p2p.rs`

## Call Stream Key Schedule And Frame Protection

The P2P handshake produces independent 32-byte base keys for each direction.
For every `call-audio`, `call-video`, `call-telemetry`, or `call-screen` stream,
the transport derives another 32-byte directional key as:

```text
HKDF-BLAKE3(
  inputKey = directionalSessionKey,
  salt = UTF8("qor-call-stream-key-salt-v1"),
  info = UTF8("qor-call-stream-key-v1:" + completeStreamId),
  length = 32
)
```

The direction, call ID, media kind, and random screen-stream ID therefore select
different keys. The complete stream ID is also authenticated as additional
data. Subkeys are cached only while their streams can still have pending
encryption or decryption work. Closing or aborting a stream retires and wipes
both directional subkeys, destroying the P2P session wipes every remaining
subkey. A session accepts at most 128 cached call-stream contexts per direction.

The P2P transport applies one authenticated frame construction to the bounded
audio batch, VP8 visual stream chunk, or telemetry probe. Its
32-byte stream key is expanded with SHA3-512 into independent AES and XChaCha
keys, and a domain-separated keyed BLAKE3 key authenticates the final
ciphertext, stream-ID additional data, and nonce. Encryption runs in this order:

1. AES-256-GCM with the first 12 nonce bytes,
2. XChaCha20-Poly1305 with the remaining 24 nonce bytes,
3. a 32-byte keyed BLAKE3 tag over the resulting ciphertext, additional data,
   and complete 36-byte nonce.

The on-wire authenticated frame is:

```text
u32be frameLength | u64be sessionSequence | composedCiphertext | blake3Tag[32]
```

The two AEAD tags add 32 bytes inside `composedCiphertext`, the header and
BLAKE3 tag add another 44 bytes, for 76 bytes of transport overhead. The nonce
is deterministically constructed from the 64-bit sequence and is not sent. A
single sequence space and 32,768-slot replay window cover the authenticated P2P
session, including frames arriving over the primary and media TCP lanes. A
sequence is committed only after the MAC and both AEAD layers authenticate, so
corrupt input cannot consume a valid replay slot. The session expires after 24
hours or when its 64-bit send sequence is exhausted.

The calling service gives codec payloads directly to this transport frame.
Audio carries a compact codec sequence and capture timestamp for playout,
camera and screen streams carry an exact binary metadata header and one bounded
raw VP8 frame. Plaintext, codec packets, frame copies, keys, and queue
entries are wiped on normal and failure paths where their memory is directly
controllable.

Code references:

- `src/lib/transport/pq-noise-session.ts`
- `src/lib/transport/p2p-transport.ts`
- `src/lib/transport/secure-calling-service.ts`
- `src/lib/cryptography/aead.ts`
- `src/lib/cryptography/hash.ts`

## Audio Pipeline

Native microphone capture produces 48 kHz mono `Float32` frames containing 960
samples, or 20 ms, and retains only the newest unconsumed frame. Linux uses a
PulseAudio record stream and Windows uses CPAL. The renderer long-pulls the
latest sequence as a binary Tauri response, so slow encoding overwrites stale
PCM at the native boundary instead of growing a capture queue. Muting changes
the native session's enabled state, disabled captures contain silence and do not
reopen the device.

Each call owns a native Opus encoder/decoder session configured for:

- 48 kHz mono speech and 20 ms frames,
- VoIP application mode,
- 24 kbit/s target bitrate, variable bitrate, and complexity 8,
- discontinuous transmission,
- in-band forward error correction with an expected 10 percent packet-loss
  rate,
- a maximum encoded packet size of 1,276 bytes.

The sender keeps at most five captured PCM frames. When capture outruns encoding,
it wipes and drops the oldest frame. Capture has an RTT-aware deadline between
160 and 320 ms and expired speech is discarded before or after encoding. The
drain takes up to four pending 20 ms frames, encodes them in sequence, and sends
their packets together in one encrypted write. This preserves codec sequencing
while amortizing Tauri IPC, Noise framing, native scheduling, and TCP flushing
across as much as 80 ms of speech. The realtime encryption queue also permits at
most five pending writes and services realtime work before normal traffic. A
one-byte Opus DTX result is marked as silence, one such packet is sent every 20
silent frames, approximately every 400 ms, while intermediate silence is
suppressed.

The plaintext audio packet has a fixed 14-byte header:

```text
u8 version | u8 flags | u32be codecSequence | u64be captureTimestampMs | opus
```

The current version is 1. Flag bit 0 marks a one-byte DTX packet and flag bit 1
marks a discontinuity caused by a dropped capture, suppressed DTX frame, failed
send, or audio-route change. A received discontinuity lets playout skip an
already obsolete sequence gap instead of synthesizing audio for it. The codec
sequence advances per captured frame and the timestamp records capture time in
milliseconds. One to four packets are enclosed in this audio batch:

```text
u8 batchVersion = 2
u8 packetCount = 1..4
u16 reserved = 0
repeat packetCount times:
  u16 packetLength
  audioPacket[packetLength]
```

The entire batch is authenticated and encrypted under the
`call-audio:<callId>` stream key. The receiver restores packet arrival times at
20 ms spacing before jitter estimation so intentional batching is not treated
as network jitter.

The receiver estimates arrival variation with a 1/16 smoothing factor and
selects a target of three to five 20 ms packets, giving a nominal 60–100 ms
jitter buffer. It starts when the target is available or the oldest packet has
waited 100 ms. For one missing packet it first asks Opus to recover FEC from the
following packet. It otherwise invokes Opus packet-loss concealment for up to
five consecutive gaps, then emits silence until a later sequence lets playout
resynchronize. Duplicate, late, oversized, and excess buffered packets are
dropped.

Decoded PCM normally goes to a selectable native output: PulseAudio on Linux or
CPAL on Windows. That playback queue is capped at ten 20 ms frames and discards
the oldest complete frame when full. If native playback cannot start, the
renderer falls back to the receiver `AudioWorklet`, whose queue remains capped
at five frames. Capture, realtime encryption, native sending, encrypted
receive, jitter, decode, and playback are therefore bounded to current audio
rather than seconds of accumulated speech. Played, dropped, and destroyed
sample buffers are wiped on a best-effort basis.

Code references:

- `public/audio-worklet-processor.js`
- `src-tauri/src/audio_codec.rs`
- `src-tauri/src/microphone_capture.rs`
- `src-tauri/src/audio_playback.rs`
- `src/lib/tauri-bindings.ts`
- `src/lib/transport/secure-calling-service.ts`

## Camera Video Pipeline

A video call opens the preferred microphone and camera through native sessions,
falling back to each platform's default device when no preference is stored or
the saved device is unavailable. Linux camera capture uses Video4Linux and
Windows uses Media Foundation. A video call requires working audio and camera
sessions, a denied permission or unusable camera fails setup instead of silently
changing the call type. The local preview and outgoing encoder share the same
persistent canvas, so the camera has one native consumer. Selecting the active
camera does not reopen it. Disabling video releases the hardware stream and
publishes low-rate black JPEG frames until it is enabled again. No bundled or
synthetic sample video is used.

Each visual stream owns one persistent WebCodecs `VideoEncoder` and one
`VideoDecoder`. The fixed format is a raw VP8 elementary stream. The encoder
draws the newest native camera image or live screen frame into one reused canvas,
wraps that canvas in a short-lived `VideoFrame`, and submits it directly to VP8.
The output callback copies only the compressed `EncodedVideoChunk`, it closes the
input frame immediately. Raw RGBA pixels never cross the Tauri boundary. The
decoder accepts the authenticated raw VP8 chunk directly and returns a bounded
`VideoFrame` to the latest-frame renderer. Camera and screen streams use the same
implementation but own separate codecs, queues, canvases, and stream keys.

Visual calls require WebCodecs `VideoEncoder`, `VideoDecoder`, `VideoFrame`, and
`EncodedVideoChunk` support for VP8 plus `createImageBitmap()` JPEG decoding for
native camera and Linux screen frames. They do not use canvas media streams,
browser media recording, a container format, object URLs, or media-source
buffers. The non-Linux screen fallback alone uses a hidden live video element.
Unsupported visual codec APIs fail that media operation, the transport does not
substitute another codec or downgrade a video call to audio.

Camera and screen encoding share one fixed ceiling: 1280x720, 2.5 Mbit/s, and a
60 FPS target. The actual target never exceeds the native source's reported
frame rate. Six adaptation levels apply dimension scales of 1.0, 0.75, 0.55,
0.40, 0.30, and 0.23 and bitrate scales of 1.0, 0.72, 0.50, 0.32, 0.20, and
0.12, with a 180 kbit/s floor. Camera starts at level 3 and screen at level 2 so
the first frames do not begin at the most expensive setting.

Adaptation uses two-second windows and a 1.5-second warmup after startup or
reconfiguration. Two stressed windows lower quality. Stress includes more than
12 percent capture loss or send failures, a remote discontinuity, encode time
above the smaller of 30 ms and 90 percent of the current frame budget, or write
time above 140 ms. Recovery requires capture loss below eight percent, send
failures below three percent, encode time below the smaller of 24 ms and 70
percent of the frame budget, write time below 90 ms, and no remote
discontinuity. A healthy level recovers after 15 seconds, a failed upgrade backs
that interval off as far as 60 seconds. The encoder preserves source aspect
ratio and never enlarges it beyond native dimensions.

The camera worker requests 1280x720 at 60 FPS and selects the closest supported
hardware format, preferring native MJPEG. It retains exactly one compressed JPEG
frame: a newer capture overwrites and wipes an unconsumed one. The renderer
long-pulls only the newest sequence and starts the next native read before
decoding the current JPEG. It validates the binary header, decodes one image,
draws it into the reused canvas, closes it, and wipes the JPEG bytes. A slow
renderer therefore drops old native frames instead of building a queue. Raw
RGBA, JSON/base64 frames, and media-recorder data never cross Tauri IPC.

The VP8 encoder admits at most three queued input frames and retains at most
twelve timestamp-only metadata records awaiting codec output. A submitted canvas
`VideoFrame` is closed synchronously. Raw VP8 output is limited to 1 MiB, and the
encoded sender retains at most four frames around the active write. Encoder or
transport pressure drops stale work, wipes owned byte arrays, and forces the next
accepted input to be a keyframe. Codec reconfiguration is reserved for an actual
quality or adaptation change.

The sender waits up to 18 ms for a second consecutive encoded frame and sends at
most two frames in one authenticated visual batch. Each output frame has its own
sequence, capture time, monotonic codec timestamp, dimensions, and keyframe bit,
so visual transmit and receive FPS count encoded frames rather than container
chunks. The encoder produces a keyframe at least every two seconds and
immediately after a receiver request, loss event, queue reset, or codec
reconfiguration.

The receiver validates framing and freshness before copying compressed bytes. At
most eight frames may be queued or awaiting codec output, and the native decoder
itself is kept below three queued inputs. A duplicate or backward sequence is
discarded. A forward gap, malformed frame, codec failure, or queue overflow wipes
dependent compressed data, replaces the decoder, and accepts nothing until a
fresh keyframe arrives. Decoded `VideoFrame` objects enter only a short
source-timestamp render queue. The timer-paced renderer selects the newest due
frame, drops superseded or stale frames, and closes every displayed or discarded
frame. This removes media-buffer retention, playback-rate catch-up, append
serialization, object-URL lifetime, and hidden-video state from call memory.

The receiver rejects a frame whose authenticated dimensions disagree with the
decoded VP8 frame or whose clock-corrected age exceeds the RTT-aware 0.9-to-2
second playout limit. The decoder watchdog resets a stalled codec, dependent
delta frames remain blocked until a fresh keyframe, and authenticated control
frames request that keyframe at most once every two seconds. Camera and native
Linux screen capture both use latest-only slots and one prefetched binary pull,
so neither source can create an unbounded producer queue. The browser screen
fallback is timer-paced at its reported source rate.

Each visual transport payload starts with this batch framing:

```text
u8  batchVersion = 1
u8  frameCount = 1..2
u16 reserved = 0
repeat frameCount times:
  u32 frameLength
  visualFrame[frameLength]
```

Each `visualFrame` has this exact 32-byte big-endian header followed by one
raw VP8 encoded frame:

```text
u8  version = 4
u8  codec = 3
u8  keyFrame
u8  reserved = 0
u32 sequence
u64 capturedAtMs
u64 codecTimestampUs
u16 width
u16 height
u32 payloadLength
```

`keyFrame` is exactly 0 or 1 and must agree with the VP8 frame-type bit. A
keyframe must also contain the canonical VP8 keyframe start code. The receiver
rejects malformed headers, unsafe dimensions, inconsistent lengths, oversized
frames, codec-marker mismatches, duplicate or backward sequences, and decoded
dimensions that disagree with the authenticated header.

A forward sequence gap, queue overflow, malformed frame, decoder error, or stale
frame wipes dependent compressed data, creates a fresh bounded decoder, and
requests an authenticated keyframe. Delta frames are rejected until that
keyframe arrives. The sender marks its next input as a keyframe without creating
a media container or restarting a playback timeline. Once clock-offset telemetry
is available, the playout limit follows measured RTT between 0.9 and 2 seconds.
The calling service renders only due, recent decoded frames and closes every
displayed, dropped, or superseded `VideoFrame`. Camera, microphone, and speaker
switches replace their native sessions, restore the previous or default device
when appropriate, and verify call ownership after every asynchronous boundary.
After full call cleanup releases local media, the next call waits up to the
remainder of an 800 ms settle interval before reacquiring devices to reduce
driver races.

Code references:

- `src/lib/transport/call-video-codec.ts`
- `src/lib/transport/secure-calling-service.ts`
- `src-tauri/src/camera_capture.rs`
- `src-tauri/src/commands/camera.rs`
- `src/components/chat/calls/CallModal.tsx`

## Screen Sharing

Screen sharing is allowed only in a connected authenticated P2P call. On Linux,
the xdg-desktop-portal chooser is the source-selection boundary: the renderer
does not supply or override the selected monitor or window. The portal returns
one restricted PipeWire remote and stream node. The packaged client starts its
app-private `gst-launch-1.0` and curated plugins with system plugin discovery
disabled, then runs this bounded capture pipeline:

```text
pipewiresrc(portal fd/node)
  -> latest-only queue
  -> videorate(max 60 FPS)
  -> I420 1280x720
  -> JPEG quality 80
  -> native latest-frame slot
  -> binary Tauri pull
  -> ImageBitmap/canvas
  -> VP8 visual encoder
```

The native worker reports capture started only after its first complete JPEG,
not after the chooser closes or GStreamer spawns. Other supported
runtimes use `getDisplayMedia()`, attach its video track to a private capture
element, and feed that element into the same VP8 pipeline.

Starting a share performs capture and peer authorization in this order:

1. Acquire the native portal session or fallback browser track and require its
   first usable source frame.
2. Create a random lossy `call-screen` stream.
3. Install the ready waiter before sending `screen-share-start`, preventing an
   immediate response from racing past local state.
4. The recipient accepts only an exact signal for the connected call and peer,
   records the announced stream ID, installs the bounded receiver, and sends
   `screen-share-ready`. Unannounced or mismatched streams are aborted.
5. Start the local VP8 encoder and require its first prepared frame within ten
   seconds.
6. Require the exact peer-ready response within ten seconds before marking the
   share active.

The recipient remembers at most 128 remote screen stream IDs per call, rejects
duplicates, and replaces prior remote-share state in a bounded way. Stopping a
share, ending the source track, or failing setup stops capture and closes the
logical stream before sending a best-effort `screen-share-stop`.

Screen frames use the persistent raw VP8 WebCodecs stream, source-rate-capped 60
FPS target, six-level adaptation, freshness bounds, decoder validation, and
timer-paced renderer used by camera video. The announced random stream ID
selects its screen key. There is no user-selectable screen quality or frame-rate
setting.

Code references:

- `src/lib/transport/secure-calling-service.ts`
- `src/lib/transport/call-video-codec.ts`
- `src-tauri/src/screen_capture.rs`
- `src/lib/types/screen-sharing-types.ts`
- `scripts/stage-gstreamer-plugins.cjs`

### Screen-Share Diagnostics

`CALL-DIAG` phases deliberately cross the portal, native worker, encoder,
transport, and receiver boundaries. Read the first missing transition in this
order:

```text
native-screen-portal-create-after
  -> native-screen-portal-select-after
  -> native-screen-portal-start-after
  -> native-screen-pipewire-ready
  -> native-screen-gstreamer-start-after
  -> native-screen-first-frame / native-screen-capture-window
  -> screen.capture-request-after
  -> screen.transport-created
  -> screen.announcement-sent
  -> screen.encoder-started / screen.local-first-frame
  -> screen.peer-ready / screen.ready
  -> remote screen first-frame pipeline event
```

If the portal and PipeWire phases succeed but every five-second native capture
window reports zero frames, the failure is before WebCodecs, encryption, media
lanes, and remote rendering. A `Failed to set pipeline to PAUSED` result after
about 30 seconds is PipeWire's own source-activation timeout. Qor does not wait
for that timeout: it validates the SPA factories before spawning GStreamer and
stops a child that produces no first frame within eight seconds. The
GStreamer/PipeWire state trace then distinguishes a remote/node connection that
remains in `CONNECTING` from stream-format negotiation that never reaches a
usable state. Conversely, nonzero native source frames with zero transmit or
receive counters move the fault boundary into the encoder or transport stages.

The private SPA root must contain both its `support` modules and
`videoconvert/libspa-videoconvert.so`, PipeWire's `client.conf` resolves
`video.convert.*` through that adapter when `pipewiresrc` creates `video.adapt`.
Because Qor overrides `SPA_PLUGIN_DIR` instead of extending the host directory,
the capture process cannot fall back to a system copy. Staging, both package
validators, AppImage cache reuse, development launch, and native startup now
reject an incomplete private root. `PIPEWIRE_DEBUG` defaults to error-level `1`
for the capture child, level `4` exposes full SPA factory and stream-state
tracing when needed. The private root also carries
`audioconvert/libspa-audioconvert.so` so it satisfies the standard client
configuration rather than representing only its support subset.

## Runtime Call Telemetry

A connected call starts one optional lossy `call-telemetry:<callId>` stream. Its
17-byte request and 33-byte response frames carry a random 64-bit probe ID and
integer millisecond timestamps. A two-byte control frame requests a fresh VP8
keyframe for the camera or screen decoder and is limited to one request per
media kind every two seconds. One probe is outstanding at a time, probes are
sent every two seconds, and an unanswered probe fails after eight seconds. The
reported RTT subtracts the peer's measured response-processing interval. The
displayed one-way estimate is RTT divided by two and is a diagnostic estimate,
not a measurement of asymmetric path delay.

Every five seconds the client emits one single-line JSON `CALL-TELEMETRY` sample,
and cleanup emits a final sample. It contains:

- latest, average, p95, maximum, lifetime-minimum, and lifetime-maximum RTT,
- the RTT/2 one-way estimate, probe failures, protocol errors, connection age,
  transport state, and time since transport activity,
- ready, active, selected, secondary, and standby audio lanes with per-lane RTT,
- the distinct visual lane and current visual adaptation level, dimensions,
  bitrate, actual source-capped FPS target, encoded bitrate, adaptation health,
  capture-loss and send-failure ratios, and recovery countdown,
- event-loop lag distribution and document visibility state,
- audio, video, and screen source, transmit, and validated-arrival rates and byte
  rates, including source-frame losses,
- decoder-admitted, decoded, and visibly rendered visual FPS,
- native pull, native source age, JPEG decode, frame preparation, VP8 encode,
  write, VP8 decode, capture-to-send, and clock-corrected capture-to-render
  duration, arrival gap, and smoothed arrival jitter,
- capture drops, send errors, receive errors, render drops, sequence
  discontinuities, key-frame requests, received key-frame requests, and lifetime
  totals,
- current encoder queues, pending work, keyframe/restart state, last-progress
  ages, failures, and delivery invalidations,
- decoder queues, pending work, watchdog resets, stale-stage drops, pipeline
  resets, last-progress ages, and waiting-for-keyframe state,
- renderer queue depth, scheduled delay, replaced frames, buffering state,
  canvas size, and last callback/render ages.

The byte counters measure plaintext codec frames at the calling-service
boundary. For audio, frame rates count individual Opus packets even when several
share one transport write. For video and screen, transmit and receive rates count
individual raw VP8 frames, `admittedFps`, `decodedFps`, and `renderedFps` describe
receiver pipeline and displayed-frame progress. Write duration covers the stream
write, including encryption and the native send. Probe timestamps estimate the
peer clock offset so visual render age can represent capture-to-display latency.
Telemetry stream setup is best effort and its absence does not prevent a call.

Code references:

- `src/lib/transport/call-telemetry.ts`
- `src/lib/transport/secure-calling-service.ts`

## Termination And Cleanup

Cleanup first invalidates outstanding media and device generations. It then:

- cancels pending Signal-session and screen-ready waits,
- removes stream listeners and detaches capture/render media elements,
- stops native microphone, camera, speaker, and Linux screen sessions plus any
  fallback browser screen track, and releases local and remote render surfaces,
- destroys fallback call-audio worklet nodes and suspends its shared audio
  context,
- stops the native Opus session and closes every visual encoder and decoder,
- closes or aborts audio, video, telemetry, and screen logical streams,
- wipes call-owned media scratch buffers,
- cancels ring, telemetry-probe, telemetry-log, and screen-ready timers,
- clears the active call and per-call screen identifiers.

The end-call UI clears its active React call state synchronously before invoking
this cleanup, so local dismissal does not wait for transport work. The service
then sends the authenticated end signal on a fire-and-forget best-effort path.

The shared authenticated P2P connection is deliberately not closed because
messaging may own or reuse it. A later block event is broader: shared P2P policy
also disconnects the blocked peer. Destroying the calling service removes all
event listeners, closes shared audio contexts, clears callbacks and rate maps,
and prevents retired-account work from reattaching.

Blocking the active peer marks the call ended and releases media before any
network wait. A global key-transparency incident also ends and cleans the call,
but sends no end signal through the transport whose authorization was just
revoked. Window unload, logout, and authenticated-account replacement follow the
same local-first privacy rule. A bound P2P connection entering `disconnected` or
`failed` immediately marks the active call ended with a failure reason, notifies
the UI, and runs the same cleanup path.

## UI, Notifications, And Local History

An admitted incoming call updates React state immediately. A native notification
and tray unread increment occur only when the document is hidden or unfocused.
Local call-log events are exact-schema, account-bound, timestamp-bounded, and
limited to 120 accepted events per 10-second window before they can affect
conversation rows or call history. Conversation-list status updates use a
separate account-bound, sanitized 500-event limit per 10 seconds. The app asks
the operating system to inhibit sleep while a call is connecting or connected
and releases that inhibitor at every terminal state or service teardown.

Terminal calls produce an encrypted, account-scoped history row with peer,
audio/video type, direction, completed/missed/declined status, recorded event
time, and optional connected duration. History is capped at 500 entries and
reloads or clears when encrypted storage binds to a different account.

Normal call lifecycle events can also create local system rows in the relevant
conversation. These rows are local UI history, not call-control messages and not
evidence that a remote signaling action was delivered. The remote camera canvas
also draws a rolling `RX n.n FPS` diagnostic in its upper-right corner, it
measures locally rendered remote camera frames and is not transmitted back to
the peer.

Code references:

- `src/hooks/calling/callbacks.ts`
- `src/hooks/app/useCallEventHandlers.ts`
- `src/contexts/CallHistoryContext.tsx`
- `src/components/chat/calls/CallLogs.tsx`

## Memory And Security Boundaries

Readable live media necessarily exists while a call is active. Microphone audio
crosses Tauri as bounded `Float32Array` frames. Camera images and native Linux
screen images cross Tauri as bounded JPEG bytes, are decoded one at a time, and
share reused canvases with their WebCodecs VP8 encoders. The non-Linux screen
fallback instead draws from its capture element. Received media uses bounded
compressed frames, one `VideoDecoder` per visual stream, short-lived decoded
`VideoFrame` objects, and visible render canvases. Raw visual pixels do not cross
Tauri IPC.
Scratch arrays are bounded and wiped where possible, but canvas backing stores,
decoded image allocations, transferred buffers, operating-system capture
buffers, and driver memory are not under JavaScript's complete control.

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
observe their local network edges. Encrypted framing, ephemeral onion services,
and Tor reduce metadata exposure, variable Opus packet and VP8 stream-chunk
sizes and realtime traffic patterns still leak coarse activity to a capable
traffic observer.

Calling prioritizes freshness over delivery. Tor latency, TCP head-of-line
blocking, peer availability, capture permissions, decoder behavior, and local
resource pressure can delay or drop live frames. There is no offline call setup,
store-and-forward media, delivery guarantee, or promise that a lost decline or
hangup reaches the peer.
