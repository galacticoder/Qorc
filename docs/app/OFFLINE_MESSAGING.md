# Offline Messaging

Offline delivery is a shared encrypted stream. The
server stores no message under a username, handle, inbox, route, bucket, or
recipient specific queue.

## Server Acceptance

The sender submits an exact `blind-route` request containing a random request ID
and one sealed envelope. Every envelope carries a one-time detection
`tag` and a 32-byte `probe`, both validated and metered and both required on
every envelope. See the Detection Tags section below. Call signaling and typing
state may additionally select the exact `live-only` delivery policy described
below. Destination selectors and all other fields are rejected. The server
validates canonical encoding, one of the two fixed ciphertext sizes, and
per-connection/global resource budgets before returning a correlated
`BLIND_ROUTE_ACK`.

That ACK means only that the opaque envelope entered the mix. It does not reveal
whether a recipient exists, is online, is blocked, or can decrypt the entry.

Code:

- `server/routing/blind-route-schema.js`
- `server/handlers/delivery-handlers.js`
- `server/routing/sealed-sender.js`

## Delayed Global Mix

Accepted envelopes first enter the Redis delay and processing sets under the
current `mixnet:{global}` namespace. Each entry receives a randomized release
time. A single-flight relay:

1. Recovers stale processing claims.
2. Atomically claims due entries.
3. Adds shape-matched cover entries.
4. Shuffles the batch.
5. Broadcasts candidates to authorized live sockets.
6. Writes only real candidates to one global spool.

Synthetic cover is broadcast with the live batch but is not retained in the
catch-up spool, so expendable cover cannot consume capacity needed by real
offline ciphertexts. Cover is generated at the spoolable size with a real
ephemeral probe, so it is indistinguishable from a genuine entry.

The spool is bounded by both count and actual serialized bytes. A Lua operation
repairs missing byte-counter or per-entry-size state from the authoritative
stored envelopes before applying the cap.

Default global spool limits are 32,768 entries, 512 MiB, and 24 hours. The
delay/processing recovery pool has a hard one-hour maximum, the catch-up spool
can be configured up to seven days. See
`docs/ENVIRONMENT_VARIABLES.md` for all deployment controls.

Code: `server/routing/blind-router.js`.

## Tagged-Lane Retrieval

Each pass, a client fetches the whole tag index (`spool/tag-index`), tests every
unseen entry's probe against its own detection key, and issues one PIR query per
match (`spool/pir`). Neither request carries a selector, an account, or a
recipient. The server publishes the tag index and PIR database as one completed
snapshot, its opaque snapshot ID prevents positions from being answered against
a different ordering. Each 132,668-byte logical record is packed into nine
fixed 16 KiB PIR rows. The native client batches all nine private row queries
with one expansion-parameter set, the server returns all nine encrypted answers
through one anonymous request, and the client reconstructs the record locally.
Tag-index and PIR requests use a dedicated Tor daemon, SOCKS listener, circuit
pool, and single-request queue. One record is retrieved at a time, so catch-up
traffic cannot occupy the primary daemon or anonymous queue used by discovery,
key transparency, messaging, and calls. A worker snapshot is not recycled while
it has queued answers.

Code:

- `server/routing/blind-router.js` , spool, tag index, PIR record source
- `server/pir/pir-service.js` , atomic double-buffered PIR snapshots
- `server/routes/api-routes.js`, `server/routes/pq-anonymous-http.js`
- `src/lib/spool/tagged-lane-retriever.ts`, `src/lib/spool/pir-fetch.ts`
- `src/hooks/app/useOfflineMessages.ts`

Retrieval is not a hard delivery guarantee: capacity eviction, expiry, or
prolonged offline time past the 24-hour retention can still remove a ciphertext
before its recipient observes it.

See `docs/app/PRIVATE_SPOOL_RETRIEVAL.md` for the tag derivation, the trapdoor
detection scheme, and the PIR cost model.

## Detection Tags

Every sealed envelope carries an 8-byte one-time `tag`. It exists so a recipient
can find its own entries by downloading a compact index rather than trial
decapsulating the whole spool. The index is tiny relative to the 132,668 bytes
in each retrievable record.

The recipient publishes an X25519 **detection public key** in its discovery
blob. For every message, the sender generates a fresh ephemeral key, computes
the shared secret, derives the tag, and attaches the ephemeral public key as the
envelope's `probe`. The recipient reaches the same tag using its detection
private key and that probe. Each tag is independent: there is no per-peer chain
state to desynchronize and no stable recipient tag that could become a
pseudonym.

Every envelope carries a real X25519 probe, including live cover traffic.
**There is deliberately no lane or type field**, and no field that is present
only on first contact: either would tell the server which entries represent new
relationships.

`GET /api/spool/tag-index` returns every live tag as one concatenated hex string.
The request carries no selector, so two clients asking are indistinguishable and
the response is byte-identical for everyone. The whole index is downloaded rather
than a delta: a delta would be cheaper but would expose a per-client cursor.

Detection is load-bearing: PIR is the only catch-up path, so an entry the index
fails to predict never reaches a recipient who was not connected for its live
broadcast. See `docs/app/PRIVATE_SPOOL_RETRIEVAL.md`.

**The spool holds exactly one ciphertext size** , 131,088 bytes, 131,054 of usable
content , so PIR records are uniform by construction rather than by filtering.
Anything else is rejected on append (`global_mix_spool_unsupported_size`).

Durable sends use the 128 KiB STANDARD frame, and the server rejects an off-size
durable request before acknowledging it.

**File chunks are not retrievable while offline.** They use the 256 KiB frame,
travel live or over P2P, and are never spooled , a uniform 262 KiB PIR record
would put the database in the gigabytes and push its build past the epoch.

Code:

- `shared/spool-tag-protocol.js`
- `src/lib/spool/`
- `server/routing/blind-router.js`

## Local Retry Queue

If recipient discovery keys or Signal setup are unavailable, the client cannot
construct a sealed server envelope. In that case it stores the operation in the
encrypted local database under the durable pending-retry queue.

Private message and edit entries carry no content in memory or in the renderer's
durable retry snapshot. Their operation IDs select native-only content records
bound to the exact account, recipient, application type, and wire operation.
Rust inserts that content only after verifying every binding. Reaction controls
may retain their bounded emoji value inline, delete controls have no content.
Reply metadata contains the target ID and optional sender but never a quoted
body. Queues are bounded by peer count, entries per peer, 500 total entries, and
a 16 MiB serialized snapshot budget. Every entry retains its original enqueue
time and becomes ineligible after one hour, loading, enqueueing, reconnect
draining, persistence, and a ten-second in-process maintenance pass all remove
expired operations and their native send bindings. A successful send removes
and persists the corresponding retry operation, then revokes or deletes its
send binding. The bounded in-memory WebSocket reconnect queue enforces the same
one-hour creation-time cutoff and prunes while disconnected as well as before
enqueue and flush.

Code:

- `src/hooks/message-sending/retry-queue.ts`
- `src/hooks/message-sending/useMessageSender.ts`
- `src-tauri/src/message_content.rs`
- `src-tauri/src/commands/signal.rs`

## Delivery Semantics

- Outgoing persistent messages are locally durable before network transmission.
- Server ingress ACK and recipient delivery receipt are separate.
- P2P writes wait for an end-to-end receipt and spool the same encrypted payload
  on timeout.
- Duplicate Signal ciphertexts and message IDs are rejected locally.
- A probe is persisted as consumed after its envelope reaches an authenticated
  terminal result, including a duplicate, stale counter, blocked message, or
  already-processed envelope. Temporary sender verification and Signal-session
  failures remain retryable.
- Native Signal receive-ratchet state and plaintext staging commit atomically.
  Once that durable stage succeeds, retrieval may advance past the entry even if
  later application/database work fails, the native pending row remains
  unacknowledged and owns the local retry. This prevents one locally durable
  candidate from indefinitely blocking every other candidate in the epoch.
- File transport ACKs stop chunk retransmission, but a file is delivered only
  after complete assembly and atomic local persistence.

## Live-Only Signals

Three signal types use the messaging encryption pipeline but are live-only rather
than durable: call signaling (`CALL_SIGNAL`) and both typing states
(`TYPING_START`, `TYPING_STOP`). The sender marks them with
`deliveryPolicy: "live-only"` on the blind-route request, the server then skips
both the mixnet delay pool and the durable spool, broadcasting to live sockets
only. They are also excluded from reconnect recovery, delivery journals, delayed
server recovery, and the local outbound queue on write failure.

Both cases are the same requirement: the signal describes a moment rather than a
fact. An old call must not ring after reconnection, and a typing indicator
replayed during catch-up would show "typing…" for a message that already
arrived. The complete call signaling and retry lifecycle is documented in
`docs/app/CALLING.md`.

Code: `src/lib/transport/unified-signal-transport.ts` (`LIVE_ONLY_SIGNAL_TYPES`),
`server/routing/blind-route-schema.js`, `server/routing/blind-router.js`.

## Metadata Limits

The server can observe blind-route timing, global mix activity, tag-index and PIR
request timing, and response sizes. It cannot tell a first message from an
ongoing one: both carry a tag and a probe it can neither derive nor recognise,
and no other field describes the message. It cannot select or confirm the
recipient from the active send or a retrieval request, and it cannot tell which
entry a PIR query selects , that is the whole point of the query.

The server decrypts the anonymous tunnel operation and therefore knows that a
given request is a tag-index or PIR fetch, while an intermediary sees only the
common route and one fixed size. Tor, per-call isolation, delay, cover, an index
identical for every caller, and a single sealed-envelope size reduce correlation,
they do not defeat a global timing-and-volume observer.
