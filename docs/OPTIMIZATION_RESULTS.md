# Optimization results

Latest implementation: [44 KiB discovery and real-app results](#implemented-44-kib-discovery-format-and-real-app-comparison). Earlier sections preserve the measurements and proposals that led to it.

## Android response bridge

Verified on 2026-11-22. The main optimization was already in the working tree
when this task began. Anonymous HTTP responses use 64 KiB application chunks
and a preallocated exact-size byte buffer. Other native callbacks retain their
5 KiB limit. This work adds bounds for the chunk-size argument and immediate
rejection when callbacks exceed an already acknowledged byte count.

The comparison uses the receiver from Git HEAD, with 5 KiB chunks and
variable-length assembly, and the current receiver, with 64 KiB chunks and
direct assembly. It compares identical payload sizes so discovery-record
compaction is not counted as a bridge improvement.

| Response | Bytes | Earlier application callbacks | Current application callbacks | Reduction |
| --- | ---: | ---: | ---: | ---: |
| Current discovery bucket | 4,210,688 | 823 | 65 | 92.10% |
| Earlier discovery bucket | 6,307,840 | 1,232 | 97 | 92.13% |
| PIR response | 786,432 | 154 | 12 | 92.21% |

For four current discovery buckets, application callbacks fall from 3,292 to
260. Instrumentation confirms that the final assembly copy falls from
16,842,752 bytes to zero. Chunk data is written directly into its final buffer.
This removes one full decoded response buffer from the assembly step, roughly
8.03 MiB to 4.02 MiB per current bucket. Those figures exclude native buffers,
Base64 strings, browser bookkeeping, and the Tauri queue.

A headless desktop Chromium benchmark measured JSON parsing, Base64 decoding,
validation, and assembly for four responses. Results are medians of nine paired
trials, with alternating order after warming both implementations.

| Four-bucket payload | Earlier assembly time | Current assembly time | Reduction |
| --- | ---: | ---: | ---: |
| Current 16.06 MiB bucket download | 91.2 ms | 72.8 ms | 20.2% |
| Earlier 24.06 MiB bucket download | 133.6 ms | 111.1 ms | 16.8% |

This measures the JavaScript portion on desktop. It excludes the native
Android/WebView crossing, network, encryption, and decryption. Tauri can perform
additional internal channel fetches for larger messages, so application callback
counts are not a count of every internal IPC operation. No physical phone or
emulator was used. Battery drain and actual Android latency remain unmeasured.
The bridge changes no bytes downloaded over the network.

All 151 receiver assertions passed. They cover both chunk sizes and assembly
modes, empty responses, byte boundaries through the 16 MiB limit, byte-for-byte
reconstruction, acknowledgement ordering, duplicate or invalid offsets,
noncanonical Base64, invalid chunk sizes, oversized chunks, incorrect lengths,
acknowledgement overrun, cancellation, timeout, and failure-buffer wiping.
TypeScript checking, targeted lint, the production client build, and Linux
Rust checking also pass. These tests do not replace an Android device check.

## Discovery download sizes

A fresh bucket lookup downloads four isolated buckets with 64 records each,
256 encrypted identity records altogether. One requested bucket comes from the
target token and three are cover queries. Each query stays isolated and each
bucket has the same fixed record count and padded response size.

The large objects are identity records, including prekeys and signed identity
material. They are not ordinary chat messages or uploaded files. Compressing a
record before encryption makes its contents fit a smaller fixed padded class.
All records still have the same wire length. The compressed length remains
inside the encrypted record. Authentication and identity verification still
apply after decoding.

| Record class | Four padded bucket responses | Saving relative to earlier format |
| --- | ---: | ---: |
| Earlier approximately 96 KiB | 24.0625 MiB | Baseline |
| Current approximately 64 KiB | 16.0625 MiB | 8 MiB, 33.25% |
| Proposed 48 KiB | About 12.0625 MiB | About 12 MiB, 49.87% |

At this earlier stage, the 64 KiB format was selected in the working tree.
`DISCOVERY_BLOB_WIRE_BYTES` is 65,535 bytes and each padded bucket response is
4,210,688 bytes. The documentation previously retained the older numbers and
was corrected at that stage. The implemented 44 KiB format is recorded below.

The 48 KiB row is a projection, not an implemented or validated target. Moving
from the current 16.06 MiB download to about 12.06 MiB would save another 25%,
not another 50%. The quoted 50% uses the old 24.06 MiB baseline.

Before shrinking the record class further, tests must establish that the largest
permitted identity bundles fit, including poorly compressible key and signature
material. Compression and decompression limits, malformed data, authenticated
round trips, fixed padding, four isolated queries, and 64 records per bucket
must be checked. A configured 64 KiB limit alone is not proof that every largest
valid bundle fits. Shrinking the class cannot silently remove required keys,
signatures, or identity checks.

These totals cover the four bucket response bodies. OPRF, manifest, transparency,
HTTP/TLS/Tor overhead, retries, and other app traffic are additional. Local
retained peer material can avoid a fresh bucket lookup altogether.

## Evidence

Current implementation references are `src/lib/runtime/callback-bytes.ts`,
`src/lib/tauri-bindings.ts`, `src-tauri/src/commands/callback_bytes.rs`,
`src-tauri/src/commands/discovery.rs`, `shared/discovery-constants.js`,
`shared/anonymous-transfer-policy.js`, and
`src/lib/crypto/oprf-discovery-crypto.ts`.

The isolated baseline, test harness, result JSON, and build logs are in
`/tmp/qorc-android-bridge.GTQgvv`. They may be removed by temporary-file cleanup.
Reproduction uses `node build.mjs`, `node check.mjs`, and `node bench.mjs` in
that folder. The harness uses this workspace and its installed browser.
No changes were committed, deployed, or packaged into an APK in this task.

## Maximum discovery efficiency from small changes

Researched and tested separately on 2026-11-22. No application implementation
changed during this investigation. Prototypes, fixtures, source research and
full results are in `/tmp/qorc-discovery-efficiency.2bB6H7`.

The previous 40 and 32 KiB targets were too optimistic for the existing recovery
record. A recovery request can contain four distinct ML-DSA public keys, six
ML-DSA signatures, and two distinct ML-KEM public keys, before other fields.
The extra pending replacement root is important when establishing the maximum.

128 specimens across 16 independent key sets exercised registration, rotation,
recovery request and recovery cancellation. Production builders and certificate /
transparency-authorization validators passed 640 checks. The largest wire need,
including 128 bytes of record overhead, was 44,130 bytes using the existing
JSON and deflate. A lossless binary/deduplication prototype plus deflate reduced
that maximum to 43,706 bytes. Raw binary packing without deflate needed up to
44,254 bytes.

| Global record class | Four bucket response bodies | Saving from original 24.0625 MiB | Saving from current 16.0625 MiB | Finding |
| --- | ---: | ---: | ---: | --- |
| 48 KiB | 12.0625 MiB | 49.87% | 24.90% | More room for legitimate size variation |
| 44 KiB | 11.0625 MiB | 54.03% | 31.13% | Leading small-change candidate, existing codec |
| 43 KiB | 10.8125 MiB | 55.06% | 32.68% | Requires experimental packing in tested cases |
| 40 KiB | 10.0625 MiB | 58.18% | 37.35% | Tested recovery record does not fit |
| 32 KiB | 8.0625 MiB | 66.49% | 49.81% | Tested recovery record does not fit |

All download rows are projections for globally uniform response classes,
retaining four isolated queries and 64 records per bucket. No size is selected
per user or per record. A 44 KiB record would be 45,054 bytes, rounded down to
a multiple of three to keep the existing unpadded canonical Base64 shape.
That leaves 924 bytes beyond the largest tested current-format specimen.

Increasing deflate quality, reordering JSON fields, Brotli, Zstandard, and
binary packing were compared. Changing compression did not produce a smaller
practical class than 44 KiB in these cases. Packed+deflate fits 43 KiB, but that
only saves another 0.25 MiB, 2.26%, relative to 44 KiB. On the initial eight
fixtures it also increased measured desktop per-record encode/decode time from
about 1.05/0.24 ms to 1.17/0.33 ms. These are Node measurements, not Android
battery results. The new parser adds implementation and validation work.

A separate harness passed 1,121 assertions covering exact object reconstruction,
production certificate and authorization validation, real AEAD round trips,
authentication of altered ciphertext, Unicode, and bounded binary parsing.
1,000 random malformed binary frames were rejected.

This is not a proof that every currently accepted input fits a smaller class.
The discovery avatar-reference validator accepts an oversized hash string when
compared with itself, whereas legitimate publisher avatar hashes have exactly
64 lowercase hexadecimal characters. An oversized 24,000-character hash still
fits the current encrypted format but needs about 62 KiB. It prevents a
universal bound over the current accepted input space. Correcting that intended
format check, then proving all other legitimate bounds, is a prerequisite to
calling a smaller class safe.

The fixtures use real ML-DSA and ML-KEM material and real verified identity and
transparency signatures. The three 64-byte native Signal prekey signatures are
structural specimens, not native-libsignal verified signatures. Complete Signal
session setup, transparency-ledger integration, and Android runtime tests remain
outside this experiment. Boundary specimens use a conservative artificial clock
and component-level handle widths, not live publications.

The smallest production change worth pursuing is a globally smaller padded
class using the existing JSON/deflate codec, matching client/server/native size
constants, strict intended metadata bounds, and coordinated republication and
release. All cryptographic material, existing verification, query isolation,
cover queries, record count, and uniform padding must remain. 44 KiB is a
candidate supported by these tests, not yet a universal safe-fit guarantee.

Sources include [DEFLATE's 32 KiB window](https://www.rfc-editor.org/rfc/rfc1951.html),
[CBOR](https://www.rfc-editor.org/rfc/rfc8949.html),
[ML-DSA sizes](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf), and
[certificate compression resource limits](https://www.rfc-editor.org/rfc/rfc8879.html).


## Implemented 44 KiB discovery format and real-app comparison

Completed on 2026-11-23. The working tree now uses a single 45,054-byte encrypted
record and a 2,899,968-byte padded bucket response. Four bucket bodies total
11.0625 MiB instead of 16.0625 MiB, saving exactly 5 MiB, 31.13%,
per fresh lookup. Relative to the older 24.0625 MiB format, this is 54.03% less.
These are discovery bucket response bodies, not a measurement of total mobile
data, Tor overhead, retries, battery use, or every other app request.

| Quantity | Before this change | After this change |
| --- | ---: | ---: |
| Encrypted record | 65,535 bytes | 45,054 bytes |
| Canonical Base64 record | 87,380 characters | 60,072 characters |
| Padded bucket response | 4,210,688 bytes | 2,899,968 bytes |
| Four bucket response bodies | 16.0625 MiB | 11.0625 MiB |
| Queries and records | 4 queries, 64 records each | 4 queries, 64 records each |

The existing JSON/deflate representation, complete key material, AEAD layers,
selector checks, certificate checks, native Signal validation, and transparency
authorization remain. Padding uses one global class for real and cover records.
The compressed length stays inside authenticated ciphertext. No user-dependent
size selection, reduced query count, weaker cryptography, or new identity fields
were introduced.

Avatar validation moved into the reusable `src/lib/avatar/avatar-ref.ts` helper.
It requires an exact object shape, 32-byte lowercase hexadecimal blob ID and
hash, canonical Base64 32-byte key, and fixed WebP MIME type. Publication and
authenticated record decoding now apply it. The unbounded avatar-hash acceptance
found in the earlier investigation is rejected.

Client, shared server policy, and Rust response-size validation select only the
new format. No old-size decoder, fallback, or compatibility path was added.
Client and server must be deployed together and clients must republish.
Only the isolated test stack was restarted. Its old ephemeral discovery rows and
publication queue were cleared while the server was stopped, preserving the
test accounts and transparency history. This was test setup, not application
migration code. The production server was left running unchanged.

### Actual native-app search timings

Both executables were release builds of the real Tauri app. Two native Linux
instances used separate profiles and synthetic accounts against an isolated
Qorc server with real PostgreSQL, Redis, TLS, Tor onion transport, authentication,
OPRF, native cryptography, and key-transparency verification. WebDriver operated
the UI. Authentication, transport, and cryptographic checks were not mocked.
The before executable was preserved before editing the discovery size.

The requested fresh after search used a new test account and empty local profile.
A precondition check recorded zero conversations. The actual New conversation
UI searched for the same target account as the baseline and opened its chat.
A read of the running progress state confirmed 11,599,872 download bytes.
A cached lookup afterward confirmed the target identity root had not changed.

| First UI search | Before | After |
| --- | ---: | ---: |
| Click username to opened chat | 37.637 s | 55.031 s |
| Reached Verifying | 29.494 s | 25.652 s |
| Reached Checking keys | 30.289 s | 26.173 s |
| Remaining verification and chat opening after that label | 7.348 s | 28.858 s |

The fresh UI run was 46.2% slower overall despite reaching
verification 3.842 seconds earlier. The final label includes remaining identity
verification and chat setup. These observations do not isolate its exact cause.
A new profile and account have different trust-cache and connection state.
This result does not support promising a 31% improvement in cold-search time.

Additional fresh-network lookups invoked the mounted app's real `findUser`
callback with its supported `forceRefresh` option. They downloaded all four
buckets and completed verification. The harness waited at least 65 seconds
after each result to avoid the built-in refresh cache. A zero-byte cached trial
was rejected and rerun, rather than counted as a network measurement.

| Fresh-network callback trial | Before | After |
| --- | ---: | ---: |
| 1 | 48.129 s | 32.991 s |
| 2 | 56.773 s | 28.182 s |
| 3 | 37.189 s | 33.062 s |
| Median | 48.129 s | 32.991 s |

The after median was 31.5% lower in these runs.
Before trials used the original test searcher. After trial 1 used that searcher
and trials 2–3 used the new clean-profile account after its first UI lookup.
They all targeted the same publisher. These are small, exploratory Tor samples
with warm trust state, not paired proof of a consistent speedup. An extra after
lookup overlapped a missing-user test and is retained as functional evidence,
but excluded from this table. The cold UI result above remains the direct UI
observation and must not be replaced by the faster callback result.

The clean account's cached lookup took 64 ms with zero bucket bytes. A missing
username returned no result after 28.265 seconds and downloaded the same four
uniform responses, 11,599,872 bytes.

### Validation and limits

All 702 assertions passed across 128 builder-produced registration, rotation,
recovery-request and recovery-cancellation specimens with independent key sets.
Tests use the actual new record codec and AEAD, plus production certificate and
transparency-signature validators. They cover exact reconstruction, valid
avatar references, malformed metadata, wrong keys, tampered records, malformed
compression, authenticated decompression overflow, oversized JSON, invalid
content lengths, strict Base64, binary bucket round trips, uniform query/record
counts, and rejection of the old record and response sizes.

The largest tested current-format specimen needs 44,130 bytes including framing,
leaving 924 bytes in the selected class. This establishes coverage of these
bounded builder-produced specimens, not a mathematical proof over arbitrary
accepted input. All original fields and signatures are retained. The isolated
codec harness throws if an unused native worker call is unexpectedly reached.
Its fixture Signal signatures are structural specimens. The real native-app
search and message tests cover genuine app-generated Signal material.

The before app delivered one test message. After the fresh UI lookup, two
messages from the new account arrived at the other native instance. The sender
and recipient produced identical native-render hashes for each message and a
delivery receipt was observed. The first recipient observation was about
282.9 seconds after send. This includes transport scheduling, possible sender
lookup, and polling. It is functional evidence, not a paired messaging-latency
benchmark, and does not establish a message-delivery speed improvement.

The production frontend and optimized Linux Rust builds passed, as did
TypeScript checking, targeted lint, and whitespace checks. No emulator or phone
was used. Android battery use, radio traffic, and device latency are not measured
by these desktop results.

The full harness, before/after executables, private profiles, real database stack,
build logs and JSON evidence are in `/tmp/qorc-live-search.0Unx8j`.
`comparison.json` summarizes the measurements. `after-clean-ui.json` and
`after-clean-profile-precondition.json` record the fresh UI test.
`codec-verification.json` and `fresh-messaging-summary.json` record validation.
Private test credentials are stored separately with restricted permissions and
are not included here. Temporary-folder cleanup may remove these artifacts.
The test apps and isolated server are stopped after validation. No commit or
production deployment was made.


## Further data-use candidates, 2026-11-23

This is an investigation after the implemented 44 KiB discovery change.
No application source was changed for these candidates. Isolated prototypes,
research and models are in `/tmp/qorc-data-next.jkgq2yrs`. Figures below apply
to the named traffic category and must not be added as percentages of total
phone traffic. No Android radio, billing counter or battery measurement was made.

| Candidate | Current | Candidate | Evidence and limits |
| --- | ---: | ---: | --- |
| Lossless key-transparency record transport | 1408 KiB per sync | 576 KiB per sync | 59.09% less per page, isolated signed-record codec and production verifier tests |
| Binary sealed-envelope transport for relayed file chunks | Six 64 KiB cells | Five 64 KiB cells | 16.67% less file relay cell traffic, size and round-trip prototype |
| Reuse successful independent cover acknowledgements for liveness | About 308.5 MiB/day of separate heartbeat ping/pong cells | About 112.3 MiB/day in the healthy model | About 196.2 MiB/day saved, conditional simulation with unresolved privacy and fault cases |

The first recommendation is key-transparency packing. File-envelope packing is
another lossless representation candidate. Heartbeat reuse is a test candidate
and is not cleared for implementation under the unchanged-privacy requirement.

### 1. Key-transparency record packing

`shared/key-transparency-protocol.js` fixes every sync response at 1408 KiB and
permits up to 4096 records. Each record carries a 64-byte epoch label and a
64-byte record hash as 128-character hexadecimal strings, plus an epoch and
version. The read path pays this padded size even for an empty or small page.
`src/lib/key-transparency/client.ts` uses that path during discovery validation,
contact monitoring, cover monitoring and log audits.

The lab representation uses 140 bytes per record: 8 bytes for an exact bounded
epoch, 4 bytes for the existing bounded version, and both complete 64-byte hashes.
It retains the full signed head and wrapper as JSON metadata. After decoding,
it reconstructs the original objects and passes them to the unchanged production
head and delta verifiers. No contact label, cursor, digest or new cache token is
added to the requests. All pages, including empty pages, would use the same new
576 KiB class. Query scheduling, coverage, circuit isolation and monitoring
frequency stay the same.

The maximum tested page has 4096 records, safe-integer boundary epochs and
maximum versions. Its binary body is 580,288 bytes and the full
anonymous response needs 586,671 bytes including
the existing tunnel overhead. It fits in 589,824 bytes with
3,153 bytes left. The design saves 832 KiB per sync.
At an illustrative 72 one-page syncs per connected day, the saving is
58.5 MiB/day. Actual sync counts depend on monitors, reconnects, records and
server history. Zero-contact cover cycles can currently perform two syncs,
so that illustrative rate is not a total app-use estimate.

All 1,068 isolated assertions passed. They include exact round trips,
genuine ML-DSA signed heads, original log-fold verification, empty and full
pages, boundary integers, invalid versions, tampering, missing and reordered
records, wrong signers, a separately signed conflicting head, invalid lengths,
and 1000 malformed frames. The prototype currently covers successful sync
responses. Error responses, native transport allowlists, coordinated client/server
rollout and real app/device integration still need implementation tests.
No legacy format fallback is proposed.

Canonical signing can coexist with a different wire representation when the
canonical signed counterpart stays invariant. This is the principle described
in [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html#section-1).
The representation expansion being removed is described by
[RFC 4648, Base16](https://www.rfc-editor.org/rfc/rfc4648.html#section-8).
Strict bounds and parser validation remain necessary, as discussed in
[RFC 8949 security considerations](https://www.rfc-editor.org/rfc/rfc8949.html#section-10).
These sources support the encoding approach, not a full Qorc privacy proof.

### 2. Binary transport for encrypted file envelopes

`src/lib/websocket/encryption.ts` serializes logical messages as JSON before
splitting them into fixed 65,536-byte encrypted cells. Each cell can carry
65,332 bytes of logical content. `src/lib/transport/unified-signal-transport.ts`
forces file-transfer envelopes into the existing 256 KiB sealed frame class.
The ciphertext, KEM ciphertext, nonce, tag and probe are then Base64 text inside
that JSON. These fields are already ciphertext or opaque bytes and can be
represented losslessly as bounded raw bytes inside the same encrypted session.

For the server-to-client sealed-envelope wrapper, the measured size model is:

| Envelope class | Current logical bytes | Binary logical bytes | Current cells | Candidate cells |
| --- | ---: | ---: | ---: | ---: |
| Standard message | 177,078 | 132,884 | 3 | 3 |
| File chunk | 351,842 | 263,956 | 6 | 5 |

The current file chunk contains 29 KiB of file data. A 10 MiB input therefore
needs 354 file chunks. The data-carrying WebSocket cells alone would fall from
132.750 to 110.625 MiB per relay leg,
saving 22.125 MiB. These are frame
calculations, not a measured file transfer. They exclude control messages,
metadata setup, acknowledgements, retransmits, discovery, TLS and Tor overhead.
P2P file paths use different framing and are not assigned this saving.

The current large expansion reflects both deliberate fixed-size privacy padding
and Base64/cell rounding. This proposal removes representation waste while
keeping the sealed ciphertexts and every cryptographic field intact. It does
not make files smaller, change image quality, remove padding, reduce broadcast
recipients, or reduce cover frequency. All supported classes would need a strict
bounded binary decoder before the same existing application validation.
The ordinary message class remains three cells, so it gets zero wire saving
from this candidate. Claiming a generic 25% or 33% app-wide saving would be wrong.

The isolated prototype checks exact object restoration and rejects malformed
headers, truncation, extra bytes and invalid binary lengths. It does not yet
integrate the new representation with authenticated cell reassembly, live
broadcast flow control, native clients or retransmission handling.
The Base64 expansion follows
[RFC 4648, Base64](https://www.rfc-editor.org/rfc/rfc4648.html#section-4).

### 3. Heartbeat reuse, conditional research candidate

`src/lib/websocket/heartbeat.ts` requests a heartbeat every 35 seconds.
`sendHeartbeatMessage` sends an encrypted logical ping and the server returns
an encrypted logical pong. Each costs one full 64 KiB cell. In a healthy,
continuously connected first 24-hour window this is 2468 pairs, about
308.5 MiB of cell traffic, before TLS and Tor overhead.

Independently scheduled cover submissions already receive request-ID-correlated
blind-route acknowledgements. The idea is to count only a successfully validated,
current-session ACK for such a cover submission as liveness evidence, while
retaining an explicit heartbeat fallback. Every cover submission and its existing
schedule must remain. User-message activity must not decide heartbeat suppression.

The lab simulated 100 seeded healthy days, with uniform 10–45 second cover gaps
and immediate valid ACKs. A rolling explicit fallback at last-probe-send +35s
used an average of 898.25 separate ping/pong pairs/day.
That is 112.28 MiB/day, saving
196.22 MiB/day, 63.60% of this heartbeat
traffic. All modeled probe-send gaps stayed within 35 seconds to floating-point
tolerance. The 100 simulated traces and 11 envelope/size checks total
111 assertions. These are scheduling and representation tests, not a
running transport implementation or measured Android savings.

It is not safe to feed an arbitrary ACK into the current heartbeat
`handleResponse` function. The new path would need one-shot nonce/request binding,
capture-time native connection and session generation, monotonic age and deadline
checks, rekey/reset/resume rejection, and protection against a delayed old ACK
clearing a newer heartbeat deadline. Existing replay acceptance windows alone
are insufficient. A route ACK is not evidence of recipient identity or delivery.

There is also an unresolved privacy issue. Cover scheduling currently skips for
authentication waiters, pending ACKs and writer backlog. Removing an independent
fixed heartbeat floor could change idle-versus-busy/auth traffic patterns even
if the new code never reads user activity directly. Idle, busy, reconnect,
backpressure and active ACK-delay/drop traces must be compared before calling
this privacy-neutral. Failure detection, rekey behavior and standalone fallback
need fault-injected tests with the existing 90-second response deadline and
missed-heartbeat policy preserved. Until then this is not recommended as an
unconditional production change.

### Held back or already optimized

The unconditional second sync for an absent local transparency key is expensive.
For a deliberately random zero-contact cover key, a steady one-page cycle costs
2.75 MiB instead of 1.375 MiB. Removing that second read would save 50% of that
path, nominally 99 MiB/day at 72 cycles. It can also miss a newer or inconsistent
signed head or an epoch closure observed by the second read. Static snapshot
output equality is insufficient. This shortcut is held back under the security
requirement. Traffic volume/timing and ongoing consistency/freshness are real
privacy and security concerns, not resolved solely by encryption:
[RFC 6973](https://www.rfc-editor.org/rfc/rfc6973.html),
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html).

Already present in the app are cumulative shared spool-index updates, hourly
checkpoints, persistent consumed-probe tracking, cached verified peer material,
avatar hash caching and in-flight suppression, batched PIR rows with one fresh
expansion-parameter set, and binary anonymous-HTTP payloads for several bulk
operations. They are not counted again as new savings. Changing cover intervals,
using recipient-specific routing, reducing PIR privacy, reusing identifying PIR
keys, lowering key sizes, dropping gossip/audits or reducing file quality is not
part of these candidates.

### Evidence and next tests

`kt-wire-test.json` records the signed-page prototype. `transport-model.json`
records cell-size and healthy heartbeat models. `results/` contains validated
primary-source research and its security limits. `report.md` collects those
research fields. All files are in `/tmp/qorc-data-next.jkgq2yrs`, outside the app.
The next implementation-quality test should be the complete key-transparency
binary path with original verifier fault cases, constant padded sizes and real
native-app timing. Heartbeat work needs separate privacy/fault tests first.
