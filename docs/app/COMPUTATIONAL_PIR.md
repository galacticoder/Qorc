# Computational PIR

## Overview

Qor uses a reviewed Private Information Retrieval (PIR) implementation so that the
server does not receive a query selector, index selector, shard selector, bundle
selector, or message-destination selector on the discovery and offline-message
paths.

There are two retrieval surfaces. Each uses a different point on the PIR spectrum,
selected as the strongest and least expensive fit for that surface:

- Discovery uses computational PIR (Google HintlessPIR / hintless SimplePIR). A
  lookup targets one specific user out of potentially millions, so the retrieved
  index must be hidden. HintlessPIR does this with no client hint download.
- Offline messages (global spool) use a uniform encrypted database: a per-epoch,
  padded, gzipped encrypted snapshot that every client downloads byte-for-byte
  identically. For a full-window scan this is cheaper than computational PIR and
  unconditionally private (no lattice assumption): because all clients receive
  identical bytes, the set of envelopes a client cares about cannot leak.

Both surfaces are pinned.

Primary references:
- HintlessPIR implementation: `https://github.com/google/hintless_pir`
- HintlessPIR paper: `https://eprint.iacr.org/2023/1733`
- Background (SimplePIR / DoublePIR): `https://eprint.iacr.org/2022/949`

---

## 1. HintlessPIR Cost Model

Measured end-to-end against the pinned worker (`bazel -c opt`):

| database | record bytes | preprocess | query compute | query download |
|---|---|---|---|---|
| 8×8 (64 recs) | 1 | ~2.4 s | ~0.35 s | ~0.24 MB |
| 8×8 | 32 | ~15 s | ~0.7 s | ~7.7 MB |
| 1024×1024 (~1M recs) | 4 | ~4.3 s | ~0.43 s | ~1.9 MB |

Two properties determine the design:

1. Query latency is approximately independent of record count. A ~1,000,000-record
   database answers a query in ~0.43 s, so the discovery database can be large at
   low cost.
2. Cost scales with record size (~480 KiB fixed upload per query, plus ~240 KiB
   download per record byte). A 1 KB record is ~240 MB per query, which is not
   viable. Each PIR record must therefore be small (a handle), and large payloads
   are fetched separately.

These properties are why discovery is two-tier (§3.1) and why the multi-KB message
spool is served as a snapshot rather than through computational PIR.

---

## 2. PIR Surfaces

### 2.1 Discovery (computational PIR, two-tier)

Discovery resolves a user's prekey bundle without revealing the username.

- The discovery PIR database maps an OPRF-derived slot to a fixed-size record of
  ~24 bytes (a slot fingerprint). The record never contains the bundle.
- Tier 1 (HintlessPIR) confirms obliviously that a match exists (the server learns
  no index) and provides cover.
- The encrypted keys-blob is retrieved by a separate k-anonymous bucket fetch.
  Records are grouped into buckets of approximately K=32. The client and server
  derive the same bucket id (`bucketId = sha256(domain || epoch || slotKey) mod
  bucketCount`). The client fetches its target's whole bucket (padded with decoys)
  and decrypt-filters locally. Only the target's blob decrypts under the client's
  OPRF-derived key.
- The keys-blob content is unchanged: the full post-quantum prekey bundle with the
  same encryption. Only its delivery differs. PIR cannot carry it efficiently at
  this size.

Privacy. The bucket fetch is k-anonymous, not oblivious: the server learns the
target's bucket (one of ~K users), not the exact user. This is reinforced by
optional cover buckets, per-epoch bucket reshuffling, and Tor. It is the same
privacy class as the avatar store, and stronger than the removed by-handle fetch
(`/api/discovery/blob`), which revealed the exact record.

Avatars are not in the keys-blob (too large for PIR. See §2). They are stored in a
separate unlinkable content store and fetched by opaque id with cover traffic. The
keys-blob carries only a small `avatarRef`. See `docs/app/AVATARS.md`.

Code references: `server/pir/page-layout.js`, `server/pir/pir-databases.js`,
`src/hooks/discovery/useDiscovery.ts`.

### 2.2 Offline messages / global spool (uniform encrypted snapshot)

Sends enter a single shared global mix spool of sealed envelopes (recipient hidden
by sealed sender). Online clients receive them live by broadcast. Offline clients
catch up by scanning the recent window. Because a client must check the entire
window (any envelope may be addressed to it), there is no index to hide.

The spool is therefore served as a uniform per-epoch encrypted snapshot: padded to
a power-of-two floor with shape-matched decoys, gzipped, digest-verified, and
byte-identical for every client (suitable for CDN/Tor). The client downloads it,
trial-decrypts every envelope, and de-duplicates with a client-side cursor.

For this surface a uniform snapshot is stronger than per-record PIR: every client
fetches identical bytes, so the set of envelopes a client cares about leaks
nothing, unconditionally, and the server cannot determine a client's catch-up
offset. Recipient identity remains hidden by sealed sender.

Code references: `server/routing/spool-snapshot-service.js`,
`server/routes/api-routes.js` (`GET /api/spool/snapshot`),
`server/routing/blind-router.js`, `src/lib/websocket/global-spool-pir-handler.ts`.

---

## 3. Discovery Record Layout

The discovery PIR database uses fixed-size records:
- Record size is public and constant per epoch (a small handle record).
- Record count is rounded up to a privacy floor. Empty slots hold random padding.
- Records occupy deterministic epoch slots derived from client-known OPRF tokens.
  Record IDs are never usernames, inbox IDs, route IDs, or bundle IDs.
- The database geometry (`db_rows × db_cols`) is a deterministic function of
  `(recordCount, recordSize)`, so the client reproduces it without it being
  transmitted.

The server may know: the epoch, the rounded record count, the fixed record size,
and query timing/volume. The server must not know: the searched handle, the
selected slot, or whether a fetched bundle decrypted successfully.

Slot derivation:
```txt
slotKey = SHA-256("qor-discovery-pir-slot-key-v1" || token)
slot    = SHA-256("qor-pir-slot-v1" || "discovery" || slotKey || epoch || recordCount || probe) mod recordCount
```
The token is an OPRF epoch token, so the slot key is not a username or any
server-side id. Collision handling uses deterministic probe candidates: the client
queries candidates through PIR and confirms by decrypting the fetched bundle.

---

## 4. Backend: Hintless Worker

Computational PIR runs only in the isolated reviewed worker.

- Scheme: hintless-simplepir (Google `hintless_pir`).
- Parameter id: `hintless-simplepir-rlwe64-v1` (fixed lattice parameters. Only the
  per-epoch geometry varies).
- Package: `workers/hintless/` — a reviewed C++ wrapper (`qor_pir_worker`,
  `qor_pir_client`) over a pinned `hintless_pir` checkout, built with `bazel -c
  opt` (unoptimized lattice code is 10–50× slower). Pins and third-party hashes:
  `workers/hintless/hintless.lock.json`.

Worker boundary (server to worker, localhost HTTP):
```txt
GET  /health            liveness + pinned identity (scheme, parameterId, sourceCommit)
POST /v1/databases      upload fixed-size records -> build + preprocess, returns hint-free public params
POST /v1/public-params  fetch the per-epoch public params for an epoch
POST /v1/query          answer one opaque HintlessPirRequest
```
There is no setup/hint download endpoint. The hintless scheme has no client hint.
The per-epoch public params are a ~350-byte blob delivered inline in the PIR
manifest over the secure WebSocket.

Upload acceptance:
```json
{ "accepted": true, "epochId": "...", "databaseDigest": "...",
  "parameterId": "hintless-simplepir-rlwe64-v1", "publicParams": "base64url(...)",
  "dbRows": 0, "dbCols": 0 }
```
Query shape (opaque. No plaintext index endpoint exists):
```json
{ "kind": "discovery", "epochId": "...", "query": "base64url(HintlessPirRequest)" }
->
{ "response": "base64url(HintlessPirResponse)" }
```

With `PIR_REQUIRE_WORKER=true` (default), server startup fails if the worker is
missing, reports the wrong scheme/parameter id, or reports the wrong pinned source
commit. Clients use `workerReady: true` together with `queryPrivacy:
"computational-pir-worker"` as the availability check.

### 4.1 Client Query Generation

The client invokes the pinned `qor_pir_client` helper (a framed-stdio daemon) so
that PIR operations stay out of the webview:
```txt
manifest (incl. publicParams) -> qor-pir-client query-record -> opaque request
   -> server -> worker -> opaque response -> qor-pir-client recover-record -> tier-1 match (cover)
   -> derive bucketId from the OPRF token -> fetch the target's bucket -> decrypt-filter locally
```
`query-record` builds the request and holds the LWE/LinPIR secret in memory under a
handle. `recover-record` recovers using that stored secret. The selected slot does
not leave the device. The keys-blob is then retrieved by the k-anonymous bucket
fetch (`/api/discovery/bucket`), not PIR.

Code: `src-tauri/src/commands/pir.rs`, `src/lib/pir/pir-client.ts`.

---

## 5. Role of the Global Mix

PIR hides which index is retrieved. It does not hide when or how much a client
sends or polls. The global mix send path removes the destination selector before
PIR is involved, and fixed-rate polling plus cover writes hide activity timing. The
full configuration is:
```txt
global mix send + fixed-rate polling + cover + (discovery: HintlessPIR two-tier, spool: uniform snapshot)
```
Discovery PIR is fail-closed: if request generation, the worker response, recovery,
the bucket fetch, or decryption fails, the lookup stops rather than requesting an
exact token, handle, or bundle id from the server.
