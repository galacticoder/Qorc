# PIR Worker Deployment

## Overview

The PIR worker is the isolated cryptographic sidecar used for **discovery**
computational PIR. Qor keeps PIR/lattice arithmetic outside the JavaScript app
server (and outside the client webview) so it can enforce fixed database layout,
pinned worker identity, and fail-closed deployment without carrying a homemade
cryptographic implementation.

Scheme: **hintless SimplePIR** (Google `hintless_pir`). It outsources the
SimplePIR hint to the server's own LinPIR work, so there is **no client hint
download**.

Default path (discovery):
```txt
client opaque PIR query -> Qor server -> pinned hintless worker -> opaque PIR answer
```
The Qor server does not parse the PIR query and the worker has no
plaintext-index endpoint.

> Offline messages do **not** use this worker. The global message spool is served
> as a uniform per-epoch encrypted snapshot (`GET /api/spool/snapshot`). See
> `COMPUTATIONAL_PIR.md` §3.2 and `OFFLINE_MESSAGING.md`.

---

## 1. Package and build

Package: `workers/hintless/` — our reviewed C++ wrapper overlaid onto a pinned
checkout of `google/hintless_pir`:
```txt
workers/hintless/src/qor_pir_common.h      shared params, geometry, base64, proto helpers
workers/hintless/src/qor_pir_worker.cc     server-side HTTP worker  -> qor-pir-worker
workers/hintless/src/qor_pir_client.cc     client-side framed-stdio daemon -> qor-pir-client
workers/hintless/third_party/{httplib.h,json.hpp}   pinned single-header deps
workers/hintless/BUILD.overlay             Bazel targets (overlaid as //qor)
workers/hintless/Dockerfile                clones hintless_pir@pin, builds -c opt
workers/hintless/hintless.lock.json        pins + third-party sha256
```

**Must build `-c opt`.** Unoptimized lattice/NTT/RLWE code is 10–50× slower
(preprocess of one shard: ~51 s unoptimized vs ~2.4 s optimized).

```sh
docker build -t qor-pir-worker workers/hintless     # builds -c opt, ships the worker
node workers/hintless/contract_test.mjs <worker_url> <path/to/qor-pir-client>   # local contract test
```

---

## 2. Source and parameter pin

```txt
repository: https://github.com/google/hintless_pir
commit:     49434e086ec56d19546ca6e97353671b690ba19b
build:      bazel -c opt
scheme id:  hintless-simplepir
parameter:  hintless-simplepir-rlwe64-v1
```
Vendored single-header deps are sha256-pinned in `hintless.lock.json`
(cpp-httplib v0.18.3, nlohmann/json v3.11.3). The app server checks the
worker-reported scheme, parameter id, and source commit before required-worker
startup succeeds.

---

## 3. Quantum security position

Hintless SimplePIR is based on Learning With Errors (LWE/RLWE) assumptions, which
are believed post-quantum. Post-quantum direction does not mean unpinned
parameters are acceptable, so Qor locks the implementation source, scheme id,
parameter id, record layout, and worker URL. Describe it as a pinned LWE-based
PIR worker, not absolute quantum-proof magic.

---

## 4. Worker API

```txt
GET  /health            -> { ok, scheme:"hintless-simplepir", parameterId, sourceCommit }
POST /v1/databases      -> upload fixed-size records, build + preprocess epoch
POST /v1/public-params  -> fetch the hint-free public params for an epoch
POST /v1/query          -> answer one opaque HintlessPirRequest
```

Upload body / acceptance:
```json
{ "manifest": { "kind":"discovery", "epochId":"...", "parameterId":"hintless-simplepir-rlwe64-v1",
                "recordSize": 24, "recordCount": 4096, "databaseDigest":"..." },
  "records": ["base64", "..."] }
->
{ "accepted": true, "epochId":"...", "databaseDigest":"...", "parameterId":"...",
  "publicParams":"base64url(...)", "dbRows": 0, "dbCols": 0 }
```

Query body / response (opaque. No plaintext-index endpoint exists):
```json
{ "kind":"discovery", "epochId":"...", "query":"base64url(HintlessPirRequest)" }
->
{ "response":"base64url(HintlessPirResponse)" }
```

There is **no** setup/hint download endpoint. The per-epoch public params are a
~350-byte hint-free blob returned by upload / `public-params` and delivered
inline in the PIR manifest over the secure WebSocket.

---

## 5. Default Docker wiring

`docker/docker-compose.yml` starts `pir-worker` in the `server` profile.

```txt
PIR_WORKER_URL=http://pir-worker:8787
PIR_WORKER_PARAMETER_ID=hintless-simplepir-rlwe64-v1
PIR_WORKER_SOURCE_COMMIT=49434e086ec56d19546ca6e97353671b690ba19b
PIR_REQUIRE_WORKER=true
```

Startup is fail-closed: the server waits for the worker healthcheck and verifies
scheme id, parameter id, and pinned source commit. It refuses startup if
required-worker validation fails. Clients treat `workerReady: true` +
`queryPrivacy: "computational-pir-worker"` as the availability check.

Code references: `docker/docker-compose.yml`, `server/pir/pir-worker-client.js`,
`workers/hintless/`.

---

## 6. Local client helper

The selected index must never reach the server, so the client shells out to the
pinned `qor-pir-client` helper built from the same source as the worker and
bundled with the app:
```txt
src-tauri/binaries/qor-pir-client
```

It is a length-prefixed framed-stdio daemon (`qor-pir-client serve`) with two
record-major operations:
```txt
query-record   { parameterId, recordCount, recordSize, publicParams, index }
                 -> { request:"base64url", handle }       (keeps the client secret under handle)
recover-record { handle, response:"base64url" } -> { record:"base64url" }
```

Client flow (discovery, two-tier):
```txt
OPRF token -> deterministic candidate slots
candidate slot -> query-record -> opaque request -> server/worker -> opaque response
   -> recover-record -> ~24B fingerprint record (tier 1, oblivious match + cover)
   -> derive bucketId from the OPRF token -> fetch the target's bucket -> decrypt-filter locally
```
Because `GenerateRequest` stashes the LWE/LinPIR secret in the Client and
`RecoverRecord` consumes it, the same in-memory Client serves both halves of a
query (kept under `handle` in a small bounded map). The selected slot never
leaves the device.

Tauri commands: see `src-tauri/src/commands/pir.rs`. TypeScript wrapper:
`src/lib/pir/pir-client.ts`.

---

## 7. What the server sees

Visible: which epoch, rounded record count, fixed record size, query timing and
volume.

Hidden from the Qor server (tier 1): the searched handle, the selected record index, and whether a
fetched bundle decrypted successfully. The keys-blob itself is fetched by a **k-anonymous bucket
fetch** (not this worker) — the server learns only the target's bucket (one of ~K=32 users), never
the exact user. See `COMPUTATIONAL_PIR.md` §3.1.

---

## 8. Tests

```bash
npm run test:security          # always-run security checks
node workers/hintless/contract_test.mjs <worker_url> <qor-pir-client>   # worker+client contract
```
The contract test uploads fixed-size records, generates an opaque request on the
client daemon, has the worker answer it, recovers the record, and asserts it
matches — exercising the real worker and client binaries end to end.
