# Qor

Qor is a Tauri desktop chat app for messaging, files, and audio/video/screen
calls. Every network path the client uses runs over Tor, and every application
payload is protected by a hybrid post-quantum layer on top of the Signal Double
Ratchet.

Current architecture docs:
- [Authentication](docs/app/AUTHENTICATION.md)
- [Discovery](docs/app/DISCOVERY.md)
- [Username enumeration resistance](docs/app/USERNAME_ENUMERATION_RESISTANCE.md)
- [Key transparency](docs/app/KEY_TRANSPARENCY.md)
- [Messaging](docs/app/MESSAGING.md)
- [Messaging cryptography](docs/app/MESSAGING_CRYPTOGRAPHY.md)
- [Offline messaging](docs/app/OFFLINE_MESSAGING.md)
- [Calling](docs/app/CALLING.md)
- [Blocking](docs/app/BLOCKING.md)
- [Avatars](docs/app/AVATARS.md)
- [Local data security](docs/app/LOCAL_DATA_SECURITY.md)
- [Environment variables](docs/ENVIRONMENT_VARIABLES.md)

## What this project is for

- Messaging app aimed to be the most secure and private in the world for anyone looking for serious self hosted messaging.
- Anonymous account entry and resume flows using an OPAQUE-style password
  envelope, a fixed-set oblivious record transfer, and Privacy Pass style
  one-time tokens instead of a stable account credential.
- Discovery through an RFC 9497 verifiable OPRF over Ristretto255 and
  fixed-shape k-anonymous bucket retrieval, so the server never receives a
  plaintext handle.
- Private append-only key transparency that authorizes discovered account roots,
  monitors contacts, and gossips signed heads inside encrypted messages. The log
  is unindexed and is never queried by account.
- Server fallback delivery through a sealed global mix spool with no per-user
  mailbox, plus direct P2P delivery over ephemeral Tor v3 onion services when
  peers can connect.
- Anti-abuse that carries no client identity at all: the server never reads or
  logs a client IP, and admission is enforced with anonymous failure counters,
  adaptive delay, and epoch-bound proof of work.
- Self-hosted deployment with Redis, Postgres, optional clustering,
  and an HAProxy edge tier.

Qor-Chat is not a metadata-free system. The server can still observe timing,
connection state, traffic volume, rounded database sizes, and some bucketed or
cover-traffic protocol artifacts.

## Run a Qor server with Docker

This is the simplest server setup. It works with Docker Linux containers on
64-bit Intel/AMD and ARM hosts running Linux, Windows, or macOS.

You need only:

- Docker Engine with Docker Compose v2 and Docker Buildx on Linux, or Docker
  Desktop on Windows or macOS. Docker Desktop already includes both plugins;
  Windows must be using Linux containers.
- Node.js 18 or newer to run the small deployment helper.
- This repository, downloaded as an archive or cloned with Git.

You do **NOT** install pnpm, Rust, Cargo, PostgreSQL, Redis, HAProxy, Tor,
OpenSSL/OQS, or their build toolchains on the host. Docker carries the server
runtime. The edge image contains authenticated, architecture matched copies of
HAProxy, patched Tor, liboqs, the OQS provider, and their private libraries.

From the repository root, run:

```bash
node scripts/start-docker.cjs all
```

When you run it, the helper:

1. Checks that Docker is running Linux containers on amd64 or arm64.
2. Creates `.env` when needed. If `SERVER_PASSWORD` is not already configured,
   it asks for that one 12-512-character value with hidden input.
3. Generates any missing database, Redis, authentication-root, and server
   identity secrets and saves them in `.env` with restricted permissions. An
   existing Redis password is replaced only when it cannot be accepted by the
   hardened Redis runtime (fewer than 32 characters or not base64url).
4. Detects occupied host ports and saves available replacements automatically.
5. Asks whether to run in the background; pressing Enter accepts the normal
   background mode.
6. Builds and starts PostgreSQL, Redis, the Qor server, HAProxy, and the Tor
   onion-service edge. TLS certificates are generated inside the stack.

The first build pulls the Docker base images and installs the Node server
dependencies inside the images; it does not install them on the host. Later
starts reuse the built images:

```bash
node scripts/start-docker.cjs all
```

After source or Dockerfile changes, force an image rebuild with:

```bash
node scripts/start-docker.cjs all --build
```

Useful management commands:

```bash
node scripts/start-docker.cjs logs
node scripts/start-docker.cjs stop all
node scripts/start-docker.cjs --help
```

Existing `.env` values are preserved, except for an invalid Redis password that
cannot start the service. The load-balancer logs print the onion service address
clients connect to. Keep `.env` and the Docker volumes backed up; they contain
the stable server identity and saved data.
`reset` intentionally removes the Docker volumes and is not a normal restart
command.

The `server` and `loadbalancer` profiles remain available separately for
advanced or multi-host deployments, but a normal single host server should use
`all`.

## Build the desktop client from source

Building the desktop application has additional requirements that are not
needed for a Docker server or for an installed Qor app:

- Node.js 18 or newer.
- pnpm through Corepack (`corepack enable pnpm`).
- Rust and Cargo.
- On Linux, the Tauri/GTK development stack, `dpkg-deb`, `patchelf`, and a
  complete GStreamer 1.0 installation. The build stages private WebKitGTK and
  screen-capture runtimes from these inputs.

Desktop source builds are supported on x86_64 and ARM64 Linux, and x86_64
Windows. A normal Linux build selects native PIR, Tor, WebKitGTK, GStreamer,
PipeWire, and AppImage assets for its host architecture. An x86_64 Linux host
can also produce real ARM64 installers through the Docker ARM64 build path. An
installed `.deb`, `.rpm`, `.AppImage`, `.msi`, or `.exe` is self-contained from
the repository and does not need Node.js, pnpm, Rust, Cargo, or the build cache.

### Install client build dependencies

```bash
node scripts/install-deps.cjs --client
```

The dependency installer targets Linux and checks source-build dependencies.

### Build and run

Start the desktop client:

```bash
node scripts/start-client.cjs
```

This stages the platform runtimes and PIR sidecar, builds the release app and
installer bundles, and then launches the result. To build the same bundles
without launching the app:

```bash
node scripts/start-client.cjs --bundle-only
```

That command builds only the host architecture. On a native ARM64 Linux host,
the same command builds ARM64 directly without emulation:

```bash
node scripts/start-client.cjs --bundle-only --target arm64
```

On x86_64 Linux, build genuine ARM64 installers through an ARM64-capable
Docker Buildx builder with:

```bash
node scripts/start-client.cjs --bundle-only --target arm64
```

Build both x86_64 and ARM64 release bundles sequentially with:

```bash
node scripts/start-client.cjs --bundle-only --all-architectures
```

Native installers are written beneath `src-tauri/target/release/bundle`.
Cross-built ARM64 installers are written beneath
`src-tauri/target/aarch64-unknown-linux-gnu/release/bundle`. Docker must be able
to build `linux/arm64` images. The ARM build keeps persistent BuildKit layers
and named Cargo, pnpm, Tauri-tool, and runtime-download caches; exported layer
metadata is kept in `.cache/buildkit/client-linux-arm64`.

For the fastest x86_64-hosted path, point the command at a native remote ARM64
Docker context and select its Buildx builder:

```bash
docker buildx create --name qor-arm64 --driver docker-container arm64-host
QOR_ARM64_BUILDER=qor-arm64 node scripts/start-client.cjs --bundle-only --target arm64
```

On an x86_64 host, `QOR_ARM64_BUILDER` is required and must point to a native
ARM64 node. Install the
client tooling and Buildx with:

```bash
node scripts/install-deps.cjs --client-arm64
```

The frontend is built in its own Docker stage. UI-only edits reuse the pnpm
dependency layer and all previously compiled Rust dependencies; only the final
application crate/link and package assembly are invalidated. AppImage assembly
also reuses the already-built Debian payload and compresses the prepared AppDir
once instead of first creating and then recompressing an intermediate AppImage.

To launch an already built AppDir or release executable without rebuilding or
restaging anything:

```bash
node scripts/start-client.cjs --run-only
```

`--run-only` is a repository development helper, not a packaging step. It uses
whatever existing output is present, so source changes are not included until a
normal or `--bundle-only` build completes. An installed `.deb`, `.rpm`,
`.AppImage`, `.msi`, or `.exe` runs independently of the repository.

## Security model brief summary

Every boundary below has a named wire form with a required algorithm binding. The complete table is in
[Messaging cryptography](docs/app/MESSAGING_CRYPTOGRAPHY.md).

| Boundary | Wire form | Primitives |
| --- | --- | --- |
| Signal storage and ratchet | libsignal PQXDH/SPQR v1 plus `signal-pq-v2` | Double Ratchet, X25519, ML-KEM-1024, SPQR, XChaCha20-Poly1305 |
| End-to-end outer envelope | `hybrid-envelope-v2` | ML-KEM-1024 + X25519, HKDF, AEAD, ML-DSA-87 |
| Server sealed sender | `ss-v2` | ML-KEM-1024, BLAKE3 KDF, AES-256-GCM |
| Direct P2P session | `hybrid-mlkem1024-mldsa87-session-v5` | ML-KEM-1024 + X25519, ML-DSA-87, directional AEAD and per-call-stream subkeys |
| Client to server WebSocket | `pq-ws-8` | two ML-KEM-1024 contributions + X25519, ML-DSA-87 server authentication, directional AEAD in authenticated 64 KiB binary cells |
| Anonymous HTTP tunnel | `qor-pq-anonymous-http-v1` | ML-KEM-1024 + X25519 request KEX, responder ML-KEM contribution, ML-DSA-87, padded AEAD |
| Account-root transparency | `qor-key-transparency-v2` | SHA3-512 rolling hash chain, ML-DSA-87 heads and root/recovery authorization, XChaCha20-Poly1305 events |
| Client-facing TLS KEX | TLS 1.3 with `X25519MLKEM768` only | hybrid ML-KEM-768 + X25519 |

- **Authentication.** Signup and login run an OPAQUE-style password envelope
  against a fixed-size anonymity set of opaque credential records, with a
  1-out-of-N oblivious record transfer over the whole set. The server performs
  identical record work for every slot and never learns a credential ID,
  username, or slot index. Each request carries a 64-byte connection-bound
  nonce that is consumed exactly once, so a captured transcript cannot be
  replayed into a different connection. A successful login blind-issues 250
  one-time `account-auth` Privacy Pass tokens plus `server-entry` tokens, and
  every later privileged operation spends a token rather than presenting a
  stable account credential.
- **Message content.** libsignal supplies the Double Ratchet with PQXDH
  ML-KEM-1024 prekeys. SPQR v1 is mandatory, non-post-quantum ratchet state is
  rejected outright, and every Signal ciphertext is additionally sealed in a
  required ML-KEM envelope, including messages on an already established
  session.
- **Outer envelope.** `hybrid-envelope-v2` encapsulates to the recipient's
  certified ML-KEM-1024 key and performs X25519 against a separate certified
  Hybrid subkey. The two secrets are domain-separated into the AEAD key, and the
  sender signs the routing header with ML-DSA-87. The receiver requires the
  certificate, outer sender hint, Hybrid signature, and final libsignal sender
  identity to agree before a plaintext is released.
- **Symmetric layer.** Application AEAD is a cascade: AES-256-GCM under one
  derived key, then XChaCha20-Poly1305 under an independent key, with a BLAKE3
  MAC over the result. Breaking one cipher is not enough to recover a plaintext.
- **P2P delivery.** Peers connect over ephemeral Tor v3 onion services on TCP,
  so neither side ever learns the other's IP address, and run a mutually
  authenticated hybrid PQ Noise-style session (ML-KEM-1024 + X25519 for key
  agreement, ML-DSA-87 for peer authentication, directional AEAD keys with a
  sliding replay window and a 24-hour session age bound). Audio, video, and
  screen share ride dedicated streams inside that one authenticated session.
  File chunks travel over the same P2P session or the live server route and are
  never written to the offline spool.
- **Server fallback delivery.** Sealed-sender envelopes are written to one
  shared global mix spool with randomized release times and shape-matched cover
  entries. There is no destination selector on the wire and no per-user mailbox.
  Live candidates are broadcast to authorized sockets and trial-decrypted
  locally, offline catch-up is retrieved by private information retrieval, so
  the server never learns which entry belongs to whom.
- **All server-bound traffic goes through Tor.** Discovery buckets, OPRF
  evaluation, key-transparency sync and append, avatar operations, and offline
  spool retrieval all travel through one `/api/anonymous` hybrid-PQ HTTP route,
  on a fresh Tor SOCKS isolated connection per request with HTTP reuse
  disabled. Each operation is pinned to a fixed request and response size class,
  so an observer sees a padded envelope of a standard size rather than an
  operation-specific length.
- **Trust anchoring.** A discovery record's keys are installed only when its
  certified account root matches the verified append-only key-transparency log
  for that handle. A verified root change, explicit revocation, or server-scoped
  security incident revokes authorization, stops queued peer work, and removes
  native Signal identities, sessions, and peer ML-KEM state before the local
  monitor checkpoint can advance.
- **Local data.** History, queues, block lists, profile data, and file metadata
  live in an encrypted account-bound native database with SQLCipher page
  encryption and authenticated row encryption. The account vault is wrapped with
  Argon2id (v1.3, 512 MiB, 6 iterations, 4 lanes, 32-byte salt) over a
  length-prefixed transcript of username, account password, and local encryption
  passphrase, then sealed with XChaCha20-Poly1305 bound to the account scope and
  published public keys. The random account master, persistent identity seeds,
  Signal state, database keys, and token-vault keys never cross Tauri IPC, the
  renderer only receives public keys and purpose-bound operation results.
  Decrypted conversation state is served in 50-message pages, one page per
  request, and inactive conversations are trimmed back to their newest 50
  records and 2,048 total. Account transitions invalidate pending async work
  before slow key cleanup begins. See
  [Local data security](docs/app/LOCAL_DATA_SECURITY.md).
- **Identity-free anti-abuse.** The server never is able to read or log a client IP, and
  it has no stable client identifier to rate-limit against. Brute-force defense
  is an anonymous failure counter with adaptive delay, and anonymous operations
  are gated by epoch-bound BLAKE3/SHA-256 proof of work with Redis backed
  single use enforcement plus global concurrency and CPU ceilings.

### Quantum-resistance boundary

Qor-Chat is a hybrid system, not a claim that every dependency and network layer
is post-quantum. Current message payloads require ML-KEM-1024 confidentiality and
ML-DSA-87 authentication layers, and Signal sessions require PQXDH plus SPQR v1.
The classical X25519 contributions remain in the hybrid derivations so security
does not depend on only one primitive family.

Qor-controlled client-facing TLS is pinned to TLS 1.3 only, with
`TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` as the only
ciphersuites and the hybrid `X25519MLKEM768` group as the only key-exchange
group, on both the Node origin and the HAProxy edge tier. Session tickets,
session resumption, and early data are all disabled on the client/server path.
Note that the TLS group is ML-KEM-768 while the application layer above it uses
ML-KEM-1024, TLS is the outer wrapper, not the layer the message security rests
on.

OPAQUE/VOPRF, Ristretto255-based discovery and Privacy Pass, Signal identity
keys, Tor path establishment, and TLS certificate signatures still contain
classical public-key cryptography. The oblivious record transfer used at login
is also not a malicious-receiver-secure OT construction, its exact residual
assumptions are documented in
[Authentication](docs/app/AUTHENTICATION.md).
Application-layer hybrid encryption protects message bytes carried over those
channels, but does not make availability, traffic analysis, discovery, or the
whole transport stack post-quantum. See the detailed limitations in
[Messaging cryptography](docs/app/MESSAGING_CRYPTOGRAPHY.md).

## Discovery and avatars

Discovery resolves a user's current encrypted key material without sending any identifiable or linkable handle to the server.

- The client normalizes the handle, hashes it to a 32-byte pseudonym, and blinds
  that point for an RFC 9497 VOPRF evaluation over Ristretto255. It verifies the
  returned DLEQ proof, then derives a stable record-encryption key and a
  different token for each six-hour discovery epoch entirely locally. The server
  evaluates a blinded point and learns nothing about the handle.
- Each lookup covers four of the 512 fixed buckets: one token-derived bucket and
  three cover buckets derived under a per-session client secret, so repeated
  lookups of the same handle reuse the same set instead of a re-randomized one
  an observer could intersect. Only the current epoch's bucket is ever
  requested, asking for the current and previous epoch together would let the
  server intersect the two sets.
- The four buckets are requested as four separate single-bucket operations, each
  on its own freshly isolated Tor circuit with its own proof of work, and every
  bucket is padded to the same 64-entry count of 131,072 character records inside a fixed 8.5 MiB response. The
  server therefore answers a stream of indistinguishable single-bucket requests,
  but it still sees their timing and volume, so discovery is k-anonymous
  retrieval rather than oblivious retrieval.
- Returned records are decrypt-filtered and identity-validated locally, then
  authorized against the append-only key-transparency log before any Signal,
  Hybrid, or P2P key is installed.
- Avatars are not embedded in discovery records. They are stored as
  end-to-end-encrypted, uniform-size PURBs (padded to a fixed 256 KiB capacity
  with the true length encrypted inside) in a content store with no owner
  column, and fetched in a shuffled ten-ID batch mixing the real target with a
  stable decoy set. A miss is answered with an identically sized synthetic blob.

## Offline delivery

The server stores no message under a
username, handle, inbox, route, bucket, or recipient-specific queue.
Server-routed messages enter a shared global mix spool as sealed encrypted
envelopes, all of one fixed size, after a randomized delay and mixed with
shape matched cover entries. Offline clients fetch a compact tag index (identical for every client) recognise their own entries from a trapdoor only
they can compute, and retrieve each one by private information retrieval, so the
server never learns which entry was taken. Each logical record is packed into
nine fixed 16 KiB PIR rows queried together under one expansion parameter set
and reconstructed locally, and the tag-index and PIR requests run on their own
dedicated Tor daemon, SOCKS listener, and circuit pool so catch-up traffic can
never share a circuit with discovery or messaging. File transfers are
live/peer-to-peer only and are not retrievable while offline.

Local retry queues are only for messages the sender cannot encrypt yet, usually
because recipient discovery material is not available locally. Local retries
and the server mix-recovery pool expire after at most one hour. The encrypted
global spool defaults to 24-hour retention and can be configured up to seven
days.

Call signaling is live-only and never enters reconnect recovery or the offline
spool. Incoming ringing also requires current key-transparency authorization
plus the calling service's schema, recipient, timestamp, blocking, rate, and
active-call checks. The complete signaling, admission, direct-media,
cryptography, retry, and cleanup architecture is in [Calling](docs/app/CALLING.md).

## Bundled desktop runtimes, Tor, and PIR client

Linux and Windows desktop releases embed the target-matched Tor Expert Bundle
and PIR client into `qor` or `qor.exe`. The build refuses to compile unless the
vendored Tor archive matches its release-pinned SHA-256, and hashes the PIR
client with BLAKE3 into the binary. Both digests are re-checked at runtime before
either artifact is materialized on disk, so a tampered on-disk copy cannot be
launched. Tor is unpacked into the private app-data directory during native
startup, so end users do not install Tor separately and the app never downloads
Tor executable code at runtime. Vendored Tor provenance and update instructions
are in
[src-tauri/vendor/tor/README.md](src-tauri/vendor/tor/README.md).

Linux bundles also carry an app-private WebKitGTK 2.52.6 runtime and helper
processes obtained from release-pinned, SHA-256-verified packages. Native Linux
screen capture carries a curated GStreamer/PipeWire runtime, launcher, plugin
scanner, SPA support, PipeWire audio/video conversion adapters, and an artifact
manifest containing every staged file's SHA-256. Package validation rejects a
runtime missing either adapter. At runtime Qor selects only a complete private
SPA root and disables GStreamer's system plugin search for the capture process,
so a user's installed GStreamer or SPA plugin set does not replace the packaged
capture implementation.

These bundled files remove any dependency on repository staging directories or
build caches. They do not replace operating-system facilities: Linux still
needs a working desktop portal and PipeWire session for screen selection and
capture, permission to access selected devices, and the base GTK/system
libraries declared by its package format.

Server package commands are in [server/package.json](server/package.json), and
Docker orchestration lives in [docker/docker-compose.yml](docker/docker-compose.yml).

## Contributing and reporting issues

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) before contributing and use
the project issue templates when reporting bugs. Security reports should follow
[SECURITY.md](docs/SECURITY.md).

## License

[![License: qorc Non-Commercial Copyleft v1.0](https://img.shields.io/badge/License-qorc%20Non--Commercial%20Copyleft%20v1.0-6d4aff.svg)](LICENSE)
