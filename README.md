# Endtoend — End‑to‑End Encrypted Messaging/Calling

Endtoend is a desktop chat client and Node.js server designed for end2end quantum secure messaging. It uses the Signal Protocol for forward secrecy with an additional post‑quantum (PQ) envelope.

For more details of the Server/Client cryptography, read [`docs/Server-Cryptography.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/Server-Cryptography.md) and [`docs/Client-Cryptography.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/Client-Cryptography.md)

## Setup

**Windows Users:**

Run this in PowerShell (Admin):

```powershell
# Install Node.js, Git, and Docker
winget install OpenJS.NodeJS Git.Git Docker.DockerDesktop -e --accept-source-agreements --accept-package-agreements

# Refresh PATH for current session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Setup pnpm for client dependencies
npm install --global corepack@latest
corepack enable pnpm
```

**Note:** 
- Close and reopen PowerShell after running these commands
- You may need to restart your computer after Docker Desktop installation

### Local Setup

1. Clone the repository
  - `git clone https://github.com/galacticoder/end2end-chat-site.git`

2. Install dependencies:
   - **Server:** `node scripts/install-deps.cjs --server`
   - **Client:** `node scripts/install-deps.cjs --client`

3. Configure environment variables (**YOU DO NOT HAVE TO CONFIGURE ANYTHING TO START THE SERVER WITH ALL FEATURES! EVERYTHING IS ALREADY SETUP IN THE PROVIDED ENV FILE!** See [`docs/ENVIRONMENT_VARIABLES.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/ENVIRONMENT_VARIABLES.md) for configuration if interested.)

4. Start the server: `node scripts/start-server.cjs`

5. Start the desktop client: `node scripts/start-client.cjs`

### Docker Deployment

1. Edit `.env` and set secure passwords

2. Build and start **server** (DB + Redis + Server):
   ```bash
   node scripts/start-docker.cjs server
   ```

3. Build and start **load balancer**:
   ```bash
   node scripts/start-docker.cjs loadbalancer
   ```

## What this project is for
- Privacy‑preserving one‑to‑one messaging with forward secrecy and PQ protection
- Operating in adversarial networks (interception, replay, future decryption attempts)
- Running as a self‑hosted service with optional clustering and a Linux‑based edge tier

This is not a metadata‑free system. The service retains the minimal routing data required to deliver messages; message contents and most user artifacts are encrypted end‑to‑end.

## Security model at a glance
- Inner layer: Signal Protocol (libsignal‑client) provides double‑ratchet forward secrecy, break‑in recovery, and authenticated key exchange. Native Kyber pre‑keys are used where supported.
- Outer layer: a PQ envelope wraps Signal ciphertext using ML‑KEM‑1024 (Kyber) for key encapsulation, AES‑256‑GCM and XChaCha20‑Poly1305 for confidentiality, and BLAKE3 for authentication.
- Device‑bound auth: refresh flows require a signed device proof (Ed25519) tied to a stable device identifier; stolen tokens alone are not sufficient.
- Local secrecy: the desktop stores history in an encrypted local database using a PQ AEAD construction; raw plaintext is not kept on disk.
- Tor: the desktop downloads and runs a bundled Tor client, configures transports (obfs4/snowflake), and verifies connectivity before use. Tor routing is required.

## Cryptography details
- Public‑key primitives
  - ML‑KEM‑1024 (Kyber) via @noble/post‑quantum for PQ KEM
  - ML‑DSA‑87 (Dilithium) via @noble/post‑quantum for signatures
  - X25519 for classical ECDH where needed
- Symmetric primitives
  - AES‑256‑GCM
  - XChaCha20‑Poly1305
  - BLAKE3 for keyed MACs and KDF contexts
- Signal layer
  - libsignal‑client for Double Ratchet and PreKeys
  - Uses native Kyber pre‑keys where available; sessions are created/rotated through standard Signal flows
- PQ envelope
  - Encapsulation: ML‑KEM‑1024 → shared secret
  - Derivation: BLAKE3/HKDF contexts
  - Encryption: AES‑GCM(inner) + XChaCha20‑Poly1305(outer) with BLAKE3 MAC

## Authentication, sessions, and tokens
- Device keys: on first run, the desktop generates an Ed25519 keypair and a stable device identifier stored in encrypted local storage.
- Refresh protocol: server issues a short challenge; client returns a signed proof binding the challenge, token ID (jti), and device ID. Server validates the signature before issuing new tokens.
- Token storage: the server persists refresh tokens and token families, supports generation counters and revocation, and maintains a blacklist. Audit entries record token events and connection risk signals.
- Session reset: when Signal session state becomes invalid, the client can request a fresh bundle and re‑establish secure channels without user intervention.

## Message storage and data handling
- On the client
  - All conversation history, username mappings, block lists, queued messages, and file metadata are stored in an encrypted SQLite database using a PQ AEAD (AES‑GCM + XChaCha20 with BLAKE3 MAC). Ephemeral stores support TTL and automatic cleanup.
- On the server
  - Messages are stored only as encrypted payloads. The server never needs plaintext to route or persist messages.
  - Offline messages are queued encrypted and delivered on reconnection.
  - User records hold password/parameter metadata and Signal key material necessary to distribute pre‑keys and bundles; sensitive values are stored as encoded hashes or ciphertext.

## Transport and delivery
- Primary channel: WebSockets over TLS with certificate pinning enforced by the desktop.
- P2P path: a minimal WebRTC signaling path allows peer‑to‑peer messaging when available; the app automatically falls back to the server path when P2P is unavailable.
- Tor: the desktop bootstraps its own Tor instance, verifies a working SOCKS proxy, and routes traffic through it. Bridge transports (obfs4 or snowflake) are supported. Bundle signature verification is performed when possible (see [`docs/ENVIRONMENT_VARIABLES.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/ENVIRONMENT_VARIABLES.md) for verification controls).

## Privacy characteristics and limitations
- The server sees: pseudonymous user identifiers, timing data, and minimal routing metadata required to deliver messages. Contents remain encrypted end‑to‑end.
- The desktop keeps local plaintext only in memory during use. Disk persistence is encrypted.
- Optional Tor reduces network observability but does not eliminate all metadata or timing correlations.
- Export controls, platform crypto backends, and OS trust stores can impact guarantees; pinning and Tor help but do not replace operational security.

## Threat model and coverage
- Passive network monitoring: contents confidential (Signal + PQ envelope); routing metadata still observable.
- Message harvesting for future decryption: mitigated by PQ envelope (ML‑KEM‑1024 + AES‑GCM/XChaCha20 + BLAKE3) and Signal forward secrecy.
- Stolen refresh token: requires device‑bound proof (Ed25519); token alone is insufficient.
- Server compromise: server stores only encrypted payloads; no plaintext message recovery. Keys are not present server‑side.
- Local disk theft (desktop): SQLite contents are encrypted with PQ AEAD; plaintext exists only in memory during use.
- Network path manipulation: TLS with certificate pinning; Tor path required.

## Contributing and reporting of issues

Please reference the [`CONTRIBUTING.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/CONTRIBUTING.md) file for contributing to the project. Please reference the [`ISSUE_TEMPLATE.md`](https://github.com/galacticoder/end2end-chat-site/blob/main/docs/ISSUE_TEMPLATE.md) file for reporting issues.

## License
[![License: qorc Non-Commercial Copyleft v1.0](https://img.shields.io/badge/License-qorc%20Non--Commercial%20Copyleft%20v1.0-6d4aff.svg)](LICENSE)
