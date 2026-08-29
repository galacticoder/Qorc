# Contributing to Qor-Chat

Thank you for considering contributing to Qor-Chat! Contributions from everyone are welcome.

## Code of Conduct

This project and everyone participating in it is governed by the [Qor Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainer at galacticoderr@gmail.com.

## Getting Started

### Prerequisites

- **Docker server:** Node.js 18 or newer plus Docker Compose v2 and Buildx.
- **Desktop client:** Node.js 18 or newer, the repository-pinned pnpm through
  Corepack, Rust/Tauri, and the platform build dependencies listed in the root
  README.
- **Git:** Only required when cloning or contributing through Git.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/galacticoder/Qor-Chat.git
    cd Qor-Chat
    ```

2.  **Start a complete Docker server:**
    ```bash
    node scripts/start-docker.cjs all
    ```
    Docker carries the server dependencies and the helper fills only missing
    `.env` values. It does not replace or rotate existing values.

3.  **Or build the desktop client:**
    ```bash
    node scripts/install-deps.cjs --client
    node scripts/start-client.cjs
    ```

### Desktop Build Modes

`node scripts/start-client.cjs` stages the platform runtimes and PIR sidecar,
builds release installers, and launches the result. Use
`node scripts/start-client.cjs --bundle-only` to perform the same build without
launching. Both commands build the host architecture. On x86_64 Linux, use
`node scripts/start-client.cjs --bundle-only --target arm64` for ARM64-only
installers or add `--all-architectures` to build native x86_64 and ARM64
installers sequentially. Native artifacts are written beneath
`src-tauri/target/release/bundle`; cross-built ARM64 artifacts are written
beneath `src-tauri/target/aarch64-unknown-linux-gnu/release/bundle`.

The ARM64 cross-build uses a secret-free source snapshot and a native ARM64
Docker build environment. Docker must support `linux/arm64` execution; Linux
Docker Engine users can run `node scripts/install-deps.cjs --client-arm64` to
install the appropriate QEMU/binfmt packages, while Docker Desktop normally
provides the emulation layer.

On Linux, the build downloads and SHA-256-validates the release-pinned WebKitGTK
packages, stages a curated GStreamer/PipeWire capture runtime from the build
host, including the SPA audio and video conversion adapters, records every
capture-runtime artifact in a SHA-256 manifest, and installs those private files
into each bundle. Bundle preparation rejects stale manifests that do not contain
both adapters. The resulting package does not use the repository or its `.cache`
directory at runtime. The host desktop portal, PipeWire session, device
permissions, and base system libraries remain platform requirements.

`node scripts/start-client.cjs --run-only` skips all building and runtime
staging. It launches the existing AppDir when available, otherwise the existing
release executable. Use it only after a completed build; it does not include
later source changes.

## Development Workflow

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally.
3.  **Create a branch** for your feature or bugfix:
    ```bash
    git checkout -b feature/your-feature-name
    ```
4.  **Make your changes.**
5.  **Run linting and type checking:**
    ```bash
    pnpm lint
    pnpm exec tsc -p tsconfig.app.json --noEmit
    ```
    Always pass `-p tsconfig.app.json`. The root `tsconfig.json` has an empty
    `files` array, so a bare `tsc` type checks nothing and exits 0.
6.  **Run the security tests** if you touched anything under `server/`:
    ```bash
    pnpm test:security
    ```
7.  **Run the standalone visual-call codec harness** if you changed the VP8
    encoder, decoder, batching, adaptation, or renderer pipeline:
    ```bash
    node scripts/test-call-video-codec.cjs
    ```
8.  **Commit your changes** with descriptive commit messages.
9.  **Push to your fork:**
    ```bash
    git push origin feature/your-feature-name
    ```
10. **Open a Pull Request** against the `main` branch of the original repository.

## Style Guide

*   **Linting:** This project uses ESLint. Please check your code passes linting before submitting a PR (`pnpm lint`). The project is pnpm-only, `pnpm-lock.yaml` is the committed lockfile.
*   **Formatting:** Try to follow the existing code style.
*   **TypeScript:** Use TypeScript for all new UI code (`.ts`, `.tsx`).

## Reporting Bugs

If you find a bug, please create an issue on GitHub. Include:
*   A clear title and description.
*   Steps to reproduce the bug.
*   Expected vs. actual behavior.
*   Screenshots if applicable.
*   Your OS and environment details.
*   For call or device failures reproduced through the client launcher, the
    relevant `logs/instance-<QOR_INSTANCE_ID>-logs.txt` file. Use a different
    `QOR_INSTANCE_ID` for each simultaneously running test client so their
    native data and logs remain separate.

## Suggesting Enhancements

I love hearing about new ideas. If you have a suggestion:
1.  Check existing issues to see if it has already been posted.
2.  Open a new issue describing the enhancement and why it would be useful.

Thank you for contributing!
