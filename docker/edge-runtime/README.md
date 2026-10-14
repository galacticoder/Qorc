# Bundled edge runtime

The load-balancer image embeds an authenticated Linux runtime for both amd64
and arm64. It does not download, install, build, or fall back to system copies
of HAProxy or Tor.

Archives:

- `qorc-edge-runtime-linux-x86_64-v1.tar.gz` (amd64)
  - SHA-256: `64cfc5bc17930cbbd2b175705c6c13c4192cff976b3d8b2a83358b2178511482`
- `qorc-edge-runtime-linux-arm64-v1.tar.gz` (arm64)
  - SHA-256: `0d0ff5dcaa235e7e13aa462ac2b0d7345d4d2f0136aa7ab741b08460a95be2a9`

The archive contains:

- HAProxy 3.2.21
- qorc's patched Tor 0.4.9.14 hidden-service runtime
- the OQS OpenSSL provider and liboqs
- the private dynamic libraries required by those binaries
- `manifest.json`, including version, source, patch, and per-file hashes

`THIRD_PARTY_NOTICES.txt` records the upstream sources and licenses and is
copied next to the extracted runtime in the load-balancer image.

The Docker build detects the Linux container architecture, authenticates the
matching complete archive before extraction, and copies only that runtime into
the final image. Runtime startup then validates the pinned HAProxy version and
its PQ TLS configuration. Tor startup accepts only the bundled absolute
executable path and verifies that an existing PID resolves to that same
executable.