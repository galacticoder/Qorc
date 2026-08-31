# Bundled edge runtime

The load-balancer image embeds an authenticated Linux runtime for both amd64
and arm64. It does not download, install, build, or fall back to system copies
of HAProxy or Tor.

Archives:

- `qorc-edge-runtime-linux-x86_64-v1.tar.gz` (amd64)
  - SHA-256: `41876029965386aa0623f4d34c8956aac664ac4f9e85e39ae3309fb0d0d3b095`
- `qorc-edge-runtime-linux-arm64-v1.tar.gz` (arm64)
  - SHA-256: `f24331e5685b04ba73ecc79b61a3deead1453537e97ba6816e3ed543c1f21fb0`

The archive contains:

- HAProxy 3.2.21
- qorc's patched Tor 0.4.9.11 hidden-service runtime
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
