# Bundled edge runtime

The load-balancer image embeds this authenticated Linux x86_64 runtime. It does
not download, install, build, or fall back to system copies of HAProxy or Tor.

Archive: `qor-edge-runtime-linux-x86_64-v1.tar.gz`

SHA-256: `c3a9cf4759fb29f17b9e0e4e4da5e6213dd5cd7a8602f9ed695cb12be89e4c33`

The archive contains:

- HAProxy 3.2.21
- Qor's patched Tor 0.4.9.11 hidden-service runtime
- the OQS OpenSSL provider and liboqs
- the private dynamic libraries required by those binaries
- `manifest.json`, including version, source, patch, and per-file hashes

`THIRD_PARTY_NOTICES.txt` records the upstream sources and licenses and is
copied next to the extracted runtime in the load-balancer image.

The Docker build authenticates the complete archive before extraction. Runtime
startup then validates the pinned HAProxy version and its PQ TLS configuration.
Tor startup accepts only the bundled absolute executable path and verifies that
an existing PID resolves to that same executable.
