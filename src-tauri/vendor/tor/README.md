# Vendored Tor Expert Bundles

Qor embeds the Tor Expert Bundle into the signed desktop
application. The app never downloads executable Tor code at runtime.

Version: `15.0.17`

| Target | Archive | SHA-256 |
| --- | --- | --- |
| Linux x86_64 | `tor-expert-bundle-linux-x86_64-15.0.17.tar.gz` | `4621e1573dbd6d5d6f4bb4121b37652a8b7204ae5abea600fb6b9e05e5695696` |
| Linux ARM64 | `tor-expert-bundle-linux-aarch64-15.0.17.tar.gz` | `a529a053d39c24dcbe53afe961b0d284b2c739d1f9ad54211ce6e5b76a50cf4f` |
| Windows x86_64 | `tor-expert-bundle-windows-x86_64-15.0.17.tar.gz` | `5f91e9426bf641dfe539dc28029088c72bed0b1d8f1c79104a0f89273cb3ebe1` |

The x86_64 archives are the official Tor Project Expert Bundles from:
`https://archive.torproject.org/tor-package-archive/torbrowser/15.0.17/`.

The Tor Project does not publish a Linux ARM64 Expert Bundle. Qor's ARM64
archive uses the authenticated Tor 0.4.9.11 executable and private libraries
from `docker/edge-runtime/qor-edge-runtime-linux-arm64-v1.tar.gz`, and a
statically linked Lyrebird 0.8.1 built for `linux/arm64`. The Lyrebird source is
tag `lyrebird-0.8.1`, commit
`0b10edbb61e0ca6fb70c7d57aeaabf315f1fade1`; its GitLab source archive SHA-256
is `a0bd43cbbd3b7932b8dedc80e9ffdb6f0092b5b94e12fccd0fe76c8a825ce2cd`.
The bundled Lyrebird executable SHA-256 is
`8c98bafcb321e426e9fc7a336b2b1a0ae1396483d969a343fcba466d13e5c0c3`.

See `THIRD_PARTY_NOTICES.txt` for source and license details.
