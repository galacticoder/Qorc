# Android Tor runtime

These files are Android/Bionic **PIE executables**, packaged as native libraries
so Android installs them in `ApplicationInfo.nativeLibraryDir`. Never `dlopen`
them, extract them to writable app storage, or substitute a GNU/Linux ARM64 build.

- Tor **0.4.9.15**, OpenSSL **3.5.9**, libevent **2.1.12**, zlib **1.3.2**.
- Lyrebird **0.8.1**, unchanged upstream commit
  `0b10edbb61e0ca6fb70c7d57aeaabf315f1fade1` and its locked Go modules.
- Android API **24**, **ARM64/x86_64**, NDK **27.3.13750724**, Go **1.27.3**.
- 16 KB ELF segment alignment, PIE, RELRO/NOW, stack protection and NX stack.
- OpenSSL/libevent/zlib are static, only Android system libraries are dynamic.
- `tor-data.tar.gz` contains GeoIP data and notices, never executable code.
- `licenses/` is included in APK assets and contains the linked components'
  upstream license texts. Desktop runtime archives are separate and unchanged.

`manifest.json` records pinned artifact and source-archive hashes. Build-time,
APK-packaging and runtime checks enforce them. Android runtime checks also reject
app-owned/writable executables and symbolic links. Gradle must preserve executable
bytes (`keepDebugSymbols`) and use native-library extraction at installation
(`useLegacyPackaging`), the shared application and the device harness do both.

The Tor source SHA-256 was verified against both signatures in
`provenance/tor-0.4.9.15.tar.gz.sha256sum.asc`, using the Tor Project's published
signing fingerprints:

- David Goulet: `B74417EDDF22AC9F9E90F49142E86A2A11F48D36`.
- Alexander Færøy signing key: `514102454D0A87DB0767A1EBBE6A0531C18A9179`
  (primary `1C1BC007A9F607AA8152C040BEA7B180B1491921`).

See [Tor's verification instructions](https://support.torproject.org/little-t-tor/getting-started/verifying/).
Sources and exact SHA-256 values for all other archives are in the manifest and
the build script. Lyrebird's immutable archive matches the already-reviewed
desktop ARM64 source pin. Go module integrity verification remains enabled.

Build from source on Linux with the pinned NDK and Go on `PATH`:

```sh
python3 scripts/build-android-tor.py
node scripts/verify-android-tor.cjs
```

`--abi arm64-v8a` or `--abi x86_64` limits the build. Rebuilds must match the
reviewed pins, differing compiler/build environments can change output bytes.
For an intentional rebuild/update, `--update-pins` writes reviewable new pins
alongside the new artifacts. Review both together before distributing an APK.
This option is never invoked by normal app builds and never runs on a device.

The Android build uses Tor Browser's
[`-checklinkname=0` compatibility flag](https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/blob/main/projects/lyrebird/build)
for the unchanged `anet` Android network-interface shim on Go 1.23+. It affects
linker symbol validation, not transport encryption or certificate validation.

See [the Android port status](../../../../docs/android.md) for test commands and
the remaining application integration requirements.
