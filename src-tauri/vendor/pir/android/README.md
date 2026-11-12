# Android PIR client

`jniLibs/{arm64-v8a,x86_64}/libqorc_pir_client.so` contains the production
`qorc-pir-client` built for Android/Bionic, API 24 and 16 KB pages. These are
executable PIEs installed with the APK, not libraries to load with `dlopen`.

The existing portable PIR algorithms, randomness, parameters, session behavior,
and wire protocol are shared with desktop. Android changes the OS allowlist,
compiler/runtime linkage and executable packaging. Android x86_64 uses its
baseline instruction set, desktop x86_64 retains its existing optimized build.
The small C++ runtime is linked statically, so no extra native library is needed.

`manifest.json` pins each executable's SHA-256 and byte length, plus the build's
source digest, Rust version and NDK version. The build verifies those pins before
generating the existing BLAKE3 runtime hash. Gradle retains the exact bytes and
extracts native executables at APK installation. The runtime checks the file's
owner, permissions, type, length and BLAKE3 hash before launching it through the
existing private stdin/stdout protocol. Executable code is never put in Android
app cache. Desktop extraction and integrity checking remain in use on desktop.

Rebuild on Linux/WSL with Rust and NDK 27.3.13750724 installed:

```sh
node scripts/build-android-pir.cjs
node scripts/verify-android-pir.cjs
# Existing build command also supports the Android client:
node scripts/build-pir-sidecars.cjs --client-only --target aarch64-linux-android
```

Use `--abi arm64-v8a` or `--abi x86_64` to select one target. An intentional
maintainer rebuild can use `--update-pins`, review new binaries and pins together.
Normal application builds never update release pins. Licenses for the PIR
sources and vendored dependencies are included under `licenses/` in APK assets.

```sh
node scripts/check-android-pir.cjs
node scripts/check-android-pir.cjs --serial emulator-5584
```

The device harness uses the production launcher and Android-installed client.
An adb-reversed loopback fixture forwards opaque queries to the real desktop
worker. It checks byte-exact retrieval, batching, out-of-order sessions, fresh
randomness, session limits, replay/discard rejection, malformed replies and EOF
shutdown. A second test APK deliberately alters a test copy of the executable
and must be rejected by the compiled BLAKE3 pin before launch. Production
executables and pins are never altered by these tests.

Android 15/API 35 emulator tests (target SDK 36) passed the normal protocol
checks, the current nine-16-KiB-row message layout and altered-executable
rejection. ARM64 compilation/packaging and desktop retrieval/extraction
regressions also passed. A complete messaging APK still requires device binding.

Full application readiness is tracked in [docs/android.md](../../../../docs/android.md).
