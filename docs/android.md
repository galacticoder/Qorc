## Building

Install Java 17, Android SDK 36 and the Android NDK, then configure `JAVA_HOME`,
`ANDROID_HOME` and `NDK_HOME`. See the
[Tauri Android prerequisites](https://v2.tauri.app/start/prerequisites/).
The minimum supported Android API level is 24.

```sh
rustup target add aarch64-linux-android x86_64-linux-android

# Signed ARM64 APK
node scripts/start-client.cjs --android --bundle-only

# ARM64, x86_64 and universal APKs
node scripts/start-client.cjs --android --bundle-only --all-architectures
```

Release APKs are written to `src-tauri/target/release/bundle/android/`.
The build prepares the frontend, synchronizes Android branding, verifies native
Tor/PIR pins, configures 16 KB native alignment, and checks the package, ABI and
signature of each resulting APK.

The first release build creates a private signing identity in
`.cache/android-signing/`. Keep it securely: subsequent updates require the same
signing key. To use an existing identity, supply all four environment variables:
`QORC_ANDROID_KEYSTORE`, `QORC_ANDROID_KEY_ALIAS`,
`QORC_ANDROID_KEYSTORE_PASSWORD` and `QORC_ANDROID_KEY_PASSWORD`.
Partial signing configuration is rejected.

## Native runtimes

Android Tor and PIR executables are pinned under `src-tauri/vendor/tor/android`
and `src-tauri/vendor/pir/android`. The build checks their digests and native
alignment before packaging them. Their source build and verification tools are:

- `scripts/build-android-tor.py`
- `scripts/build-android-pir.cjs`
- `scripts/verify-android-tor.cjs`
- `scripts/verify-android-pir.cjs`
- `scripts/verify-android-runtime.cjs`

Android device binding uses the Android Keystore. Message content, account keys
and local data continue to use the encrypted native storage APIs.