use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub fn generate(
    target: &str,
    manifest_dir: &Path,
    out_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (abi, arch) = match target {
        "aarch64-linux-android" => ("arm64-v8a", "aarch64"),
        "x86_64-linux-android" => ("x86_64", "x86_64"),
        _ => {
            return Err(format!(
                "No authenticated Android Tor runtime for {target}, use aarch64 or x86_64"
            )
            .into());
        }
    };
    let root = manifest_dir.join("vendor/tor/android");
    let manifest = root.join("manifest.json");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let pins: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
    let read_pin = |value: &serde_json::Value| -> Result<String, Box<dyn std::error::Error>> {
        let pin = value.as_str().ok_or("Missing Android Tor release pin")?;
        if pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Invalid Android Tor release pin".into());
        }
        Ok(pin.to_owned())
    };
    let tor_pin = read_pin(&pins["abis"][abi]["libqorc_tor.so"])?;
    let lyrebird_pin = read_pin(&pins["abis"][abi]["libqorc_lyrebird.so"])?;
    let data_pin = read_pin(&pins["dataSha256"])?;
    for (path, pin) in [
        (
            root.join("jniLibs").join(abi).join("libqorc_tor.so"),
            &tor_pin,
        ),
        (
            root.join("jniLibs").join(abi).join("libqorc_lyrebird.so"),
            &lyrebird_pin,
        ),
        (root.join("tor-data.tar.gz"), &data_pin),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read(&path)?;
        let actual = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if actual != *pin {
            return Err(format!(
                "Android Tor artifact failed its pinned SHA-256 check: {}",
                path.display()
            )
            .into());
        }
    }
    let path = root.join("tor-data.tar.gz");
    let digest = Sha256::digest(fs::read(&path)?);
    let digest = digest
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let version = pins["version"]
        .as_str()
        .ok_or("Missing Android Tor version")?;
    fs::write(
        out_dir.join("embedded_tor_bundle.rs"),
        format!(
            "pub static EMBEDDED_TOR_BUNDLE: &[u8] = include_bytes!({path:?});\n\
             pub const EMBEDDED_TOR_BUNDLE_SHA256: [u8; 32] = [{digest}];\n\
             pub const EMBEDDED_TOR_BUNDLE_SHA256_HEX: &str = {data_pin:?};\n\
             pub const EMBEDDED_TOR_BUNDLE_VERSION: &str = {version:?};\n\
             pub const EMBEDDED_TOR_BUNDLE_TARGET: &str = {bundle_target:?};\n\
             pub const EMBEDDED_TOR_PLATFORM: &str = {platform:?};\n\
             pub const EMBEDDED_TOR_ARCH: &str = {arch:?};\n\
             pub const ANDROID_TOR_SHA256: &str = {tor_pin:?};\n\
             pub const ANDROID_LYREBIRD_SHA256: &str = {lyrebird_pin:?};\n",
            path = path.to_string_lossy(),
            bundle_target = format!("android-{abi}"),
            platform = "android",
        ),
    )?;
    Ok(())
}
