use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub fn generate(
    target: &str,
    manifest_dir: &Path,
    out_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let abi = match target {
        "aarch64-linux-android" => "arm64-v8a",
        "x86_64-linux-android" => "x86_64",
        _ => {
            return Err(format!("No Android PIR runtime for {target}; use ARM64 or x86_64").into());
        }
    };
    let root = manifest_dir.join("vendor/pir/android");
    let manifest = root.join("manifest.json");
    let binary = root.join("jniLibs").join(abi).join("libqorc_pir_client.so");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed={}", binary.display());
    let pins: serde_json::Value = serde_json::from_slice(&fs::read(manifest)?)?;
    let bytes = fs::read(&binary)?;
    let expected = pins["abis"][abi]["sha256"]
        .as_str()
        .ok_or("Missing Android PIR SHA-256 pin")?;
    let actual = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if actual != expected || pins["abis"][abi]["size"].as_u64() != Some(bytes.len() as u64) {
        return Err("Android PIR binary failed its release-pinned hash/length check".into());
    }
    let hash = blake3::hash(&bytes)
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        out_dir.join("embedded_pir_client.rs"),
        format!(
            "pub const EMBEDDED_PIR_CLIENT_HASH: [u8; 32] = [{hash}];\n\
         pub const EMBEDDED_PIR_CLIENT_LEN: u64 = {len};\n\
         pub const EMBEDDED_PIR_CLIENT_FILE_NAME: &str = {name:?};\n",
            len = bytes.len(),
            name = "libqorc_pir_client.so"
        ),
    )?;
    Ok(())
}
