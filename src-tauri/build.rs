use std::{env, fs, path::PathBuf};

use sha2::{Digest, Sha256};

const TOR_BUNDLE_VERSION: &str = "15.0.17";

fn byte_array_literal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn embedded_tor_bundle(target: &str) -> (&'static str, &'static str, &'static str, &'static str) {
    match target {
        "x86_64-unknown-linux-gnu" => (
            "linux",
            "x86_64",
            "linux-x86_64",
            "4621e1573dbd6d5d6f4bb4121b37652a8b7204ae5abea600fb6b9e05e5695696",
        ),
        "x86_64-pc-windows-msvc" | "x86_64-pc-windows-gnu" => (
            "windows",
            "x86_64",
            "windows-x86_64",
            "5f91e9426bf641dfe539dc28029088c72bed0b1d8f1c79104a0f89273cb3ebe1",
        ),
        _ => panic!(
            "no embedded Tor Expert Bundle is vendored for target {target}; supported client targets are x86_64 Linux GNU and x86_64 Windows"
        ),
    }
}

fn main() {
    let target = env::var("TARGET").expect("Cargo did not provide TARGET");
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("Cargo did not provide CARGO_MANIFEST_DIR"),
    );
    let executable_suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let staged_name = format!("qor-pir-client-{target}{executable_suffix}");
    let staged_path = manifest_dir.join("binaries").join(&staged_name);

    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-changed={}", staged_path.display());

    let bytes = fs::read(&staged_path).unwrap_or_else(|error| {
        panic!(
            "embedded PIR client is missing at {} ({error}); run pnpm run build:pir first",
            staged_path.display()
        )
    });
    let digest = *blake3::hash(&bytes).as_bytes();
    let digest_literal = byte_array_literal(&digest);
    let source_path = format!("{:?}", staged_path.to_string_lossy());
    let generated = format!(
        "pub static EMBEDDED_PIR_CLIENT: &[u8] = include_bytes!({source_path});\n\
         pub const EMBEDDED_PIR_CLIENT_HASH: [u8; 32] = [{digest_literal}];\n\
         pub const EMBEDDED_PIR_CLIENT_FILE_NAME: &str = {file_name:?};\n",
        file_name = format!("qor-pir-client{executable_suffix}")
    );
    let output = PathBuf::from(env::var("OUT_DIR").expect("Cargo did not provide OUT_DIR"))
        .join("embedded_pir_client.rs");
    fs::write(output, generated).expect("failed to generate embedded PIR client metadata");

    let (tor_platform, tor_arch, tor_target, expected_tor_sha256) = embedded_tor_bundle(&target);
    let tor_file_name = format!("tor-expert-bundle-{tor_target}-{TOR_BUNDLE_VERSION}.tar.gz");
    let tor_path = manifest_dir.join("vendor").join("tor").join(&tor_file_name);
    println!("cargo:rerun-if-changed={}", tor_path.display());

    let tor_bytes = fs::read(&tor_path).unwrap_or_else(|error| {
        panic!(
            "embedded Tor Expert Bundle is missing at {} ({error})",
            tor_path.display()
        )
    });
    let tor_digest: [u8; 32] = Sha256::digest(&tor_bytes).into();
    let actual_tor_sha256 = lowercase_hex(&tor_digest);
    assert_eq!(
        actual_tor_sha256,
        expected_tor_sha256,
        "vendored Tor Expert Bundle failed its release-pinned SHA-256 check: {}",
        tor_path.display()
    );

    let tor_source_path = format!("{:?}", tor_path.to_string_lossy());
    let tor_generated = format!(
        "pub static EMBEDDED_TOR_BUNDLE: &[u8] = include_bytes!({tor_source_path});\n\
         pub const EMBEDDED_TOR_BUNDLE_SHA256: [u8; 32] = [{digest}];\n\
         pub const EMBEDDED_TOR_BUNDLE_SHA256_HEX: &str = {sha256:?};\n\
         pub const EMBEDDED_TOR_BUNDLE_VERSION: &str = {version:?};\n\
         pub const EMBEDDED_TOR_BUNDLE_TARGET: &str = {bundle_target:?};\n\
         pub const EMBEDDED_TOR_PLATFORM: &str = {platform:?};\n\
         pub const EMBEDDED_TOR_ARCH: &str = {arch:?};\n",
        digest = byte_array_literal(&tor_digest),
        sha256 = expected_tor_sha256,
        version = TOR_BUNDLE_VERSION,
        bundle_target = tor_target,
        platform = tor_platform,
        arch = tor_arch,
    );
    let tor_output = PathBuf::from(env::var("OUT_DIR").expect("Cargo did not provide OUT_DIR"))
        .join("embedded_tor_bundle.rs");
    fs::write(tor_output, tor_generated).expect("failed to generate embedded Tor bundle metadata");

    tauri_build::build()
}
