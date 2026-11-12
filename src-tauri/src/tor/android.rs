use super::*;
use jni::objects::{JObject, JString};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub(super) const TOR_NAME: &str = "libqorc_tor.so";
pub(super) const TRANSPORT_NAME: &str = "libqorc_lyrebird.so";

pub(super) fn native_library_dir() -> QorcResult<PathBuf> {
    let get_path = || -> Result<PathBuf, jni::errors::Error> {
        let context = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }?;
        let mut env = vm.attach_current_thread()?;
        
        let context = unsafe { JObject::from_raw(context.context().cast()) };
        let info = env
            .call_method(
                &context,
                "getApplicationInfo",
                "()Landroid/content/pm/ApplicationInfo;",
                &[],
            )?
            .l()?;
        let value = env
            .get_field(info, "nativeLibraryDir", "Ljava/lang/String;")?
            .l()?;
        let value = JString::from(value);
        let path: String = env.get_string(&value)?.into();
        Ok(PathBuf::from(path))
    };
    let path = get_path()
        .map_err(|_| invalid_tor_bundle("Android native library directory is unavailable"))?;
        
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(u8::is_ascii_whitespace)
    {
        return Err(invalid_tor_bundle(
            "invalid Android native library directory",
        ));
    }
    validate_installed_path(&path, true)?;
    Ok(path)
}

fn validate_installed_path(path: &Path, directory: bool) -> QorcResult<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() == unsafe { libc::geteuid() }
        || unsafe {
            libc::access(
                std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                    .map_err(|_| invalid_tor_bundle("invalid installed path"))?
                    .as_ptr(),
                libc::W_OK,
            )
        } == 0
    {
        return Err(invalid_tor_bundle(
            "Android executable path is writable, linked, or not APK-installed",
        ));
    }
    Ok(())
}

pub(super) fn verify_executable(path: &Path, expected: &str) -> QorcResult<()> {
    validate_installed_path(path, false)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.permissions().mode() & 0o111 == 0 || metadata.len() > MAX_TOR_BUNDLE_BYTES {
        return Err(invalid_tor_bundle("invalid installed Android executable"));
    }
    let mut total = 0;
    let hash = digest_reader(&mut file, metadata.len(), &mut total)?;
    if hex::encode(hash) != expected {
        return Err(invalid_tor_bundle(
            "installed Android executable failed its pinned SHA-256 check",
        ));
    }
    Ok(())
}

pub(super) fn verify_runtime(manager: &TorManager) -> QorcResult<()> {
    let installed = manager
        .native_library_dir
        .as_ref()
        .ok_or_else(|| invalid_tor_bundle("Android runtime is not initialized"))?;
    validate_installed_path(installed, true)?;
    if manager.tor_path != installed.join(TOR_NAME) {
        return Err(invalid_tor_bundle(
            "Tor path does not match the APK installation",
        ));
    }
    verify_executable(&manager.tor_path, embedded::ANDROID_TOR_SHA256)?;
    verify_executable(
        &installed.join(TRANSPORT_NAME),
        embedded::ANDROID_LYREBIRD_SHA256,
    )
}
