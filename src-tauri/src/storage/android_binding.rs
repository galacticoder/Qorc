use crate::error::{QorcError, QorcResult};
use jni::objects::{JByteArray, JClass, JObject, JValue};
use sha3::{Digest, Sha3_256};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MARKER: &str = "android-device-binding.v1";

fn unavailable() -> QorcError {
    QorcError::StorageInitFailed(
        "Android device binding is unavailable or does not match this installation".into(),
    )
}

fn derive(allow_create: bool) -> QorcResult<Zeroizing<Vec<u8>>> {
    let invoke = || -> Result<Zeroizing<Vec<u8>>, jni::errors::Error> {
        let context = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }?;
        let mut env = vm.attach_current_thread()?;
        
        let context = unsafe { JObject::from_raw(context.context().cast()) };
        let result = (|| {
            let loader = env
                .call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
                .l()?;
            let name = env.new_string("com.qorc.security.DeviceBinding")?;
            let class = env
                .call_method(
                    &loader,
                    "loadClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;",
                    &[JValue::Object(name.as_ref())],
                )?
                .l()?;
            let class = JClass::from(class);
            let bytes = env
                .call_static_method(
                    class,
                    "derive",
                    "(Z)[B",
                    &[JValue::Bool(allow_create.into())],
                )?
                .l()?;
            let bytes = JByteArray::from(bytes);
            let value = Zeroizing::new(env.convert_byte_array(&bytes)?);
            let count = env.get_array_length(&bytes)?;
            if count == 32 {
                env.set_byte_array_region(&bytes, 0, &[0i8; 32])?;
            }
            Ok(value)
        })();
        if env.exception_check()? {
            env.exception_clear()?;
        }
        result
    };
    let binding = invoke().map_err(|_| unavailable())?;
    if binding.len() != 32 {
        return Err(unavailable());
    }
    Ok(binding)
}

pub(super) async fn get_context(config_dir: &Path) -> QorcResult<Zeroizing<Vec<u8>>> {
    let marker_path = config_dir.join(MARKER);
    let previous = match super::file::read_file_bounded(&marker_path, 32).await {
        Ok(bytes) if bytes.len() == 32 => Some(bytes),
        Ok(_) => return Err(unavailable()),
        Err(QorcError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let master_exists = super::file::private_file_exists(&config_dir.join("master.key")).await?;
    let mut records = tokio::fs::read_dir(config_dir.join("secure-store")).await?;
    let has_records = records.next_entry().await?.is_some();
    if previous.is_none() && (master_exists || has_records) || has_records && !master_exists {
        return Err(unavailable());
    }
    let allow_create = previous.is_none();
    let binding = tokio::task::spawn_blocking(move || derive(allow_create))
        .await
        .map_err(|_| unavailable())??;
    let context =
        Zeroizing::new([crate::protocol_keys::MACHINE_ANDROID, binding.as_slice()].concat());
    let fingerprint = Sha3_256::digest(context.as_slice());
    if let Some(previous) = previous {
        if !bool::from(previous.as_slice().ct_eq(fingerprint.as_slice())) {
            return Err(unavailable());
        }
    } else if !super::file::atomic_write_if_absent(&marker_path, fingerprint.as_slice(), 0o600)
        .await?
    {
        let existing = super::file::read_file_bounded(&marker_path, 32).await?;
        if !bool::from(existing.as_slice().ct_eq(fingerprint.as_slice())) {
            return Err(unavailable());
        }
    }
    Ok(context)
}
