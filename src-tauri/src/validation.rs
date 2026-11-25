use crate::constants::validation::{AUTH_USERNAME_MAX_BYTES, AUTH_USERNAME_MIN_BYTES};

pub(crate) fn is_canonical_auth_username(value: &str) -> bool {
    (AUTH_USERNAME_MIN_BYTES..=AUTH_USERNAME_MAX_BYTES).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

pub(crate) fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn is_hex_256(value: &str) -> bool {
    value.len() == 64 && is_lowercase_hex(value)
}
