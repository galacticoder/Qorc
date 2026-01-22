//! Cryptographic utilities
//!
//! Security-critical utility functions.

use subtle::ConstantTimeEq;

/// Constant-time byte array comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
