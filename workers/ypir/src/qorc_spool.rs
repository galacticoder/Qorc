//! Spool record packing for qorc.
//!
//! A YPIR SimplePIR row is `db_cols` plaintext words of `pt_bits` each, and a
//! retrieval returns exactly one row.

use crate::bits::{read_bits, write_bits};

/// Plaintext words needed to hold `len` bytes at `pt_bits` per word.
pub fn words_for_bytes(len: usize, pt_bits: usize) -> usize {
    (len * 8).div_ceil(pt_bits)
}

pub fn pack_record(record: &[u8], pt_bits: usize, db_cols: usize) -> Vec<u16> {
    assert!(pt_bits > 0 && pt_bits <= 16);
    let needed = words_for_bytes(record.len(), pt_bits);
    assert!(
        needed <= db_cols,
        "record of {} bytes needs {needed} words but a row holds {db_cols}",
        record.len()
    );
    let mut out = vec![0u16; db_cols];
    for (index, slot) in out.iter_mut().enumerate().take(needed) {
        *slot = read_bits(record, index * pt_bits, pt_bits) as u16;
    }
    out
}

pub fn unpack_record(words: &[u64], pt_bits: usize, len: usize) -> Vec<u8> {
    assert!(pt_bits > 0 && pt_bits <= 16);
    let mut out = vec![0u8; len];
    let needed = words_for_bytes(len, pt_bits);
    for (index, word) in words.iter().enumerate().take(needed) {
        let remaining = len * 8 - index * pt_bits;
        write_bits(&mut out, *word, index * pt_bits, pt_bits.min(remaining));
    }
    out
}





/// Wire encoding for the pieces that cross a process boundary.
///
/// The client generates its query and expansion parameters locally and never
/// discloses which row it wants, so these travel as opaque bytes. Dimensions are
/// carried explicitly rather than inferred, so a malformed frame is rejected
/// instead of being reinterpreted against the server's own parameters.
pub mod wire {
    use spiral_rs::params::Params;
    use spiral_rs::poly::{PolyMatrix, PolyMatrixNTT};

    const MAGIC: u32 = 0x5150_4952; // "QPIR"
    const BATCH_MAGIC: u32 = 0x5142_5432;

    pub fn encode_batch(items: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + items.iter().map(|item| 4 + item.len()).sum::<usize>();
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&BATCH_MAGIC.to_le_bytes());
        out.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for item in items {
            out.extend_from_slice(&(item.len() as u32).to_le_bytes());
            out.extend_from_slice(item);
        }
        out
    }

    pub fn decode_batch<'a>(
        bytes: &'a [u8],
        max_items: usize,
        max_item_bytes: usize,
    ) -> Option<Vec<&'a [u8]>> {
        if bytes.len() < 8 || u32::from_le_bytes(bytes[0..4].try_into().ok()?) != BATCH_MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if count == 0 || count > max_items {
            return None;
        }
        let mut offset = 8usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize;
            offset += 4;
            if len == 0 || len > max_item_bytes {
                return None;
            }
            let item = bytes.get(offset..offset + len)?;
            offset += len;
            out.push(item);
        }
        if offset != bytes.len() {
            return None;
        }
        Some(out)
    }

    pub fn encode_u64s(values: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + values.len() * 8);
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&(values.len() as u32).to_le_bytes());
        for value in values {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }

    pub fn decode_u64s(bytes: &[u8]) -> Option<Vec<u64>> {
        if bytes.len() < 8 {
            return None;
        }
        if u32::from_le_bytes(bytes[0..4].try_into().ok()?) != MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if bytes.len() != 8 + count * 8 {
            return None;
        }
        let mut out = Vec::with_capacity(count);
        for chunk in bytes[8..].chunks_exact(8) {
            out.push(u64::from_le_bytes(chunk.try_into().ok()?));
        }
        Some(out)
    }

    pub fn encode_matrices(matrices: &[PolyMatrixNTT]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&(matrices.len() as u32).to_le_bytes());
        for matrix in matrices {
            out.extend_from_slice(&(matrix.rows as u32).to_le_bytes());
            out.extend_from_slice(&(matrix.cols as u32).to_le_bytes());
            let data = matrix.as_slice();
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            for value in data {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        out
    }

    pub fn decode_matrices<'a>(
        params: &'a Params,
        bytes: &[u8],
        max_matrices: usize,
    ) -> Option<Vec<PolyMatrixNTT<'a>>> {
        if bytes.len() < 8 || u32::from_le_bytes(bytes[0..4].try_into().ok()?) != MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
        if count > max_matrices {
            return None;
        }
        let mut offset = 8usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < offset + 12 {
                return None;
            }
            let rows = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
            let cols = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().ok()?) as usize;
            let len = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().ok()?) as usize;
            offset += 12;
            if rows == 0 || cols == 0 || rows > 8 || cols > 1 << 20 {
                return None;
            }
            if bytes.len() < offset + len * 8 {
                return None;
            }
            let mut matrix = PolyMatrixNTT::zero(params, rows, cols);
            if matrix.as_slice().len() != len {
                return None;
            }
            let target = matrix.as_mut_slice();
            for (index, chunk) in bytes[offset..offset + len * 8].chunks_exact(8).enumerate() {
                target[index] = u64::from_le_bytes(chunk.try_into().ok()?);
            }
            offset += len * 8;
            out.push(matrix);
        }
        if offset != bytes.len() {
            return None;
        }
        Some(out)
    }
}
