use spiral_rs::{arith::*, params::*};

use super::server::ToM512;

pub fn fast_batched_dot_product_avx512<const K: usize, T: Copy>(
    params: &Params,
    c: &mut [u64],
    a: &[u64],
    a_elems: usize,
    b_t: &[T], // transposed
    b_rows: usize,
    b_cols: usize,
) where
    *const T: ToM512,
{
    assert_eq!(a_elems, b_rows);

    // debug!("Multiplying {}x{} by {}x{}", K, a_elems, b_rows, b_cols);

    let simd_width = 8;

    let chunk_size = (8192 / K.next_power_of_two()).min(a_elems / simd_width);
    let num_chunks = (a_elems / simd_width) / chunk_size;
    // debug!("k_chunk_size: {}, k_num_chunks: {}", chunk_size, num_chunks);

    let j_chunk_size = 1;
    let j_num_chunks = b_cols / j_chunk_size;
    // debug!(
    //     "j_chunk_size: {}, j_num_chunks: {}",
    //     j_chunk_size, j_num_chunks
    // );

    // let mut result = AlignedMemory64::new(b_cols);
    // let res_mut_slc = result.as_mut_slice();
    let res_mut_slc = c;

    unsafe {
        let mut a_slcs: [&[u64]; K] = [&[]; K];
        for (slc_mut, chunk) in a_slcs.iter_mut().zip(a.chunks_exact(a.len() / K)) {
            *slc_mut = chunk;
        }

        // let a_ptr = a.as_ptr();
        let b_ptr = b_t.as_ptr();

        for k_outer in 0..num_chunks {
            for j_outer in 0..j_num_chunks {
                for j_inner in 0..j_chunk_size {
                    let j = j_outer * j_chunk_size + j_inner;

                    let mut total_sum_lo = [crate::m512::zero(); K];
                    let mut total_sum_hi = [crate::m512::zero(); K];
                    let mut tmp = [crate::m512::zero(); K];

                    for k_inner in 0..chunk_size {
                        let k = simd_width * (k_outer * chunk_size + k_inner);

                        let a_idx = k;
                        let b_idx = j * b_rows + k;
                        let b_val_simd = b_ptr.add(b_idx).to_m512();

                        for batch in 0..K {
                            tmp[batch] = crate::m512::load(a_slcs[batch].as_ptr().add(a_idx));
                        }

                        for batch in 0..K {
                            let a_val_lo = tmp[batch];
                            let a_val_hi = crate::m512::srli32(tmp[batch]);

                            total_sum_lo[batch] = crate::m512::add64(
                                total_sum_lo[batch],
                                crate::m512::mul_lo32(a_val_lo, b_val_simd),
                            );
                            total_sum_hi[batch] = crate::m512::add64(
                                total_sum_hi[batch],
                                crate::m512::mul_lo32(a_val_hi, b_val_simd),
                            );
                        }
                    }

                    let res_mut_slcs = res_mut_slc.chunks_exact_mut(res_mut_slc.len() / K);
                    for (batch, res_mut_slc) in (0..K).zip(res_mut_slcs) {
                        let mut values_lo = [0u64; 8];
                        let mut values_hi = [0u64; 8];
                        crate::m512::store((&mut values_lo).as_mut_ptr(), total_sum_lo[batch]);
                        crate::m512::store((&mut values_hi).as_mut_ptr(), total_sum_hi[batch]);

                        let res_lo = values_lo[0]
                            + values_lo[1]
                            + values_lo[2]
                            + values_lo[3]
                            + values_lo[4]
                            + values_lo[5]
                            + values_lo[6]
                            + values_lo[7];

                        let res_hi = values_hi[0]
                            + values_hi[1]
                            + values_hi[2]
                            + values_hi[3]
                            + values_hi[4]
                            + values_hi[5]
                            + values_hi[6]
                            + values_hi[7];

                        // res_mut_slc[j] = res_lo + res_hi;

                        let (lo, hi) = (
                            barrett_coeff_u64(params, res_lo as u64, 0),
                            barrett_coeff_u64(params, res_hi as u64, 1),
                        );

                        // res_mut_slc[j] = lo | (hi << 32);

                        let res = params.crt_compose_2(lo, hi);
                        res_mut_slc[j] = barrett_u64(params, res_mut_slc[j] + res);
                    }
                }
            }
        }
    }
}
