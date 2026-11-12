use spiral_rs::{arith::*, params::*, poly::*};

use super::server::ToU64;

pub fn negacyclic_perm(a: &[u64], shift: usize, modulus: u64) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0u64; n];

    for i in 0..shift + 1 {
        out[i] = a[shift - i];
    }

    for i in shift + 1..n {
        out[i] = modulus - (a[n - (i - shift)] % modulus);
        if out[i] == modulus {
            out[i] = 0;
        }
    }

    out
}

pub fn negacyclic_matrix(a: &[u64], modulus: u64) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0u64; n * n];

    for i in 0..n {
        let perm = negacyclic_perm(a, i, modulus);
        for j in 0..n {
            out[j * n + i] = perm[j];
        }
    }

    out
}

pub fn get_negacylic<'a>(poly: &PolyMatrixRaw<'a>) -> PolyMatrixRaw<'a> {
    let mut out = poly.clone();

    (&mut out.as_mut_slice()[1..]).reverse();

    for z in 1..out.data.len() {
        out.data[z] = out.params.modulus - out.data[z];
    }

    out
}

pub fn reduce_copy(params: &Params, out: &mut [u64], inp: &[u64]) {
    for n in 0..params.crt_count {
        for z in 0..params.poly_len {
            out[n * params.poly_len + z] = barrett_coeff_u64(params, inp[z], n);
        }
    }
}

pub fn add_into_no_reduce(res: &mut PolyMatrixNTT, a: &PolyMatrixNTT) {
    assert!(res.rows == a.rows);
    assert!(res.cols == a.cols);

    for i in 0..res.rows {
        for j in 0..res.cols {
            let res_poly = res.get_poly_mut(i, j);
            let pol2 = a.get_poly(i, j);
            for (res_poly, pol2) in res_poly.iter_mut().zip(pol2.iter()) {
                *res_poly += *pol2;
            }
        }
    }
}

pub fn add_into_at_no_reduce(
    res: &mut PolyMatrixNTT,
    a: &PolyMatrixNTT,
    t_row: usize,
    t_col: usize,
) {
    let params = res.params;
    for i in 0..a.rows {
        for j in 0..a.cols {
            let res_poly = res.get_poly_mut(t_row + i, t_col + j);
            let pol2 = a.get_poly(i, j);
            for z in 0..params.crt_count * params.poly_len {
                res_poly[z] += pol2[z];
            }
        }
    }
}

pub fn modular_reduce_poly<'a>(a: &mut PolyMatrixNTT<'a>) {
    let params = a.params;
    for i in 0..a.rows {
        for j in 0..a.cols {
            let pol = a.get_poly_mut(i, j);
            for z in 0..params.crt_count * params.poly_len {
                pol[z] = barrett_coeff_u64(params, pol[z], z / params.poly_len);
            }
        }
    }
}

pub fn scalar_multiply_avx(res: &mut PolyMatrixNTT, a: &PolyMatrixNTT, b: &PolyMatrixNTT) {
    assert_eq!(a.rows, 1);
    assert_eq!(a.cols, 1);

    let params = res.params;
    let pol2 = a.get_poly(0, 0);
    for i in 0..b.rows {
        for j in 0..b.cols {
            let res_poly = res.get_poly_mut(i, j);
            let pol1 = b.get_poly(i, j);
            crate::packing::multiply_poly_avx(params, res_poly, pol1, pol2);
        }
    }
}

pub fn concat_horizontal(v_a: &[Vec<u64>], a_rows: usize, a_cols: usize) -> Vec<u64> {
    let mut out = vec![0u64; a_rows * a_cols * v_a.len()];

    for i in 0..a_rows {
        for j in 0..a_cols {
            for k in 0..v_a.len() {
                let idx = i * a_cols + j;
                let out_idx = i * a_cols * v_a.len() + k * a_cols + j;
                out[out_idx] = v_a[k][idx];
            }
        }
    }

    out
}

#[cfg(target_feature = "avx2")]
pub fn is_avx() -> bool {
    true
}

#[cfg(not(target_feature = "avx2"))]
pub fn is_avx() -> bool {
    false
}



pub fn multiply_matrices_raw_not_transposed<T>(
    params: &Params,
    a: &[u64],
    a_rows: usize,
    a_cols: usize,
    b: &[T], // NOT transposed
    b_rows: usize,
    b_cols: usize,
) -> Vec<u64>
where
    T: ToU64 + Copy,
{
    assert_eq!(a_cols, b_rows);

    let mut result = vec![0u128; a_rows * b_cols];

    for i in 0..a_rows {
        for k in 0..a_cols {
            for j in 0..b_cols {
                let a_idx = i * a_cols + k;
                let b_idx = k * b_cols + j;
                let res_idx = i * b_cols + j;

                unsafe {
                    let a_val = *a.get_unchecked(a_idx);
                    let b_val = (*b.get_unchecked(b_idx)).to_u64();

                    let prod = a_val as u128 * b_val as u128;
                    result[res_idx] += prod;
                }
            }
        }
    }

    let mut result_u64 = vec![0u64; a_rows * b_cols];
    for i in 0..result.len() {
        result_u64[i] = barrett_reduction_u128(params, result[i]);
    }

    result_u64
}
