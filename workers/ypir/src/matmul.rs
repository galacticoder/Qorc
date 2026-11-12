use log::debug;

extern "C" {
    fn matMulVecPacked(out: *mut u32, a: *const u32, b: *const u32, a_rows: usize, a_cols: usize);
    fn matMulVecPacked2(
        out: *mut u32,
        a: *const u32,
        b_full: *const u32,
        a_rows: usize,
        a_cols: usize,
    );
    fn matMulVecPacked4(
        out: *mut u32,
        a: *const u32,
        b_full: *const u32,
        a_rows: usize,
        a_cols: usize,
    );
    fn matMulVecPacked8(
        out: *mut u32,
        a: *const u32,
        b_full: *const u32,
        a_rows: usize,
        a_cols: usize,
    );
}

/// Returns `out = a * b` where `a` is a matrix of shape `(a_rows, a_cols)` and
/// `b` is a vector of shape `(b_rows, b_cols)`. `out` is a vector of shape
/// `(a_rows, b_cols)`.
///
/// `a_cols * 4` must equal `b_rows`. `b_cols` must be 1. `out` must have length
/// greater than or equal to `a_rows + 8`.
pub fn matmul_vec_packed(
    out: &mut [u32],
    a: &[u32],
    b: &[u32],
    a_rows: usize,
    a_cols: usize,
    b_rows: usize,
    b_cols: usize,
) {
    debug!(
        "matmul_vec_packed: a_rows: {}, a_cols: {}, b_rows: {}, b_cols: {}",
        a_rows, a_cols, b_rows, b_cols
    );
    assert_eq!(a.len(), a_rows * a_cols);
    assert_eq!(b.len(), b_rows * b_cols);
    assert_eq!(a_cols * 4, b_rows);
    assert!(out.len() >= a_rows + 8);

    unsafe {
        if b_cols == 1 {
            matMulVecPacked(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), a_rows, a_cols);
        } else if b_cols == 2 {
            matMulVecPacked2(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), a_rows, a_cols);
        } else if b_cols == 4 {
            matMulVecPacked4(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), a_rows, a_cols);
        // } else if b_cols == 6 {
        //     matMulVecPacked6(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), a_rows, a_cols);
        } else if b_cols == 8 {
            matMulVecPacked8(out.as_mut_ptr(), a.as_ptr(), b.as_ptr(), a_rows, a_cols);
        } else {
            panic!("b_cols must be 1, 2, 4, or 8");
        }
    }
}
