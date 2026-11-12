use crate::{params::*, poly::*};

pub fn get_bits_per(params: &Params, dim: usize) -> usize {
    let modulus_log2 = params.modulus_log2;
    if dim as u64 == modulus_log2 {
        return 1;
    }
    ((modulus_log2 as f64) / (dim as f64)).floor() as usize + 1
}

pub fn build_gadget(params: &Params, rows: usize, cols: usize) -> PolyMatrixRaw {
    let mut g = PolyMatrixRaw::zero(params, rows, cols);
    let nx = g.rows;
    let m = g.cols;

    assert_eq!(m % nx, 0);

    let num_elems = m / nx;
    let params = g.params;
    let bits_per = get_bits_per(params, num_elems);

    for i in 0..nx {
        for j in 0..num_elems {
            if bits_per * j >= 64 {
                continue;
            }
            let poly = g.get_poly_mut(i, i + j * nx);
            poly[0] = 1u64 << (bits_per * j);
        }
    }
    g
}

pub fn gadget_invert_rdim<'a>(out: &mut PolyMatrixRaw<'a>, inp: &PolyMatrixRaw<'a>, rdim: usize) {
    assert_eq!(out.cols, inp.cols);

    let params = inp.params;
    let mx = out.rows;
    let num_elems = mx / rdim;
    let bits_per = get_bits_per(params, num_elems);
    let mask = (1u64 << bits_per) - 1;

    for j in 0..rdim {
        for i in 0..inp.cols {
            for z in 0..params.poly_len {
                let val = inp.get_poly(j, i)[z];
                for k in 0..num_elems {
                    let bit_offs = k * bits_per;
                    let piece = if bit_offs >= 64 {
                        0
                    } else {
                        (val >> bit_offs) & mask
                    };

                    out.get_poly_mut(j + k * rdim, i)[z] = piece;
                }
            }
        }
    }
}

pub fn gadget_invert<'a>(out: &mut PolyMatrixRaw<'a>, inp: &PolyMatrixRaw<'a>) {
    gadget_invert_rdim(out, inp, inp.rows);
}

pub fn gadget_invert_alloc<'a>(mx: usize, inp: &PolyMatrixRaw<'a>) -> PolyMatrixRaw<'a> {
    let mut out = PolyMatrixRaw::zero(inp.params, mx, inp.cols);
    gadget_invert(&mut out, inp);
    out
}
