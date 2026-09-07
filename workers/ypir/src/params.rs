use log::debug;

use spiral_rs::{arith::*, params::*};

use super::lwe::LWEParams;

static DEFAULT_MODULI: [u64; 2] = [268369921u64, 249561089u64];

fn internal_params_for(
    nu_1: usize,
    nu_2: usize,
    p: u64,
    q2_bits: usize,
    t_exp_left: usize,
) -> Params {
    Params::init(
        2048,
        &DEFAULT_MODULI,
        16.042421,
        1,
        p,
        u64::max(q2_bits as u64, MIN_Q2_BITS),
        4,
        t_exp_left,
        2,
        3,
        true,
        nu_1,
        nu_2,
        1,
        2048 * log2_ceil(p) as usize / 8,
        0,
    )
}

pub fn params_for_scenario(num_items: usize, item_size_bits: usize) -> Params {
    let total_db_bytes = num_items * item_size_bits / 8;
    let lwe_pt_word_bytes = 1;
    let num_items = total_db_bytes / lwe_pt_word_bytes;
    let num_tiles = num_items as f64 / (2048. * 2048.);
    let num_tiles_usize = num_tiles.ceil() as usize;
    let num_tiles_log2 = (num_tiles_usize as f64).log2().ceil() as usize;

    let (nu_1, nu_2) = if num_tiles_log2 % 2 == 0 {
        (num_tiles_log2 / 2, num_tiles_log2 / 2)
    } else {
        ((num_tiles_log2 + 1) / 2, (num_tiles_log2 - 1) / 2)
    };

    debug!("chose nu_1: {}, nu_2: {}", nu_1, nu_2);

    let p = 32768;
    let q2_bits = 28;
    let t_exp_left = 3;

    internal_params_for(nu_1, nu_2, p, q2_bits, t_exp_left)
}

pub fn params_for_scenario_simplepir(num_items: usize, item_size_bits: usize) -> Params {
    let db_rows = num_items;
    let db_cols = (item_size_bits as f64 / (2048.0 * 14.0)).ceil() as usize;

    debug!("db_rows: {}, db_cols: {}", db_rows, db_cols);

    let nu_1 = (db_rows.next_power_of_two().trailing_zeros() as usize)
        .checked_sub(11)
        .unwrap_or(0);
    debug!("chose nu_1: {}", nu_1);

    let p = 1 << 14;
    let q2_bits = 28;
    let t_exp_left = 3;

    let mut params = internal_params_for(nu_1, 1, p, q2_bits, t_exp_left);
    params.instances = db_cols;
    params
}

pub trait GetQPrime {
    /// The smaller reduced modulus, used on the second row of the encoding
    fn get_q_prime_1(&self) -> u64;

    /// The larger reduced modulus, used on the first row of the encoding
    fn get_q_prime_2(&self) -> u64;
}

impl GetQPrime for Params {
    fn get_q_prime_1(&self) -> u64 {
        1 << 20
    }

    fn get_q_prime_2(&self) -> u64 {
        if self.q2_bits == self.modulus_log2 {
            self.modulus
        } else {
            Q2_VALUES[self.q2_bits as usize]
        }
    }
}

impl GetQPrime for LWEParams {
    fn get_q_prime_1(&self) -> u64 {
        u64::MAX // unsupported
    }

    fn get_q_prime_2(&self) -> u64 {
        if self.q2_bits == (self.modulus as f64).log2().ceil() as usize {
            self.modulus
        } else {
            Q2_VALUES[self.q2_bits as usize]
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct YPIRParams {
    pub is_simplepir: bool,
}

#[cfg(test)]
mod qorc_sizing {
    use super::*;

    #[test]
    fn spool_scenario_params_are_sane() {
        let entry_bytes = 16 * 1024;
        let rows_per_record = (1_568usize + 12 + 131_072 + 16).div_ceil(entry_bytes);
        for &record_count in &[64usize, 219, 455] {
            let num_items = record_count * rows_per_record;
            let params = params_for_scenario_simplepir(num_items, entry_bytes * 8);
            let db_rows = 1usize << (params.db_dim_1 + params.poly_len_log2);
            let db_cols = params.instances * params.poly_len;
            println!(
                "items={num_items} rows={db_rows} cols={db_cols} pt_mod={} db_bytes={}",
                params.pt_modulus,
                db_rows * db_cols * 2
            );
            assert!(db_rows >= num_items, "rows {db_rows} < items {num_items}");
            assert!(db_cols > 0);
        }
    }

    #[test]
    fn current_spool_response_fits_the_one_mib_anonymous_class() {
        let entry_bytes = 16 * 1024;
        let rows_per_record = (1_568usize + 12 + 131_072 + 16).div_ceil(entry_bytes);
        for record_count in [219usize, 3_031, 24_248] {
            let params =
                params_for_scenario_simplepir(record_count * rows_per_record, entry_bytes * 8);
            let switched_part_bits = ((params.get_q_prime_1() as f64).log2().ceil() as usize
                + (params.get_q_prime_2() as f64).log2().ceil() as usize)
                * params.poly_len;
            let switched_part_bytes = switched_part_bits.div_ceil(8);
            let row_response_bytes = 4 + params.instances * (4 + switched_part_bytes);
            let raw_response_bytes = 8 + rows_per_record * (4 + row_response_bytes);
            let base64_response_bytes = raw_response_bytes.div_ceil(3) * 4;

            assert!(raw_response_bytes <= 760 * 1024);
            assert!(base64_response_bytes + 8 * 1024 < 1024 * 1024);
        }
    }
}
