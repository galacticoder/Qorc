#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("qorc YPIR supports only Linux and Windows");

pub mod bits;
pub mod client;
pub mod convolution;
pub mod kernel;
pub mod lwe;
pub mod m512;
pub mod matmul;
pub mod measurement;
pub mod modulus_switch;
pub mod noise_analysis;
pub mod packing;
pub mod params;
pub mod qorc_spool;
pub mod scheme;
pub mod server;
pub mod transpose;
pub mod util;
