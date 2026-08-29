# Vendored PIR Sources

Everything needed to build YPIR lives in this tree. The build never reaches the
network: `workers/ypir/.cargo/config.toml` sets `net.offline = true` and
redirects crates.io to `workers/ypir/vendor/`.

## What Is Here And Where It Came From

| Path | Upstream | Pinned at |
| --- | --- | --- |
| `workers/ypir` | `github.com/menonsamir/ypir` | `a73e550a469605c2fa23945a4d96c20fb2f4a839` |
| `workers/spiral-rs` | `github.com/menonsamir/spiral-rs` | `6929441` |
| `workers/ypir/vendor` | crates.io, via `cargo vendor` | `workers/ypir/Cargo.lock` |

Both are MIT licensed, the upstream `LICENSE` files are kept in place.

## Local Modifications

Each of these exists for a reason. Re-apply them if the pins are ever moved.

1. **`spiral-rs` is a path dependency, not a git dependency.** Upstream declares
   `spiral-rs = { git = "...", rev = "6929441" }`, which makes every build fetch
   from GitHub. It is now `{ path = "../spiral-rs" }`.
2. **`#![feature(stdarch_x86_avx512)]` removed** from `ypir/src/lib.rs` and
   `spiral-rs/src/lib.rs`. The feature was stabilised in Rust 1.89, and a
   `#![feature]` attribute is a hard error on stable.
3. **`rust-toolchain.toml` deleted.** It pinned `nightly-2024-02-07`, which
   rustup would download on any machine that lacks it — a network fetch at build
   time. The crate builds on stable with (2) applied.
4. **`clap`, `env_logger`, and `test-log` dropped**, along with `src/bin/run.rs`
   (upstream's research CLI) and `rodeo/` (benchmark data). These pulled the
   entire `windows-sys` family in transitively: the vendor tree went from 70
   crates / 99 MB to 37 crates / 17 MB. The two `use test_log::test,` lines in
   `src/kernel.rs` and `src/scheme.rs` were removed with them, those test modules
   work under the standard harness.
5. **`build.rs` no longer uses `-march=native`.** x86-64 builds use
   `-march=x86-64-v3`, so `matmul.cpp` targets the same baseline as the Rust
   side instead of the build machine. ARM64 builds use the compiler's portable
   architecture baseline.
6. **`spiral-rs/.cargo/config.toml` deleted**, and its `-C target-cpu=native`
   folded into `workers/ypir/.cargo/config.toml` instead. A config file in a path
   dependency is not read when building from `workers/ypir`, so keeping it there
   made the effective ISA depend on which directory the build was invoked from.

`Cargo.lock` is upstream's. Do not delete it: regenerating floats `serde` and
friends forward to versions using `#[diagnostic]`, which upstream's pinned
nightly cannot parse.

## Build

```sh
cd workers/ypir && cargo build --release --offline
```

This produces the library plus `qor-pir-worker`, the persistent PIR worker Qor
runs. Qor-specific code is confined to two files so the upstream pins stay easy
to move: `src/qor_spool.rs` (record packing and wire framing) and
`src/bin/qor-pir-worker.rs`. `src/m512.rs` is the SIMD port described below.

## SIMD Paths, And Why `src/m512.rs` Exists

As vendored, YPIR only compiled with AVX-512 enabled. That was not a deliberate
hardware requirement, it was a gap: upstream provided a fallback for
`not(target_feature = "avx2")`, which aliased the 512-bit lane type to a bare
`u64`, and a separate fallback for `not(avx512f)` that cast a raw pointer to
that lane type. The two only type-check *together*. The configuration real
hardware actually has — **AVX2 present, AVX-512 absent** — was not expressible,
so it failed to build:

| Target | As vendored | Now |
| --- | --- | --- |
| `target-cpu=native` (AVX-512 host) | builds | builds |
| `target-cpu=x86-64-v3` (AVX2) | `E0605: non-primitive cast: *const u8 as __m512i` | builds |
| `target-cpu=x86-64` (baseline) | `E0308` in `kernel.rs`, `E0425 multiply_no_reduce` | not supported |

This mattered because Intel disabled AVX-512 on consumer parts from 12th
generation onward and AMD only has it from Zen 4, so an AVX-512-only binary
**crashes with SIGILL** on a large share of desktop hardware.

`src/m512.rs` replaces the broken fallbacks with one eight-lane u64 abstraction
that has two implementations selected by `cfg`: the real `_mm512_*` intrinsics
when `avx512f` is available, and a portable `[u64, 8]` version otherwise, which
LLVM vectorises to AVX2. `kernel.rs`, `packing.rs`, and `server.rs` now call the
shim instead of intrinsics directly. This also fixed the stabilised const-generic
signature (`_mm512_srli_epi64::<32>(a)`), which was the other reason the crate
would not build on stable.

The x86-64 shipping baseline is `x86-64-v3` (AVX2, Haswell 2013 and later), set
in `ypir/.cargo/config.toml`. The Docker server also builds on ARM64. That path
uses the portable `m512` implementation, scalar NTT routines, and a scalar
`multiply_no_reduce` fallback, x86-only compiler flags and intrinsics are gated
to x86-64. This lets an Apple Silicon or Linux ARM64 Docker host build the
server-side PIR worker without emulating an x86 server image.

### Verification

Both implementations must agree, and a divergence would corrupt plaintext rather
than raise an error, so it is checked. `m512::tests` asserts
the lane operations against an independently written reference, and the ported
call sites are covered end to end. Every one of these passes under both
`target-cpu=x86-64-v3` and `target-cpu=native`:

| Test | AVX2 | AVX-512 |
| --- | --- | --- |
| `m512::tests` (3 tests) | pass | pass |
| `kernel::test::test_fast_batched_dot_product_avx512` | pass | pass |
| `packing::test` (4 tests) | pass 7.25s | pass 1.17s |
| `scheme::test::test_ypir_basic` (end to end) | pass 12.11s | pass 6.82s |

The portable path costs roughly 1.8× end to end and ~6× on packing alone. That
is the price of running on hardware that lacks AVX-512, and it is still far
faster than downloading the whole spool.

Both PIR sidecars cross-build as AArch64 executables. Under AArch64 emulation,
the portable NTT round-trip tests, all three portable `m512` operation tests,
and a real client-side query-generation round trip pass. The Docker server
builds its worker natively when its Linux container runtime reports `arm64`,
while the desktop build stages the client matching its Rust target triple.

The desktop build requests only `qor-pir-client`, the server worker is not
linked a second time during every app build. Release builders can stage a
specific architecture explicitly, for example:

```sh
node scripts/build-pir-sidecars.cjs --client-only \
  --target aarch64-unknown-linux-gnu
```

To recheck after any change to the shim or its call sites:

```sh
cd workers/ypir
for CPU in x86-64-v3 native; do
  RUSTFLAGS="-C target-cpu=$CPU" cargo test --release --offline m512
  RUSTFLAGS="-C target-cpu=$CPU" cargo test --release --offline kernel
  RUSTFLAGS="-C target-cpu=$CPU" cargo test --release --offline ypir_basic
done
```
