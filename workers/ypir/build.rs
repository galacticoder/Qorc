fn main() {
    println!("cargo:rerun-if-changed=src/matmul.cpp");
    let mut build = cc::Build::new();
    build.cpp(true).file("src/matmul.cpp").opt_level(3);

    let msvc = build.get_compiler().is_like_msvc();
    build.std(if msvc { "c++14" } else { "c++11" });

    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        build.flag(if msvc {
            "/arch:AVX2"
        } else {
            "-march=x86-64-v3"
        });
    }

    build.compile("matmul");
}
