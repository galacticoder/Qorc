fn main() {
    println!("cargo:rerun-if-changed=src/matmul.cpp");
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/matmul.cpp")
        .flag("-O3")
        .flag("-std=c++11");

    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        build.flag("-march=x86-64-v3");
    }

    build.compile("matmul");
}
