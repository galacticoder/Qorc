fn main() {
    println!("cargo:rerun-if-changed=src/matmul.cpp");
    cc::Build::new()
        .cpp(true)
        .file("src/matmul.cpp")
        .flag("-O3")
        .flag("-march=x86-64-v3")
        .flag("-std=c++11")
        .compile("matmul");
}
