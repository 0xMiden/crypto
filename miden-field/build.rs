use std::env;

fn main() {
    println!("cargo::rerun-if-env-changed=MIDENC_TARGET_IS_MIDEN_VM");
    println!("cargo::rustc-check-cfg=cfg(miden)");

    // `cargo-miden` compiles Rust to Wasm which will then be compiled to Miden VM code by `midenc`.
    // When targeting a "real" Wasm runtime (e.g. `wasm32-unknown-unknown` for a web SDK), we want a
    // regular felt representation instead.
    if env::var_os("MIDENC_TARGET_IS_MIDEN_VM").is_some() {
        println!("cargo::rustc-cfg=miden");
    }
}
