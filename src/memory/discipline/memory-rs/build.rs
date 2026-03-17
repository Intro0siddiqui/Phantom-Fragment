fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let zig_file = std::path::Path::new(&manifest_dir).join("../memory-zig/src/main.zig");
    let lib_path = std::path::Path::new(&out_dir).join("libphantom_memory.a");

    let status = std::process::Command::new("zig")
        .args([
            "build-lib",
            zig_file.to_str().unwrap(),
            "-fPIC",
            &format!("-femit-bin={}", lib_path.display()),
            "-target",
            "x86_64-linux-gnu",
            "-O",
            "ReleaseFast",
            "-lc",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("Error: Zig compilation failed with status: {}", s);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: Failed to execute zig command: {}", e);
            eprintln!("Make sure Zig 0.14+ is installed and in your PATH.");
            std::process::exit(1);
        }
    }

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=phantom_memory");
    println!("cargo:rerun-if-changed={}", zig_file.display());
    println!(
        "cargo:rerun-if-changed={}/../memory-zig/src/buffer_pool.zig",
        manifest_dir
    );
    println!(
        "cargo:rerun-if-changed={}/../memory-zig/src/ksm_manager.zig",
        manifest_dir
    );
}
