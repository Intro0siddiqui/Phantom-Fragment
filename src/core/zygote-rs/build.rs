fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let zig_file = "src/zygote.zig";
    let lib_path = std::path::Path::new(&out_dir).join("libzygote.a");

    // Invoke the `zig build-lib` command to compile the Zig code into a static library with PIC
    let status = std::process::Command::new("zig")
        .args([
            "build-lib",
            zig_file,
            "-fPIC", // Position Independent Code for linking with Rust
            &format!("-femit-bin={}", lib_path.display()),
            "-target",
            "x86_64-linux-gnu",
            "-O",
            "ReleaseFast",
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

    // Link the static library
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=zygote");
    println!("cargo:rerun-if-changed={}", zig_file);
}
