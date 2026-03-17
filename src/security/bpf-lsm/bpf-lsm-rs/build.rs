use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Tell cargo to check for the bpf_compiled cfg flag
    println!("cargo::rustc-check-cfg=cfg(bpf_compiled)");

    // Use absolute paths based on CARGO_MANIFEST_DIR
    let monitor_c =
        Path::new(&manifest_dir).join("../../../orchestration/security-rs/bpf/monitor.c");
    let monitor_o = Path::new(&out_dir).join("monitor.o");

    println!("cargo:rerun-if-changed={}", monitor_c.display());
    println!("cargo:rerun-if-changed=build.rs");

    // Check if clang is available
    let clang_check = Command::new("which").arg("clang").output();

    if clang_check.is_err() || !clang_check.unwrap().status.success() {
        println!("cargo:warning=clang not found, skipping BPF compilation");
        return;
    }

    // Compile monitor.c to BPF bytecode
    let status = Command::new("clang")
        .args([
            "-O2",
            "-target",
            "bpf",
            "-c",
            monitor_c.to_str().unwrap(),
            "-o",
            monitor_o.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-cfg=bpf_compiled");
            println!("cargo:warning=BPF program compiled successfully");
        }
        Ok(_) => {
            println!("cargo:warning=BPF compilation failed, graceful fallback enabled");
        }
        Err(e) => {
            println!(
                "cargo:warning=Failed to run clang: {}, graceful fallback enabled",
                e
            );
        }
    }
}
