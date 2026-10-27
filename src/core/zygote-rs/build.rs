use std::process::Command;

/// Phantom Fragment's Zig sources target the 0.16 std API.
const MIN_ZIG_MINOR: u32 = 16;

/// Fail early with an actionable message instead of a wall of Zig compile errors.
fn check_zig_version() {
    let output = Command::new("zig")
        .arg("version")
        .output()
        .unwrap_or_else(|e| {
            eprintln!(
                "error: could not run `zig` ({e}).\n\
             Phantom Fragment requires Zig 0.16 or newer to build its native libraries.\n\
             Install it from https://ziglang.org/download/ and make sure `zig` is in PATH."
            );
            std::process::exit(1);
        });

    if !output.status.success() {
        eprintln!(
            "error: `zig version` failed with status {}.\n\
             Phantom Fragment requires Zig 0.16 or newer; check your Zig installation.",
            output.status
        );
        std::process::exit(1);
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mut parts = version.split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);

    if major == 0 && minor < MIN_ZIG_MINOR {
        eprintln!(
            "error: Zig {version} is too old; Phantom Fragment requires Zig 0.16 or newer.\n\
             Install a supported toolchain from https://ziglang.org/download/ and make sure it is first in PATH."
        );
        std::process::exit(1);
    }
}

fn main() {
    check_zig_version();

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
            eprintln!("Make sure Zig 0.16+ is installed and in your PATH.");
            std::process::exit(1);
        }
    }

    // Link the static library
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=zygote");
    println!("cargo:rerun-if-changed={}", zig_file);
}
