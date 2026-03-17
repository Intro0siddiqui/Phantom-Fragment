fn main() {
    // No C compilation needed anymore
    println!("cargo:rerun-if-changed=build.rs");
}
