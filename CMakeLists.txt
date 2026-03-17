cmake_minimum_required(VERSION 3.16)
project(PhantomFragment C ASM)

# Minimal CMake for local C/ASM components (BPF/Shims)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE REQUIRED fuse3)

# Note: Core logic has migrated to Rust and Zig.
# C components remain only for BPF and hardware shims.
