# Memory Discipline

Status: implemented, thinly wired in. Last verified against `8b51686`.

Allocation in this subsystem is **Zig**. `memory-rs` is a 136-line safe wrapper: it
contains no allocation, no `mmap`, and no pointer arithmetic. Its `unsafe` blocks are the
FFI boundary only.

## What it provides

| Concern | Where | Status |
|---|---|---|
| Buffer pool | `memory-zig/src/buffer_pool.zig` | working; 4096-aligned `posix_memalign`, mutex-guarded free list, grows on demand |
| KSM dedup | `memory-zig/src/ksm_manager.zig` | working; `madvise(MADV_MERGEABLE)`, enabling KSM needs root |
| NUMA | `memory-zig/src/main.zig` | working; `mbind` + sysfs `cpumap`, no libnuma dependency |
| CPU affinity | `memory-zig/src/main.zig` | working; raw `sched_setaffinity` |
| Rust wrapper | `memory-rs/src/lib.rs` | safe API, `NonNull` + RAII guard |

## How allocation works

`BufferPool::init` pre-allocates `capacity` buffers of `buffer_size` with
`posix_memalign(&ptr, 4096, size)`. 4096 alignment is not for performance: it is the
granularity KSM merges at. `get` pops from the free list (or allocates if it is empty);
`put` pushes back, and frees instead of growing past `capacity`.

The Rust side exposes that as an RAII guard, so a buffer cannot be leaked or double-put:

```rust
let pool = BufferPool::new(64 * 1024, 1000).expect("pool");
let mut buf = pool.get().expect("buffer");   // BufferGuard<'_>
buf[..4].copy_from_slice(b"data");           // DerefMut to [u8]
// drop returns the buffer to the pool
```

`BufferGuard` holds `NonNull<u8>` + length + `&BufferPool`. `Deref`/`DerefMut` build a
slice with `from_raw_parts`; `Drop` calls `phantom_buffer_pool_put`. That is the only
pointer handling in Rust, and it is four lines long.

The one genuinely unsafe call for the caller is `NumaManager::free(ptr, size)`, which is
`pub unsafe fn` with the contract documented. Everything else is safe.

## Safety model

| Layer | Responsibility |
|---|---|
| Zig | owns the allocation, alignment, free list, and the syscalls |
| `memory-rs` | never lets a raw pointer escape; ties buffer lifetime to the pool |
| Caller | must not use a `NumaManager` allocation after `free` (hence `unsafe fn`) |

## Where it is actually used

- `commands/benchmark.rs`: the only consumer of `BufferPool`.
- `execution-rs`: `set_cpu_affinity` and `NumaManager::bind_node` from the hardware
  profile.

**What is not in Zig:** image download, layer decompression, rootfs extraction and the
rest of the I/O path use ordinary `Vec<u8>` / `Bytes` on the system allocator. That is
safe Rust, but it is not this subsystem. The Zig allocator is not carrying the runtime's
memory traffic yet.

## Measured

From `src/memory/discipline/memory-zig/stress_test` on the development machine. Not
re-run since; treat as indicative, not as a guarantee.

| Test | Result |
|---|---|
| Pool init (1000 × 64 KB) | 3.6 ms |
| 100k get/put cycles | 361,760 ops/s (~22 GB/s) |
| 4 threads | 470,983 ops/s (~28.75 GB/s) |
| Pooled vs `malloc`/`free` | 26.7 ms vs 874.7 ms for the same cycle count |

The last row is the honest headline: the win is avoiding allocator churn, not a faster
`memcpy`.

## Building

```bash
cd src/memory/discipline/memory-zig
zig build                      # builds libphantom_memory.a, linked by memory-rs build.rs
zig build-exe test_numa.zig -lc && ./test_numa
```

Zig 0.16 is required; `build.rs` in `memory-rs` invokes the Zig build automatically, so
`cargo build` needs `zig` on `PATH`.
