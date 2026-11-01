# Policy DSL

Status: implemented for seccomp and Landlock. Last verified against `8b51686`.

`policy-dsl-rs` turns a YAML policy into enforcement: a libseccomp filter and a list of
Landlock rules with access masks. There is no AOT cache and no BPF-LSM generation — the
earlier "AOT-compiled runtime" claim was wrong, and the compiler has no timing target.

## Policy format

```yaml
name: production-hardened
version: "1"
seccomp:
  default_action: kill
  rules:
    - syscall: read
      action: allow
    - syscall: openat
      action: errno          # returns EPERM
landlock:
  rules:
    - path: /usr
      access: [read, execute]
    - path: /tmp
      access: [read, write, read_dir, remove]
cgroups:                     # parsed, not compiled into the output
  pids_limit: 64
  memory_limit_mb: 256
  cpu_quota: 0.5
```

Supported seccomp actions: `allow`, `kill`, `trap`, `errno` (EPERM), `log`. Anything else
falls back to `kill`. `default_action` is `allow` or `kill`; an unrecognised value is
treated as `kill`.

Landlock access names map to the ABI bits: `read`, `write`, `execute`, `read_dir`,
`remove`, `make_*`.

## Compilation

```rust
let mut compiler = PolicyCompiler::new();
let name = compiler.load_yaml(yaml)?;     // returns the policy name
let compiled: CompiledPolicy = compiler.compile(&name)?;
// compiled.seccomp_filter: Option<Vec<u8>>  — BPF bytecode
// compiled.landlock_rules: Vec<CompiledLandlockRule> { path, access_mask }
```

Seccomp rules are added to a `libseccomp` context and exported with `export_bpf`. Because
some libseccomp builds lack `export_bpf_mem`, the export goes through a temp file at
`$TMPDIR/phantom_seccomp_<pid>.bpf`, which is read and removed. That is the only I/O the
compiler performs.

Landlock rules are reduced to `(path, access_mask)` pairs; the caller applies them with
`landlock-rs`.

## What it does not do

- **No cgroups in the output.** `CgroupPolicy` is parsed and validated, but `CompiledPolicy`
  carries only seccomp and Landlock. Limits are applied by `cgroups-rs` elsewhere.
- **No BPF-LSM programs.** `bpf-lsm-rs` loads its own object; the DSL does not emit one.
- **No WASM policy.**
- **No AOT cache.** Compilation happens per call; there is no on-disk compiled artifact.
- **No dependency resolution or optimizer.** Earlier diagrams showed both; neither exists.
  Rules are added in the order given.

## Where it is used

`security-rs` applies a `SecurityPolicy` as a unit, and the CLI resolves a profile to a
seccomp profile name directly (`engine/sandbox.rs::seccomp_profile_for`) without going
through the DSL. The DSL is the general path; the profiles are the fast path.
