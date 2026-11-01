# Native Cold Executor

Status: implemented (Phases A1–A3). Owner: CLI + security stack.

## Why

`phantom run <image>` used to delegate to `RootfsExecutor`, which shells out to
`bwrap`. That path applies user/mount/PID/IPC/UTS namespaces, `/proc`, `/dev` and
`/tmp`, but it never applied seccomp, Landlock or capability dropping:
`rootfs_executor.rs` has no reference to the security crates, and
`SecurityManager::apply_container_security` is only called in the no-image
branch of `run.rs`.

Warm execution was therefore *more* confined than cold execution. The native
engine closes that inversion: it is the default for image runs, and bubblewrap
remains a classified fallback until the native engine reaches parity.

## Goals

- One native execution path for cold image runs: userns, mount ns, PID/IPC/UTS
  namespaces, network ns when disabled, chroot, `/proc`, `/dev`, `/tmp`, then
  Landlock → capability drop/`no_new_privs` → seccomp → `execve`.
- Reuse the security-stack code that the warm mother already uses; do not fork a
  second implementation of Landlock/caps/seccomp.
- Keep bubblewrap selectable and automatic as a fallback while native parity is
  incomplete.
- Never silently weaken a `hardened` request.

## Non-goals

- Removing `RootfsExecutor`: `--proot`, `--overlay`, `--runtime <oci>`,
  `--root` and `--engine bwrap` keep using it.
- Replacing the warm mother. Warm stays a pre-sandboxed long-lived process; cold
  is a one-shot sandbox.
- cgroup creation and BPF-LSM attachment. The native engine does not create a
  cgroup, so `memory_mb`/`cpu_count` from a profile are still not enforced on
  the cold path; `run.rs` only logs whether BPF-LSM is supported, it does not
  attach a program.
- Volumes, `create`/`exec`/`attach` and output streaming. Those are the
  lifecycle track and build on this engine later.

## Process layout

```text
phantom (CLI)                    host pid namespace
  └─ sandbox child               unshare + maps, then forks
       └─ reaper                 first process in the new pid namespace (PID 1)
            └─ command child     Landlock + caps + seccomp, then execve (PID 2)
```

Two kernel facts force this shape:

- `/proc` can only be mounted from inside the PID namespace that owns it. After
  `unshare(CLONE_NEWPID)` the caller is still in the old namespace, so the mount
  must happen after the fork, in the reaper. Mounting before the fork fails with
  `EPERM`.
- The command cannot be PID 1. PID 1 ignores signals it has no handler for, so a
  `SIGTERM` sent to the namespace would be lost. The reaper installs handlers,
  forwards `SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT` to the command, reaps it and
  exits with its status. It also dies with the CLI (`PR_SET_PDEATHSIG`), which
  tears down the PID namespace and therefore the command.

## Execution sequence

Parent (the `phantom` CLI):

1. Resolve the profile to `ChildPolicy { file_write, seccomp }` and the image
   user to `(inside_uid, inside_gid)` via the image's own `/etc/passwd` and
   `/etc/group`.
2. Create the mount-point directories (`proc`, `tmp`, `dev`, `dev/pts`,
   `dev/shm`, `etc`) on the host path of the rootfs and open the host files that
   will be bound (`/etc/resolv.conf` when network is enabled).
3. Create a sync pipe, then `fork(2)`.

Sandbox child (stays in the host PID namespace):

1. `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
   CLONE_NEWUTS | (network ? 0 : CLONE_NEWNET))`.
2. Write `/proc/self/setgroups` = `deny`, then `uid_map`/`gid_map` as
   `"<inside> <outside> 1"`. Mapping inside 0 to the invoking uid is how the
   image runs as root inside without host root; mapping inside N to N keeps the
   invoking user.
3. `mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)`.
4. `fork(2)`; the child is PID 1 of the new namespace.

Reaper (PID 1):

1. Mount through the **host** paths — `<rootfs>/dev`, `<rootfs>/tmp`,
   `<rootfs>/proc` — while the host root is still visible.
2. `tmpfs` on `/dev`, `tmpfs` on `/tmp`, `proc` on `/proc`.
3. Recreate `/dev/pts` and `/dev/shm` on the fresh tmpfs, bind the host device
   nodes over empty files, mount `devpts` with
   `newinstance,ptmxmode=0666,mode=0620` (falling back to a read-only bind of
   the host `/dev/pts`), symlink `/dev/ptmx` → `pts/ptmx`, `tmpfs` on
   `/dev/shm`.
4. Bind the resolv.conf when network is enabled.
5. `chroot(rootfs)`, `chdir("/")`.
6. `PR_SET_PDEATHSIG(SIGKILL)`, `fork(2)` the command, install the forwarding
   handlers, `waitpid`, exit with the command's status.

Command child (PID 2):

1. Landlock (`file_write` decides read-only vs. read-write, plus execute).
2. Drop the capability bounding set, clear the sets, set `no_new_privs`.
3. Install the seccomp profile.
4. `execvpe` with the request environment.

Every failure before the chroot is reported to the CLI over the sync pipe as
`Unsupported`; every failure after it, and every security-stack failure, is
reported as `Fatal`.

### Mounts are made before the root switch

Bind-mounting through `/proc/self/fd/<n>` does **not** work here: inside the new
root the magic link resolves to the same path it is being mounted onto, so the
bind becomes a file-onto-itself mount and fails with `EINVAL`. The reaper
therefore binds by host path first and chroots afterwards, which is what
bubblewrap does too.

### Supplementary groups

An unprivileged `gid_map` write requires `setgroups=deny`, which permanently
blocks `setgroups(2)` in the new namespace; clearing groups *before* writing the
map is refused with `EPERM`. Host supplementary groups therefore stay in the
group list, but none of them is mapped, so they appear as gid 65534 and grant
nothing. This matches the warm mother's behaviour. Running the image as a
non-root uid hides the issue entirely, because the group list is checked against
the mapped gid.

## Fallback rules

- `--engine auto` (default): native, then bubblewrap only if native reports
  `Unsupported` (user namespaces disabled, `mount` denied, `/proc` unavailable).
  A `Fatal` failure (Landlock/seccomp/capability/exec) never falls back.
- `--engine native`: any failure is fatal.
- `--engine bwrap`: `RootfsExecutor` as before.
- A profile that requires confinement the bubblewrap path does not apply never
  falls back: `hardened`, any profile with `file_write = false`, and any profile
  with a non-default seccomp profile.
- `--proot`, `--overlay`, `--runtime`, `--root` and `--wasm` always use
  `RootfsExecutor`; combining them with `--engine native` is an error.
- Every fallback prints one warning that names the reason and states that the
  bubblewrap fallback applies namespace isolation only.

## Landlock enforcement scope

`LandlockContext` requests `LANDLOCK_RESTRICT_SELF_TSYNC` (Landlock ABI 8, kernel 6.7+),
so a ruleset covers every thread in the process, not only the thread that applied it.

| Kernel ABI | Behaviour |
|---|---|
| >= 8 | ruleset applies to all threads; `RestrictionStatus::all_threads` is `true` |
| < 8 | `CompatLevel::BestEffort` drops the flag instead of failing; only the applying thread and its children are restricted, and a warning is logged |

A thread-scoped ruleset is silent under-enforcement if Landlock is ever applied inside a
threaded runtime. Phantom applies it in a freshly forked single-threaded child, where the
two scopes are equivalent, so TSYNC is defence in depth rather than a live fix. Test it by
checking `RestrictionStatus::all_threads`, not by inspecting the requested flags —
`RulesetCreated` keeps those private.

## Code layout

- `src/cli/phantom-cli/src/engine/sandbox.rs`: shared `ChildPolicy`, profile
  resolution, Landlock, capability drop, seccomp. Moved out of `daemon/warm.rs`;
  warm imports it unchanged.
- `src/cli/phantom-cli/src/engine/native.rs`: the sequence above.
- `src/cli/phantom-cli/src/engine/mod.rs`: `EngineChoice { auto, native, bwrap }`.
- `commands/run.rs`: engine selection, uid/gid resolution, environment, fallback
  classification; `RootfsExecutor` stays for the non-native paths.

## Verified behaviour

Measured on Void Linux, kernel 6.12, unprivileged user, alpine 3.24 rootfs:

| Check | Result |
|-------|--------|
| `phantom run alpine true` | exit 0, `Engine: native` |
| `cat /etc/alpine-release` | `3.24.3` |
| `id` | `uid=0(root) gid=0(root)` |
| `sh -c 'exit 42'` | exit 42 |
| hardened `touch /denied.txt` | `Operation not permitted`, no file created |
| sandbox `touch /allowed.txt` | exit 0, file created |
| hardened `echo hi > /dev/null` | works (device rules added to Landlock) |
| hardened network | 1 link, 0 routes |
| `-n` | 3 routes, public resolv.conf |
| `/proc/self/status` | `NoNewPrivs: 1`, `Seccomp: 2`, `CapEff: 0` |
| command PID | 2; `/proc/1/comm` is `phantom` |
| `SIGTERM` to the CLI | exit 143, no leftover processes |
| `--engine bwrap` | unchanged |
| `--engine native --proot` | hard error |

## Phases

1. **A1 — extract the shared security stack.** Done (`4066149`). `ChildPolicy`,
   `resolve_child_policy`, `seccomp_profile_for`, `apply_child_landlock`,
   `drop_child_capabilities`, `write_proc_file` and the Landlock constants live
   in `engine/sandbox.rs`. Warm calls them; all 66 CLI tests pass.
2. **A2 — native executor, opt-in.** Done. `--engine native` implements the
   sequence above.
3. **A3 — default and fallback.** Done. Native is the default, `--engine
   auto|native|bwrap` selects, and the fallback classification is implemented.

## Tests

- Unit: uid/gid map formatting, profile → seccomp mapping, engine selection,
  fallback classification.
- Integration (host with userns): chroot visibility, `/proc` shows PID 1 for the
  reaper, `/tmp` is tmpfs, network disabled has no route, hardened write denied,
  sandbox write allowed, signal forwarding, exit code propagation.
- Regression: all warm daemon tests; cold `--engine bwrap` unchanged.

## Known gaps

- No cgroup on the native path, so profile memory/CPU limits are not enforced.
- BPF-LSM is not attached; `run.rs` no longer claims it is "active".
- Image `USER` resolution is implemented but has not been exercised on a local
  image with a non-root `USER` (no such image available during development).
- No volumes, no `create`/`exec`/`attach`, no output streaming beyond inheriting
  the CLI's stdio.
