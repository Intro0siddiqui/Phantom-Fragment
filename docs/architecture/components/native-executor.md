# Native Cold Executor

Status: planned (Phase A). Owner: CLI + security stack.

## Why

`phantom run <image>` currently delegates to `RootfsExecutor`, which shells out to
`bwrap`. That path applies user/mount/PID/IPC/UTS namespaces, `/proc`, `/dev` and
`/tmp`, but it never applies seccomp, Landlock or capability dropping:
`rootfs_executor.rs` has no reference to the security crates, and
`SecurityManager::apply_container_security` is only called in the no-image
branch of `run.rs`.

Warm execution is therefore *more* confined than cold execution. This document
closes that inversion by making the native engine the default for image runs and
keeping bubblewrap as a fallback until the native engine reaches parity.

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

- Removing `RootfsExecutor`: `--proot`, `--overlay`, `--runtime <oci>` and
  `--engine bwrap` keep using it.
- Replacing the warm mother. Warm stays a pre-sandboxed long-lived process; cold
  is a one-shot sandbox.
- Volumes, `create`/`exec`/`attach` and output streaming. Those are the
  lifecycle track and build on this engine later.

## Execution sequence

Parent (the `phantom` CLI):

1. Resolve the profile to `ChildPolicy { file_write, seccomp }` and the image
   user to `(inside_uid, inside_gid)`.
2. Create the cgroup when a hardware profile is present (best effort, as warm
   does).
3. Create a sync pipe, then `fork(2)`.

Child:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
   CLONE_NEWUTS | (network ? 0 : CLONE_NEWNET))`.
2. Write `/proc/self/setgroups` = `deny`, then `uid_map`/`gid_map` as
   `"<inside> <outside> 1"`. Mapping inside 0 to the invoking uid is how the
   image runs as root inside without host root; mapping inside N to N keeps the
   invoking user.
3. `mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)`.
4. `chroot(rootfs)`, `chdir("/")`.
5. `mount("proc", "/proc", "proc", ...)`.
6. `mount("tmpfs", "/tmp", "tmpfs", ...)`.
7. `/dev`: `mount("tmpfs", "/dev", "tmpfs", ...)`, bind the host's
   `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`,
   `/dev/tty`, and mount `devpts` on `/dev/pts` so inherited ttys keep working.
8. `fork(2)` once more. The first child in the new PID namespace is PID 1; it
   forks the command, waits, and forwards `SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT`
   to it. This is the reaper, and it is what makes `--unshare-pid` correct.
9. In the command child: apply Landlock (`file_write`), drop the capability
   bounding set and clear the sets, set `no_new_privs`, install the seccomp
   profile, set `PATH` and the request environment, `execvp`.

Parent: `waitpid` the outer child, translate the status to an exit code, destroy
the cgroup.

The security stack is applied **after** chroot and mounts and **before**
`execve`, exactly as in `sandbox_mother`. It is never applied in the CLI parent.

## Fallback rules

- `--engine native` (default): run native.
- `--engine bwrap`: use `RootfsExecutor` as today.
- `--engine auto`: native, then bubblewrap only if native reports
  `Unsupported` (user namespaces disabled, `mount` denied, `/proc` unavailable).
  A `Security` failure (Landlock/seccomp/capability setup) never falls back.
- A `hardened` profile never falls back: if native cannot enforce it, the run
  fails.
- Every fallback prints one warning that names the reason and states that the
  bubblewrap fallback does not apply seccomp/Landlock yet.

## Code layout

- `src/cli/phantom-cli/src/engine/sandbox.rs`: shared `ChildPolicy`, profile
  resolution, Landlock, capability drop, seccomp. Moved out of `daemon/warm.rs`;
  warm imports it unchanged.
- `src/cli/phantom-cli/src/engine/native.rs`: the sequence above, `spawn` and
  `execute`.
- `commands/run.rs`: choose the engine; `RootfsExecutor` stays for the
  non-native paths.

## Phases

1. **A1 — extract the shared security stack.** Move `ChildPolicy`,
   `resolve_child_policy`, `seccomp_profile_for`, `apply_child_landlock`,
   `drop_child_capabilities` and the Landlock constants into
   `engine/sandbox.rs`. Warm calls them. All 34 daemon tests and 66 CLI tests
   keep passing. No behavior change.
2. **A2 — native executor, opt-in.** Implement the sequence with
   `--engine native`. Verify on alpine: `true`, `cat /etc/alpine-release`,
   hardened `touch` denied, sandbox `touch` allowed, exit codes, signals, tty,
   network on/off, image USER.
3. **A3 — default and fallback.** Make native the default, wire
   `--engine auto|native|bwrap`, implement the fallback classification, and
   update README/AGENTS and the warm docs to describe one engine with two
   backends.

## Tests

- Unit: uid/gid map formatting, profile → seccomp mapping, engine selection,
  fallback classification.
- Integration (host with userns): chroot visibility (`/etc/os-release` hidden
  from the host), `/proc` shows PID 1 for the command, `/tmp` is tmpfs,
  network disabled has no route, hardened write denied, sandbox write allowed,
  signal forwarding, exit code propagation.
- Regression: all warm daemon tests; cold `--engine bwrap` unchanged.

## Open questions

- `devpts` mount options (`newinstance,ptmxmode=0666,mode=0620`) need to work
  inside a rootless userns on the supported kernels. If not, fall back to
  binding the host `/dev/pts` read-only and document the weaker tty isolation.
- Whether to keep the extra init/reaper process or let the command be PID 1.
  The reaper is required for correct signal handling and zombie collection;
  keep it.
