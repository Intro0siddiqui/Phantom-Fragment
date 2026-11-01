# Warm Exec v2 — Plan

> **Status: beta.** The tables above are current. Sections 1–9 below are the original
> design record from 2026-10-27, kept because they explain *why* the warm path is shaped
> the way it is. Read them as history, not as a description of today's behaviour: every
> defect listed there has been fixed or is tracked in "Known limitations".

## What warm is

Warm is an **execution mode**, not a security level and not a second program. It runs
the same fragment as cold; the only thing it changes is *where the latency is paid*.

Cold pays, per command: create the namespaces, build the root, mount `/proc`, `/tmp` and
`/dev`, apply the security stack, `exec`. Warm pays that once and then serves each
command from a fragment that already exists. That is the entire idea. Everything else
below is a different answer to "which part of cold do we refuse to pay twice".

There is no separate "daemon" execution mode. The long-lived process **is** the fragment.
The small host process that accepts sockets is only its listener; it does not run the
command and it is not a warm method of its own.

### Method 1: the mother fragment

One long-lived fragment is built in the state the user runs most, and every later
fragment is forked from it. Two kinds:

- **Complete mother** — the full fragment state, image included. A fork needs no image
  work at all: the rootfs, the mounts and the security stack are already in place.
- **Semi mother** — holds only the expensive-to-build parts (namespaces, isolation,
  security stack) and not the image, which is applied dynamically at runtime. Cheaper to
  build and to keep, more work per request.

Whether a mother is faster than cold was unproven for a long time: early warm runs were
*slower*, because the mother learned of a child's exit on a 50 ms poll tick and the
client resolved an image the fragment already owned. Both are fixed (see "Measured
today" below), and the mother now wins clearly on the same machine.

### Method 2: the zygote pool

Not one fragment: a **collection of fragments created ahead of time**, then frozen and
compressed so they cost almost no CPU and almost no RAM while idle. The mental model is
that the user has already run many cold fragments and stored them; when one is wanted,
the machine does not fork — the stored fragment is already exactly the desired state, so
it only has to be made active.

This is the only method that can plausibly beat cold by a wide margin, and it is also
the one where the entire question is *restore cost*: thawing, page faults and re-mapping
are the latency. Note that the Zig pool in this tree is **not** that yet — it pre-forks
processes and still forks a grandchild per request (see the status table below).

### Method 3: artifact / cache warm

No button, no pool, no long-lived process. The first cold run of a fragment type leaves
artifacts behind — pulled layers, an extracted rootfs, build outputs, compiled caches —
and later cold runs reuse them, so latency drops after the first run. It is **advanced
cold start**: the same path, less work. Today only image and rootfs reuse exists.

## Terminology

| Term | Definition |
|------|------------|
| **Fragment** | One running instance: namespaces, private root, security stack, a command |
| **Mother fragment** | A long-lived fragment that other fragments are forked from |
| **Complete mother** | A mother that already contains the image |
| **Semi mother** | A mother that contains the isolation/security state but not the image; the image is applied at runtime |
| **Zygote** | A pre-created fragment stored frozen and compressed until activated |
| **Zygote pool** | A collection of frozen zygotes, activated on demand |
| **Artifact cache** | On-disk products of previous cold runs, reused by later cold runs |

> **Implementation note.** The mother is a pre-sandboxed process: chroot, namespaces,
> Landlock, capability drop, seccomp and (when delegated) a cgroup are applied once at
> pool-fill time; each request is a `fork` + `exec` of it. It is forked by a small
> host-side listener that owns the Unix socket, because a process inside a mount
> namespace cannot accept a host path. The listener is not the fragment.

---

## Status of each method

| Method | Status | What exists today |
|---|---|---|
| **Mother fragment** | Implemented, beta | One pre-sandboxed mother per pool, forked once at pool fill; chroot, user/mount/PID/IPC/UTS namespaces, procfs, Landlock, caps, seccomp and (when delegated) a cgroup applied once. Each request is a `fork` + `exec` with the caller's stdin/stdout/stderr passed over the socket (SCM_RIGHTS); when stdin is a terminal the client allocates a pty instead and proxies it. Ctrl+C/SIGTERM are relayed to the command, and a slot whose client dies is reclaimed. Profile is bound at creation and a mismatch is a hard error. A slot whose daemon died (crash, reboot) is rebuilt on the next run with the pool's profile instead of degrading the pool to cold forever. |
| **Semi mother** | Not implemented | The pool always builds a complete mother for one image. There is no image-less mother with the image applied per request. |
| **Zygote pool** | Partial, different model | The Zig pool pre-forks processes and, per request, `unshare`s the mount ns, `pivot_root`s into the rootfs and forks a grandchild to `execve`. It is a spawn accelerator, not frozen-state activation: no thawing, no compression, no restore. It applies no seccomp, Landlock or capability drop, so `run --zygote` skips it whenever a policy is requested. Not connected to the mother path. |
| **Artifact / cache warm** | Partial | Pulled layers, the extracted rootfs and the build cache are reused by later cold runs. There is no compiled-artifact or executed-work cache, and nothing measures the latency drop. |

### Known limitations

| Limitation | Impact |
|---|---|
| One command per fragment at a time (D5) | A long-running command blocks health checks on that fragment; scale the pool instead of queueing |
| Pty output is merged | With a terminal, stdout and stderr are one stream, as in `docker run -t` |
| No semi mother | Every pool pays full image setup, even for images used only briefly |
| Zygote is not frozen-state activation | No restore path, so it cannot reach the sub-millisecond target by activation |
| No artifact cache beyond images | Repeated cold runs redo work that a compiler-cache model would keep |

### Measured today (2026-10-31)

Release build, same box, `alpine` cached, command `true`, 30 samples after 3 warm-ups,
median (min in parentheses):

| Path | Time |
|---|---|
| `phantom --version` | 7 ms |
| cold `run alpine true` | 39 ms (30) |
| warm `run --warm alpine true` | 11 ms (10) |
| rootless `podman run --rm alpine:latest true` | 378 ms (337) |
| direct daemon RPC `Exec` | 2–3 ms |

Warm is ~3.5× faster than cold and ~34× faster than rootless podman. Two fixes produced
that, and both were latency, not security: the mother now waits on a `pidfd` instead of
a 50 ms poll tick, and the client no longer builds a registry client and opens the image
store to resolve a rootfs the fragment already has.

### Key files

```
src/cli/phantom-cli/src/
├── commands/warm.rs          # warm create/list/remove/benchmark
├── commands/run.rs           # run dispatch (cold, --warm, --zygote)
├── daemon/warm.rs            # host listener + pre-sandboxed mother + per-request fork
├── engine/sandbox.rs         # shared Landlock/caps/seccomp stack
├── fragment_pool.rs          # pool metadata
└── config.rs                 # paths

src/core/zygote-rs/
├── src/lib.rs                # Rust wrapper around the Zig pool
└── src/zygote.zig            # clone/fork, unshare, pivot_root, execve
```

---

---

## 0. Why this plan existed (2026-10-27)

> **Historical.** This section describes the state before Phase 1. In particular, the
> "warm" row below — host binary, no chroot, no security stack — is no longer true: the
> mother is now pre-sandboxed and refuses profile mismatches. The measurements are kept
> because they are still the only end-to-end numbers recorded for the warm path.

At the time, `phantom run --warm` was not a slower version of `phantom run`. It was a
different, incorrect program. Measured on this box (release, 14-core Ultra 5 225H,
kernel 7.3.0):

| Path | Time | What actually runs |
|---|---|---|
| `phantom --version` (no container work at all) | 9 ms | — |
| cold `run alpine true` | 32 ms | image binary, seccomp + landlock + caps + chroot |
| warm `run --warm alpine true` | 37–40 ms | **host binary**, no seccomp, no landlock, no caps, no chroot |
| direct daemon RPC `Exec` (fork+setup+exec+waitpid) | 2.4 ms | — |
| direct daemon RPC `HealthCheck` | 0.03–0.2 ms | — |

Three facts fall out of that table:

1. **Warm is slower than cold while doing less work.** ~28 ms of the 40 ms is client-side
   work that cold also pays, plus pool bookkeeping, plus a round trip.
2. **The daemon is not the bottleneck.** The entire exec RPC is 2.4 ms.
3. **The IPC transport is not the bottleneck.** A full socket round trip is ~1 ms. No
   amount of ring-buffer, io_uring, or framing work changes the 40 ms.

So this plan is ordered by *correctness first, cost second, transport last*.

## 1. Confirmed defects

### D1 — warm never enters the rootfs (critical)

`daemon/warm.rs:1089-1126` (child branch of `execute_command`) does:

```rust
libc::unshare(CLONE_NEWNS);   // mount ns
mount("/tmp", tmpfs); mount("/dev/shm", tmpfs);
chdir(target_cwd);            // target_cwd is inside rootfs_path
```

and then `execvp(request.command, ...)` at `warm.rs:1171`. There is **no `chroot`,
no `pivot_root`, and no `CLONE_NEWUSER` anywhere in `warm.rs`.** The command string is
passed through unmodified (`warm.rs:979` returns `request.command.clone()` with the
comment "it will be resolved in the chroot" — a chroot that never happens).

Consequences:

- `phantom run --warm alpine /bin/echo` executes **the host's `/bin/echo`**.
- A bare name (`sh`) is validated against the rootfs (`warm.rs:953-967`) and then
  resolved by `execvp` against the **host's `PATH`**. Validation and execution
  disagree about which file they mean.
- The host filesystem is fully visible (only `/tmp` and `/dev/shm` are replaced).
- No seccomp, no Landlock, no capability drop. `warm.rs` imports none of them.

This is an escape primitive, not a missing feature: a user who expects isolation from
`--warm` gets the host's binaries with the host's filesystem.

> **Fixed in `9bfb691`.** The child now enters a user namespace
> (`CLONE_NEWUSER|CLONE_NEWNS`), maps the caller's uid/gid, chroots, then execs. Failures
> are reported to the parent over a CLOEXEC pipe and the child fails closed with 127.
> Verified live: `--warm alpine sh -c 'ls /'` lists the image root, and a host-only binary
> is not reachable. Residual risk: the child still allocates (`format!`) on the failure
> path after `fork()` in a 31-thread daemon — not async-signal-safe in principle. Worth
> replacing with preallocated buffers and raw `write(2)` if the daemon ever forks under
> load.

### D2 — warm output is discarded

`start_daemon_background` spawns the daemon with `Stdio::null()` ×3
(`warm.rs:1665-1667`). The child sets stdin to `/dev/null` and **inherits** stdout/stderr
(`warm.rs:1158-1166`) — i.e. the daemon's `/dev/null`. `run.rs:325-337` consumes only an
exit code. `echo hi` over warm prints nothing.

> **Fixed (2026-10-31).** `exec_in_daemon` hands its stdio to the daemon with the request
> (`write_message_with_fds`, `SCM_RIGHTS`); the daemon forwards them to the mother and the
> forked child `dup2`s them onto 0/1/2 before `exec`. Both sides close their copies
> immediately, so a pipe still sees EOF. When stdin is a terminal the client allocates a
> pty instead, because a descriptor inherited from the caller's terminal cannot be read
> from the mother's session (see D14). Verified: `run --warm alpine sh -c 'echo one;
> echo two >&2; exit 7'` prints both streams, returns 7, and accepts piped stdin.

### D3 — the protocol is one-request-one-response

`handle_client` reads exactly one frame, dispatches, writes exactly one reply, closes the
socket (`warm.rs:709-763`). There is no session, no sequence number, no frame kind, and
the response layout (`warm.rs:1434-1458`) is a single terminal struct. Adding output is
therefore not a field addition — it is a change of shape.

> **Status: Open.** `handle_client` still reads one frame, dispatches, writes one reply,
> closes (`daemon/warm.rs:884-928`). Closed by Phase 2 (ExecV2 session protocol).

### D4 — the client retries the whole request on any failure

`exec_in_daemon` (`warm.rs:1733-1831`) retries the entire request up to 3×. Harmless today
because a failed reply means nothing ran. Once output streams, a mid-stream failure
**re-executes the command** — duplicate side effects on `rm -rf`.

> **Status: Open.** `exec_in_daemon` still retries the whole request up to 3×
> (`daemon/warm.rs:2113`, `for attempt in 1..=3`). Closed by Phase 2 (retry only before
> `ExecStarted`).

### D5 — one exec blocks the whole daemon

`handle_client` runs inline under `block_in_place` with `&mut self`
(`warm.rs:672-682`, `run_test_loop` at `1570-1580`). A long-running command stalls every
other client, including health checks.

> **Status: Open.** `handle_client` still runs inline under `block_in_place` with
> `&mut self` (`daemon/warm.rs:844-848`). Closed by Phase 2/3 (per-session tasks).

### D6 — the daemon inherits the launching shell's session

`start_daemon_background` uses `Command::spawn` with no `setsid()`. A `Ctrl+C` in the shell
that ran `phantom warm create` signals the daemon and all its children. This is a large
part of the "daemon stability issues" recorded in the roadmap.

> **Fixed in Phase 1.3.** The daemon calls `setsid()`, ignores `SIGHUP` and clears
> `PR_SET_PDEATHSIG` before the accept loop; see §3.

### D7 — the health probe hardcodes the wire format

`monitoring/health/health-rs/src/lib.rs:92-101` sends a literal 10-byte buffer
(`magic = 0`, version 1, type 4) and treats "10 bytes came back" as healthy. It only
works because the daemon answers with an `Error` frame. Any header or version change
silently breaks every supervisor health check. It must use the real codec.

> **Fixed in `1802f71`.** The probe now builds a real `HealthCheck` frame, validates the
> full reply, and requires a `HealthResponse` with an `OK` payload. Verified against a live
> daemon. Behaviour change: a non-responding daemon reports `Unhealthy` (restart) rather
> than `Degraded` (alive with issues).

### D8 — the per-request fsync

`FragmentPool::acquire_pid`/`release_pid` rewrite `meta.json` and `sync_all()`
(`fragment_pool.rs:188-227`, `125-150`), and `FragmentPool::list()` scans directories.
Two fsyncs (~0.68 ms each on this fs) plus a directory scan, per request, for state the
daemon already holds in memory.

> **Status: Open.** `FragmentPool::save()` still calls `sync_all()` on the temp file
> (`fragment_pool.rs:308`); `acquire_pid`/`release_pid` still call `save()` per request.
> Closed by Phase 3.1 (pool state in daemon, meta.json as crash-recovery artifact).

### D9 — Landlock is applied without TSYNC

`security/landlock-rs/src/lib.rs:122-123` calls `ruleset.restrict_self()` with no
`.all_threads(true)`. On ABI ≥ 8 the flag maps to `LANDLOCK_RESTRICT_SELF_TSYNC`; without
it the ruleset covers only the calling thread. **Not a live bug** — the call site is a
freshly forked single-threaded child — but it is one refactor away from becoming one, and
the fix is one method call.

> **Fixed in `717b708`.** The ruleset now requests TSYNC and inspects
> `RestrictionStatus::all_threads`; on ABI < 8 it logs a warning and keeps the previous
> thread-scoped behaviour. See "Landlock enforcement scope" in
> [`native-executor.md`](./native-executor.md).

### D10 — cold execution passes a non-numeric user to bwrap (found 2026-10-28)

`phantom-config.json` in the pulled rootfs contains `"user": "root"`. The cold path
(`storage/image-puller/src/rootfs_executor.rs`) forwards that string verbatim as
`bwrap --uid root`, and bubblewrap requires a numeric uid:

```
$ phantom run alpine true
Running as user: root
bwrap: Invalid uid: root
```

Cold execution is therefore completely broken for any image whose config carries a
non-numeric `user`. Pre-existing: the last change to `rootfs_executor.rs` was a clippy fix
(`4d0e8d7`), and nothing in the warm work touches it. Fix by resolving the name to a uid
(or omitting `--uid` when it is not numeric) before building the bwrap argv.

> **Fixed (`8081893`).** `rootfs_executor.rs` now resolves `user[:group]` before building the bwrap
> argv: numeric ids pass through, names are looked up against the **image's**
> `/etc/passwd` and `/etc/group` (not the host's), and a user-only spec defaults the gid
> to that user's primary group instead of the user string. If a name cannot be resolved
> the flags are omitted with a warning, leaving bwrap to keep the invoking user.

### D11 — warm argv carries a phantom trailing empty argument (found 2026-10-29)

`execute_command()` built the child argv by pushing an empty `CString` after the real
arguments, believing `execvp` needed a caller-supplied NULL terminator. It does not:
`nix::unistd::execvp` takes a `&[CString]` and terminates the array itself, so the empty
entry was passed as a genuine argument. Every applet's `argc` was one too high:

```
$ phantom run --warm alpine ls /etc/alpine-release   # exit 1, "cannot access ''"
$ phantom run --warm alpine test -e /etc/alpine-release   # exit 2, usage error
$ phantom run --warm alpine sh -c 'exit 3'           # exit 3 — masked the bug
```

`sh -c` and `true` ignore trailing arguments, which is why the defect survived the first
round of warm tests. Pre-existing since v1.0.0 (`61e5a63`), not introduced by the warm
work.

> **Fixed in `925d88f`.** The empty entry was removed. `test_exec_passes_exact_argv`
> runs a rootfs probe that records `$#` and each argument, and asserts the child sees
> exactly `[prog, alpha, beta]`. Live: `ls /etc/alpine-release` and `test -e …` both
> exit 0 under warm, `cat /etc/alpine-release` inside the child prints `3.24.3`.

### D12 — `warm remove` leaks the daemon (found 2026-10-29)

`FragmentPool::remove()` is `fs::remove_dir_all(&dir)`. It deletes the pool directory
(and with it the PID files) but never signals the daemon. Because 1.3 (setsid + cleared
PDEATHSIG) deliberately detaches the daemon from its launcher, nothing kills it: the
process is reparented to init and keeps listening on the now-unlinked socket, ~25 MB RSS
wasted indefinitely. The follow-up `warm create` could not find a PID file to kill, so
it spawned a second daemon on the same path (two inodes, one listening socket).

> **Fixed (`b8534ca`).** `warm remove` and `warm remove-all` now call `kill_existing_daemons()` on
> the pool directory *before* deleting it, and wait for the daemons to exit. The
> `warm create` path already did this; `remove` simply never had. Verified: the
> daemon is gone within ~1 s of `warm remove`.

### D13 — a signal frame outlives its request and breaks the next one (found 2026-10-31)

`await_mother_response` polls both the mother and the client. When the client is killed,
the socket reports `POLLHUP` on every iteration, and a closed socket stays readable
(EOF) forever: the daemon therefore wrote one `Signal` frame per poll tick instead of
one. The mother consumed the first frames while waiting for the child, but the leftovers
sat in the stream and were read as the *next* request's first frame — which the mother
rejected with `mother only accepts Exec requests, got Signal`. `run.rs` then treated
that as a broken fragment, `SIGKILL`ed the healthy daemon, and fell back to cold. One
killed client permanently removed a pool slot and killed its daemon.

> **Fixed (2026-10-31).** After the client reaches EOF the daemon stops polling it and
> sends exactly one `SIGKILL` frame. As defence in depth, the mother now drops a
> `Signal` frame that arrives between requests instead of rejecting the following
> request. Verified: client `SIGKILL` → slot reclaimed → next `run --warm` succeeds on
> the same daemon, pool returns to `available_pids`.

### D14 — a 5 s read deadline re-ran long commands (found 2026-10-31)

`exec_in_daemon` set a 5 s read timeout on the daemon socket and retried a failed read
up to three times. The deadline covers the *whole* command, not just the handshake, so
any warm command that lived longer than 5 s hit it, was treated as a transport failure,
and was sent again — `sleep 8` ran three times and took 24 s. The retry was silent
because the first attempt's output had already been written.

> **Fixed (2026-10-31).** The client now clears the read timeout
> (`set_read_timeout(None)`) and keeps a deadline only on the write side, which is what
> actually guards a wedged daemon. A long command is not a timeout: liveness comes from
> the daemon's `Exited` frame. Verified: `sleep 9` returns once, in 9.09 s.

### D15 — a warm command was not interactive (found 2026-10-31)

Handing the caller's own 0/1/2 to the command is enough for pipes and files but not for
a terminal. The command runs in the mother's session, not the terminal's, so the
inherited slave has no foreground process group: `read(2)` returns `EIO` and `sh` prints
`can't access tty; job control turned off`. `test -t 0` succeeded (the fd *is* a tty)
while `stty` and `ttyname(3)` failed — the two checks disagree because one only inspects
the descriptor and the other needs the session's controlling terminal.

> **Fixed (2026-10-31).** The client allocates a pty (`openpty`) sized like its terminal,
> puts its own terminal into raw mode, sends the slave as 0/1/2 and proxies the master
> to stdout while reading stdin back into the master. The child calls `setsid()` +
> `ioctl(TIOCSCTTY)` when stdin is a tty, which makes the pty its controlling terminal.
> Resize is polled and pushed with `TIOCSWINSZ`; buffered output is drained after exit;
> termios is restored on drop. Non-tty runs keep the direct fd path. Verified: a shell
> prompt, `read`, Ctrl+C, `exit 5`, and `test -t 0` all behave as in cold.

### D16 — warm fragments had no procfs and no PID/IPC/UTS namespaces (found 2026-10-31)

The mother unshared only `CLONE_NEWUSER|CLONE_NEWNS`, and mounted only `/tmp` and
`/dev/shm`. `/proc` was therefore absent (inherited from the daemon, which is in the
host's PID namespace, or missing entirely after `chroot`), so `ps`, `top`, `ttyname(3)`
and `/proc/self` failed. Commands also saw host pids, host semaphores and the host
hostname — weaker isolation than the cold engine, which unshares all five.

> **Fixed (2026-10-31).** `prepare_namespaces` unshares
> `USER|NS|PID|IPC|UTS`; the process that mounts procfs and serves requests is a `fork`
> of it (a PID namespace only applies to children), so the structure is
> daemon → supervisor (host pid) → init (PID 1 in the new namespace). The init mounts
> `/proc` (`MS_NOSUID|MS_NODEV|MS_NOEXEC`), then chroots, mounts tmpfs, applies the
> security stack and serves. The supervisor closes its copy of the protocol socket,
> waits and mirrors the child's status; the init carries `PDEATHSIG=SIGKILL` so it
> cannot outlive the supervisor. Verified: `ps` shows PID 1 = `warm-daemon`,
> `/proc/self/comm` works, and the warm/cold parity probe matches (`$$` small,
> `/proc` entry count, hostname, `nproc`, `notty0` for piped stdin).

## 2. Non-goals

Explicitly out of scope for this plan, so they stop being conflated with it:

- **Shared-memory ring buffer for IPC.** Reduces ~1 ms to ~0.0002 ms. Invisible next to
  23 ms of setup. Revisit only after §5 lands and the RPC is the dominant term.
- **io_uring.** Does not accelerate `fork`/`exec`/`chroot`/cgroup setup. It is an I/O
  optimisation for pull/extract/build, a different workstream.
- **Zig 0.17 migration.** Real, but independent (§8).
- **`phantom attach` / N-concurrent-attachers.** The protocol below does not preclude it.

## 3. Phase 1 — Correctness (no protocol change)

Ship these first. They are small, independently testable, and D1 is a security bug.

| # | Change | File | Test |
|---|---|---|---|
| 1.1 | `chroot(rootfs_path)` + `chdir("/")` in the child, after the mount setup and before env/exec. Use `chroot` (not `pivot_root`) because the child is in a private mount ns with no old root to detach. Validate the resolved command **inside** the new root with `execvp` on the original argv, and delete the now-misleading host-side resolution at `warm.rs:945-982`. | `daemon/warm.rs:1089-1171` | `--warm alpine /bin/echo` must print the image's echo; `ls /` must match cold; a binary present only on the host must exit 127 |
| 1.2 | Apply the same security stack as cold in the child: seccomp profile, Landlock ruleset, capability drop. Order: cgroup → unshare → chroot → landlock → caps → seccomp → exec. | `daemon/warm.rs`, reuse `security-rs` | `--warm -p hardened` denies network; a seccomp-denied syscall fails identically to cold |
| 1.3 | `setsid()` + `SIGHUP` ignore + `PR_SET_PDEATHSIG=0` in `daemon_main` before the accept loop. | `warm.rs:1942-1991` | `Ctrl+C` the launching shell; daemon and children survive; `phantom warm list` still works |
| 1.4 | Rewrite the health probe to use the real `Message` codec instead of the hardcoded 10-byte buffer. Add a test that changes `PROTOCOL_VERSION` and asserts the probe still works. | `health-rs/src/lib.rs:92-101` | unit test + supervisor health check against a live daemon |
| 1.5 | `.all_threads(true)` on the Landlock ruleset, with `HardRequirement` compatibility so it fails loudly rather than silently under-enforcing. | `landlock-rs/src/lib.rs:122` | existing landlock tests + a threaded-process test that asserts a sibling thread is restricted |

> **Progress:** 1.1 (`9bfb691`), 1.2 + 1.3 (`da29af7`), 1.4 (`1802f71`) and 1.5
> (`717b708`) landed. Phase 1 is complete.
>
> **1.2 — security stack in the warm child (landed).** The child now applies the
> profile after `chroot(2)`, in this order:
>
> ```
> cgroup → unshare → chroot → landlock → caps/no_new_privs → seccomp → setenv → execvp
> ```
>
> - **Landlock** (`landlock-rs::LandlockContext`) with rules written in the
>   post-chroot namespace (`/`, plus `/tmp` and `/dev/shm`, which are separate
>   tmpfs mounts and therefore need their own rule). `file_write == false` grants
>   read+execute only; `file_write == true` also grants write/create/remove.
>   `landlock-rs`'s write flag was extended to include the creation/removal
>   rights — a `WriteFile`-only rule still denies `open(O_CREAT)`.
> - **Capabilities**: bounding set dropped for every capability, capability sets
>   cleared via `capset`, then `PR_SET_NO_NEW_PRIVS`. Best effort by design: the
>   child is already unprivileged in the parent namespace, so a refusal is logged
>   and the exec proceeds.
> - **Seccomp** (`seccomp-rs::apply_profile`) last, so the filter cannot block
>   the child's own setup syscalls. Fail closed: if the profile's filter cannot
>   be installed, the child reports it over the CLOEXEC status pipe and
>   `_exit(127)`s instead of exec'ing unfiltered. The hardened whitelist gained
>   the libc startup syscalls (`newfstatat`, `pread64`, `statx`, `prlimit64`,
>   `rseq`, …) it needs to exec a dynamically linked `/bin/sh` at all.
>   `clone3` is **not** on the whitelist: libseccomp does not synthesise the
>   rule automatically, so the hardened branch adds an explicit
>   `clone3 → ENOSYS`. glibc's `fork()`/`posix_spawn()` fall back to `clone` on
>   ENOSYS but not on EPERM, and denying `clone3` also keeps its
>   `CLONE_INTO_CGROUP` flag away from the child (a cgroup-limit escape).
>   Two `seccomp-rs` tests pin this: `clone3` returns ENOSYS and `fork()` still
>   succeeds under the hardened filter.
>
> **How the profile name reaches the daemon.** `ExecRequest` has no profile field
> and `PROTOCOL_VERSION` stays 1, so the client (`commands/run.rs::
> fork_from_daemon`) sends the resolved `--profile` name in the **existing env
> map** under the reserved variable `PHANTOM_PROFILE` — the default `sandbox`
> when none was requested, so warm and cold agree. The daemon resolves the name
> through the same config path as the CLI (`config::Config::load()` →
> `get_profile()`), strips the variable from the child environment, and refuses
> an unknown name instead of running the command unconfined. **This is a
> temporary v1-compatible carrier, not the design:** `ExecV2` (Phase 2) gets a
> real profile field and `PHANTOM_PROFILE` is removed.
>
> **1.3 — the daemon leaves the launcher's session (landed).** Before the accept
> loop the daemon calls `setsid()` (EPERM = already a session leader, ignored),
> ignores `SIGHUP` and clears `PR_SET_PDEATHSIG`, so `Ctrl+C` in the shell that
> ran `phantom warm create` no longer signals the daemon or its children.

Phase 1 makes `--warm` *correct*. It does not make it fast, and it will make it slightly
slower (it now does the security setup it was skipping).

## 4. Phase 2 — Protocol v2: fd handoff, not proxying

**Decision: stdio is transferred as file descriptors; the control socket carries only
lifecycle.** Rationale, from the runtime survey in §7:

- With fd handoff the **daemon is not on the data path**. If it dies mid-command, output
  keeps flowing and the command keeps running. No alternative has that property.
- Zero copies, zero framing, zero credit accounting, kernel-native backpressure.
- `isatty(1)` is genuinely correct because the child's fd *is* the user's terminal, so
  colour detection, `tcgetattr`, `TIOCGWINSZ`, and `COLUMNS` all work with no faking.
- Shell pipelines (`| wc -c`) and redirection (`> file`) behave exactly like a local
  command.

Framed streaming exists only as a fallback for peers that cannot pass fds.

### 4.1 Wire format

**Keep the 10-byte header and keep `PROTOCOL_VERSION = 1`.** A v1 daemon hard-rejects
`version != 1`, so bumping it breaks every daemon already running. Capability negotiation
goes in new message types, and the existing `_ => send_error(...)` arm gives free version
detection: **a v2 client that gets `Error` in reply to `Hello` is talking to a v1 daemon
and falls back to legacy `Exec`.**

New types `0x10..0x1D`, little-endian, header unchanged:

```
0x10 Hello        c→d  [proto_min:u16][proto_max:u16][flags:u32][client_pid:u32]
                        flags: 0x1 FD_PASS 0x2 PTY 0x4 FRAMES 0x8 PIDFD
0x11 HelloAck     d→c  [proto:u16][flags:u32][daemon_pid:u32][daemon_epoch:u64][max_data_frame:u32]
0x12 ExecV2       c→d  [session_id:u64][flags:u32]
                        [stdin_mode:u8][stdout_mode:u8][stderr_mode:u8]  # 0=null 1=passed 2=framed
                        [rows:u16][cols:u16][timeout_ms:u32]
                        [v1 Exec payload body, byte-identical, from here on]
                        flags: 0x1 WANT_PIDFD 0x2 WANT_PTY 0x4 KILL_ON_DISCONNECT 0x8 DETACHED
                        ancillary: exactly N fds, ascending stream order, N = count(mode==1);
                        the fds MUST ride the same sendmsg() as this frame's iovec
0x13 ExecStarted  d→c  [session_id:u64][pid:u32][pgid:u32][started_at_ms:u64]
                        ancillary: pidfd (if WANT_PIDFD), pty master (if WANT_PTY)
0x14 StdoutData   d→c  [session_id:u64][seq:u64][bytes ≤ 64 KiB]
0x15 StderrData   d→c  [session_id:u64][seq:u64][bytes ≤ 64 KiB]
0x16 StdinData    c→d  [session_id:u64][seq:u64][bytes ≤ 64 KiB]
0x17 StdinEof     c→d  [session_id:u64]
0x18 Signal       c→d  [session_id:u64][signo:u8]
0x19 Resize       c→d  [session_id:u64][rows:u16][cols:u16]
0x1A Exited       d→c  [session_id:u64][wait_status:u32][exit_code:i32][termsig:u8][core:u8]
                        [flags:u8][ru_maxrss_kb:u32][wall_ms:u64]
                        flags: 0x1 EXIT_STATUS_VALID 0x2 DAEMON_LOST_CHILD 0x4 OUTPUT_TRUNCATED
0x1B Credit       c→d  [session_id:u64][bytes:u32]           # framed mode only
0x1C Cancel       c→d  [session_id:u64][grace_ms:u32]
0x1D SessionError d→c  [session_id:u64][stage:u8][code:u16][msg_len:u16][msg]
                        stage: 0=parse 1=spawn 2=exec 3=io 4=internal
```

`Error` (0xFF) keeps its exact v1 payload. `ExecResponse` (0x02) is still emitted for
legacy `Exec` (0x01), byte-for-byte, including `Stdio::null()`.

### 4.2 Contract

1. Per session: `ExecV2` → exactly one `ExecStarted` **or** one `SessionError` →
   `(data|control)*` → exactly one `Exited`. Nothing after `Exited`.
2. `Exited` is sent only **after both output streams hit EOF and the child is reaped**.
   This is the "last 8 KiB lost" bug (podman #11503). In fd mode "drained" is trivial;
   in framed mode it means `read() == 0` on both pipes *before* `waitpid`.
3. `seq` is per `(session_id, stream)`, from 0, strictly monotonic, no gaps. A gap aborts
   the session locally; never silently splice.
4. Data frames ≤ 64 KiB and ≤ `max_data_frame`. `MAX_MESSAGE_SIZE` (1 MiB) stays for
   control frames; a `StdoutData` claiming 1 MiB is a protocol error. Today
   `read_message` allocates `vec![0u8; length]` after checking only the 1 MiB cap.
5. `session_id` is monotonic and namespaced by `daemon_epoch`; never accept a session
   from a different epoch.

### 4.3 Mode selection

| Situation | Mode |
|---|---|
| stdout/stderr are pipes or files (normal shell, CI) | fd handoff, `FD_PASS` |
| stdout is a tty **and** stdin is a tty | PTY: client `openpty()`, slave as 0/1/2, child `setsid()` + `TIOCSCTTY`, client proxies master ↔ terminal |
| stdin is a tty but stdout is redirected | fd handoff for stdout/stderr, framed stdin (never hand over the user's tty stdin) |
| peer refuses fds (`SO_PASSRIGHTS=0`, `EPERM`) | framed, `Credit` flow control |

**Never pass the client's tty stdin directly.** A terminal has one foreground process
group per session; the daemon's child is not in the client's, so a bare `read(0)` would
`SIGTTIN`-stop it, and `tcsetpgrp` is unavailable cross-session (`EPERM`). PTY is the only
correct answer for interactive, which is why every runtime does it.

Consequence to document: with a PTY, stdout and stderr are one stream — same tradeoff
Docker and runc make explicitly.

### 4.4 Client outcome matrix

| Observed | Meaning | Action |
|---|---|---|
| `Exited`, `EXIT_STATUS_VALID`, `termsig == 0` | clean | exit `exit_code` |
| `Exited`, `termsig != 0` | signalled | exit `128 + sig`, print signal name |
| `ExecStarted` then EOF before `Exited` | daemon died, child alive | poll the pidfd, wait, report "exited, status unavailable" |
| EOF before `ExecStarted` | died during spawn | safe to retry; if epoch changed, fall back to cold |
| no `HelloAck` in 2 s | daemon wedged | fall back to cold |
| no `ExecStarted` in 5 s | spawn stuck | `Cancel`, fall back |
| `SessionError{stage}` | refused before exec | surface, exit 127 |
| `Exited` with `DAEMON_LOST_CHILD` | reaped elsewhere | exit 125 |

**A long-running command is not a timeout.** No read deadline after `ExecStarted`;
liveness comes from the `Exited` frame (or the pidfd, if one is ever passed). The fixed
5 s read/write timeouts at `warm.rs:712-717` and `1748-1753` are handshake-only — the
client now clears the read deadline entirely (D14).

### 4.5 Signals and disconnect

- **Tty mode needs no protocol for Ctrl+C/Z/\\ or SIGWINCH.** Client is in raw mode, so
  `0x03` is a byte → written to the master → the slave's line discipline turns it into
  `SIGINT` to the PTY's foreground pgrp. Resize is `ioctl(TIOCSWINSZ)` on the master.
  This is why conmon keeps resize on a separate ctl fifo — keep it off the data path.
- **Non-tty:** child is `setpgid`'d into its own group so a terminal `Ctrl+C` aimed at the
  client's pgrp cannot kill daemon children. Client forwards `SIGINT/SIGQUIT/SIGTERM/SIGHUP`
  as `Signal{session_id, signo}`, then keeps waiting for `Exited`.
- **Client disconnect:** fd mode gives this for free (consumer's read end closes → child
  gets `EPIPE`/`SIGPIPE` on next write, exactly like a dead pipeline). Control plane:
  with `KILL_ON_DISCONNECT`, `SIGHUP` the session pgrp after a 2 s grace (allowing a
  future reattach), then `SIGTERM`, then `SIGKILL`. With `DETACHED`, do nothing — a lost
  client is no reason to stop the output.

> **What landed (2026-10-31).** Non-tty: the client installs `SIGINT`/`SIGTERM` handlers
> for the duration of one warm request and writes the signal number as a byte to the
> daemon socket; the daemon relays it as a `Signal` frame; the mother `kill(2)`s the
> command and keeps waiting. Client EOF is treated as `KILL_ON_DISCONNECT` with no grace
> period. Tty: the client owns a pty and stays in raw mode, so `Ctrl+C`/`Ctrl+D`/`Ctrl+Z`
> travel as bytes and the slave's line discipline turns them into signals for the
> command; resize is pushed with `TIOCSWINSZ` from the client's poll loop (D15).

### 4.6 Implementation notes

- `nix` 0.27 already exposes `ControlMessage::ScmRights` under the `socket` feature;
  `libc::openpty` needs no `-lutil` on glibc ≥ 2.34.
- `MSG_CMSG_CLOEXEC` on every `recvmsg`; `MSG_CTRUNC` is a hard error, never success
  (the kernel silently closes the excess fds).
- `SCM_MAX_FD` is 253; in-flight fds over `RLIMIT_NOFILE` without `CAP_SYS_RESOURCE`
  give `ETOOMANYREFS`.
- **Close the daemon's copy of every passed fd immediately after `fork`**, or the pipe's
  read end never sees EOF and `phantom run … | wc -c` hangs. This is the #1 bug in
  hand-rolled fd passing; assert `/proc/<daemon>/fd` count is stable over 1000 execs.
- `fstat` every received fd; accept only tty/pipe/regular, reject the rest with
  `SessionError{stage=parse}`. Set `SO_PASSRIGHTS=0` on the metrics and health sockets.
- `handle_client` becomes a per-session task with independent read/write halves; never
  blocking-write from the reader task (full-duplex deadlock at ~64 KiB otherwise).
- Delete the whole-request retry (D4). Retry only before `ExecStarted`.
- Session records: write `{session_id, pid, started_at}` to a per-daemon file at
  `ExecStarted` and the exit status at `Exited`, so a supervisor restart can answer
  "what happened to session N" after the daemon died.

### 4.7 Test matrix

| # | Failure | Test |
|---|---|---|
| 1 | fd count mismatch / `MSG_CTRUNC` | send 2 when 3 declared → `SessionError`, no exec; send 300 → `EINVAL` |
| 2 | daemon keeps passed fds | 1000 execs, daemon fd count constant |
| 3 | daemon dies mid-command | `kill -9` during `sleep 5`; client must not hang, reports status unavailable |
| 4 | client `SIGKILL`ed | child gone within grace; with `DETACHED`, still running |
| 5 | PTY master closed early | tty child that `read`s must not die instantly |
| 6 | full-duplex deadlock | `cat` with 10 MB in and 10 MB out simultaneously |
| 7 | slow consumer | reader at 1 KB/s for 10 s; child blocked, daemon RSS flat |
| 8 | large output | `yes \| head -c 100000000` completes, daemon RSS flat |
| 9 | frame gap | injected drop → session aborted, no splice |
| 10 | fd-refusing peer | `SO_PASSRIGHTS=0` → transparent fallback to framed |
| 11 | `ExecStarted` lost | connection dropped at exactly that point → daemon kills the orphan |
| 12 | rootfs escape | §3.1 tests, re-run under v2 |

Plus: a golden-file parser test replaying recorded byte streams (malformed lengths,
`len > max`, truncated header) and a fuzz target on `read_message` — preserving the
existing property that length is validated *before* allocation, for every new type.

## 5. Phase 3 — Remove the client-side 28 ms

**Implementation status (3.4 + 3.5 landed in `fdb10ea`).** The "mother fragment" is now a
*pre-sandboxed* process. `WarmDaemon::new` forks exactly one mother after binding the
listener and before starting the metrics thread or the tokio runtime. The mother closes
every inherited fd except 0/1/2 and its socketpair end, opens the host `/dev/null`,
then applies the sandbox **once**: cgroup membership (from `hardware_profile`),
`unshare(CLONE_NEWUSER|CLONE_NEWNS)`, uid/gid maps, `MS_PRIVATE|MS_REC`, `chroot` into
the image, tmpfs on `/tmp` and `/dev/shm`, Landlock (profile `file_write`), capability
drop + `no_new_privs`, and the profile's seccomp filter. It then blocks on the
daemon↔mother `socketpair`.

Per request the daemon sends the existing v1 `ExecRequest` payload over that socketpair;
the mother reads one framed message, `fork(2)`s, redirects the child's 0/1/2 from the
pre-opened `/dev/null`, applies the request environment, and `execvp`s. The mother
`wait4`s the child and returns `ExecResponse`; the request path is
`read_message` (the socketpair read, `recvmsg`-class) → `fork` → `execve` → `wait4`.
No cgroup/userns/chroot/mount/Landlock/caps/seccomp work remains on the hot path.

The security profile is bound to the pool at creation (`phantom warm create -p/--profile`,
default `sandbox`) and passed to the daemon as `--profile`. A request whose
`PHANTOM_PROFILE` differs is refused before the mother is contacted, so a sandbox pool
can never silently serve a hardened request with weaker confinement. Named mothers
(`--mother` selection, multiple profiles per pool) are the next increment; `mother_name`
is already stored in `DaemonConfig` for it. The mother is forked once; it is not
re-forked per request. Its parent-death signal is `SIGKILL`, so `warm remove` (which
SIGKILLs the daemon) cannot leave an orphaned chrooted process behind.

This is where the actual speed lives, and none of it is protocol work.

| # | Change | Status |
|---|---|---|
| 3.1 | Pool state lives in the daemon; `meta.json` becomes a crash-recovery artifact written on change, not per request. Drop the two `sync_all()` calls from the hot path. | planned |
| 3.2 | Client sends `image_ref`; the daemon caches the resolved rootfs path. Client does one `stat`, not a directory scan. | planned |
| 3.3 | Stop re-initialising `ImagePuller::with_config` + config + paths on the exec path; one lazily-initialised context. | planned |
| 3.4 | Exec into a **pre-forked child**, not a fresh `fork` from the 31-thread, 237-VMA tokio daemon. Pool children block in `recvmsg()` on a `socketpair`; per-request work is `recvmsg` → `dup2` → `execve`. | ✅ `fdb10ea` |
| 3.5 | Move `chroot`, mount ns, cgroup membership, seccomp and Landlock to **pool-fill time** — they are properties of image+policy, not of `argv`. | ✅ `fdb10ea` |
| 3.6 | Independent session tasks (§4.6) so concurrency stops being serialised. | removes the queue |

Budget after Phase 3:

```
cold 32 ms ≈ 9 (CLI start) + ~19 (client setup) + ~2 (fork/exec/wait)
warm 12 ms ≈ 9 (CLI start) + ~2 (client) + ~1 (RPC)      → ≈2.7× faster than cold
```

The floor is 9 ms of process start (dynamic linking + clap) and ~0.6 ms of `execve` of a
dynamically linked binary. **Sub-millisecond `phantom run --warm` from a shell cannot
exist**; it is only reachable by measuring the RPC directly or adding a resident client.

## 6. Phase 4 — CI and toolchain (independent, do first)

Our CI is currently dead: Node 20 was removed from GitHub runners on 2026-09-16 and every
action we pin is Node 20.

> **Done in `12df12a`.** All actions moved to their Node 24 generations, `sccache-action`
> pinned exactly, `cargo-nextest` pinned to 0.9.150 with `nextest-version` required in
> `.config/nextest.toml`, and Rust pinned to 1.99.1 in `rust-toolchain.toml` and CI.
> `dependency-review-action@v5` and `dtolnay/rust-toolchain@1.99.1` resolve as branches,
> not tags — that is how both actions ship a floating version.
> Note: `download-artifact@v8` turns digest mismatches into hard errors, so any drift
> between the upload and release jobs now fails the release instead of warning.

| File | Change |
|---|---|
| `.github/workflows/ci.yml` | `checkout@v6→v7`, `upload-artifact@v6→v7`, `download-artifact@v6→v8` (digest mismatch now **errors**), `dependency-review@v4→v5`, `action-gh-release@v2→v3`, pin `sccache-action@v0.0.11` exactly (no floating major exists), pin nextest `0.9.150` (GHSA-vc25-qg58-w57c: arbitrary code execution via malicious run recordings) |
| `rust-toolchain.toml` | pin `1.99.1` — fixes an x86_64 **FFI `bool`-return miscompilation**, directly relevant to our Zig↔Rust FFI |
| `.config/nextest.toml` | add `nextest-version = { required = "0.9.150" }` |

`mlugg/setup-zig@v2.0.5` stays; verify it can install 0.16 (release predates it).
`Swatinem/rust-cache@v2` and `dtolnay/rust-toolchain` need no change.

## 7. Why fd handoff (prior art summary)

| Runtime | non-tty | tty |
|---|---|---|
| runc foreground | in-process pipes | PTY, in-process pump |
| runc detached / `exec` | inherits caller's 0..2 | PTY master over console socket via `SCM_RIGHTS` |
| containerd | pipes + fifo stdin | `ReceiveMaster()` + `CopyConsole` |
| youki / crun | inherits fds | `sendmsg(SCM_RIGHTS)` of the master |
| podman/CRI-O | conmon attach socket | same |
| docker | hijacked HTTP + 8-byte frame header | raw PTY, no multiplexing |
| kubernetes | WebSocket channels | same |

The split is not stylistic — it follows from *who is alive to do the copying*. We choose
handoff because it keeps the daemon off the data path, which none of the proxying designs
achieve.

Also worth copying: runc's `--pidfd-socket` (liveness as an fd) and Kubernetes v5's
explicit per-stream CLOSE (it took five protocol revisions to learn that socket close is
not a stream EOF).

## 8. Deferred

| Item | Why deferred |
|---|---|
| Zig 0.16 → 0.17 | 0.17 shipped 2026-10-02; deletes `std.fs.File`/`Dir` (→ `std.Io.File`), shrinks `std.posix`, drops custom build steps and `addTranslateC`. Mechanical but touches every file-I/O call in the zygote and memory libs. 0.18 removes the shims, so deferring doubles the cost — schedule it, don't do it here. |
| `CLONE_AUTOREAP` / `CLONE_NNP` / `CLONE_PIDFD_AUTOKILL` (7.1) | `CLONE_PIDFD_AUTOKILL` kills the child when the pidfd closes, removing the orphan/zombie class we patched by hand in `zygote.zig`. Needs a 7.1 floor. |
| io_uring per-task restrictions (7.0+) | Replace blanket-blocking with `IORING_REGISTER_RESTRICTIONS_TASK`. Applies to pull/build/extract, not exec. |
| Shared-memory ring buffer | After §5, if the RPC is still the dominant term. `memfd_create` + `mmap(MAP_SHARED)` + atomics + eventfd. |
| Rust edition 2024 + MSRV | Denies `unsafe_op_in_unsafe_fn` (hits FFI/syscall layers), changes drop order, ~9 new warn-by-default clippy lints under `-D warnings`. Bounded cleanup, own branch. |
| Landlock ABI 11 `NO_NEW_PRIVS` flag | Sets `no_new_privs` atomically with enforcement; small follow-up to §3.5. |
| Landlock namespace/capability control (ABI 12, unmerged) | Would let us deny `CLONE_NEWUSER`/`CAP_*` from *inside* a fragment. Track only. |

## 9. Landing order

1. **Phase 4** (CI/toolchain) — mechanical, unblocks the pipeline, zero risk.
2. **Phase 1** (correctness) — D1 first; it is a security bug and it changes what
   `--warm` *means*.
3. **Phase 3** (cost) — makes warm actually faster than cold.
4. **Phase 2** (protocol) — output, stdin, tty, signals, concurrency. Capability, not
   performance; do it once Phase 1 has settled what the child looks like.

Doing Phase 2 before Phase 1 would mean designing a session protocol for a child that
runs the wrong binary.

---

## Implementation roadmap (task breakdown)

> **Note.** The per-phase status columns below are the original plan from before Phase 1
> landed. They are kept for the task breakdown, not as current status: chroot, the
> security stack, `setsid`, the health probe, Landlock TSYNC and the remove-leak fix are
> all done. The authoritative status is the "Status of each method" table above.

### Phase 0: Resource Limits Infrastructure

**Goal**: Enable unprivileged users to apply cgroup resource limits without sudo, similar to Docker rootless mode

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Priority | Complexity | Dependencies |
|---|------|--------|----------|------------|--------------|
| 0.1 | Implement user cgroup delegation support | 🔴 NOT STARTED | P0 | High | - |
| 0.2 | Add systemd user slice integration | 🔴 NOT STARTED | P1 | Medium | 0.1 |
| 0.3 | Create cgroup delegation setup script | 🔴 NOT STARTED | P1 | Low | 0.1 |
| 0.4 | Add fallback to manual cgroup delegation | 🔴 NOT STARTED | P1 | Medium | 0.1 |
| 0.5 | Integrate with cgroups-rs for per-fragment limits | 🔴 NOT STARTED | P2 | High | 0.1 |

---

### Phase 1: Keep Mother Alive

**Goal**: Fix daemon to stay alive continuously and accept connections

**Status**: ✅ Landed — the mother is sandboxed at pool fill and serves requests over a
socketpair; it does not re-apply the sandbox per request.

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 1.1 | Replace shell daemon with persistent listener | 🔴 NOT STARTED | Medium | - |
| 1.2 | Implement socket-based IPC protocol | 🔴 NOT STARTED | Medium | 1.1 |
| 1.3 | Add mother process health monitoring | 🔴 NOT STARTED | Medium | 1.2 |
| 1.4 | Create daemon pidfile on startup | 🔴 NOT STARTED | Low | 1.1 |
| 1.5 | Add daemon restart on crash | 🔴 NOT STARTED | Medium | 1.3 |
| 1.6 | Implement graceful shutdown | 🔴 NOT STARTED | Medium | 1.3 |

#### Current Broken Implementation

```bash
# Current daemon in warm.rs:324-349 - exits immediately
daemon_script = r""
while true; do
    for f in "$PHANTOM_CMD_DIR"/*.cmd; do
        # Polls for files - primitive and unreliable
        ...
    done
    sleep 0.1
done
""
```

---

### Phase 2: Zygote Pool Management

**Goal**: Create frozen zygotes from mother, store in pool, activate on demand

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 2.1 | Implement fork-from-mother in daemon | 🔴 NOT STARTED | High | Phase 1.2 |
| 2.2 | Add zygote state tracking (frozen/active) | 🔴 NOT STARTED | Medium | 2.1 |
| 2.3 | Implement zygote activation protocol | 🔴 NOT STARTED | Medium | 2.1 |
| 2.4 | Add zygote recycling on fragment exit | 🔴 NOT STARTED | Medium | 2.3 |
| 2.5 | Implement pool refill on low watermark | 🔴 NOT STARTED | Medium | 2.4 |
| 2.6 | Connect fragment_pool.rs to daemon | 🔴 NOT STARTED | Medium | 2.3 |

---

### Phase 3: Adaptive Resource Control

**Goal**: Child processes get independent limits from mother using cgroups

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 3.1 | Integrate cgroups-rs for per-fragment limits | 🔴 NOT STARTED | High | Phase 2 |
| 3.2 | Implement adaptive engine integration | 🔴 NOT STARTED | Medium | 3.1 |
| 3.3 | Add memory limit inheritance | 🔴 NOT STARTED | Medium | 3.1 |
| 3.4 | Implement CPU affinity control | 🔴 NOT STARTED | Medium | 3.1 |
| 3.5 | Add I/O limits per fragment | 🔴 NOT STARTED | High | 3.1 |
| 3.6 | Security policy application per fragment | 🔴 NOT STARTED | Medium | 3.2 |

---

### Phase 4: Integration & Polish

**Status**: 🔴 NOT STARTED

#### Tasks

| # | Task | Status | Complexity | Dependencies |
|---|------|--------|------------|--------------|
| 4.1 | Connect warm execution in run.rs | 🔴 NOT STARTED | Medium | Phase 2 |
| 4.2 | Add proper error handling | 🔴 NOT STARTED | Medium | Phase 2 |
| 4.3 | Implement pool metrics | 🔴 NOT STARTED | Low | Phase 2 |
| 4.4 | Add integration tests | 🔴 NOT STARTED | Medium | All phases |
| 4.5 | Performance benchmarking | 🔴 NOT STARTED | Low | Phase 2 |

---

## Dependencies Graph

```
Phase 0 (foundational - enables all others)
├── 0.1 User cgroup delegation ──────────────────────────┐
│   ├── 0.2 Systemd user slice                          │
│   ├── 0.3 Setup script                                │
│   ├── 0.4 Manual fallback                             │
│   └── 0.5 Cgroups-rs integration ────────────────────┤
│                                                       │
Phase 1                                                │
├── 1.1 Fix daemon script                              │
│   └── 1.2 Socket IPC protocol                        │
│       └── 1.3 Health monitoring                      │
│           ├── 1.5 Daemon restart                      │
│           └── 1.6 Graceful shutdown                   │
                                                        │
Phase 2                                                │
├── 2.1 Fork-from-mother ──────────────────────────────┤
│   └── 2.2 State tracking                             │
│       └── 2.3 Activation protocol                    │
│           └── 2.4 Recycling                          │
│               └── 2.5 Pool refill                    │
│                   └── 2.6 Pool integration            │
                                                │
Phase 3 (depends on Phase 0, Phase 2)                 │
├── 3.1 Cgroups integration ───────────────────────────┤
│   └── 3.2 Adaptive engine                            │
│       └── 3.3 Memory limits                          │
│       └── 3.4 CPU affinity                           │
│       └── 3.5 I/O limits                             │
│       └── 3.6 Security policy                         │
                                                │
Phase 4 (depends on all)                              │
├── 4.1 Connect run.rs ────────────────────────────────┘
├── 4.2 Error handling
├── 4.3 Metrics
├── 4.4 Integration tests
└── 4.5 Benchmarking
```

---

## Complexity Summary

| Phase | Tasks | Total Complexity | Est. Total Effort |
|-------|-------|------------------|-------------------|
| Phase 0 | 5 | High | 10-14 hours |
| Phase 1 | 6 | Medium | 12-18 hours |
| Phase 2 | 6 | Medium-High | 16-22 hours |
| Phase 3 | 6 | High | 12-18 hours |
| Phase 4 | 5 | Low-Medium | 8-12 hours |
| **TOTAL** | **28** | - | **58-84 hours** |

---

## Implementation Priority Order

1. **P0 (Critical)**: 0.1, 1.1, 1.2, 2.1, 4.1
2. **P1 (High)**: 0.2, 0.3, 0.4, 1.3, 2.2, 2.3, 3.1
3. **P2 (Medium)**: 0.5, 2.4, 2.5, 3.2, 4.2, 4.3, 4.4
4. **P3 (Low)**: 1.4, 1.5, 1.6, 3.3, 3.4, 3.5, 3.6, 4.5

---

## Testing Strategy (When Implemented)

### Unit Tests
- IPC protocol parsing
- State machine transitions
- Pool management logic

### Integration Tests
- `phantom warm fragment create alpine` → creates pool
- `phantom run alpine echo hello` → uses warm fragment
- Pool exhaustion → falls back to cold
- Daemon crash → restart + refill

### Benchmarking Targets
- Cold start: ~32 ms measured (baseline)
- Warm start target: <1 ms (NOT YET ACHIEVED; current warm is dominated by CLI startup)
- Pool initialization: measure overhead

---

## Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Daemon crash leaves orphaned processes | High | Medium | Health monitor + restart (Phase 1.5) |
| Socket race conditions | Medium | Medium | Proper locking in Rust (Phase 1.2) |
| Cgroups permissions | Medium | High | Graceful degradation to cold execution |
| Memory pressure from too many zygotes | Medium | Medium | Pool size limits (Phase 2.5) |
| Rootfs changes not reflected | Medium | Low | Invalidate on image update |

---

## Future Enhancements (Post-MVP)

- [ ] NUMA-aware pool placement
- [ ] Landlock security on zygotes
- [ ] Cross-host zygote migration
- [ ] Priority-based pool allocation
- [ ] Predictive pre-warming based on usage patterns
