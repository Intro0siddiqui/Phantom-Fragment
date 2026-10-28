# Warm Exec v2 — Plan

> Status: proposed · 2026-10-27 · supersedes the protocol sections of `warm-fragment-roadmap.md`

## 0. Why this exists

`phantom run --warm` is not a slower version of `phantom run`. It is a different,
incorrect program. Measured on this box (release, 14-core Ultra 5 225H, kernel 7.3.0):

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

### D3 — the protocol is one-request-one-response

`handle_client` reads exactly one frame, dispatches, writes exactly one reply, closes the
socket (`warm.rs:709-763`). There is no session, no sequence number, no frame kind, and
the response layout (`warm.rs:1434-1458`) is a single terminal struct. Adding output is
therefore not a field addition — it is a change of shape.

### D4 — the client retries the whole request on any failure

`exec_in_daemon` (`warm.rs:1733-1831`) retries the entire request up to 3×. Harmless today
because a failed reply means nothing ran. Once output streams, a mid-stream failure
**re-executes the command** — duplicate side effects on `rm -rf`.

### D5 — one exec blocks the whole daemon

`handle_client` runs inline under `block_in_place` with `&mut self`
(`warm.rs:672-682`, `run_test_loop` at `1570-1580`). A long-running command stalls every
other client, including health checks.

### D6 — the daemon inherits the launching shell's session

`start_daemon_background` uses `Command::spawn` with no `setsid()`. A `Ctrl+C` in the shell
that ran `phantom warm create` signals the daemon and all its children. This is a large
part of the "daemon stability issues" recorded in the roadmap.

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

### D9 — Landlock is applied without TSYNC

`security/landlock-rs/src/lib.rs:122-123` calls `ruleset.restrict_self()` with no
`.all_threads(true)`. On ABI ≥ 8 the flag maps to `LANDLOCK_RESTRICT_SELF_TSYNC`; without
it the ruleset covers only the calling thread. **Not a live bug** — the call site is a
freshly forked single-threaded child — but it is one refactor away from becoming one, and
the fix is one method call.

> **Fixed in `717b708`.** The ruleset now requests TSYNC and inspects
> `RestrictionStatus::all_threads`; on ABI < 8 it logs a warning and keeps the previous
> thread-scoped behaviour. See `docs/security/security-line-rate.md` for the scope table.

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

> **Fixed.** `rootfs_executor.rs` now resolves `user[:group]` before building the bwrap
> argv: numeric ids pass through, names are looked up against the **image's**
> `/etc/passwd` and `/etc/group` (not the host's), and a user-only spec defaults the gid
> to that user's primary group instead of the user string. If a name cannot be resolved
> the flags are omitted with a warning, leaving bwrap to keep the invoking user.

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

> **Progress:** 1.1 (`9bfb691`), 1.4 (`1802f71`) and 1.5 (`717b708`) landed. 1.2 and 1.3 are open.

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
| stdout is a tty **and** stdin is a tty | PTY: daemon `openpty()`, child `setsid()` + `TIOCSCTTY` on the slave, master sent to client in `ExecStarted` |
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
liveness comes from the pidfd (readable ⇒ exited). The fixed 5 s read/write timeouts at
`warm.rs:712-717` and `1748-1753` must become handshake-only.

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

This is where the actual speed lives, and none of it is protocol work.

| # | Change | Expected |
|---|---|---|
| 3.1 | Pool state lives in the daemon; `meta.json` becomes a crash-recovery artifact written on change, not per request. Drop the two `sync_all()` calls from the hot path. | −1.4 ms |
| 3.2 | Client sends `image_ref`; the daemon caches the resolved rootfs path. Client does one `stat`, not a directory scan. | −5…10 ms |
| 3.3 | Stop re-initialising `ImagePuller::with_config` + config + paths on the exec path; one lazily-initialised context. | −5…10 ms |
| 3.4 | Exec into a **pre-forked child**, not a fresh `fork` from the 31-thread, 237-VMA tokio daemon. Pool children block in `recvmsg()` on a `socketpair`; per-request work is `recvmsg` → `dup2` → `execve`. | 2.4 ms → ~1 ms |
| 3.5 | Move `chroot`, mount ns, cgroup membership, seccomp and Landlock to **pool-fill time** — they are properties of image+policy, not of `argv`. | removes per-request setup |
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
