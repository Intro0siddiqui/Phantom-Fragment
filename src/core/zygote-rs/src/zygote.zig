//! Zygote Pool - Complete Implementation with IPC
//!
//! Uses socketpair for command passing between parent and child.
//! Children wait for commands before exec'ing.

const std = @import("std");
const linux = std.os.linux;

/// Spin mutex compatible with the C ABI entry points, which cannot take an
/// `std.Io` instance. Critical sections here are short pool bookkeeping.
const Mutex = struct {
    state: std.atomic.Mutex = .unlocked,

    fn lock(self: *Mutex) void {
        while (!self.state.tryLock()) std.atomic.spinLoopHint();
    }

    fn unlock(self: *Mutex) void {
        self.state.unlock();
    }
};

const SIGCHLD: usize = 17;

const SYS_clone: usize = 56;
const SYS_kill: usize = 62;
const SYS_getpid: usize = 39;
const SYS_getppid: usize = 110;
const SYS_wait4: usize = 61;
const SYS_close: usize = 3;
const SYS_open: usize = 2;
const SYS_getdents64: usize = 217;
const SYS_socketpair: usize = 53;
const SYS_read: usize = 0;
const SYS_write: usize = 1;
const SYS_execve: usize = 59;
const SYS_chdir: usize = 80;
const SYS_unshare: usize = 272;
const SYS_setsid: usize = 112;
const SYS_dup2: usize = 33;
const SYS_fcntl: usize = 72;
const SYS_pivot_root: usize = 155;
const SYS_mount: usize = 165;
const SYS_umount2: usize = 166;
const SYS_fork: usize = 57;

const F_DUPFD_CLOEXEC: usize = 1030;
const EINTR: isize = 4;
const WNOHANG: i32 = 1;

const ZYGOTE_POOL_MAX: usize = 32;

/// Largest command the wire protocol accepts (must match `MAX_COMMAND_SIZE`
/// in `lib.rs`). The 4-byte length prefix is included in this total.
const MAX_COMMAND_SIZE: usize = 8192;
/// 4 (len) + 1 (type) + 2 (rootfs len) + 2 (exec len) + 1 (argc) +
/// 1 (envc) + 2 (cwd len) + 4 (flags) = 17 bytes with every variable empty.
const MIN_COMMAND_SIZE: usize = 17;
/// Filesystem paths (rootfs, exec path, cwd) are capped at PATH_MAX.
const MAX_PATH: usize = 4096;
/// A single argument/env entry can never exceed the whole command budget.
const MAX_STRING: usize = MAX_COMMAND_SIZE;
/// Error messages are truncated to this size so a reader can always drain one
/// short read and stay in sync with the stream.
const MAX_ERROR_LEN: usize = 256;
/// Command scratch space in the child. Sized for a full command plus
/// NUL-terminated copies of every string.
const SCRATCH_SIZE: usize = 64 * 1024;

const CLONE_NEWNS: u32 = 0x00020000;
const MS_BIND: usize = 4096;
const MS_REC: usize = 16384;
const MS_PRIVATE: usize = 1 << 18;
const MNT_DETACH: i32 = 2;

const ZygoteEntry = struct {
    pid: i32,
    socket_fd: i32,
    in_use: bool,
};

const EMPTY_ENTRY = ZygoteEntry{
    .pid = -1,
    .socket_fd = -1,
    .in_use = false,
};

var g_pool: [ZYGOTE_POOL_MAX]ZygoteEntry = undefined;
/// Number of slots currently occupied in `g_pool`.
var g_pool_size: usize = 0;
/// Configured pool size; slots beyond this are never used.
var g_pool_capacity: usize = 0;
var g_initialized: bool = false;
var g_pool_mutex: Mutex = .{};

fn getpid_syscall() i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_getpid),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return @intCast(ret);
}

fn kill_syscall(pid: i32, sig: i32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_kill),
          [pid] "{rdi}" (@as(usize, @bitCast(@as(isize, pid)))),
          [sig] "{rsi}" (@as(usize, @intCast(sig))),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return 0;
}

fn close_syscall(fd: i32) void {
    if (fd < 0) return;
    _ = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_close),
          [fd] "{rdi}" (@as(usize, @intCast(fd))),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn read_syscall(fd: i32, buf: [*]u8, len: usize) isize {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_read),
          [fd] "{rdi}" (@as(usize, @intCast(fd))),
          [buf] "{rsi}" (@intFromPtr(buf)),
          [len] "{rdx}" (len),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -@as(isize, @intCast(ret & 0xFFF));
    }
    return @intCast(ret);
}

fn write_syscall(fd: i32, buf: [*]const u8, len: usize) isize {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_write),
          [fd] "{rdi}" (@as(usize, @intCast(fd))),
          [buf] "{rsi}" (@intFromPtr(buf)),
          [len] "{rdx}" (len),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -@as(isize, @intCast(ret & 0xFFF));
    }
    return @intCast(ret);
}

/// Write the whole buffer, retrying on EINTR and short writes.
fn write_all(fd: i32, bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = write_syscall(fd, bytes.ptr + offset, bytes.len - offset);
        if (n == -EINTR) continue;
        if (n <= 0) return false;
        offset += @intCast(n);
    }
    return true;
}

/// Read exactly `len` bytes, retrying on EINTR.
fn read_exact(fd: i32, buf: [*]u8, len: usize) bool {
    var total: usize = 0;
    while (total < len) {
        const n = read_syscall(fd, buf + total, len - total);
        if (n == -EINTR) continue;
        if (n <= 0) return false;
        total += @as(usize, @intCast(n));
    }
    return true;
}

fn socketpair_syscall(domain: i32, sock_type: i32, protocol: i32, sv: *[2]i32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_socketpair),
          [domain] "{rdi}" (@as(usize, @intCast(domain))),
          [sock_type] "{rsi}" (@as(usize, @intCast(sock_type))),
          [protocol] "{rdx}" (@as(usize, @intCast(protocol))),
          [sv] "{r10}" (@intFromPtr(sv)),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return 0;
}

fn chdir_syscall(path: [*:0]const u8) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_chdir),
          [path] "{rdi}" (@intFromPtr(path)),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return 0;
}

fn unshare_syscall(flags: u32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_unshare),
          [flags] "{rdi}" (@as(usize, flags)),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return 0;
}

/// wait4 with EINTR retries. Returns the pid on success, 0 with WNOHANG when
/// the child is still running, or a negative errno.
fn wait4_retry(pid: i32, status: *i32, options: i32) isize {
    while (true) {
        const ret = asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [sys] "{rax}" (SYS_wait4),
              [pid] "{rdi}" (@as(usize, @bitCast(@as(isize, pid)))),
              [status] "{rsi}" (@intFromPtr(status)),
              [options] "{rdx}" (@as(usize, @bitCast(@as(isize, options)))),
            : .{ .rcx = true, .r11 = true, .memory = true });
        if (ret > 0xFFFFFFFFFFFFF000) {
            const err = -@as(isize, @intCast(ret & 0xFFF));
            if (err == -EINTR) continue;
            return err;
        }
        return @intCast(ret);
    }
}

fn execve_syscall(path: [*:0]const u8, argv: [*]?[*:0]u8, envp: [*]?[*:0]u8) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_execve),
          [path] "{rdi}" (@intFromPtr(path)),
          [argv] "{rsi}" (@intFromPtr(argv)),
          [envp] "{rdx}" (@intFromPtr(envp)),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn open_syscall(path: [*:0]const u8, flags: linux.O) i32 {
    const flags_int: u32 = @bitCast(flags);
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_open),
          [path] "{rdi}" (@intFromPtr(path)),
          [flags] "{rsi}" (@as(usize, flags_int)),
          [mode] "{rdx}" (@as(usize, 0o644)),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return @intCast(ret);
}

fn pivot_root_syscall(new_root: [*:0]const u8, put_old: [*:0]const u8) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_pivot_root),
          [new_root] "{rdi}" (@intFromPtr(new_root)),
          [put_old] "{rsi}" (@intFromPtr(put_old)),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) return -1;
    return 0;
}

fn mount_syscall(source: [*:0]const u8, target: [*:0]const u8, filesystemtype: [*:0]const u8, mountflags: usize, data: ?*const anyopaque) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_mount),
          [source] "{rdi}" (@intFromPtr(source)),
          [target] "{rsi}" (@intFromPtr(target)),
          [fstype] "{rdx}" (@intFromPtr(filesystemtype)),
          [flags] "{r10}" (mountflags),
          [data] "{r8}" (@intFromPtr(data)),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) return -1;
    return 0;
}

fn umount2_syscall(target: [*:0]const u8, flags: i32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_umount2),
          [target] "{rdi}" (@intFromPtr(target)),
          [flags] "{rsi}" (@as(usize, @intCast(flags))),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) return -1;
    return 0;
}

fn fork_syscall() i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_fork),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) return -1;
    return @intCast(ret);
}

/// Move `fd` to a descriptor above stdio so it is never confused with
/// stdin/stdout/stderr (and never closed by `close_all_fds_except_stdio`).
fn dup_high(fd: i32) i32 {
    if (fd > 2) return fd;
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_fcntl),
          [fd] "{rdi}" (@as(usize, @intCast(fd))),
          [cmd] "{rsi}" (F_DUPFD_CLOEXEC),
          [arg] "{rdx}" (@as(usize, 3)),
        : .{ .rcx = true, .r11 = true, .memory = true });
    if (ret > 0xFFFFFFFFFFFFF000) return fd;
    const new_fd: i32 = @intCast(ret);
    close_syscall(fd);
    return new_fd;
}

fn close_all_fds_except_stdio(except_fd: i32) void {
    const open_flags = linux.O{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
    };
    const fd_dir = open_syscall("/proc/self/fd\x00", open_flags);
    if (fd_dir < 0) {
        var fd: i32 = 3;
        while (fd < 1024) : (fd += 1) {
            if (fd != except_fd) {
                close_syscall(fd);
            }
        }
        return;
    }

    var buf: [1024]u8 = undefined;

    while (true) {
        const nread = asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [sys] "{rax}" (SYS_getdents64),
              [fd] "{rdi}" (@as(usize, @intCast(fd_dir))),
              [buf] "{rsi}" (@intFromPtr(&buf)),
              [len] "{rdx}" (buf.len),
            : .{ .rcx = true, .r11 = true, .memory = true });

        if (nread == 0) break;
        if (nread > 0xFFFFFFFFFFFFF000) break;

        var b: usize = 0;
        while (b < nread) {
            const entry = @as(*linux.dirent64, @ptrCast(@alignCast(&buf[b])));
            const reclen = entry.reclen;

            const name_ptr = @as([*:0]u8, @ptrCast(&entry.name));
            const name_len = std.mem.len(name_ptr);
            const name = name_ptr[0..name_len];

            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                if (std.fmt.parseInt(i32, name, 10)) |fd_num| {
                    if (fd_num > 2 and fd_num != fd_dir and fd_num != except_fd) {
                        close_syscall(fd_num);
                    }
                } else |_| {}
            }

            b += reclen;
        }
    }

    close_syscall(fd_dir);
}

fn do_clone() i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_clone),
          [flags] "{rdi}" (SIGCHLD),
          [stack] "{rsi}" (@as(usize, 0)),
          [ptid] "{rdx}" (@as(usize, 0)),
          [ctid] "{r10}" (@as(usize, 0)),
          [tls] "{r8}" (@as(usize, 0)),
        : .{ .rcx = true, .r11 = true, .memory = true });

    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return @intCast(ret);
}

fn read_u32(fd: i32) ?u32 {
    var buf: [4]u8 = undefined;
    if (!read_exact(fd, &buf, 4)) return null;
    return std.mem.readInt(u32, &buf, .little);
}

fn read_u16(fd: i32) ?u16 {
    var buf: [2]u8 = undefined;
    if (!read_exact(fd, &buf, 2)) return null;
    return std.mem.readInt(u16, &buf, .little);
}

fn write_u32(fd: i32, val: u32) bool {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, val, .little);
    return write_all(fd, &buf);
}

fn write_u16(fd: i32, val: u16) bool {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, val, .little);
    return write_all(fd, &buf);
}

fn write_error(fd: i32, err_msg: []const u8) void {
    const msg = err_msg[0..@min(err_msg.len, MAX_ERROR_LEN)];
    _ = write_u32(fd, 0xFFFFFFFF);
    _ = write_u16(fd, @intCast(msg.len));
    _ = write_all(fd, msg);
}

/// Drain `len` bytes from the socket so the next response stays aligned.
fn drain_bytes(fd: i32, len: usize) bool {
    var remaining = len;
    var buf: [256]u8 = undefined;
    while (remaining > 0) {
        const chunk = @min(remaining, buf.len);
        if (!read_exact(fd, &buf, chunk)) return false;
        remaining -= chunk;
    }
    return true;
}

/// Bounds-checked reader over one complete command message.
const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn take(self: *Cursor, n: usize) ?[]const u8 {
        if (n > self.buf.len - self.pos) return null;
        const out = self.buf[self.pos..][0..n];
        self.pos += n;
        return out;
    }

    fn u8v(self: *Cursor) ?u8 {
        const bytes = self.take(1) orelse return null;
        return bytes[0];
    }

    fn u16v(self: *Cursor) ?u16 {
        const bytes = self.take(2) orelse return null;
        return std.mem.readInt(u16, bytes[0..2], .little);
    }

    fn u32v(self: *Cursor) ?u32 {
        const bytes = self.take(4) orelse return null;
        return std.mem.readInt(u32, bytes[0..4], .little);
    }

    fn remaining(self: *Cursor) usize {
        return self.buf.len - self.pos;
    }
};

/// Bump allocator over the child's scratch mapping. All metadata lives outside
/// the mapping, so the whole mapping can be dropped with MADV_DONTNEED while
/// the child is idle.
const Scratch = struct {
    buf: []u8,
    used: usize = 0,

    fn reset(self: *Scratch) void {
        self.used = 0;
    }

    fn allocCStr(self: *Scratch, bytes: []const u8) ?[*:0]u8 {
        if (bytes.len + 1 > self.buf.len - self.used) return null;
        @memcpy(self.buf[self.used..][0..bytes.len], bytes);
        self.buf[self.used + bytes.len] = 0;
        const ptr: [*:0]u8 = @ptrCast(self.buf.ptr + self.used);
        self.used += bytes.len + 1;
        return ptr;
    }
};

fn set_sigpipe(handler: ?linux.Sigaction.handler_fn) void {
    var act = std.mem.zeroes(linux.Sigaction);
    act.handler = .{ .handler = handler };
    _ = linux.sigaction(.PIPE, &act, null);
}

/// Roadmap Phase 3 (see roadmap/HYBRID_MODEL.md): release the resident command
/// scratch pages before blocking on the next command. The mapping is anonymous
/// private memory and all bookkeeping lives outside it, so MADV_DONTNEED is
/// safe: the kernel re-zeroes pages on next touch and no state is lost.
fn trim_idle_memory(buf: []u8) void {
    _ = linux.madvise(buf.ptr, buf.len, linux.MADV.DONTNEED);
}

/// Configure the root filesystem for a mother/fragment zygote.
/// Returns an error message on failure, or null on success.
fn setup_rootfs(rootfs: [*:0]const u8) ?[]const u8 {
    if (unshare_syscall(CLONE_NEWNS) < 0) return "unshare failed";
    if (mount_syscall("none\x00", "/\x00", "none\x00", MS_REC | MS_PRIVATE, null) < 0) {
        return "make-rprivate failed";
    }
    if (mount_syscall(rootfs, rootfs, "none\x00", MS_BIND | MS_REC, null) < 0) {
        return "bind mount failed";
    }
    if (chdir_syscall(rootfs) < 0) return "chdir failed";
    if (pivot_root_syscall(".\x00", ".\x00") < 0) return "pivot_root failed";
    _ = umount2_syscall(".\x00", MNT_DETACH);
    if (chdir_syscall("/\x00") < 0) return "chdir / failed";
    return null;
}

/// Fork a grandchild, exec the command in it, wait for it, and report the raw
/// wait status to the parent over the socket.
fn fork_exec(socket_fd: i32, path: [*:0]const u8, argv: [*]?[*:0]u8, envp: [*]?[*:0]u8) void {
    const pid = fork_syscall();
    if (pid == 0) {
        // Grandchildren must get default SIGPIPE behaviour: only the zygote
        // itself wants EPIPE instead of death when the pool goes away.
        set_sigpipe(linux.SIG.DFL);
        close_syscall(socket_fd);
        _ = execve_syscall(path, argv, envp);
        linux.exit(126);
    } else if (pid > 0) {
        var status: i32 = 0;
        const ret = wait4_retry(pid, &status, 0);
        if (ret < 0) {
            write_error(socket_fd, "wait4 failed");
            return;
        }
        _ = write_u32(socket_fd, @bitCast(status));
    } else {
        write_error(socket_fd, "fork failed");
    }
}

fn child_loop(socket_fd: i32) noreturn {
    // A broken parent must not kill idle zygotes via SIGPIPE; writes should
    // fail with EPIPE so the loop can exit cleanly.
    set_sigpipe(linux.SIG.IGN);

    const scratch_buf = std.heap.page_allocator.alloc(u8, SCRATCH_SIZE) catch linux.exit(1);
    var scratch = Scratch{ .buf = scratch_buf };
    var msg_buf: [MAX_COMMAND_SIZE]u8 = undefined;

    cmd_loop: while (true) {
        // Idle point: drop command scratch pages before blocking.
        scratch.reset();
        trim_idle_memory(scratch_buf);

        // EOF means the parent pool was destroyed; exit without noise.
        const total_len = read_u32(socket_fd) orelse linux.exit(0);
        if (total_len < MIN_COMMAND_SIZE or total_len > MAX_COMMAND_SIZE) {
            // The stream cannot be resynchronised; report and exit so the
            // parent retires this slot instead of reading garbage.
            write_error(socket_fd, "invalid command length");
            linux.exit(1);
        }
        if (!read_exact(socket_fd, &msg_buf, total_len - 4)) {
            write_error(socket_fd, "truncated command");
            linux.exit(1);
        }
        var cur = Cursor{ .buf = msg_buf[0 .. total_len - 4] };

        const cmd_type = cur.u8v() orelse {
            write_error(socket_fd, "malformed command");
            continue :cmd_loop;
        };
        if (cmd_type > 4) {
            write_error(socket_fd, "unsupported command type");
            continue :cmd_loop;
        }

        const rootfs_len = cur.u16v() orelse {
            write_error(socket_fd, "malformed rootfs length");
            continue :cmd_loop;
        };
        if (rootfs_len > MAX_PATH) {
            write_error(socket_fd, "rootfs path too long");
            continue :cmd_loop;
        }
        var rootfs: ?[*:0]u8 = null;
        if (rootfs_len > 0) {
            const bytes = cur.take(rootfs_len) orelse {
                write_error(socket_fd, "truncated rootfs");
                continue :cmd_loop;
            };
            rootfs = scratch.allocCStr(bytes) orelse {
                write_error(socket_fd, "scratch exhausted");
                continue :cmd_loop;
            };
        }

        const exec_path_len = cur.u16v() orelse {
            write_error(socket_fd, "malformed exec length");
            continue :cmd_loop;
        };
        if (exec_path_len > MAX_PATH) {
            write_error(socket_fd, "exec path too long");
            continue :cmd_loop;
        }
        var exec_path: ?[*:0]u8 = null;
        if (exec_path_len > 0) {
            const bytes = cur.take(exec_path_len) orelse {
                write_error(socket_fd, "truncated exec path");
                continue :cmd_loop;
            };
            exec_path = scratch.allocCStr(bytes) orelse {
                write_error(socket_fd, "scratch exhausted");
                continue :cmd_loop;
            };
        }

        const args_count = cur.u8v() orelse {
            write_error(socket_fd, "malformed args count");
            continue :cmd_loop;
        };
        // argv[0] is the program name (filled in below); serialized args
        // become argv[1..]. The extra slot holds the NULL terminator.
        var argv: [257]?[*:0]u8 = undefined;
        var ai: usize = 0;
        while (ai < args_count) : (ai += 1) {
            const arg_len = cur.u16v() orelse {
                write_error(socket_fd, "malformed arg length");
                continue :cmd_loop;
            };
            if (arg_len > MAX_STRING) {
                write_error(socket_fd, "arg too long");
                continue :cmd_loop;
            }
            const bytes = cur.take(arg_len) orelse {
                write_error(socket_fd, "truncated arg");
                continue :cmd_loop;
            };
            const terminator = cur.u8v() orelse {
                write_error(socket_fd, "truncated arg terminator");
                continue :cmd_loop;
            };
            if (terminator != 0) {
                write_error(socket_fd, "malformed arg terminator");
                continue :cmd_loop;
            }
            argv[ai + 1] = scratch.allocCStr(bytes) orelse {
                write_error(socket_fd, "scratch exhausted");
                continue :cmd_loop;
            };
        }
        argv[args_count + 1] = null;

        const env_count = cur.u8v() orelse {
            write_error(socket_fd, "malformed env count");
            continue :cmd_loop;
        };
        var envp: [256]?[*:0]u8 = undefined;
        var ei: usize = 0;
        while (ei < env_count) : (ei += 1) {
            const env_len = cur.u16v() orelse {
                write_error(socket_fd, "malformed env length");
                continue :cmd_loop;
            };
            if (env_len > MAX_STRING) {
                write_error(socket_fd, "env var too long");
                continue :cmd_loop;
            }
            const bytes = cur.take(env_len) orelse {
                write_error(socket_fd, "truncated env var");
                continue :cmd_loop;
            };
            const terminator = cur.u8v() orelse {
                write_error(socket_fd, "truncated env terminator");
                continue :cmd_loop;
            };
            if (terminator != 0) {
                write_error(socket_fd, "malformed env terminator");
                continue :cmd_loop;
            }
            envp[ei] = scratch.allocCStr(bytes) orelse {
                write_error(socket_fd, "scratch exhausted");
                continue :cmd_loop;
            };
        }
        envp[env_count] = null;

        const cwd_len = cur.u16v() orelse {
            write_error(socket_fd, "malformed cwd length");
            continue :cmd_loop;
        };
        if (cwd_len > MAX_PATH) {
            write_error(socket_fd, "cwd path too long");
            continue :cmd_loop;
        }
        var cwd: ?[*:0]u8 = null;
        if (cwd_len > 0) {
            const bytes = cur.take(cwd_len) orelse {
                write_error(socket_fd, "truncated cwd");
                continue :cmd_loop;
            };
            cwd = scratch.allocCStr(bytes) orelse {
                write_error(socket_fd, "scratch exhausted");
                continue :cmd_loop;
            };
        }

        const flags = cur.u32v() orelse {
            write_error(socket_fd, "malformed flags");
            continue :cmd_loop;
        };
        if (cur.remaining() != 0) {
            write_error(socket_fd, "trailing command data");
            continue :cmd_loop;
        }

        switch (cmd_type) {
            // Setup Mother / Fragment: configure rootfs, stay alive.
            1, 3 => {
                const rs = rootfs orelse {
                    write_error(socket_fd, "rootfs missing for setup");
                    continue :cmd_loop;
                };
                if (setup_rootfs(rs)) |err_msg| {
                    write_error(socket_fd, err_msg);
                    // The mount namespace may be half-configured; never reuse
                    // this zygote for untrusted work.
                    linux.exit(1);
                }
                _ = write_u32(socket_fd, 0);
            },
            // Execute via Mother / Fragment fork & exec.
            2, 4 => {
                const path = exec_path orelse {
                    write_error(socket_fd, "exec_path required");
                    continue :cmd_loop;
                };
                if (cwd) |dir| {
                    if (chdir_syscall(dir) < 0) {
                        write_error(socket_fd, "chdir failed");
                        continue :cmd_loop;
                    }
                }
                if (flags != 0 and unshare_syscall(flags) < 0) {
                    write_error(socket_fd, "unshare failed");
                    continue :cmd_loop;
                }
                argv[0] = path;
                fork_exec(socket_fd, path, argv[0..].ptr, envp[0..].ptr);
            },
            // Legacy/generic spawn (cmd_type 0).
            else => {
                const path = exec_path orelse {
                    write_error(socket_fd, "exec_path required");
                    continue :cmd_loop;
                };
                if (cwd) |dir| {
                    if (chdir_syscall(dir) < 0) {
                        write_error(socket_fd, "chdir failed");
                        continue :cmd_loop;
                    }
                }
                if (flags != 0 and unshare_syscall(flags) < 0) {
                    write_error(socket_fd, "unshare failed");
                    continue :cmd_loop;
                }
                argv[0] = path;
                fork_exec(socket_fd, path, argv[0..].ptr, envp[0..].ptr);
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Pool bookkeeping (all `*_locked` helpers require g_pool_mutex to be held)
// ---------------------------------------------------------------------------

fn find_free_slot() ?usize {
    var i: usize = 0;
    while (i < g_pool_capacity) : (i += 1) {
        if (g_pool[i].pid <= 0) return i;
    }
    return null;
}

fn retire_entry_locked(idx: usize) void {
    if (g_pool[idx].socket_fd >= 0) {
        close_syscall(g_pool[idx].socket_fd);
        g_pool[idx].socket_fd = -1;
    }
    const pid = g_pool[idx].pid;
    if (pid > 0) {
        _ = kill_syscall(pid, @intFromEnum(linux.SIG.KILL));
        var status: i32 = 0;
        _ = wait4_retry(pid, &status, 0);
    }
    g_pool[idx].pid = -1;
    g_pool[idx].in_use = false;
}

/// Check whether a slot's zygote is still alive. Dead zygotes are reaped and
/// retired so their PIDs cannot be confused with reused PIDs.
fn entry_alive_locked(idx: usize) bool {
    const pid = g_pool[idx].pid;
    if (pid <= 0) return false;

    var status: i32 = 0;
    const ret = wait4_retry(pid, &status, WNOHANG);
    if (ret == pid) {
        // Exited and reaped here.
        if (g_pool[idx].socket_fd >= 0) {
            close_syscall(g_pool[idx].socket_fd);
            g_pool[idx].socket_fd = -1;
        }
        g_pool[idx].pid = -1;
        g_pool[idx].in_use = false;
        return false;
    }
    if (ret == 0) return true;

    // -ECHILD: reaped elsewhere or not our child; the slot is unusable.
    retire_entry_locked(idx);
    return false;
}

fn spawn_zygote_locked() bool {
    const slot = find_free_slot() orelse return false;

    var sv: [2]i32 = undefined;
    if (socketpair_syscall(1, 1, 0, &sv) < 0) {
        return false;
    }
    sv[0] = dup_high(sv[0]);
    sv[1] = dup_high(sv[1]);

    const pid = do_clone();
    if (pid < 0) {
        close_syscall(sv[0]);
        close_syscall(sv[1]);
        return false;
    } else if (pid == 0) {
        close_syscall(sv[0]);
        close_all_fds_except_stdio(sv[1]);
        child_loop(sv[1]);
    }

    close_syscall(sv[1]);
    g_pool[slot] = ZygoteEntry{
        .pid = pid,
        .socket_fd = sv[0],
        .in_use = false,
    };
    if (slot >= g_pool_size) {
        g_pool_size = slot + 1;
    }
    return true;
}

/// Destroy every pool entry. Must be called with the mutex held. Safe to call
/// when the pool was only partially constructed (g_initialized is false).
fn destroy_locked() void {
    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].socket_fd >= 0) {
            close_syscall(g_pool[i].socket_fd);
            g_pool[i].socket_fd = -1;
        }
        const pid = g_pool[i].pid;
        if (pid > 0) {
            _ = kill_syscall(pid, @intFromEnum(linux.SIG.KILL));
            var status: i32 = 0;
            _ = wait4_retry(pid, &status, 0);
        }
        g_pool[i] = EMPTY_ENTRY;
    }
    g_pool_size = 0;
    g_pool_capacity = 0;
    g_initialized = false;
}

export fn phantom_zygote_pool_create(size: usize) c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    // Re-creating the pool must not deadlock on our own mutex.
    destroy_locked();
    for (&g_pool) |*entry| entry.* = EMPTY_ENTRY;

    const actual_size = @min(size, ZYGOTE_POOL_MAX);
    if (actual_size == 0) {
        return -1;
    }

    g_pool_capacity = actual_size;

    var i: usize = 0;
    while (i < actual_size) : (i += 1) {
        if (!spawn_zygote_locked()) {
            destroy_locked();
            return -1;
        }
    }

    g_initialized = true;
    return @intCast(g_pool_size);
}

export fn phantom_numa_pool_get() c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized or g_pool_size == 0) {
        return -1;
    }

    // Prefer an existing free, live slot; reap dead zygotes as we go.
    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].pid <= 0) continue;
        if (!entry_alive_locked(i)) continue;
        if (!g_pool[i].in_use and g_pool[i].socket_fd >= 0) {
            g_pool[i].in_use = true;
            return g_pool[i].pid;
        }
    }

    // No free slot: spawn a replacement only if a slot is actually available.
    if (find_free_slot() != null and spawn_zygote_locked()) {
        i = 0;
        while (i < g_pool_size) : (i += 1) {
            if (!g_pool[i].in_use and g_pool[i].pid > 0 and g_pool[i].socket_fd >= 0) {
                g_pool[i].in_use = true;
                return g_pool[i].pid;
            }
        }
    }

    return -1;
}

export fn phantom_zygote_get_socket(pid: c_int) c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return -1;
    }

    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].pid == pid and g_pool[i].socket_fd >= 0) {
            return g_pool[i].socket_fd;
        }
    }

    return -1;
}

export fn phantom_zygote_send_command(
    pid: c_int,
    cmd_ptr: ?[*]const u8,
    cmd_len: usize,
) c_int {
    const ptr = cmd_ptr orelse return -1;
    if (cmd_len < MIN_COMMAND_SIZE or cmd_len > MAX_COMMAND_SIZE) {
        return -1;
    }

    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return -1;
    }

    var entry_idx: ?usize = null;
    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].pid == pid) {
            entry_idx = i;
            break;
        }
    }

    const idx = entry_idx orelse return -1;
    if (g_pool[idx].socket_fd < 0) {
        return -1;
    }

    // The buffer is self-describing; reject a mismatched prefix before
    // writing anything so the child's parser stays in sync.
    const declared_len = std.mem.readInt(u32, ptr[0..4], .little);
    if (declared_len != cmd_len) {
        return -1;
    }

    const socket_fd = g_pool[idx].socket_fd;
    if (!write_all(socket_fd, ptr[0..cmd_len])) {
        retire_entry_locked(idx);
        return -1;
    }

    const resp = read_u32(socket_fd) orelse {
        // Connection lost - zygote died unexpectedly.
        retire_entry_locked(idx);
        return -1;
    };

    if (resp == 0xFFFFFFFF) {
        // Command failed but the zygote may still be alive. Drain the full
        // error body to keep the stream aligned for the next command.
        const err_len = read_u16(socket_fd) orelse {
            retire_entry_locked(idx);
            return -1;
        };
        if (!drain_bytes(socket_fd, err_len)) {
            retire_entry_locked(idx);
            return -1;
        }
        return -1;
    }

    // Raw wait status of the executed grandchild.
    return @intCast(resp);
}

export fn phantom_zygote_pool_put(pid: c_int) c_int {
    if (pid <= 0) {
        return -1;
    }

    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return -1;
    }

    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].pid == pid) {
            if (!g_pool[i].in_use) {
                // Double release: report it instead of silently accepting.
                return -1;
            }
            g_pool[i].in_use = false;
            return 0;
        }
    }

    return -1;
}

export fn phantom_zygote_pool_destroy() c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    destroy_locked();
    return 0;
}

export fn phantom_zygote_init() c_int {
    return phantom_zygote_pool_create(4);
}

export fn phantom_zygote_fork() c_int {
    g_pool_mutex.lock();
    const initialized = g_initialized;
    g_pool_mutex.unlock();

    if (!initialized) {
        const result = phantom_zygote_init();
        if (result < 0) {
            return -1;
        }
    }

    return phantom_numa_pool_get();
}

export fn phantom_zygote_pool_status() c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return -1;
    }

    var available: i32 = 0;
    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].pid <= 0) continue;
        if (!entry_alive_locked(i)) continue;
        if (!g_pool[i].in_use and g_pool[i].socket_fd >= 0) {
            available += 1;
        }
    }

    return available;
}

export fn phantom_zygote_pool_size() c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return -1;
    }
    return @intCast(g_pool_size);
}

export fn phantom_zygote_pool_refill() c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return -1;
    }

    // Reap dead zygotes first so their slots can be reused.
    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].pid > 0) {
            _ = entry_alive_locked(i);
        }
    }

    var spawned: i32 = 0;
    while (find_free_slot() != null) {
        if (!spawn_zygote_locked()) {
            break;
        }
        spawned += 1;
    }

    return spawned;
}
