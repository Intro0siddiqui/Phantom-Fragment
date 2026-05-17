//! Zygote Pool - Complete Implementation with IPC
//!
//! Uses socketpair for command passing between parent and child.
//! Children wait for commands before exec'ing.

const std = @import("std");
const linux = std.os.linux;

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
const SYS_pivot_root: usize = 155;
const SYS_mount: usize = 165;
const SYS_umount2: usize = 166;
const SYS_fork: usize = 57;

const ZYGOTE_POOL_MAX: usize = 32;

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

var g_pool: [ZYGOTE_POOL_MAX]ZygoteEntry = undefined;
var g_pool_size: usize = 0;
var g_initialized: bool = false;
var g_pool_mutex = std.Thread.Mutex{};

fn getpid_syscall() i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_getpid),
        : "rcx", "r11", "memory");
    return @intCast(ret);
}

fn kill_syscall(pid: i32, sig: i32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_kill),
          [pid] "{rdi}" (@as(usize, @intCast(pid))),
          [sig] "{rsi}" (@as(usize, @intCast(sig))),
        : "rcx", "r11", "memory");
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return 0;
}

fn close_syscall(fd: i32) void {
    _ = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_close),
          [fd] "{rdi}" (@as(usize, @intCast(fd))),
        : "rcx", "r11", "memory");
}

fn read_syscall(fd: i32, buf: [*]u8, len: usize) isize {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_read),
          [fd] "{rdi}" (@as(usize, @intCast(fd))),
          [buf] "{rsi}" (@intFromPtr(buf)),
          [len] "{rdx}" (len),
        : "rcx", "r11", "memory");
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
        : "rcx", "r11", "memory");
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -@as(isize, @intCast(ret & 0xFFF));
    }
    return @intCast(ret);
}

fn socketpair_syscall(domain: i32, sock_type: i32, protocol: i32, sv: *[2]i32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_socketpair),
          [domain] "{rdi}" (@as(usize, @intCast(domain))),
          [sock_type] "{rsi}" (@as(usize, @intCast(sock_type))),
          [protocol] "{rdx}" (@as(usize, @intCast(protocol))),
          [sv] "{r10}" (@intFromPtr(sv)),
        : "rcx", "r11", "memory");
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
        : "rcx", "r11", "memory");
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
        : "rcx", "r11", "memory");
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return 0;
}

fn wait4_syscall(pid: i32, status: *i32, options: i32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_wait4),
          [pid] "{rdi}" (@as(usize, @intCast(pid))),
          [status] "{rsi}" (@intFromPtr(status)),
          [options] "{rdx}" (@as(usize, @intCast(options))),
        : "rcx", "r11", "memory");
    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return @intCast(ret);
}

fn execve_syscall(path: [*:0]const u8, argv: [*]?[*:0]u8, envp: [*]?[*:0]u8) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_execve),
          [path] "{rdi}" (@intFromPtr(path)),
          [argv] "{rsi}" (@intFromPtr(argv)),
          [envp] "{rdx}" (@intFromPtr(envp)),
        : "rcx", "r11", "memory");
}

fn open_syscall(path: [*:0]const u8, flags: linux.O) i32 {
    const flags_int: u32 = @bitCast(flags);
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_open),
          [path] "{rdi}" (@intFromPtr(path)),
          [flags] "{rsi}" (@as(usize, flags_int)),
          [mode] "{rdx}" (@as(usize, 0o644)),
        : "rcx", "r11", "memory");
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
        : "rcx", "r11", "memory");
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
        : "rcx", "r11", "memory");
    if (ret > 0xFFFFFFFFFFFFF000) return -1;
    return 0;
}

fn umount2_syscall(target: [*:0]const u8, flags: i32) i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_umount2),
          [target] "{rdi}" (@intFromPtr(target)),
          [flags] "{rsi}" (@as(usize, @intCast(flags))),
        : "rcx", "r11", "memory");
    if (ret > 0xFFFFFFFFFFFFF000) return -1;
    return 0;
}

fn fork_syscall() i32 {
    const ret = asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [sys] "{rax}" (SYS_fork),
        : "rcx", "r11", "memory");
    if (ret > 0xFFFFFFFFFFFFF000) return -1;
    return @intCast(ret);
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
            : "rcx", "r11", "memory");

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
        : "rcx", "r11", "memory");

    if (ret > 0xFFFFFFFFFFFFF000) {
        return -1;
    }
    return @intCast(ret);
}

const CommandBuffer = struct {
    data: [8192]u8,
    len: usize,
};

fn read_exact(fd: i32, buf: [*]u8, len: usize) bool {
    var total: usize = 0;
    while (total < len) {
        const n = read_syscall(fd, buf + total, len - total);
        if (n <= 0) return false;
        total += @as(usize, @intCast(n));
    }
    return true;
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

fn read_u8(fd: i32) ?u8 {
    var buf: [1]u8 = undefined;
    if (!read_exact(fd, &buf, 1)) return null;
    return buf[0];
}

fn read_bytes(fd: i32, len: usize, arena: *std.heap.ArenaAllocator) ?[]u8 {
    const buf = arena.allocator().alloc(u8, len) catch return null;
    if (!read_exact(fd, buf.ptr, len)) return null;
    return buf;
}

fn write_u32(fd: i32, val: u32) bool {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, val, .little);
    return write_syscall(fd, &buf, 4) == 4;
}

fn write_u16(fd: i32, val: u16) bool {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, val, .little);
    return write_syscall(fd, &buf, 2) == 2;
}

fn write_u8(fd: i32, val: u8) bool {
    return write_syscall(fd, @constCast(&val), 1) == 1;
}

fn write_bytes(fd: i32, bytes: []const u8) bool {
    return write_syscall(fd, bytes.ptr, bytes.len) == @as(isize, @intCast(bytes.len));
}

fn write_error(fd: i32, err_msg: []const u8) void {
    _ = write_u32(fd, 0xFFFFFFFF);
    _ = write_u16(fd, @intCast(err_msg.len));
    _ = write_bytes(fd, err_msg);
}

fn child_loop(socket_fd: i32) noreturn {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    while (true) {
        _ = arena.reset(.free_all);

        _ = read_u32(socket_fd) orelse {
            linux.exit(0);
        };

        const cmd_type = read_u8(socket_fd) orelse {
            linux.exit(1);
        };

        const rootfs_len = read_u16(socket_fd) orelse {
            linux.exit(1);
        };
        const rootfs = if (rootfs_len > 0) read_bytes(socket_fd, rootfs_len, &arena) orelse {
            write_error(socket_fd, "Failed to read rootfs");
            linux.exit(1);
        } else null;

        const exec_path_len = read_u16(socket_fd) orelse {
            linux.exit(1);
        };
        const exec_path = read_bytes(socket_fd, exec_path_len, &arena) orelse {
            write_error(socket_fd, "Failed to read exec_path");
            linux.exit(1);
        };

        const args_count = read_u8(socket_fd) orelse {
            write_error(socket_fd, "Failed to read args count");
            linux.exit(1);
        };

        var args = arena.allocator().alloc(?[*:0]u8, args_count + 1) catch {
            write_error(socket_fd, "Out of memory for args");
            linux.exit(1);
        };

        for (0..args_count) |i| {
            const arg_len = read_u16(socket_fd) orelse {
                write_error(socket_fd, "Failed to read arg length");
                linux.exit(1);
            };
            const arg = read_bytes(socket_fd, arg_len + 1, &arena) orelse {
                write_error(socket_fd, "Failed to read arg");
                linux.exit(1);
            };
            arg[arg_len] = 0;
            args[i] = @as([*:0]u8, @ptrCast(@constCast(arg.ptr)));
        }
        args[args_count] = null;

        const env_count = read_u8(socket_fd) orelse {
            write_error(socket_fd, "Failed to read env count");
            linux.exit(1);
        };

        var envp = arena.allocator().alloc(?[*:0]u8, env_count + 1) catch {
            write_error(socket_fd, "Out of memory for env");
            linux.exit(1);
        };

        for (0..env_count) |i| {
            const env_len = read_u16(socket_fd) orelse {
                write_error(socket_fd, "Failed to read env length");
                linux.exit(1);
            };
            const env = read_bytes(socket_fd, env_len + 1, &arena) orelse {
                write_error(socket_fd, "Failed to read env");
                linux.exit(1);
            };
            env[env_len] = 0;
            envp[i] = @as([*:0]u8, @ptrCast(@constCast(env.ptr)));
        }
        envp[env_count] = null;

        const cwd_len = read_u16(socket_fd) orelse {
            write_error(socket_fd, "Failed to read cwd length");
            linux.exit(1);
        };
        const cwd = read_bytes(socket_fd, cwd_len, &arena) orelse {
            write_error(socket_fd, "Failed to read cwd");
            linux.exit(1);
        };

        const flags = read_u32(socket_fd) orelse {
            write_error(socket_fd, "Failed to read flags");
            linux.exit(1);
        };

        if (cmd_type == 1) { // Setup Mother
            if (rootfs) |rs| {
                if (unshare_syscall(CLONE_NEWNS) < 0) {
                    write_error(socket_fd, "unshare failed");
                    continue;
                }
                _ = mount_syscall("none\x00", "/\x00", "none\x00", MS_REC | MS_PRIVATE, null);

                const rs_null = arena.allocator().allocSentinel(u8, rs.len, 0) catch {
                    write_error(socket_fd, "OOM for rootfs");
                    continue;
                };
                @memcpy(rs_null, rs);

                if (mount_syscall(rs_null, rs_null, "none\x00", MS_BIND | MS_REC, null) < 0) {
                    write_error(socket_fd, "bind mount failed");
                    continue;
                }
                if (chdir_syscall(rs_null) < 0) {
                    write_error(socket_fd, "chdir failed");
                    continue;
                }
                if (pivot_root_syscall(".\x00", ".\x00") < 0) {
                    write_error(socket_fd, "pivot_root failed");
                    continue;
                }
                _ = umount2_syscall(".\x00", MNT_DETACH);
                _ = chdir_syscall("/\x00");

                _ = write_u32(socket_fd, 0); // Success
                continue;
            } else {
                write_error(socket_fd, "rootfs missing for mother setup");
                continue;
            }
        }

        if (cmd_type == 3) { // Fragment Setup
            if (rootfs) |rs| {
                if (unshare_syscall(CLONE_NEWNS) < 0) {
                    write_error(socket_fd, "unshare failed");
                    continue;
                }
                _ = mount_syscall("none\x00", "/\x00", "none\x00", MS_REC | MS_PRIVATE, null);

                const rs_null = arena.allocator().allocSentinel(u8, rs.len, 0) catch {
                    write_error(socket_fd, "OOM for rootfs");
                    continue;
                };
                @memcpy(rs_null, rs);

                if (mount_syscall(rs_null, rs_null, "none\x00", MS_BIND | MS_REC, null) < 0) {
                    write_error(socket_fd, "bind mount failed");
                    continue;
                }
                if (chdir_syscall(rs_null) < 0) {
                    write_error(socket_fd, "chdir failed");
                    continue;
                }
                if (pivot_root_syscall(".\x00", ".\x00") < 0) {
                    write_error(socket_fd, "pivot_root failed");
                    continue;
                }
                _ = umount2_syscall(".\x00", MNT_DETACH);
                _ = chdir_syscall("/\x00");

                _ = write_u32(socket_fd, 0); // Success - fragment stays alive
                continue;
            } else {
                write_error(socket_fd, "rootfs missing for fragment setup");
                continue;
            }
        }

        if (cwd_len > 4096) {
            write_error(socket_fd, "cwd path too long");
            linux.exit(1);
        }
        if (cwd_len > 0) {
            const cwd_null = arena.allocator().alloc(u8, cwd_len + 1) catch {
                write_error(socket_fd, "Out of memory for cwd");
                linux.exit(1);
            };
            @memcpy(cwd_null[0..cwd_len], cwd);
            cwd_null[cwd_len] = 0;
            _ = chdir_syscall(@as([*:0]u8, @ptrCast(cwd_null.ptr)));
        }

        if (flags != 0) {
            _ = unshare_syscall(flags);
        }

        if (exec_path_len > 4096) {
            write_error(socket_fd, "exec path too long");
            linux.exit(1);
        }
        const exec_path_null = arena.allocator().alloc(u8, exec_path_len + 1) catch {
            write_error(socket_fd, "Out of memory for exec path");
            linux.exit(1);
        };
        @memcpy(exec_path_null[0..exec_path_len], exec_path);
        exec_path_null[exec_path_len] = 0;

        if (cmd_type == 2) { // Execute via Mother
            const pid = fork_syscall();
            if (pid == 0) {
                close_syscall(socket_fd);
                const exec_path_z: [*:0]u8 = @ptrCast(exec_path_null.ptr);
                _ = execve_syscall(exec_path_z, args.ptr, envp.ptr);
                linux.exit(126);
            } else if (pid > 0) {
                // Wait for grandchild to complete and get exit status
                var status: i32 = 0;
                _ = wait4_syscall(pid, &status, 0);
                // Return exit status to caller
                _ = write_u32(socket_fd, @bitCast(status));
                continue;
            } else {
                write_error(socket_fd, "fork failed");
                continue;
            }
        }

        if (cmd_type == 4) { // Fragment Fork & Exec
            if (exec_path_len == 0) {
                write_error(socket_fd, "exec_path required for fragment exec");
                continue;
            }

            if (cwd_len > 0) {
                const cwd_null = arena.allocator().alloc(u8, cwd_len + 1) catch {
                    write_error(socket_fd, "Out of memory for cwd");
                    continue;
                };
                @memcpy(cwd_null[0..cwd_len], cwd);
                cwd_null[cwd_len] = 0;
                _ = chdir_syscall(@as([*:0]u8, @ptrCast(cwd_null.ptr)));
            }

            if (flags != 0) {
                _ = unshare_syscall(flags);
            }

            const pid = fork_syscall();
            if (pid == 0) {
                close_syscall(socket_fd);
                const exec_path_z: [*:0]u8 = @ptrCast(exec_path_null.ptr);
                _ = execve_syscall(exec_path_z, args.ptr, envp.ptr);
                linux.exit(126);
            } else if (pid > 0) {
                // Wait for grandchild to complete and get exit status
                var status: i32 = 0;
                _ = wait4_syscall(pid, &status, 0);
                // Return exit status to caller
                _ = write_u32(socket_fd, @bitCast(status));
                continue;
            } else {
                write_error(socket_fd, "fork failed");
                continue;
            }
        }

        // Legacy / cmd_type 0 - Fork & Exec (for zygote recycling)
        const pid = fork_syscall();
        if (pid == 0) {
            close_syscall(socket_fd);
            const exec_path_z: [*:0]u8 = @ptrCast(exec_path_null.ptr);
            _ = execve_syscall(exec_path_z, args.ptr, envp.ptr);
            linux.exit(126);
        } else if (pid > 0) {
            // Wait for grandchild to complete and get exit status
            var status: i32 = 0;
            _ = wait4_syscall(pid, &status, 0);
            // Return exit status to caller
            _ = write_u32(socket_fd, @bitCast(status));
            continue;
        } else {
            write_error(socket_fd, "fork failed");
            continue;
        }
    }
}

export fn phantom_zygote_pool_create(size: usize) c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (g_initialized) {
        _ = phantom_zygote_pool_destroy();
    }

    const actual_size = if (size > ZYGOTE_POOL_MAX) ZYGOTE_POOL_MAX else size;
    if (actual_size == 0) {
        return -1;
    }

    g_pool_size = 0;

    var i: usize = 0;
    while (i < actual_size) : (i += 1) {
        var sv: [2]i32 = undefined;
        if (socketpair_syscall(1, 1, 0, &sv) < 0) {
            _ = phantom_zygote_pool_destroy();
            return -1;
        }

        const pid = do_clone();

        if (pid < 0) {
            close_syscall(sv[0]);
            close_syscall(sv[1]);
            _ = phantom_zygote_pool_destroy();
            return -1;
        } else if (pid == 0) {
            close_syscall(sv[0]);
            close_all_fds_except_stdio(sv[1]);
            child_loop(sv[1]);
        } else {
            close_syscall(sv[1]);

            g_pool[i] = ZygoteEntry{
                .pid = pid,
                .socket_fd = sv[0],
                .in_use = false,
            };
            g_pool_size += 1;
        }
    }

    g_initialized = true;
    return @intCast(g_pool_size);
}

fn spawn_single_zygote() bool {
    var sv: [2]i32 = undefined;
    if (socketpair_syscall(1, 1, 0, &sv) < 0) {
        return false;
    }

    const pid = do_clone();

    if (pid < 0) {
        close_syscall(sv[0]);
        close_syscall(sv[1]);
        return false;
    } else if (pid == 0) {
        close_syscall(sv[0]);
        close_all_fds_except_stdio(sv[1]);
        child_loop(sv[1]);
    } else {
        close_syscall(sv[1]);

        var found_slot: bool = false;
        var i: usize = 0;
        while (i < ZYGOTE_POOL_MAX) : (i += 1) {
            if (g_pool[i].pid <= 0) {
                g_pool[i] = ZygoteEntry{
                    .pid = pid,
                    .socket_fd = sv[0],
                    .in_use = false,
                };
                if (i >= g_pool_size) {
                    g_pool_size = i + 1;
                }
                found_slot = true;
                break;
            }
        }

        if (found_slot) {
            return true;
        }

        _ = kill_syscall(pid, linux.SIG.KILL);
        var status: i32 = 0;
        _ = wait4_syscall(pid, &status, 0);
        close_syscall(sv[0]);
        return false;
    }

    return false;
}

export fn phantom_numa_pool_get() c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized or g_pool_size == 0) {
        return -1;
    }

    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (!g_pool[i].in_use and g_pool[i].pid > 0 and g_pool[i].socket_fd > 0) {
            g_pool[i].in_use = true;
            return g_pool[i].pid;
        }
    }

    if (spawn_single_zygote()) {
        var j: usize = 0;
        while (j < ZYGOTE_POOL_MAX) : (j += 1) {
            if (!g_pool[j].in_use and g_pool[j].pid > 0 and g_pool[j].socket_fd > 0) {
                g_pool[j].in_use = true;
                return g_pool[j].pid;
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
        if (g_pool[i].pid == pid) {
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
    if (cmd_ptr == null) {
        return -1;
    }

    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return -1;
    }

    var socket_fd: i32 = -1;
    var entry_idx: ?usize = null;

    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        if (g_pool[i].pid == pid) {
            socket_fd = g_pool[i].socket_fd;
            entry_idx = i;
            break;
        }
    }

    if (socket_fd < 0) {
        return -1;
    }

    const n = write_syscall(socket_fd, cmd_ptr.?, cmd_len);
    if (n != @as(isize, @intCast(cmd_len))) {
        return -1;
    }

    const resp = read_u32(socket_fd);
    if (resp == null) {
        // Connection lost - zygote died unexpectedly
        close_syscall(socket_fd);
        if (entry_idx) |idx| {
            g_pool[idx].socket_fd = -1;
            g_pool[idx].pid = -1;
        }
        return -1;
    }

    if (resp.? == 0xFFFFFFFF) {
        // Command failed but zygote is still alive - keep socket open
        const err_len = read_u16(socket_fd) orelse return -1;
        var err_buf: [256]u8 = undefined;
        const to_read = @min(err_len, 256);
        _ = read_exact(socket_fd, &err_buf, to_read);
        // Socket stays open for reuse
        return -1;
    }

    // Success - return the grandchild PID (the actual spawned process)
    // Socket stays open for zygote recycling
    // The zygote is still waiting for the next command
    return @intCast(resp.?);
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
            // True zygote recycling: just mark as not in use
            // Keep pid and socket_fd alive for reuse
            g_pool[i].in_use = false;
            return 0;
        }
    }

    return -1;
}

export fn phantom_zygote_pool_destroy() c_int {
    g_pool_mutex.lock();
    defer g_pool_mutex.unlock();

    if (!g_initialized) {
        return 0;
    }

    var i: usize = 0;
    while (i < g_pool_size) : (i += 1) {
        const pid = g_pool[i].pid;
        if (pid > 0) {
            if (g_pool[i].socket_fd > 0) {
                close_syscall(g_pool[i].socket_fd);
                g_pool[i].socket_fd = -1;
            }
            _ = kill_syscall(pid, linux.SIG.KILL);
            var status: i32 = 0;
            _ = wait4_syscall(pid, &status, 0);
        }
        g_pool[i].pid = -1;
        g_pool[i].in_use = false;
    }

    g_pool_size = 0;
    g_initialized = false;

    return 0;
}

export fn phantom_zygote_init() c_int {
    return phantom_zygote_pool_create(4);
}

export fn phantom_zygote_fork() c_int {
    if (!g_initialized) {
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
        if (!g_pool[i].in_use and g_pool[i].pid > 0 and g_pool[i].socket_fd > 0) {
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

    var spawned: i32 = 0;
    var i: usize = 0;
    while (i < ZYGOTE_POOL_MAX) : (i += 1) {
        if (g_pool[i].pid <= 0) {
            if (spawn_single_zygote()) {
                spawned += 1;
            } else {
                break;
            }
        }
    }

    return spawned;
}
