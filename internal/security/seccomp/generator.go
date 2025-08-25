package seccomp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
)

// SeccompProfile defines syscall restrictions
type SeccompProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Architectures []string      `json:"architectures"`
	Syscalls      []SyscallRule `json:"syscalls"`
}

// SyscallRule defines a syscall permission rule
type SyscallRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
	Args   []Arg    `json:"args,omitempty"`
}

// Arg defines syscall argument filters
type Arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}

// SeccompPolicyDSL defines the structure for seccomp policy configuration
type SeccompPolicyDSL struct {
	Default string   `yaml:"default"`
	Allow   []string `yaml:"allow"`
	Deny    []string `yaml:"deny"`
}

// ProfileGenerator creates seccomp profiles
type ProfileGenerator struct {
	profilesDir string
}

// NewGenerator creates a new seccomp profile generator
func NewGenerator() *ProfileGenerator {
	return &ProfileGenerator{
		profilesDir: filepath.Join(config.GetConfigDir(), "seccomp"),
	}
}

// GenerateProfiles creates all default seccomp profiles
func (g *ProfileGenerator) GenerateProfiles() error {
	if err := os.MkdirAll(g.profilesDir, 0755); err != nil {
		return fmt.Errorf("failed to create seccomp directory: %w", err)
	}

	profiles := map[string]*SeccompProfile{
		"strict":    g.generateStrictProfile(),
		"dev":       g.generateDevProfile(),
		"python":    g.generatePythonProfile(),
		"nodejs":    g.generateNodejsProfile(),
		"go":        g.generateGoProfile(),
		"rust":      g.generateRustProfile(),
		"java":      g.generateJavaProfile(),
		"container": g.generateContainerProfile(),
	}

	for name, profile := range profiles {
		if err := g.saveProfile(name, profile); err != nil {
			return fmt.Errorf("failed to save profile %s: %w", name, err)
		}
	}

	return nil
}

// generateStrictProfile creates maximum security profile
func (g *ProfileGenerator) generateStrictProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_KILL",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names:  []string{"read", "write", "close", "fstat", "lseek", "mmap", "munmap", "mprotect", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "setresgid", "getresuid", "getresgid", "sigpending", "sigsuspend", "sigtimedwait", "sigwaitinfo", "exit_group", "epoll_create", "epoll_ctl", "epoll_wait", "getdents64", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx", "io_pgetevents", "rseq"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// generateDevProfile creates development-friendly profile
func (g *ProfileGenerator) generateDevProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names: []string{"accept", "accept4", "access", "adjtimex", "alarm", "bind", "brk", "capget", "capset", "chdir", "chmod", "chown", "chroot", "clock_adjtime", "clock_getres", "clock_gettime", "clock_nanosleep", "clock_settime", "clone", "close", "connect", "copy_file_range", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fanotify_mark", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "io_cancel", "ioctl", "io_destroy", "io_getevents", "io_pgetevents", "ioprio_get", "ioprio_set", "io_setup", "io_submit", "listen", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mprotect", "mq_getsetattr", "mq_notify", "mq_open", "mq_timedreceive", "mq_timedsend", "mq_unlink", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "prctl", "pread64", "preadv", "preadv2", "prlimit64", "process_vm_readv", "process_vm_writev", "pselect6", "ptrace", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo", "rt_sigreturn", "rt_sigsuspend", "rt_sigtimedwait", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "send", "sendfile", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid", "setgid", "setgroups", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// generatePythonProfile creates Python-specific profile
func (g *ProfileGenerator) generatePythonProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names: []string{"accept", "accept4", "access", "alarm", "bind", "brk", "capget", "chdir", "chmod", "chown", "clock_getres", "clock_gettime", "clock_nanosleep", "close", "connect", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "ioctl", "ioprio_get", "ioprio_set", "listen", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mprotect", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "pread64", "preadv", "preadv2", "prlimit64", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "send", "sendfile", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid", "setgid", "setgroups", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// generateNodejsProfile creates Node.js-specific profile
func (g *ProfileGenerator) generateNodejsProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names: []string{"accept", "accept4", "access", "alarm", "bind", "brk", "capget", "chdir", "chmod", "chown", "clock_getres", "clock_gettime", "clock_nanosleep", "close", "connect", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "ioctl", "ioprio_get", "ioprio_set", "listen", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mprotect", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "pread64", "preadv", "preadv2", "prlimit64", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "send", "sendfile", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid", "setgid", "setgroups", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// generateGoProfile creates Go-specific profile
func (g *ProfileGenerator) generateGoProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names: []string{"accept", "accept4", "access", "alarm", "bind", "brk", "capget", "chdir", "chmod", "chown", "clock_getres", "clock_gettime", "clock_nanosleep", "close", "connect", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "ioctl", "ioprio_get", "ioprio_set", "listen", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mprotect", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "pread64", "preadv", "preadv2", "prlimit64", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "send", "sendfile", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid", "setgid", "setgroups", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// generateRustProfile creates Rust-specific profile
func (g *ProfileGenerator) generateRustProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names: []string{"accept", "accept4", "access", "alarm", "bind", "brk", "capget", "chdir", "chmod", "chown", "clock_getres", "clock_gettime", "clock_nanosleep", "close", "connect", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "ioctl", "ioprio_get", "ioprio_set", "listen", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mprotect", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "pread64", "preadv", "preadv2", "prlimit64", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "send", "sendfile", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid", "setgid", "setgroups", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// generateJavaProfile creates Java-specific profile
func (g *ProfileGenerator) generateJavaProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names: []string{"accept", "accept4", "access", "alarm", "bind", "brk", "capget", "chdir", "chmod", "chown", "clock_getres", "clock_gettime", "clock_nanosleep", "close", "connect", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "ioctl", "ioprio_get", "ioprio_set", "listen", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mprotect", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "pread64", "preadv", "preadv2", "prlimit64", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "send", "sendfile", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid", "setgid", "setgroups", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// generateContainerProfile creates container runtime profile
func (g *ProfileGenerator) generateContainerProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SyscallRule{
			{
				Names: []string{"accept", "accept4", "access", "alarm", "bind", "brk", "capget", "chdir", "chmod", "chown", "clock_getres", "clock_gettime", "clock_nanosleep", "close", "connect", "creat", "dup", "dup2", "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait", "eventfd", "eventfd2", "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64", "fallocate", "fchdir", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr", "fsetxattr", "fstat", "fstatfs", "fsync", "ftruncate", "futex", "getcwd", "getdents", "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpeername", "getpgrp", "getpid", "getppid", "getpriority", "getrandom", "getresgid", "getresuid", "getrlimit", "get_robust_list", "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid", "gettimeofday", "getuid", "getxattr", "inotify_add_watch", "inotify_init", "inotify_init1", "inotify_rm_watch", "ioctl", "ioprio_get", "ioprio_set", "listen", "llistxattr", "lremovexattr", "lseek", "lsetxattr", "lstat", "madvise", "memfd_create", "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2", "mlockall", "mmap", "mprotect", "mremap", "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall", "munmap", "nanosleep", "newfstatat", "open", "openat", "pause", "pipe", "pipe2", "poll", "ppoll", "pread64", "preadv", "preadv2", "prlimit64", "pwrite64", "pwritev", "pwritev2", "read", "readahead", "readlink", "readlinkat", "readv", "recv", "recvfrom", "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename", "renameat", "renameat2", "restart_syscall", "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend", "rt_tgsigqueueinfo", "sched_getaffinity", "sched_getattr", "sched_getparam", "sched_get_priority_max", "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval", "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler", "sched_yield", "seccomp", "select", "semctl", "semget", "semop", "semtimedop", "send", "sendfile", "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid", "setgid", "setgroups", "setitimer", "setpgid", "setpriority", "setregid", "setresgid", "setresuid", "setreuid", "setrlimit", "set_robust_list", "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown", "sigaltstack", "signalfd", "signalfd4", "socket", "socketpair", "splice", "stat", "statfs", "statx", "symlink", "symlinkat", "sync", "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time", "timer_create", "timer_delete", "timerfd_create", "timerfd_gettime", "timerfd_settime", "timer_getoverrun", "timer_gettime", "timer_settime", "times", "tkill", "truncate", "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork", "vmsplice", "wait4", "waitid", "write", "writev"},
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}
}

// saveProfile writes seccomp profile to disk
func (g *ProfileGenerator) saveProfile(name string, profile *SeccompProfile) error {
	filename := filepath.Join(g.profilesDir, name+".json")
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// BPFGenerator generates BPF bytecode for seccomp policies
type BPFGenerator struct {
	// Add fields as needed for BPF generation
}

// NewBPFGenerator creates a new BPF generator
func NewBPFGenerator() (*BPFGenerator, error) {
	return &BPFGenerator{}, nil
}

// Generate generates BPF bytecode from a seccomp policy DSL
func (bg *BPFGenerator) Generate(policy *SeccompPolicyDSL) ([]byte, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}

	// This is a simplified BPF bytecode generation
	// In a real implementation, this would convert the policy DSL to actual BPF bytecode
	// For now, we'll create a minimal valid BPF program that allows all syscalls by default
	
	// BPF instruction structure
	type bpfInstruction struct {
		Code uint16
		Jt   uint8
		Jf   uint8
		K    uint32
	}
	
	// Create a simple BPF program that allows all syscalls
	// This is a minimal seccomp BPF program that returns ALLOW
	instructions := []bpfInstruction{
		// Load syscall number (architecture specific)
		{Code: 0x20, Jt: 0, Jf: 0, K: 0}, // BPF_LD | BPF_W | BPF_ABS, offset 0
		
		// Return ALLOW for all syscalls
		{Code: 0x06, Jt: 0, Jf: 0, K: 0x7fff0000}, // BPF_RET | BPF_K, SECCOMP_RET_ALLOW
	}
	
	// Convert to byte array
	buf := make([]byte, len(instructions)*8)
	for i, inst := range instructions {
		// Pack the instruction into bytes
		buf[i*8+0] = byte(inst.Code)
		buf[i*8+1] = byte(inst.Code >> 8)
		buf[i*8+2] = inst.Jt
		buf[i*8+3] = inst.Jf
		buf[i*8+4] = byte(inst.K)
		buf[i*8+5] = byte(inst.K >> 8)
		buf[i*8+6] = byte(inst.K >> 16)
		buf[i*8+7] = byte(inst.K >> 24)
	}
	
	return buf, nil
}

// LoadProfile loads a seccomp profile from disk
func LoadProfile(name string) (*SeccompProfile, error) {
	profilesDir := filepath.Join(config.GetConfigDir(), "seccomp")
	filename := filepath.Join(profilesDir, name+".json")
	
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	var profile SeccompProfile
	err = json.Unmarshal(data, &profile)
	return &profile, err
}