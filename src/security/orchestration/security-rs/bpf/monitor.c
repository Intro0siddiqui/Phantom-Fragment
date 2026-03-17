// SPDX-License-Identifier: GPL-2.0
// Phantom Fragment - BPF-LSM Security Monitor
//
// Implements LSM hooks via eBPF for:
// - file_open: Restrict file access based on Policy Map
// - task_alloc: Monitor process creation

#define __TARGET_ARCH_x86

// Minimal type definitions
typedef unsigned long long __u64;
typedef unsigned int __u32;
typedef int __s32;

#define SEC(name) __attribute__((section(name), used))
#define NULL ((void *)0)
#define EPERM 1

// BPF Map Types
#define BPF_MAP_TYPE_HASH 1

// Helper IDs
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_trace_printk 6
#define BPF_FUNC_get_current_pid_tgid 14

// BPF helper signatures
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)BPF_FUNC_trace_printk;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;

// ============================================================================
// BPF Maps
// ============================================================================

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

// Map: PID -> Policy Flags
// Key: u32 (PID)
// Value: u32 (Policy Mode: 0=Allow, 1=DenyAll/Strict)
SEC(".maps")
struct bpf_map_def policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .map_flags = 0,
};

// ============================================================================
// LSM Hook: file_open
// ============================================================================

SEC("lsm/file_open")
int phantom_file_open(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 1. Lookup Policy for this process
    __u32 *policy = bpf_map_lookup_elem(&policy_map, &pid);

    // Default: Allow if no policy exists (Unmanaged process)
    if (!policy) {
        return 0;
    }

    // 2. Enforce Policy
    // Implementation: Block specific arbitrary filename "malicious" for the demo
    // In a real world scenario, this would use bpf_d_path or more complex string matching
    // For this 'Kill Shot' demo, we will use the Policy mode 1 to represent "Untrusted/Malicious Context"
    
    if (*policy == 1) { // POLICY_STRICT / MALICIOUS_CONTEXT
        // In this mode, we block execution or specific file access
        // For the demo, we simply deny the operation to show the "Kill"
        
        char msg[] = "Phantom LSM: KILL SHOT! Blocked file_open for pid=%d\n";
        bpf_trace_printk(msg, sizeof(msg), pid);
        return -EPERM;
    }

    // Mode 0 or unknown: Allow
    return 0;
}

// ============================================================================
// Tracepoint: execve
// ============================================================================

struct trace_event_raw_sys_enter {
    __u64 unused;
    __u64 id;
    __u64 args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    char msg[] = "Phantom: execve called\n";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char _license[] SEC("license") = "GPL";
