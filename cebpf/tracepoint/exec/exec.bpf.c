//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>


#define TASK_COMM_LEN 256

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(void *ctx) {
    struct event e = {};
    // 获取用户id
    e.uid = (__u32)bpf_get_current_uid_gid();
    // 获取 tgid
    e.pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // 获取父进程id
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &(task -> real_parent));
        if (parent) {
            bpf_probe_read_kernel(&e.ppid, sizeof(e.ppid), &(parent -> pid));
        }
    }
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";



