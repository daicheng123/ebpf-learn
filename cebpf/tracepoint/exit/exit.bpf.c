#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
//#include <bpf/bpf_core_read.h>
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    u32 pid;
    u32 ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} event_map SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx) {

    struct event *e = NULL;
    pid = (u32)bpf_get_current_pid_tgid()>> 32;
    tid = (u32)bpf_get_current_pid_tgid();
    if (pid != tid) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&event_map, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(task, , )

}
