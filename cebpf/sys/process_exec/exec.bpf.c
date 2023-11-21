//go:build ignore
#include <common.h>

struct process {
    __u32 pid;
    char process_name[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 <<20);
} process_map SEC(".maps");

/*
    sys_enter_execve是一个eBPF追踪点(tracepoint)
    它表示Linux内核中的execve系统调用 用于执行一个新程序

    当execve()系统调用被触发时，当前新进程的用户空间代码和数据将被替换为新程序的代码和数据，新程序将成为新的进程，并从其入口点执行

    perf list查看内核预定义hook函数
*/

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_tp(void *ctx) {
    struct process *p = NULL;
    p = bpf_ringbuf_reserve(&process_map, sizeof(*p), 0);
    if (!p) {
        return 0;
    }

    p -> pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(p -> process_name, sizeof(p->process_name));

    bpf_ringbuf_submit(p, 0);
    return 0;
}





