//go:build ignore
/*
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    包含了系统运行Linux内核源码代码中使用的所有类型定义
*/
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

struct process {
    __u32 pid;
    __u32 ppid;
    char process_name[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 <<20);
} process_map SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_execve")
int handle_tp(void *ctx) {
    struct process *p = NULL;
    p = bpf_ringbuf_reserve(&process_map, sizeof(*p), 0);
    if (!p) {
        return 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    p -> pid = pid;
    p -> ppid = 0;

    /*
        task_struct (进程描述符)
        在 Linux 系统中进程在内核空间一般用任务/Task来表示，内核中对应的结构为 task_struct，每个进程之间通过该结构进行资源隔离，内核中的调度器基于 task_struct 结构进行调度。
        bpf_get_current_task
        获取当前正在执行的进程或线程的task_struct指针，以便在程序中对进程或线程进行操作。例如，可以使用task_struct指针来获取进程
        或线程的进程ID、进程状态等信息，或者使用task_struct指针来修改进程或线程的状态、资源限制等
    */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &(task -> real_parent));
        if (parent) {
            bpf_probe_read_kernel(&p -> ppid, sizeof(p -> ppid), &parent -> pid);
        }
    }
    bpf_get_current_comm(p->process_name, sizeof(p->process_name));

    bpf_ringbuf_submit(p, 0);
    return 0;
}
char __license[] SEC("license") = "GPL";



