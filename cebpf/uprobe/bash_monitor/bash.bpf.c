//go:build ignore
/*
uprobe和uretprobe用于挂载到用户程序函数上
1、uprobe挂载在函数进入之前，可以获取到函数的参数值
2、uretprobe时挂载在函数返回之前，可以获取到函数返回值

首先通过 nm -D $(which bash)找到bash的符号表
符号 readline 探测用户输入参数
*/
#include "common.h"

#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 line[80];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));
//    __uint(max_entries, 1 << 20);
//	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
//	.key_size = sizeof(int);
//    .value_size = sizeof(u32);
} events SEC(".maps");

SEC("uretprobe/readline")
int uretprobe_bash_readline(struct pt_regs *ctx) {
	struct event event;

	event.pid = bpf_get_current_pid_tgid();
	/*
	    PT_REGS_RC 
	*/
	bpf_probe_read(&event.line, sizeof(event.line), (void *)PT_REGS_RC(ctx));

	bpf_perf_event3_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

