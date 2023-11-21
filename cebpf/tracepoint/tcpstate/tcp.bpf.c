//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>
#define TASK_COMM_LEN 16

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

struct event {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
//    __u32 saddr;
//    __u32 daddr;
	__u64 skaddr;
	__u64 ts_us;
	__u64 delta_us;
	__u32 pid;
	int oldstate;
	int newstate;
	__u16 family;
	__u16 sport;
	__u16 dport;
	char task[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} sports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} dports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, __u64);
} timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
//    struct sock *sk = (struct sock *)ctx;

    struct sock *sk = (struct sock *)ctx;
    __u16 family = ctx->family;
    __u16 sport = bpf_ntohs(ctx->sport);
    __u16 dport = bpf_ntohs(ctx->dport);
    __u64 *tsp, delta_us, ts;
    struct event e = {};
    if (bpf_ntohs(ctx->protocol) != IPPROTO_TCP && family != AF_INET) {
        return 0;
    }

    tsp = bpf_map_lookup_elem(&timestamps, &sk);
    ts = bpf_ktime_get_ns();

    if (!tsp) {
        delta_us = 0;
    	}
    else {
        delta_us = (ts - *tsp) / 1000;
    	}

    e.skaddr = (__u64)sk;
    e.ts_us = ts / 1000;
    e.delta_us = delta_us;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.oldstate = ctx->oldstate;
    e.newstate = ctx->newstate;
    e.family = family;
    e.sport = sport;
    e.dport = dport;
    bpf_get_current_comm(&e.task, sizeof(e.task));

    bpf_probe_read_kernel(&e.saddr, sizeof(e.saddr), &sk->__sk_common.skc_rcv_saddr);
	bpf_probe_read_kernel(&e.daddr, sizeof(e.daddr), &sk->__sk_common.skc_daddr);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    e.saddr = bpf_ntohl(e.saddr);
    e.daddr = bpf_ntohl(e.daddr);
	if (ctx->newstate == TCP_CLOSE)
		bpf_map_delete_elem(&timestamps, &sk);
	else
		bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);
	return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";