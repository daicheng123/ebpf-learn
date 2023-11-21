//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define TASK_COMM_LEN 256

char __license[] SEC("license") = "Dual MIT/GPL";

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
};


struct sock {
	struct sock_common __sk_common;
};

struct event {
	u8 comm[16];
	__u16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
};
struct piddata {
    char comm[TASK_COMM_LEN];
    __be64 ts_us;
    __be32 tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock);
	__type(value, struct piddata);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};


struct event {
    __be32 saddr;
    __be32 daddr;
    __be16 lport;
    __be16 dport;
    __u64 delta_us;
    __u64 ts_us;
    __u32 tgid;
    char comm[TASK_COMM_LEN];
    int af;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("kprobe/tcp_connect")
int fentry_tcp_v4_connect(struct sock *sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
            return 0;
        }

    struct piddata pdata = {};

    pdata.tgid = bpf_get_current_pid_tgid() >>32;

    bpf_get_current_comm(&pdata.comm, TASK_COMM_LEN);
    pdata.ts_us = bpf_ktime_get_ns();

//    bpf_map_update_elem(&start, sk, &pdata, 0);
    return 0;
}

//SEC("fentry/tcp_rcv_state_process")
//int fentry_tcp_rcv_state_process(struct sock *sk) {
//           struct piddata *pdata;
//           struct event e = {};
//
//           unsigned char skc_state;
//           bpf_probe_read_kernel_str((void *)&skc_state, sizeof(skc_state), (const void *)&sk -> __sk_common.skc_state);
//           if (skc_state != TCP_SYN_SENT) {
//               return 0;
//           }
//
//           pdata = bpf_map_lookup_elem(&start, &sk);
//           if (!pdata) {
//               return 0;
//           }
//
//          __u64 ts = bpf_ktime_get_ns();
//          __u64 delta = (__u64)(ts - pdata->ts_us);
//          if (delta < 0) {
//               goto cleanup;
//          }
//
//          e.delta_us = delta / 1000U;
//          e.ts_us = ts / 1000;
//          __builtin_memcpy(&e.comm, pdata -> comm, sizeof(e.comm));
//          e.tgid = pdata -> tgid;
//          bpf_probe_read_kernel(&e.lport, sizeof(e.lport), &sk -> __sk_common.skc_num);
//          bpf_probe_read_kernel(&e.dport, sizeof(e.dport), &sk -> __sk_common.skc_dport);
//          bpf_probe_read_kernel(&e.af, sizeof(e.af), &sk -> __sk_common.skc_family);
//          bpf_probe_read_kernel(&e.saddr, sizeof(e.saddr), &sk -> __sk_common.skc_rcv_saddr);
//          bpf_probe_read_kernel(&e.daddr, sizeof(e.daddr), &sk -> __sk_common.skc_daddr);
//
//          bpf_ringbuf_submit(&e, 0);
//
//          cleanup:
//               bpf_map_delete_elem(&start, &sk);
//               return 0;
//}

/// "Trace open family syscalls."
char __license[] SEC("license") = "Dual MIT/GPL";
