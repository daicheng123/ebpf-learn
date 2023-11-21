//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
SEC("classifier")
int first_tc_example(struct __sk_buff *skb) {
    bpf_printk("HELLO WORLD");
    return 0; // direct-action 可以在 classifier中直接使用action作为返回值
}