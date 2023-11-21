//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct tc_data {
    __u32 source_ip;
    __u32 dest_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} traffic_controller_map SEC(".maps");

/*
    inline 关键字
    能够将函数打入函数调用里面，而不产生函数调用指令，以此来提升性能，但是编译比较慢
    一般如果我们做ebpf程序，函数就只是这一个文件使用，就可以使用这个
*/

static inline int iph_dr(struct __sk_buff *skb, struct iphdr *ip) {
    int offset = sizeof(struct ethhdr)
    return bpf_skb_load_bytes(skb, offset, ip, sizeof(*ip));
}

/*
    解析ip报文
*/
SEC("classifier")
int ip_package_example(struct __sk_buff *skb) {

    struct iphdr ip;
    iph_dr(skb, &ip);
    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }

    struct tc_data *data = NULL;
    data = bpf_ringbuf_reserve(&traffic_controller_map, sizeof(*data), 0);
    if (data) {
        data -> source_ip = bpf_ntohl(ip.saddr);
        data -> dest_ip = bpf_ntohl(ip.daddr);
        bpf_ringbuf_submit(data, 0);
    }
    return 0;
}