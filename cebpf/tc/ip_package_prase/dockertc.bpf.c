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
    解析ip报文
*/
SEC("classifier")
int ip_package_example(struct __sk_buff *skb) {
    struct ethhdr eth;
    /*
       bpf_skb_load_bytes专门用来读取 __sk_buff对象，直接读取无权限
       0 由于取得是链路层的数据，第一层，所以offset从0开始
      长度为eth包的大小
    */
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    // 读取ip层
    int offset = sizeof(eth);
    struct iphdr ip;
    bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip));
    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }
//  bpf_printk("protocol=%d\n", ip.protocol);
    struct tc_data *data = NULL;
    data = bpf_ringbuf_reserve(&traffic_controller_map, sizeof(*data), 0);
    if (data) {
        data -> source_ip = bpf_ntohl(ip.saddr);
        data -> dest_ip = bpf_ntohl(ip.daddr);
//        bpf_ringbuf_output(&traffic_controller_map, *data, sizeof(*data), 0);
        bpf_ringbuf_submit(data, 0);
    }
    return 0; // direct-action 可以在 classifier中直接使用action作为返回值
}

