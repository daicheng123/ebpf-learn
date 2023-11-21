//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>
#define ARP_PROTO 2054
#define MAC_LEN 6

struct arp_data {
    unsigned char source_mac[MAC_LEN];
    __u32 source_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<< 20);
} arp_map SEC(".maps");

SEC("xdp")
int get_user_mac_example(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx -> data;
    void *data_end = (void*)(long)ctx -> data_end;

    struct ethhdr *eth = data;
    if ((void*)data + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }
    if (bpf_htons(eth -> h_proto) == ARP_PROTO) {
        // 获取arp数据包
        struct arphdr *arp = (struct arphdr*)((char *)eth + sizeof(struct ethhdr));
        if ((void*)arp + sizeof(*arp) > data_end) {
                return XDP_DROP;
            }
        if (bpf_htons(arp -> ar_op) != 1) {
            return XDP_PASS; // 如果不是请求直接放行
        }
        struct iphdr *ip;
        if(get_ip_data(ctx, eth, &ip) <0) {
            return XDP_PASS;
        }

        struct arp_data *data = NULL;
        data = bpf_ringbuf_reserve(&arp_map, sizeof(*data), 0);
        if (!data) {
            return XDP_PASS;
        }
        data->sip=bpf_ntohl(ip->saddr);
        bpf_probe_read_kernel(&data -> source_mac,MAC_LEN, eth -> h_source);
        bpf_ringbuf_submit(data, 0);
    }

    return XDP_PASS;
}

