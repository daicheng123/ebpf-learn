//go:build ignore
// 参考 https://github.com/torvalds/linux/blob/master/samples/bpf/tcbpf1_kern.c#L39
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>
//#include <netinet/in.h>
#include "bpf_legacy.h"

/*
    tpc报文 包头前16个字节为源地址端口号17-32字节为目的地址端口
    报头中的16位校验和===>每次修改报文数据都需要更新，否则三次握手时连接会被重置、关闭掉
    重新计算l4(tcp/udp/icmp)16位校验和(CheckSum)的帮助函数：
    bpf_l4_csum_replace(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags)
    offset 修改起始位如目标地址端口为17
    from 修改的源字段
    to   修改的新值
    flags 新值的size
    ==========>仅仅修改还是不够的，还需要利用重新封包==>
    bpf_skb_store_bytes(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) 帮助函数
    存储缓冲区from的len字节到skb所关联的封包的offset位置
*/
char _license[] SEC("license") = "GPL";
#define ETH_HLEN  14  //以太网头部size 固定14
/*
 offsetof 直接获取到iphdr头部checksum的offset
*/
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define TCP_SPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define IS_PSEUDO 0x10


struct tc_data {
    __u32 source_ip;
    __u32 dest_ip;
    __be16 source_port;
    __be16 dest_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} traffic_controller_map SEC(".maps");

static inline int iph_dr(struct __sk_buff *skb, struct iphdr *ip) {
    int offset = sizeof(struct ethhdr);
    return bpf_skb_load_bytes(skb, offset, ip, sizeof(*ip));
}

static inline int tcph_dr(struct __sk_buff *skb, struct iphdr *ip,struct tcphdr *tcp) {
    int offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    return bpf_skb_load_bytes(skb, offset, tcp, sizeof(*tcp));
}

static inline void set_tcp_source_port(struct __sk_buff *skb, __u16 new_port_host) {

    __u16 old_port = bpf_htons(load_half(skb, TCP_SPORT_OFF)); // 函数用于加载半字节（16位）的数据，这里表示加载目标端口的原始值
    __u16 new_port = bpf_htons(new_port_host);
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
	bpf_skb_store_bytes(skb, TCP_SPORT_OFF, &new_port, sizeof(new_port), 0);
}

static inline void set_tcp_dest_port(struct __sk_buff *skb, __u16 new_port_host) {

    __u16 old_port = bpf_htons(load_half(skb, TCP_DPORT_OFF)); // 函数用于加载半字节（16位）的数据，这里表示加载目标端口的原始值
    __u16 new_port = bpf_htons(new_port_host);
    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port));
	bpf_skb_store_bytes(skb, TCP_DPORT_OFF, &new_port, sizeof(new_port), 0);

}

SEC("classifier")
int tcp_package_example(struct __sk_buff *skb) {

    // 加载 ip 层数据
    struct iphdr ip;
    iph_dr(skb, &ip);

    // 加载tcp数据
    struct tcphdr tcp;
    tcph_dr(skb, &ip, &tcp);

    if (ip.protocol == IPPROTO_TCP) {
            __u16 source_port = bpf_htons(tcp.source);
            __u16 watch_port = bpf_htons(tcp.dest); // 源目标端口 主机字节序需要转换为网络字节序
            __u32 watch_ip = bpf_htonl(0xAC110002);  // 172.17.0.2的16进制 主机字节序需要转换为网络字节序
            if(watch_port == 8080 && ip.daddr == watch_ip) {
                set_tcp_dest_port(skb, 80);
                tcph_dr(skb, &ip, &tcp);
            }

            if(source_port == 80 && ip.saddr == watch_ip) {
                 set_tcp_source_port(skb, 8080);
                 tcph_dr(skb, &ip, &tcp);
            }
        }

    struct tc_data *data = NULL;
    data = bpf_ringbuf_reserve(&traffic_controller_map, sizeof(*data), 0);
    if (data) {
        data -> source_ip = bpf_ntohl(ip.saddr);
        data -> dest_ip = bpf_ntohl(ip.daddr);
        data -> source_port = bpf_ntohs(tcp.source);
        data -> dest_port = bpf_ntohs(tcp.dest);
        bpf_ringbuf_submit(data, 0);
    }
    return 0;
}

