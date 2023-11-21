//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>
#include <xdp_helper.h>
#define ARP_PROTO 2054

SEC("xdp")
int first_arp_example(struct xdp_md *ctx) {
//    void *data = (void*)(long)ctx -> data;
//    void *data_end = (void*)(long)ctx -> data_end;
//
//    struct ethhdr *eth = data;
//    if ((void*)data + sizeof(*eth) > data_end) {
//        return XDP_DROP;
//    }
    struct ethhdr *eth;
    if (get_eth_data(ctx, &eth) < 0) {
        return XDP_PASS;
    }

    if(!is_arp(eth)) {
        return XDP_PASS;
    }

    /*
        h_proto
        h_proto字段的取值是一个16位的整数，表示以太网帧中的协议类型。以下是一些常见的h_proto取值

        0x0800 表示以太网帧中的协议类型为IPv4 2048
        0x08DD 表示以太网帧中的协议类型为IPv6
        0x0806 表示以太网帧中的协议类型为ARP ======> bpf_htons(eth.h_proto) == 2054
    */

    /*
           struct arphdr {
            	__be16 ar_hrd;  表示硬件地址类型(Hardware Type)例如以太网(Ethernet)地址、无线局域网（Wireless LAN）地址等。字段的数据类型为__be16
            	__be16 ar_pro;
            	unsigned char ar_hln; 表示硬件地址长度
            	unsigned char ar_pln; 表示协议地址长度
            	__be16 ar_op;
            };
           ar_op 操作类型。请求(Request)或响应(Reply)
           1: ARP请求(ARP Request)
           2: ARP响应(ARP Reply)
           3: RARP请求(RARP Request)
           4: RARP响应(RARP Reply)
           5: InARP请求(InARP Request)
           6: INARP响应(InARP Reply)
        */
    if (bpf_htons(eth -> h_proto) == ARP_PROTO) {
        // 获取arp数据包
//        struct arphdr *arp = (struct arphdr*)((char *)eth + sizeof(struct ethhdr));
//        if ((void*)arp + sizeof(*arp) > data_end) {
//                return XDP_DROP;
//            }
//            bpf_printk("op:%d", bpf_htons(arp -> ar_op));
        struct arphdr *arp;
        if(get_arp_data(ctx, eth, &arp)<0) {
            return XDP_PASS;
        }
       if (bpf_htons(arp -> ar_op) != 1 ) {
             return XDP_PASS;
       }
    }

    return XDP_PASS;

}