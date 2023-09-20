#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int my_pass(struct xdp_md* ctx) {
    void *data_end = (void*)(long) ctx->data_end;
    void *data = (void*)(long) ctx -> data;
    int pkg_size = data_end - data;

    // 链路层 ethhdr定义在if_ether.h头文件中
    struct ethhdr *eth = data;

	if ((viod*)eth + sizeof(*eth) > data_end) { // 如果包被篡改或者包不完整，直接drop
        return XDP_DROP
	}
	// 进入到ip层
	struct iphdr *ip = data + sizeof(*eth) // 在数据链路层的数据包基础上根据得到的数据链路包大小进行位移得到ip层数据包
	if ((viod*)ip + sizeof(*ip) > data_end) { // 如果包被篡改或者包不完整，直接drop
	    return XDP_DROP
	}

    unsigned int src_ip = ip -> saddr;
    unsigned char bytes[4];

    bytes[0] = (src_ip >> 0) & 0xFF;
    bytes[1] = (src_ip >> 8) & 0xFF;
    bytes[2] = (src_ip >> 16) & 0xFF;
    bytes[3] = (src_ip >> 24) & 0xFF;

    bpf_printk("ip is %d.%d.%d", bytes[0], bytes[1],bytes[2]); // bpf_printk最多只能传递3个参数
    bpf_printk("%d",bytes[3]);
    return XDP_PASS;
}
char __license[] SEC("license") = "GPL"
