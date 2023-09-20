#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

SEC("classifier")
int traffic_controller_example(struct __sk_buff *skb) {
    struct ethhdr eth;
    /*
        tc中 skb对象中的属性无法直接调用，需要通过bpf_skb_load_bytes辅助函数来获取
        0 由于ethhdr是第一层数据故offset从0开始
    */
    bpf_skb_load_bytes(skb,0, &eth, sizeof(eth));

    int offset = sizeof(eth);

    struct iphdr iph;
    bpf_skb_load_bytes(skb, offset, &iph, sizeof(iph));
    bpf_printk("protocol=%d\n", iph.protocol);
}