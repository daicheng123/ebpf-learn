//go:build ignore
#include <common.h>
#include <bpf_endian.h>
#include <linux/tcp.h>
struct ip_data {
    __u32 source_ip; //来源IP
    __u32 dest_ip;
    __u32 package_size; //包大小
    __u32 ingress_interface_index;
    __be16 source_port; // 来源端口 __be16 无符号整型16位
    __be16 dest_port; // 目的端口
       };

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,1<<20);
 } ip_map SEC(".maps");

struct bpf_map_def SEC("maps") allow_ips_map = {
     .type = BPF_MAP_TYPE_HASH,
     .key_size = sizeof(__u32),
     .value_size = sizeof(__u8),
     .max_entries = 1024,
 };

SEC("xdp")
int my_pass(struct xdp_md* ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    int package_size = data_end - data;

    struct ethhdr *eth = data;  // 链路层
    if ((void*)eth + sizeof(*eth) > data_end) {  //如果包不完整、或者被篡改， 我们直接DROP
        bpf_printk("Invalid ethernet header\n");
        return XDP_DROP;
    }

    struct iphdr *ip = data + sizeof(*eth); // 得到 ip层
    if ((void*)ip + sizeof(*ip) > data_end) {
        bpf_printk("Invalid IP header\n");
        return XDP_DROP;
    }

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void*)tcp + sizeof(*tcp) > data_end) {
        bpf_printk("Invalid tcp header\n");
        return XDP_DROP;
    }

    if (ip -> protocol != 6) { // 如果不是tcp协议就不处理了
            return XDP_PASS;
    }
     struct ip_data *ipdata = NULL;
     ipdata = bpf_ringbuf_reserve(&ip_map, sizeof(*ipdata), 0);
     if(!ipdata){
        return 0;
    }

    ipdata -> source_ip = bpf_ntohl(ip -> saddr); //bpf_ntohl 网络字节序转换成主机字节序 32位情况下(涉及到大小端)
    ipdata -> dest_ip = bpf_ntohl(ip -> daddr);
    ipdata -> package_size = package_size;
    ipdata -> ingress_interface_index = ctx -> ingress_ifindex;
    ipdata -> source_port = bpf_ntohs(tcp -> source);  //bpf_ntohs 网络字节序转换成主机字节序 16位情况下(涉及到大小端)
    ipdata -> dest_port = bpf_ntohs(tcp -> dest);

    bpf_ringbuf_submit(ipdata, 0);

    __u32 source_ip = bpf_ntohl(ip -> saddr);
    __u8 *allow = bpf_map_lookup_elem(&allow_ips_map, &source_ip); // 查看元素是否存在于map中
    if (allow && *allow ==1) {
        return XDP_PASS;
    }
    return XDP_DROP;
}
char __license[] SEC("license") = "GPL";
