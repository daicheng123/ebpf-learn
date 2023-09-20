//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct ip_data {
     __u32 sip; //来源IP
     __u32 dip; //目标IP
     __be16  sport; //来源端口
     __be16  dport; //目的端口
};
struct {
     __uint(type, BPF_MAP_TYPE_RINGBUF);
     __uint(max_entries,1<<20);
 } ip_map SEC(".maps");

SEC("xdp")
int mydocker(struct xdp_md* ctx) {
     void *data = (void*)(long)ctx->data;
      void *data_end = (void*)(long)ctx->data_end;

      struct ethhdr *eth = data;  // 链路层
      if ((void*)eth + sizeof(*eth) > data_end) {
           return XDP_DROP;
     }
     struct iphdr *ip = data + sizeof(*eth); // 得到了 ip层
     if ((void*)ip + sizeof(*ip) > data_end) {
         return XDP_DROP;
     }
     if (ip->protocol != 6) { //如果不是TCP 就不处理了。累死了
         return XDP_PASS;
     }
     struct tcphdr *tcp = (void*)ip + sizeof(*ip);  // 得到tcp层
       if ((void*)tcp + sizeof(*tcp) > data_end) {
             return XDP_DROP;
       }

     // 开始构建业务数据和ringbuf初始化
      struct ip_data *ipdata = NULL;
      ipdata = bpf_ringbuf_reserve(&ip_map, sizeof(*ipdata), 0);
      if(!ipdata){
        return XDP_PASS;
      }

      ipdata->sip=bpf_ntohl(ip->saddr);// 网络字节序 转换成 主机字节序  32位
      ipdata->dip=bpf_ntohl(ip->daddr);
      ipdata->sport=bpf_ntohs(tcp->source); //16位
      ipdata->dport=bpf_ntohs(tcp->dest);

      bpf_ringbuf_submit(ipdata, 0);
      return XDP_PASS;
}