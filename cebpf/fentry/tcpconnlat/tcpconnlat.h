#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

// #include <inttypes.h>
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 256

struct event {
    __u32 saddr;
    __u32 daddr;
    __u16 lport;
    __u16 dport;
    __u64 delta_us;
    __u64 ts_us;
    __u32 tgid;
    char comm[TASK_COMM_LEN];
    int af;

//    union {
//        __u32 saddr_v4;
//        __u8  saddr_v6[16];
//    };
//
//    union {
//        __u32 daddr_v4;
//        __u8  daddr_v6[16];
//    };
//    char comm[TASK_COMM_LEN];
//    __u64 delta_us;
//    __u64 ts_us;
//    __u32 tgid;
//    int af;
//    __u16 lport;
//    __u16 dport;
};

#endif /* __TCPCONNLAT_H_ */