package arp_user_mac

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS arp arp.bpf.c -- -I $BPF_HEADERS
