package black_ip

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS xdp xdp.bpf.c -- -I $BPF_HEADERS
