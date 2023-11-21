package tcpstate

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 tcp tcp.bpf.c -- -I $BPF_HEADERS
