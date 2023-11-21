package all_interface_monitor

//_go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 dockerxdp dockerxdp.bpf.c -- -I $BPF_HEADERS

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 dockertc dockertc.bpf.c -- -I $BPF_HEADERS
