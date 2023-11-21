package process_kernel_data

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS sys  kernel_data.bpf.c -- -I $BPF_HEADERS
