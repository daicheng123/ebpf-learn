package exec

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 exec exec.bpf.c -- -I $BPF_HEADERS
