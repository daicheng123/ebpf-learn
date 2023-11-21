package process_exec

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS exec exec.bpf.c -- -I $BPF_HEADERS
