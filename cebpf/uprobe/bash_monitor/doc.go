package bash_monitor

//go:generate bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bash_monitor bash.bpf.c -- -I $BPF_HEADERS
