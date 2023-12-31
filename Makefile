CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror

EBPF_ROOT = /root/ebpf/pro/ebpf-learn/cebpf
MY_HEADERS = $(EBPF_ROOT)/headers

all: generate

generate: export BPF_CLANG=$(CLANG)
generate: export BPF_CFLAGS=$(CFLAGS)
generate: export BPF_HEADERS=$(MY_HEADERS)
generate:
	go generate ./...
