package main

import (
	"fmt"
	"github.com/daicheng123/ebpf-learn/cebpf/xdp/black_ip"
)

func main() {
	fmt.Println("开始启动eBPF")
	black_ip.LoadXDP()
}
