package main

import (
	"fmt"
	"github.com/daicheng123/ebpf-learn/cebpf/sys/process_exec"
	"log"
)

func main() {
	fmt.Println("开始启动eBPF")
	log.Fatalln(process_exec.LoadSystemExecProcess())
}
