package main

import (
	"fmt"
	"github.com/daicheng123/ebpf-learn/cebpf/uprobe/bash_monitor"

	//"github.com/daicheng123/ebpf-learn/cebpf/tc/ip_package_prase"
	"log"
	//"github.com/daicheng123/ebpf-learn/cebpf/tc/preload_with_golang"
)

func main() {
	fmt.Println("开始启动eBPF")
	//tc.Mak
	//preload_with_golang.MakeTrafficController("docker0")
	log.Fatalln(bash_monitor.LoadBashUserProbeProcess())
}
