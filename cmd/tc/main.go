package main

import (
	"fmt"
	"github.com/daicheng123/ebpf-learn/cebpf/tc/reseal_package"
	"log"
	//"github.com/daicheng123/ebpf-learn/cebpf/tc/preload_with_golang"
)

func main() {
	fmt.Println("开始启动eBPF")
	//tc.Mak
	//preload_with_golang.MakeTrafficController("docker0")
	//log.Fatalln(tcp_package_prase.MakeTrafficController("docker0"))
	log.Fatalln(reseal_package.MakeTrafficController())
}
