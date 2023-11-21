package main

import (
	"github.com/daicheng123/ebpf-learn/cebpf/fentry/tcpconnlat"
	"log"
)

func main() {
	log.Println(tcpconnlat.LoadTCPConnectStates())
}
