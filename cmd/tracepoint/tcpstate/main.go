package main

import (
	"github.com/daicheng123/ebpf-learn/cebpf/tracepoint/tcpstate"
	"log"
)

func main() {
	log.Println(tcpstate.LoadTCPStatesProcess())
}
