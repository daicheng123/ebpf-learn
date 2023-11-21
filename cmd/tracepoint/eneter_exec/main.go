package main

import (
	"github.com/daicheng123/ebpf-learn/cebpf/tracepoint/exec"
	"log"
)

func main() {
	log.Fatalln(exec.LoadSystemExecProcess())
}
