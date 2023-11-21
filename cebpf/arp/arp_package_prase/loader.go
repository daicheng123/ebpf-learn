package arp_package_prase

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/daicheng123/ebpf-learn/pkg/nets"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func LoadArp() {
	obj := &arpObjects{}

	err := loadArpObjects(obj, nil)
	if err != nil {
		panic(err)
	}
	defer obj.Close()
	go func() {
		set := make(map[string]bool)
		for {
			ifaces := nets.GetVethList()
			for _, iface := range ifaces {
				if _, ok := set[iface.Name]; ok {
					continue
				}
				l, err := link.AttachXDP(link.XDPOptions{
					Program:   obj.FirstArpExample,
					Interface: iface.Index,
				})
				if err != nil {
					log.Println(err)
				} else {
					set[iface.Name] = true
				}
				defer l.Close()
			}
			time.Sleep(time.Millisecond * 50)
		}
	}()
	fmt.Println("开始ARP监听")
	signalChan := make(chan os.Signal, 0)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-signalChan
	fmt.Println("结束ARP监听")
}
