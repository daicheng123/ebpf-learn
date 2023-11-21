package arp_user_mac

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/daicheng123/ebpf-learn/pkg/nets"
	"log"
	"time"
	"unsafe"
)

// TODO 本课程来自 程序员在囧途(www.jtthink.com) 咨询群：98514334
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
					Program:   obj.GetUserMacExample,
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

	// TODO 本课程来自 程序员在囧途(www.jtthink.com) 咨询群：98514334
	rd, err := ringbuf.NewReader(obj.ArpMap)
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	fmt.Println("开始ARP监听")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if len(record.RawSample) > 0 {
			data := (*ArpData)(unsafe.Pointer(&record.RawSample[0]))
			fmt.Println("ARP请求Mac是：,IP是%s",
				hex.EncodeToString(data.SMAC[:]),
				nets.ResolveIP(data.SourceIP, true),
			)
		}
	}
}

const MAC_LEN = 6

type ArpData struct {
	SMAC     [MAC_LEN]byte
	SourceIP uint32
}
