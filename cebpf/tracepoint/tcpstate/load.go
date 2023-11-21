package tcpstate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/daicheng123/ebpf-learn/pkg/nets"
	"log"
	"math/big"
	"net"
	"os"
)

func LoadTCPStatesProcess() (err error) {
	object := new(tcpObjects)

	if err := loadTcpObjects(object, nil); err != nil {
		return err
	}
	defer object.Close()

	tp, err := link.Tracepoint(
		"sock", "inet_sock_set_state", object.InetSockSetState, nil)
	if err != nil {
		return err
	}
	defer tp.Close()

	rd, err := perf.NewReader(object.Events, os.Getpagesize())
	if err != nil {
		return err
	}

	defer rd.Close()

	log.Println("开始监听execve")
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("received signal, exit...")
				return err
			}
			log.Printf("reading from reader err:%+v", err)
			continue
		}
		//if len(record.RawSample) > 0 {
		//	event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
		//	log.Printf("%-16s %-15s %-6d -> %-15s %-6d\n",
		//		event.Task,
		//		event.Saddr,
		//		event.Sport,
		//		event.Daddr,
		//		event.Dport,
		//	)
		//}
		//Parse the ringbuf event entry into a bpfEvent structure.
		var event = new(Event)
		if len(record.RawSample) > 0 {
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, event); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}
			log.Printf("%-16s %-15s %-6d -> %-15s %-6d",
				bytes.TrimRight(event.Task[:], "0x00"),
				nets.ResolveIP2(event.Saddr.Uint64(), true).To4().String(),
				event.Sport,
				nets.ResolveIP2(event.Daddr.Uint64(), true).To4().String(),
				event.Dport,
			)
		}
	}
}

type Event struct {
	PID   uint32
	Task  [256]byte
	Saddr big.Int
	Daddr big.Int
	Sport uint16
	Dport uint16
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

/*
struct event {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u64 skaddr;
	__u64 ts_us;
	__u64 delta_us;
	__u32 pid;
	int oldstate;
	int newstate;
	__u16 family;
	__u16 sport;
	__u16 dport;
	char task[TASK_COMM_LEN];
};
*/
