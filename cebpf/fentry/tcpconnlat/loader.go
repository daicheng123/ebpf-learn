package tcpconnlat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"net"
	"unsafe"
)

func LoadTCPConnectStates() error {
	var (
		err     error
		objects = &tcpObjects{}
	)
	err = loadTcpObjects(objects, nil)
	if err != nil {
		return err
	}
	defer objects.Close()

	rd, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		log.Printf("creating event reader: %s", err)
		return err
	}
	defer rd.Close()

	fmt.Println("开始TCP CONNECT监听")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return err
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if len(record.RawSample) > 0 {
			data := (*TCPData)(unsafe.Pointer(&record.RawSample[0]))
			log.Printf("%-15s %-6d -> %-15s %-6d",
				intToIPV4(data.SaddrV4),
				data.LPort,
				intToIPV4(data.DaddrV4),
				data.DPort,
			)
		}
	}

}

const MAC_LEN = 6

type TCPData struct {
	SaddrV4 	uint32
	DaddrV4 	uint32
	LPort  		uint16
	DPort   	uint16
	Comm    	[256]byte
	DeltaUS  	uint64
	TsUS        uint64
	TGid		uint32
}

func intToIPV4(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
