package http_payload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"unsafe"
)

type IpData struct {
	SourceIP uint32
	DestIP   uint32
	//PackageSize           uint32
	//IngressInterfaceIndex uint32
	SourcePort uint16
	DestPort   uint16
	PayLoad    [1024]byte
}

func initAllowMap(m *ebpf.Map) {
	ipAddr1 := binary.BigEndian.Uint32(net.ParseIP("172.17.0.2").To4()) //小端转大段,为了和bpf程序中的__u32保持一致
	ipAddr2 := binary.BigEndian.Uint32(net.ParseIP("172.17.0.1").To4())
	m.Put(ipAddr1, uint8(1))
	m.Put(ipAddr2, uint8(1))
}

func LoadXDP() {
	xdpObj := xdpObjects{}
	err := loadXdpObjects(&xdpObj, nil)
	if err != nil {
		log.Fatalln("加载出错:", err)
	}

	defer xdpObj.Close()
	initAllowMap(xdpObj.AllowIpsMap) //初始化白名单
	iface, err := net.InterfaceByName("docker0")
	if err != nil {
		log.Fatalln(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpObj.MyPass, // xdp 函数
		Interface: iface.Index,   // 绑定哪一个网卡接口
	})
	if err != nil {
		log.Fatalln(err)
	}
	defer l.Close()

	//创建reader 用来读取  内核Map
	rd, err := ringbuf.NewReader(xdpObj.IpMap)

	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	fmt.Println("开始监听xdp")
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
			data := (*IpData)(unsafe.Pointer(&record.RawSample[0]))
			// 转换为网络字节序
			ipAddr1 := resolveIP(data.SourceIP, true)
			ipAddr2 := resolveIP(data.DestIP, true)
			fmt.Printf("来源IP:%s,目标IP:%s,来源端口:%d,目标端口:%d\n,http报文:%s\n",
				ipAddr1.To4().String(),
				ipAddr2.To4().String(),
				data.SourcePort,
				data.DestPort,
				unix.ByteSliceToString(data.PayLoad[:]),
			)
		}
	}
}

func resolveIP(input_ip uint32, isbig bool) net.IP {
	ipNetworkOrder := make([]byte, 4)
	if isbig {
		binary.BigEndian.PutUint32(ipNetworkOrder, input_ip)
	} else {
		binary.LittleEndian.PutUint32(ipNetworkOrder, input_ip)
	}

	return ipNetworkOrder
}
