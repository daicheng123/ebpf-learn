package tcp_package_prase

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/daicheng123/ebpf-learn/pkg/nets"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

const (
	XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << 0

	XDP_FLAGS_AUTO_MODE = 0 // custom
	XDP_FLAGS_SKB_MODE  = 1 << 1
	XDP_FLAGS_DRV_MODE  = 1 << 2
	XDP_FLAGS_HW_MODE   = 1 << 3
	XDP_FLAGS_REPLACE   = 1 << 4

	XDP_FLAGS_MODES = XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE
	XDP_FLAGS_MASK  = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE
)

/*
MakeTrafficController 加载tc ebpf 程序
大致过程：
1、选择网络设备 --->
2、创建队列(qdisc) --->
3、创建分类class(用于设定带宽级别)--->
4、创建filter，把流量进行分类，并将包分发到前面定义的class中
*/
func MakeTrafficController(ifaceName string) (err error) {
	// 1、选择网络设备
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		panic(err)
	}

	filterattrs := netlink.FilterAttrs{
		LinkIndex: iface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS, // 指定在ingress有效
		Handle:    netlink.MakeHandle(0, 1),   // 创建一个交互句柄
		Protocol:  unix.ETH_P_ALL,             // 所有协议都支持
		Priority:  1,
	}
	// 2.2、为队列添加属性
	attrs := netlink.QdiscAttrs{
		LinkIndex: iface.Attrs().Index,
		// 0xffff 表示 “根”或“无父”句柄的队列规则
		Handle: netlink.MakeHandle(0xffff, 0),
		Parent: netlink.HANDLE_CLSACT, //父队列选择为eBPF专用 clsact队列
	}
	//2.1、创建 ebpf专用的队列规则
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	//好比执行了 tc qdisc add dev docker0  clsact
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("QdiscAdd err: ", err)
	}
	defer func() {
		if err := netlink.QdiscDel(qdisc); err != nil {
			log.Fatalf("QdiscDel err: ", err.Error())
		}
	}()
	// cilium/ebpf 转换过后的 对象
	objs := &dockertcObjects{}
	err = loadDockertcObjects(objs, nil)
	if err != nil {
		return fmt.Errorf("loadDockertcxdpObjects err: ", err)
	}

	//  创建出 eBPF分类器
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.TcpPackageExample.FD(),
		Name:         "tcp_package_example",
		DirectAction: true,
	}

	// 好比执行了 tc filter add dev docker0 ingress bpf direct-action obj dockertcxdp_bpfel_x86.o
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("FilterAdd err: ", err)
	}

	defer func() {
		err = netlink.FilterDel(filter)
		if err != nil {
			log.Fatalf("FilterDel err : ", err.Error())
		}
	}()

	go func() {
		rd, err := ringbuf.NewReader(objs.TrafficControllerMap)
		if err != nil {
			return
		}

		defer rd.Close()
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
				data := (*TcData)(unsafe.Pointer(&record.RawSample[0]))
				// 转换为网络字节序
				ipAddr1 := nets.ResolveIP(data.SourceIP, true)
				ipAddr2 := nets.ResolveIP(data.DestIP, true)
				fmt.Printf("来源IP:%s,来源端口:%d,目标IP:%s,目标端口:%d\n",
					ipAddr1.To4().String(),
					data.SourcePort,
					ipAddr2.To4().String(),
					data.DestPort,
				)
			}
		}
	}()

	fmt.Println("开始TC监听")
	signalChan := make(chan os.Signal, 0)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-signalChan
	fmt.Println("结束TC监听")
	return nil
}

type TcData struct {
	SourceIP   uint32
	DestIP     uint32
	SourcePort uint16
	DestPort   uint16
}
