package reseal_package

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
func MakeTrafficController() (err error) {
	objects := &dockertcObjects{}
	if err := loadDockertcObjects(objects, nil); err != nil {
		return err
	}
	veths := nets.GetVethList()
	for i := 0; i < len(veths); i++ {
		defers, err := watchInterface(veths[i].Name, objects.TcpPackageExample.FD(), "ip_package_example")
		defer func() {
			for _, deferFunction := range defers {
				deferFunction()
			}
		}()
		if err != nil {
			return err
		}
	}

	go func() {
		rd, err := ringbuf.NewReader(objects.TrafficControllerMap)
		if err != nil {
			//return errors.New(fmt.Sprintf("creating event reader: %s", err))
			fmt.Println("creating event reader: ", err)
			return
		}
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

				ipAddr1 := nets.ResolveIP(data.SourceIP, true)
				ipAddr2 := nets.ResolveIP(data.DestIP, true)

				fmt.Printf("来源地址:%s:%d---->目标地址:%s:%d\n",
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

func watchInterface(ifaceName string, fd int, name string) (defers []func(), err error) {
	defers = make([]func(), 0)
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return defers, err
	}

	filterattrs := netlink.FilterAttrs{
		LinkIndex: iface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS | netlink.HANDLE_MIN_EGRESS, // netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: iface.Attrs().Index,
		// 0xffff 表示 “根”或“无父”句柄的队列规则
		Handle: netlink.MakeHandle(0xffff, 0),
		Parent: netlink.HANDLE_CLSACT, //eBPF专用 clsact
	}
	//创建 ebpf专用的队列规则
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	//好比执行了 tc qdisc add dev docker0  clsact
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return defers, errors.New(fmt.Sprintf("qdisc add err: %s", err.Error()))

	}
	defers = append(defers, func() {
		if err := netlink.QdiscDel(qdisc); err != nil {
			log.Fatalf("QdiscDel err: ", err.Error())
		}
	})
	// cilium/ebpf 转换过后的 对象

	//  创建出 eBPF分类器
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           fd,
		Name:         name,
		DirectAction: true,
	}

	// 好比执行了 tc filter add dev docker0 ingress bpf direct-action obj dockertcxdp_bpfel_x86.o
	if err := netlink.FilterAdd(filter); err != nil {
		return defers, errors.New(fmt.Sprintf("FilterAdd err: %s", err.Error()))
	}
	defers = append(defers, func() {
		err = netlink.FilterDel(filter)
		if err != nil {
			fmt.Println("FilterDel err : ", err.Error())
		}
	})

	return defers, nil
}

type TcData struct {
	SourceIP   uint32
	DestIP     uint32
	SourcePort uint16
	DestPort   uint16
}
