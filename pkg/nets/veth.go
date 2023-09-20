package nets

import (
	"github.com/vishvananda/netlink"
	"net"
)

func GetVethList() []*net.Interface {
	links, err := netlink.LinkList()
	if err != nil {
		panic(err)
	}
	ret := make([]*net.Interface, 0)
	// 遍历所有网络接口，找到属于 namespace 的 veth 设备
	for _, link := range links {
		if link.Type() == "veth" {
			if iface, err := net.InterfaceByName(link.Attrs().Name); err == nil {
				ret = append(ret, iface)
			}
		}
	}
	return ret
}
