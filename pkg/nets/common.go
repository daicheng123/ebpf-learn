package nets

import (
	"encoding/binary"
	"net"
)

func ResolveIP(input_ip uint32, isbig bool) net.IP {
	ipNetworkOrder := make([]byte, 4)
	if isbig {
		binary.BigEndian.PutUint32(ipNetworkOrder, input_ip)
	} else {
		binary.LittleEndian.PutUint32(ipNetworkOrder, input_ip)
	}
	return ipNetworkOrder
}

func ResolveIP2(input_ip uint64, isbig bool) net.IP {
	ipNetworkOrder := make([]byte, 4)
	if isbig {
		binary.BigEndian.PutUint64(ipNetworkOrder, input_ip)
	} else {
		binary.LittleEndian.PutUint64(ipNetworkOrder, input_ip)
	}
	return ipNetworkOrder
}
