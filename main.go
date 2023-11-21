package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

func main() {
	fmt.Println(time.Now())
	ip, ipnet, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		panic(err)
	}
	//_ = ip
	// 计算子网掩码
	ds, _ := hex.DecodeString(ipnet.Mask.String())
	fmt.Println(net.IP(ds).To4().String())

	// 计算ip段可用ip地址
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		fmt.Println(ip)
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
