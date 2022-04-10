package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var os string
var destIP *string

var (
	infoSet = make(map[string]info)
	ch      = make(chan bool)
)

type info struct {
	Mac net.HardwareAddr
}

type send struct {
	ips   []net.IP
	ipNet *net.IPNet
	iface net.Interface
}

func init() {
	if runtime.GOOS == "linux" {
		os = "linux"
	} else if runtime.GOOS == "windows" {
		os = "windows"
	} else {
		os = "unknown"
	}

	destIP = flag.String("ip", "", "dest IP")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	if *destIP == "" {
		fmt.Println("error: destIP is null")
		return
	}
	if os == "unknown" {
		fmt.Println("error: os is unknown")
		return
	}

	var ifaceSet []net.Interface
	var err error

	sendInfos := []*send{}

	if os == "linux" {
		ifaceSet, err = net.Interfaces()
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
		for _, it := range ifaceSet {
			if it.Flags&net.FlagUp == 0 {
				continue
			} else if it.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := it.Addrs()
			for _, addr := range addrs {
				if ip, ok := addr.(*net.IPNet); ok {
					if ip.IP.To4() != nil {
						sendInfo := &send{}
						sendInfo.ips = getIPSet(ip)
						sendInfo.ipNet = ip
						sendInfo.iface = it
						sendInfos = append(sendInfos, sendInfo)
						break
					}
				}
			}
		}
	}
	if os == "windows" {
		// windows得到所有的(网络)设备
		devices, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
		ifaceSet, err := net.Interfaces()
		if err != nil {
			fmt.Println("error: ", err)
			return
		}
		var localip string
		for _, it := range ifaceSet {
			if it.Flags&net.FlagUp == 0 {
				continue
			} else if it.Flags&net.FlagLoopback != 0 {
				continue
			}

			addrs, _ := it.Addrs()
			for _, address := range addrs {
				if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						localip = ipnet.IP.String()
						break
					}
				}
			}
			if localip == "" {
				continue
			}
			interfaceName := ""
		LOOP:
			for _, d := range devices {
				for _, a := range d.Addresses {
					if a.IP.To4() != nil && a.IP.String() == localip {
						interfaceName = d.Name
						break LOOP
					}
				}
			}
			if interfaceName == "" {
				return
			}

			for _, addr := range addrs {
				if ip, ok := addr.(*net.IPNet); ok {
					if ip.IP.To4() != nil {
						sendInfo := &send{}
						sendInfo.ips = getIPSet(ip)
						sendInfo.ipNet = ip
						sendInfo.iface = it
						sendInfo.iface.Name = interfaceName
						sendInfos = append(sendInfos, sendInfo)
						break
					}
				}
			}
		}

	}
OUTLOOP:
	for _, sendInfo := range sendInfos {
		if len(infoSet) > 0 {
			return
		}
		handle, err := pcap.OpenLive(sendInfo.iface.Name, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal("pcap open fail, err:", err)
		}
		defer handle.Close()

		ctx, cancel := context.WithCancel(context.Background())

		//开启一个的goroutine, 监听ARP响应包
		go listenArpPacket(handle, ctx, sendInfo.iface)

		interval := 1
		processNum := 300 //一个goroutine负责发送300个ARP包
		wg := &sync.WaitGroup{}

		if len(sendInfo.ips) <= processNum {
			processNum = len(sendInfo.ips)
		} else {
			interval = int(math.Ceil(float64(len(sendInfo.ips)) / float64(processNum)))
		}

		for i := 0; i < len(sendInfo.ips); i += interval {
			length := i + interval
			if length >= len(sendInfo.ips) {
				length = len(sendInfo.ips)
			}
			wg.Add(1)

			//发送ARP包
			go func(ips []net.IP) {
				defer wg.Done()
				for _, ip := range ips {
					sendInfo.sendArpPacket(handle, ip)
				}
			}(sendInfo.ips[i:length])
		}

		wg.Wait()

		t := time.NewTicker(200 * time.Millisecond)
		for {
			select {
			case <-t.C:
				cancel()
				continue OUTLOOP
			case timeStamp := <-ch:
				if timeStamp {
					//停止旧的定时器
					t.Stop()
				} else {
					//开启新的定时器，确保收到一个ARP包往后延续3s。如果3s时间内没有收到ARP响应包，程序退出
					t = time.NewTicker(200 * time.Millisecond)
				}
			}
		}
	}
}

func getIPSet(ipNet *net.IPNet) (ipSet []net.IP) {
	var ipStringSet []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); nextIP(ip) {
		if ip[len(ip)-1]&0xff == 0 {
			continue
		}
		ipStringSet = append(ipStringSet, ip.String())
	}
	for _, ipString := range ipStringSet {
		ip := net.ParseIP(ipString)
		if ip != nil {
			ipSet = append(ipSet, ip)
		}
	}
	return
}

func nextIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func (sendInfo *send) sendArpPacket(handle *pcap.Handle, ip net.IP) {
	localHaddr := sendInfo.iface.HardwareAddr
	srcIP := sendInfo.ipNet.IP.To4()
	dstIP := ip.To4()
	//fmt.Println(srcIP.String())
	//fmt.Println(dstIP.String())

	if srcIP == nil || dstIP == nil {
		log.Fatal("source address or destination address is empty!")
	}

	eth := &layers.Ethernet{
		SrcMAC:       localHaddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1),
		SourceHwAddress:   localHaddr,
		SourceProtAddress: srcIP,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIP,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, eth, a)
	outgoingPacket := buffer.Bytes()

	err := handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("Failed to send package")
	}
}

func listenArpPacket(handle *pcap.Handle, ctx context.Context, iface net.Interface) {
	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			arpLayer := p.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
					// This is a packet I sent.
					continue
				}
				if arp.Operation == layers.ARPReply {
					mac := net.HardwareAddr(arp.SourceHwAddress)
					if net.IP(arp.SourceProtAddress).String() == *destIP {
						fmt.Println(mac.String())
						if _, ok := infoSet[net.IP(arp.SourceProtAddress).String()]; !ok {
							ch <- true
							infoSet[net.IP(arp.SourceProtAddress).String()] = info{mac}
							ch <- false
						}
					} else {
						continue
					}
				}
			}
		}
	}
}
