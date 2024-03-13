package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"log"
	"math/rand"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
)

const DEFAULT_MAX_HOPS = 32

var (
	DnsPort int
	Dest    string
	Qname   string
	Qtype   string
	Timeout int
	Iface   string
)

func init() {
	flag.StringVar(&Dest, "dest", "", "dest addr")
	flag.StringVar(&Qname, "qname", "", "qname")
	flag.StringVar(&Qtype, "qtype", "A", "qtype")
	flag.IntVar(&DnsPort, "dnsport", 53, "dns port")
	flag.IntVar(&Timeout, "timeout", 5, "time out")
	flag.StringVar(&Iface, "i", "any", "iface")
}

type TracerouteHop struct {
	Address     net.IP
	Host        string
	ipId        uint16
	ElapsedTime time.Duration
}
type DnsPacketInfo struct {
	id            uint16
	payLoadString string
	recvTime      time.Time
}
type IcmpInfo struct {
	srcIp      net.IP
	originalID uint16
	recvTime   time.Time
}
type QueryInfo struct {
	ttl      int
	ipId     uint16
	dnsId    uint16
	sendTime time.Time
}
type DnsResult struct {
	dnsPacketInfo DnsPacketInfo
	ipId          uint16
	ttl           int
}

func printHops(ttl int, hops []TracerouteHop) {
	for i, hop := range hops {
		hostName, err := net.LookupAddr(hop.Address.String())
		if err == nil {
			hop.Host = hostName[0]
		} else {
			hop.Host = hop.Address.String()
		}
		if i == 0 {
			fmt.Printf("%-3d %v (%v)  %v\n", ttl, hop.Host, hop.Address.String(), hop.ElapsedTime)
		} else {
			fmt.Printf("    %v (%v)  %v\n", hop.Host, hop.Address.String(), hop.ElapsedTime)
		}
	}
}
func printDnsResult(result DnsResult) {
	fmt.Printf("Received DNS response on ttl %d\n", result.ttl)
	fmt.Printf(result.dnsPacketInfo.payLoadString)
}
func ipv4ToBytes(ip net.IP) [4]byte {
	var ipBytes [4]byte
	copy(ipBytes[:], ip.To4()[:4])
	return ipBytes
}
func makeDNSQuery(qname string, qtype string, dnsId uint16) []byte {
	dnsMsg := new(dns.Msg)
	dnsType, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		log.Fatal("dns type error")
	}
	dnsMsg.SetQuestion(dns.Fqdn(qname), dnsType)
	dnsMsg.Id = dnsId
	dnsMsgBytes, _ := dnsMsg.Pack()
	return dnsMsgBytes
}
func parseDnsPayload(dnsBuf []byte) (uint16, bool, string, string) {

	dnsMsg := new(dns.Msg)
	err := dnsMsg.Unpack(dnsBuf)
	if err != nil {
		return 0, false, "", ""
	}
	if len(dnsMsg.Question) > 0 {
		return dnsMsg.Id, dnsMsg.Response, dnsMsg.Question[0].Name, dnsMsg.String()
	} else {
		return dnsMsg.Id, dnsMsg.Response, "", dnsMsg.String()
	}

}
func recvIcmpPacket(iface string, c chan<- IcmpInfo) {
	// 获取指定iface下所有time exceed 报文
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 设置过滤器，只捕获TCP数据包
	err = handle.SetBPFFilter("ip")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("listen icmp on %v\n", iface)
	// 开始捕获数据包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	timeout := time.After(time.Duration(Timeout) * time.Second) //在指定时间后捕获结束
	for {
		var srcIp net.IP
		select {
		case packet := <-packets:
			for _, l := range packet.Layers() {
				switch l.LayerType() {
				case layers.LayerTypeIPv4:
					srcIp = l.(*layers.IPv4).SrcIP
				case layers.LayerTypeICMPv4:
					if l.LayerContents()[0] == 11 { //time execeed
						originalID := binary.BigEndian.Uint16(l.LayerPayload()[4:6])
						c <- IcmpInfo{srcIp, originalID, time.Now()}
						// payload data :Internet Header + the first 64 bits of the original datagram's data.
						// dnsId maybe not in payload data
					}
				}
			}
		case <-timeout:
			close(c)
			return

		}
	}
}
func recvDnsPacket(iface string, c chan<- DnsPacketInfo) {
	// 获取所有iface上收到的dns应答报文
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("udp")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("listen dns on %v\n", iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	timeout := time.After(time.Duration(Timeout) * time.Second)
	for {
		select {
		case packet := <-packets:
			for _, l := range packet.Layers() {
				switch l.LayerType() {
				case layers.LayerTypeDNS:
					id, isResp, qname, payloadStr := parseDnsPayload(l.LayerContents())
					if isResp && strings.TrimSuffix(qname, ".") == strings.TrimSuffix(Qname, ".") {
						c <- DnsPacketInfo{id, payloadStr, time.Now()}
					}
				}
			}
		case <-timeout:
			close(c)
			return

		}
	}
}
func makeQuery(destAddr net.IP) []QueryInfo {
	sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		err = errors.New("Create Socket Error")
		log.Fatal(err)
	}
	defer syscall.Close(sendSocket)
	syscall.SetsockoptInt(sendSocket, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1) //设置 IP_HDRINCL 告诉内核不要添加 IP 头

	info := make([]QueryInfo, 0, DEFAULT_MAX_HOPS)
	for ttl := 1; ttl <= DEFAULT_MAX_HOPS; ttl++ {
		for retry := 1; retry <= 3; retry++ {
			dnsSendPort := rand.Intn(65535-49152) + 49152
			dnsId := uint16(ttl*3 + retry) //不重复
			// Set up the socket to send packets out.
			ipId := uint16(ttl*3 + retry)
			//DNS payload
			dnsQuery := makeDNSQuery(Qname, Qtype, dnsId)
			//Ipv4Header
			ipv4Header := &ipv4.Header{
				Version:  ipv4.Version,
				Len:      ipv4.HeaderLen,
				TotalLen: ipv4.HeaderLen + 8 + len(dnsQuery),
				TOS:      16,
				ID:       int(ipId),
				Dst:      destAddr,
				Protocol: syscall.IPPROTO_UDP,
				TTL:      ttl,
			}
			ipHeader, _ := ipv4Header.Marshal()

			// UDP Header
			udpHeader := make([]byte, 8)
			binary.BigEndian.PutUint16(udpHeader[0:2], uint16(dnsSendPort))     // 源端口
			binary.BigEndian.PutUint16(udpHeader[2:4], uint16(DnsPort))         // 目的端口
			binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(dnsQuery))) // UDP长度

			// 构建完整的IP报文（IP头部＋UDP头部＋UDP负载）
			packet := append(ipHeader, udpHeader...)
			packet = append(packet, dnsQuery...)
			syscall.Sendto(sendSocket, packet, 0, &syscall.SockaddrInet4{Port: DnsPort, Addr: ipv4ToBytes(destAddr)})
			info = append(info, QueryInfo{ttl, ipId, dnsId, time.Now()})
			time.Sleep(time.Millisecond * 10)
		}
	}
	return info

}
func DnsTraceRoute() error {
	rand.Seed(time.Now().UnixNano())
	destAddr := net.ParseIP(Dest).To4()
	if destAddr == nil {
		log.Fatal(errors.New("parse ip error"))
	}

	icmpCh := make(chan IcmpInfo, 1000)
	dnsPackCh := make(chan DnsPacketInfo, 1000)
	go recvDnsPacket(Iface, dnsPackCh)
	go recvIcmpPacket(Iface, icmpCh)

	qInfo := makeQuery(destAddr)

	result := make(map[int][]TracerouteHop)
	dnsResult := make([]DnsResult, 0, DEFAULT_MAX_HOPS)

	fmt.Printf("Sending package done,Parsing now...\n")

	for {
		if icmpCh == nil && dnsPackCh == nil {
			break
		}
		select {
		case icmp, ok := <-icmpCh:
			if ok {
				for _, queryInfo := range qInfo {
					if queryInfo.ipId == icmp.originalID {
						if _, ok := result[queryInfo.ttl]; !ok {
							result[queryInfo.ttl] = []TracerouteHop{}
						}
						result[queryInfo.ttl] = append(result[queryInfo.ttl], TracerouteHop{
							Address:     icmp.srcIp,
							ipId:        queryInfo.ipId,
							ElapsedTime: icmp.recvTime.Sub(queryInfo.sendTime),
						})
						//fmt.Printf("get icmp time exceed package at ttl %d\n", queryInfo.ttl)
					}
				}
			} else {
				icmpCh = nil
			}
		case dns, ok := <-dnsPackCh:
			if ok {
				for _, queryInfo := range qInfo {
					if queryInfo.dnsId == dns.id {
						dnsResult = append(dnsResult, DnsResult{ttl: queryInfo.ttl, dnsPacketInfo: dns, ipId: queryInfo.ipId})
						//fmt.Printf("get dns response package at ttl %d\n", queryInfo.ttl)
					}
				}
			} else {
				dnsPackCh = nil
			}
		}
	}

	sort.Slice(dnsResult, func(i, j int) bool {
		return dnsResult[i].ttl < dnsResult[j].ttl
	})
	fmt.Printf("Result:\n")
	var resultKeys []int
	for k := range result {
		resultKeys = append(resultKeys, k)
	}
	sort.Ints(resultKeys)
	for _, k := range resultKeys {
		printHops(k, result[k])
	}

	fmt.Printf("\nThe following icmp time out messages match the Dns Response:\n")
	for _, _dns := range dnsResult {
		printDnsResult(_dns)
		for ttl, res := range result {
			for _, r := range res {
				if r.ipId == _dns.ipId {
					fmt.Printf("%v:    %v  %v\n", ttl, r.Address.String(), r.ElapsedTime)
				}
			}
		}
	}

	return nil

}
func main() {

	flag.Parse()

	if Qname == "" || Dest == "" {
		log.Fatal("qname or dest addr is nil\n")
		return
	}

	err := DnsTraceRoute()
	if err != nil {
		log.Fatal("Error: ", err)

	}
}

