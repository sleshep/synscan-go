package main

import (
	"fmt"
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SYNSender interface {
	Send(addr string, port int) (err error)
}

type SYNSenderImpl struct {
	rawPacketConn net.PacketConn

	srcPort int
	srcIP   string
	gwMac   net.HardwareAddr
	srcMac  net.HardwareAddr

	eth layers.Ethernet
	ip4 layers.IPv4
	tcp layers.TCP
}

var _ SYNSender = (*SYNSenderImpl)(nil)

func NewSYNSender(srcIP string, srcPort int, gwMac net.HardwareAddr, srcMac net.HardwareAddr) (sender SYNSender, err error) {
	s := &SYNSenderImpl{
		srcIP:   srcIP,
		srcPort: srcPort,
		gwMac:   gwMac,
		srcMac:  srcMac,
	}

	rawPacketConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return
	}
	s.rawPacketConn = rawPacketConn
	sender = s
	s.eth = layers.Ethernet{
		SrcMAC:       s.srcMac,
		DstMAC:       s.gwMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	src := net.ParseIP(s.srcIP)
	s.ip4 = layers.IPv4{
		SrcIP:    src.To4(),
		DstIP:    nil, // on demand
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	s.tcp = layers.TCP{
		SrcPort: layers.TCPPort(sourcePort),
		DstPort: 0, // on demand
		SYN:     true,
	}
	return
}

// Send implements SYNSender
func (s *SYNSenderImpl) Send(addr string, port int) (err error) {
	s.tcp.DstPort = layers.TCPPort(port)
	s.ip4.DstIP = net.ParseIP(addr)
	err = s.tcp.SetNetworkLayerForChecksum(&s.ip4)
	if err != nil {
		return
	}
	err = s.send(s.eth, s.ip4, s.tcp)
	if err != nil {
		fmt.Printf("Error sending to %v: %v\n", addr, err)
	}
	return
}

func (s *SYNSenderImpl) send(eth layers.Ethernet, ip layers.IPv4, tcp layers.TCP) (err error) {
	// create packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts,
		// &eth,
		&ip,
		&tcp)
	if err != nil {
		return err
	}
	// send packet
	// return handle.WritePacketData(buf.Bytes())
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	bAddr, err := ip.DstIP.MarshalText()
	if err != nil {
		return err
	}
	err = syscall.Sendto(fd, buf.Bytes(), 0, &syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{bAddr[0], bAddr[1], bAddr[2], bAddr[3]},
	})
	return
}
