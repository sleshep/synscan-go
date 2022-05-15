package main

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

type SYNReceiver interface {
	Receive(ctx context.Context) (resChan chan *net.TCPAddr, err error)
}

type SYNReceiverImpl struct {
	rawPacketConn *ipv4.PacketConn
	srcIP         net.IP
	srcPort       int
	gwMac         net.HardwareAddr
	srcMac        net.HardwareAddr
}

var _ SYNReceiver = (*SYNReceiverImpl)(nil)

func NewSYNReceiver(rawPacketConn *ipv4.PacketConn, srcIP net.IP, srcPort int, gwMac net.HardwareAddr, srcMac net.HardwareAddr) (receiver SYNReceiver, err error) {
	receiver = &SYNReceiverImpl{
		rawPacketConn: rawPacketConn,
		srcIP:         srcIP,
		srcPort:       srcPort,
		gwMac:         gwMac,
		srcMac:        srcMac,
	}
	return
}

// Receive implements SYNReceiver
func (r *SYNReceiverImpl) Receive(ctx context.Context) (resChan chan *net.TCPAddr, err error) {
	resChan = make(chan *net.TCPAddr)
	go func() {
		buf := make([]byte, 65535)
		var (
			n int
			// addr net.Addr
		)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				var src net.Addr
				n, _, src, err = r.rawPacketConn.ReadFrom(buf)
				if err != nil {
					return
				}
				packet := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, gopacket.Default)
				if packet.TransportLayer() == nil {
					continue
				}
				tcp, ok := packet.TransportLayer().(*layers.TCP)
				if !ok {
					continue
				}
				if tcp.RST {
					continue
				}
				srcIP := src.(*net.IPAddr).IP
				// ignore local packets
				if srcIP.String() == "127.0.0.1" {
					continue
				}
				if tcp.DstPort != layers.TCPPort(r.srcPort) {
					continue
				}
				addr := &net.TCPAddr{
					IP:   srcIP,
					Port: int(tcp.SrcPort),
				}
				resChan <- addr
			}
		}
	}()
	return
}
