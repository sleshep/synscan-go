package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type AddressIterator interface {
	Iter() <-chan *net.TCPAddr
}

type AddressIteratorImpl struct {
	ctx       context.Context
	IPIters   []*IPCidrRange
	PortRange []*PortRange
}

var _ AddressIterator = (*AddressIteratorImpl)(nil)

type IPCidrRange struct {
	ctx context.Context
	net *net.IPNet
}

func (i *IPCidrRange) Iter() <-chan net.IP {
	ch := make(chan net.IP)

	ip := i.net.IP.Mask(i.net.Mask)
	incIP := func() {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}
	go func() {
		defer close(ch)
		for {
			x := make(net.IP, len(ip))
			// copy to avoid modifying the original ip
			copy(x, ip)
			select {
			case <-i.ctx.Done():
				return
			case ch <- x:
				incIP()
				if !i.net.Contains(ip) {
					return
				}
			}
		}
	}()
	return ch
}

type PortRange struct {
	ctx   context.Context
	start int
	end   int
}

func (p *PortRange) Iter() <-chan int {
	ch := make(chan int)
	go func() {
		defer close(ch)
		for i := p.start; i <= p.end; i++ {
			select {
			case <-p.ctx.Done():
				return
			case ch <- i:
			}
		}
	}()
	return ch
}

func NewAddressIterator(ctx context.Context, addrExpression string, portExpression string) (iterator AddressIterator, err error) {
	i := &AddressIteratorImpl{
		ctx: ctx,
	}
	err = i.parseExpresion(ctx, addrExpression, portExpression)
	if err != nil {
		return
	}
	iterator = i
	return
}

func (i *AddressIteratorImpl) parseExpresion(ctx context.Context, addrExpression string, portExpression string) (err error) {
	i.IPIters = make([]*IPCidrRange, 0)
	i.PortRange = make([]*PortRange, 0)

	for _, e := range strings.Split(addrExpression, ",") {
		if !strings.Contains(e, "/") {
			e = e + "/32"
		}
		var ipNet *net.IPNet
		_, ipNet, err = net.ParseCIDR(e)
		if err != nil {
			return
		}
		i.IPIters = append(i.IPIters, &IPCidrRange{
			ctx: ctx,
			net: ipNet,
		})
	}

	for _, e := range strings.Split(portExpression, ",") {
		var start, end int
		parts := strings.Split(e, "-")
		start, err = strconv.Atoi(parts[0])
		if err != nil {
			return
		}
		if len(parts) == 1 {
			end = start
		} else {
			end, err = strconv.Atoi(parts[1])
			if err != nil {
				return
			}
		}
		i.PortRange = append(i.PortRange, &PortRange{
			ctx:   ctx,
			start: start,
			end:   end,
		})
	}
	fmt.Printf("parse done, %d ip, %d port\n", len(i.IPIters), len(i.PortRange))
	return
}

// Iter implements AddressIterator
func (i *AddressIteratorImpl) Iter() <-chan *net.TCPAddr {
	ch := make(chan *net.TCPAddr)
	go func() {
		defer close(ch)
		for _, ipRange := range i.IPIters {
			for ip := range ipRange.Iter() {
				for _, portRange := range i.PortRange {
					for port := range portRange.Iter() {
						select {
						case <-i.ctx.Done():
							return
						case ch <- &net.TCPAddr{
							IP:   ip,
							Port: port,
						}:
						}
					}
				}
			}
		}
	}()
	return ch
}
