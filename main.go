package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
)

var (
	// commandline args
	targetString string
	portsString  string
	sourcePort   int
	rate         int
	wait         time.Duration
	silence      bool
	outFile      string

	attack bool

	// global variables
	printMu *sync.Mutex
	out     *os.File

	// global vars
	// sendChan   chan *net.TCPAddr
	// srcIP      net.IP
	// logVerbose bool
	// writeOut   func(s string) error
	// verboseMu  *sync.Mutex
)

func main() {
	flag.StringVar(&targetString, "t", "192.168.0.0/24", "Target IP address, comma separated list of IP or CIDR notation, e.g. 192.168.1.0/24,10.0.0.0/24, default is 192.168.0.0/24")
	flag.StringVar(&portsString, "p", "80,443", "port or port range, e.g. 80,443,8080-8090, default 80,443")
	flag.IntVar(&sourcePort, "c", 50001, "source port, default 50001")
	flag.IntVar(&rate, "r", 100000, "rate limit, in packets per second, default is 100k packets per second")
	flag.DurationVar(&wait, "w", time.Second*1, "wait for finish")
	flag.StringVar(&outFile, "o", "-", "result output file, default is stdout")
	flag.BoolVar(&silence, "s", false, "silence, no info output, default is false")
	flag.BoolVar(&attack, "a", false, "attack mode, keep sending to target, default is false")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -t 10.0.0.0/24,192.168.1.0/24 -p 80,443,8080-8090 -o result.txt\n", os.Args[0])
		fmt.Printf("\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if targetString == "" {
		_, _ = fmt.Fprintf(os.Stderr, "target is required\n")
		flag.Usage()
		return
	}
	err := scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func scan() (err error) {
	printMu = &sync.Mutex{}
	if outFile != "-" {
		out, err = os.Create(outFile)
		if err != nil {
			return
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}
	// gether network infomation
	iface, err := pickIface()
	if err != nil {
		return
	}
	gwIP, err := getGwIP()
	if err != nil {
		return
	}

	gwMac, err := getGwMac(gwIP)
	if err != nil {
		return
	}
	outboundIP, err := getOutboundIP()
	if err != nil {
		return
	}
	sender, err := NewSYNSender(outboundIP.String(), sourcePort, gwMac, iface.HardwareAddr)
	if err != nil {
		return
	}
	packetConn, err := openRawConn()
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	errG := &errgroup.Group{}
	i, err := NewAddressIterator(ctx, targetString, portsString)
	if err != nil {
		cancel()
		return
	}
	receiver, err := NewSYNReceiver(packetConn, outboundIP, sourcePort, iface.HardwareAddr, gwMac)
	if err != nil {
		cancel()
		return
	}
	logf("start scanning,srcIP:%s,gwMac:%s,iface:%s\n", outboundIP, gwMac, iface.Name)

	// start goroutines
	errG.Go(func() (err error) {
		defer logf("receiver done.\n")
		r, err := receiver.Receive(ctx)
		if err != nil {
			cancel()
			return
		}
		for result := range r {
			writeResult(result.String())
		}
		return
	})

	c := i.Iter()
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()
	done := make(chan struct{})
	errG.Go(func() (err error) {
		defer func() {
			logf("sender done.\n")
			close(done)
		}()
		for {
			select {
			case <-ctx.Done():
				break
			case <-ticker.C:
				addr, ok := <-c
				if !ok {
					return
				}
				logfSampling("sending %s\r", addr)
				for {
					if err := sender.Send(addr.IP.String(), addr.Port); err != nil {
						return err
					}
					if !attack {
						break
					}
				}
			}
		}
	})
	<-done
	cancel()
	logf("waiting for %s\n", wait)
	time.Sleep(wait)
	if err != nil && !errors.Is(err, context.Canceled) {
		return
	}
	return
}

func openRawConn() (conn *ipv4.PacketConn, err error) {
	l, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return
	}
	conn = ipv4.NewPacketConn(l)
	return
}

func logf(format string, a ...interface{}) {
	if !silence {
		printMu.Lock()
		// clear line
		_, _ = fmt.Fprintf(os.Stderr, "\033[2K\r")
		_, _ = fmt.Fprintf(os.Stderr, "[*] "+format, a...)
		printMu.Unlock()
	}
}

var (
	logOnce = &sync.Once{}
	logChan = make(chan string, 100)
)

// log every 100 or 100ms
func logfSampling(format string, a ...interface{}) {
	logOnce.Do(func() {
		throttling := 200 * time.Millisecond
		go func() {
			n := 0
			t := time.NewTimer(throttling)
			defer t.Stop()
			last := ""
			for {
				select {
				case <-t.C:
					if last != "" {
						logf(last)
						last = ""
						t.Reset(throttling)
					}
				case s := <-logChan:
					last = s
					n++
					if n >= 100 {
						logf(last)
						n = 0
						t.Reset(throttling)
						last = ""
					}
				}
			}
		}()
	})
	logChan <- fmt.Sprintf(format, a...)
}

func writeResult(s string) {
	printMu.Lock()
	// clear current line
	_, _ = fmt.Fprint(os.Stderr, strings.Repeat("\033[2K\r", 2))
	_, _ = fmt.Fprintln(out, s)
	printMu.Unlock()
}

func getOutboundIP() (ip net.IP, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip = localAddr.IP
	return
}

// getGwIP returns the IP address of the default gateway.
// using /proc/net/route
func getGwIP() (ip net.IP, err error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// skip header line
		if strings.Contains(scanner.Text(), "Iface") {
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[2] == "00000000" {
			continue
		}
		var b []byte
		b, err = hex.DecodeString(fields[2])
		if err != nil {
			return
		}
		ip = net.IP([]byte{b[3], b[2], b[1], b[0]})
		return
	}
	err = fmt.Errorf("no default route found")
	return
}

// getGwMac returns the MAC address of the default gateway.
// using /proc/net/arp
func getGwMac(gwIP net.IP) (mac net.HardwareAddr, err error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if fields[0] == gwIP.String() {
			mac, err = net.ParseMAC(fields[3])
			if err != nil {
				return
			}
			return
		}
	}
	err = fmt.Errorf("no default gateway found")
	return
}

func pickIface() (iFace *net.Interface, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
			iFace = &i
			break
		}
	}
	if iFace == nil {
		err = fmt.Errorf("no network interface found")
		return
	}
	return
}
