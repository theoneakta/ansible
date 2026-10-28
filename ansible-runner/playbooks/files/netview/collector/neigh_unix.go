//go:build !windows

package main

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// arpSweep: the MACs of the addresses that answer ARP. Sending one UDP
// packet to an address on a local subnet makes the kernel resolve it; the
// answers are in its neighbor table (/proc/net/arp) - no privilege needed.
func arpSweep(ips []net.IP) map[string]string {
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip.String()] = true
	}
	for round := 0; round < 2; round++ {
		parallel(ips, 256, func(ip net.IP) {
			if c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 9}); err == nil {
				_, _ = c.Write([]byte{0})
				c.Close()
			}
		})
		time.Sleep(2500 * time.Millisecond)
	}
	out := map[string]string{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan() // the header
	for s.Scan() {
		p := strings.Fields(s.Text())
		// IP address, HW type, Flags (0x2 = complete), HW address, Mask, Device
		if len(p) >= 4 && want[p[0]] && p[2] != "0x0" && p[3] != "00:00:00:00:00:00" {
			out[p[0]] = strings.ToUpper(p[3])
		}
	}
	return out
}

// pingSweep: the addresses that answer an ICMP echo, with the round trip
// in ms. An unprivileged ICMP socket where the system allows it
// (net.ipv4.ping_group_range), else a raw one (root or CAP_NET_RAW), else none.
func pingSweep(ips []net.IP) map[string]float64 {
	out := map[string]float64{}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	unpriv := true
	if err != nil {
		if c, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err != nil {
			return out
		}
		unpriv = false
	}
	defer c.Close()
	var mu sync.Mutex
	sent := map[string]time.Time{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1500)
		for {
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, peer, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			m, err := icmp.ParseMessage(1, b[:n])
			if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			ip := peer.String()
			if ua, ok := peer.(*net.UDPAddr); ok {
				ip = ua.IP.String()
			} else if ia, ok := peer.(*net.IPAddr); ok {
				ip = ia.IP.String()
			}
			mu.Lock()
			if t, ok := sent[ip]; ok {
				if _, seen := out[ip]; !seen {
					out[ip] = float64(time.Since(t).Microseconds()) / 1000
				}
			}
			mu.Unlock()
		}
	}()
	for i, ip := range ips {
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: i & 0xffff, Data: []byte("sentry-lens")}}
		b, _ := msg.Marshal(nil)
		var dst net.Addr = &net.IPAddr{IP: ip}
		if unpriv {
			dst = &net.UDPAddr{IP: ip}
		}
		mu.Lock()
		sent[ip.String()] = time.Now()
		mu.Unlock()
		_, _ = c.WriteTo(b, dst)
		if i%200 == 199 {
			time.Sleep(50 * time.Millisecond) // ~4000 a second at most
		}
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return out
}
