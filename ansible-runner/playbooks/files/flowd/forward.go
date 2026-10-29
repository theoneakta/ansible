package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// Forwarder: every datagram received, passed on unchanged to another
// collector - to run flowd in front of one (Akvorado) while both store the
// same traffic. Collectors tell exporters apart by the datagram's source
// address, so with preserve_source the copy keeps the exporter's (a raw IPv4
// socket: Linux, CAP_NET_RAW). An IPv6 exporter, or a copy too big for one
// packet, goes from flowd's own address instead (counted).
type ForwardConfig struct {
	Host           string `json:"host"`            // the other collector, e.g. akvorado-akvorado-inlet-1
	PreserveSource bool   `json:"preserve_source"` // keep the exporter's address (needs CAP_NET_RAW)
}

type Forwarder struct {
	cfg   ForwardConfig
	stats *Stats
	mu    sync.Mutex
	dst   netip.Addr
	when  time.Time
	raw   int // raw socket, -1 if none
	udp   *net.UDPConn
}

func newForwarder(cfg ForwardConfig, stats *Stats) (*Forwarder, error) {
	f := &Forwarder{cfg: cfg, stats: stats, raw: -1}
	u, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	f.udp = u
	if cfg.PreserveSource {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW) // IP_HDRINCL implied
		if err != nil {
			return nil, fmt.Errorf("forward with the exporters' addresses needs CAP_NET_RAW: %w", err)
		}
		f.raw = fd
	}
	return f, nil
}

// target: the other collector's address, looked up again every minute (a
// container's address changes when it's recreated).
func (f *Forwarder) target() (netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dst.IsValid() && time.Since(f.when) < time.Minute {
		return f.dst, nil
	}
	ips, err := net.LookupIP(f.cfg.Host)
	if err != nil {
		if f.dst.IsValid() {
			return f.dst, nil // keep the last one
		}
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().Is4() {
			f.dst, f.when = a.Unmap(), time.Now()
			return f.dst, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s: no IPv4 address", f.cfg.Host)
}

// Send: payload, as received from src on port, to the same port of the other collector.
func (f *Forwarder) Send(src netip.AddrPort, port uint16, payload []byte) {
	dst, err := f.target()
	if err != nil {
		f.stats.global("forward_errors", 1)
		return
	}
	s := src.Addr().Unmap()
	if f.raw >= 0 && s.Is4() && len(payload)+28 <= 1500 {
		pkt := ipv4UDP(s, src.Port(), dst, port, payload)
		sa := &syscall.SockaddrInet4{Addr: dst.As4()}
		if err := syscall.Sendto(f.raw, pkt, 0, sa); err == nil {
			f.stats.global("forwarded", 1)
			return
		} else {
			log.Printf("forward (raw): %v", err)
		}
	}
	if _, err := f.udp.WriteToUDPAddrPort(payload, netip.AddrPortFrom(dst, port)); err != nil {
		f.stats.global("forward_errors", 1)
		return
	}
	f.stats.global("forwarded_own_address", 1)
}

// ipv4UDP: an IPv4 + UDP packet from src to dst (UDP checksum 0: none, allowed over IPv4).
func ipv4UDP(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64 // TTL
	b[9] = 17 // UDP
	s4, d4 := src.As4(), dst.As4()
	copy(b[12:16], s4[:])
	copy(b[16:20], d4[:])
	binary.BigEndian.PutUint16(b[10:], ipChecksum(b[:20]))
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
