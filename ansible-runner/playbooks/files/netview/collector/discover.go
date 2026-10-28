package main

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A device as Sentry Lens wants it (assets.py: collector_results).
type Host struct {
	IP       string  `json:"ip"`
	MAC      string  `json:"mac"`
	Vendor   string  `json:"vendor"`
	Hostname string  `json:"hostname"`
	NetBIOS  string  `json:"netbios"`
	Ports    []int   `json:"ports"`
	RTT      float64 `json:"rtt_ms"`
	Method   string  `json:"method"`
}

// nmap's 100 most common TCP ports.
var topPorts = []int{7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199,
	389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
	1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
	5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100,
	9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157}

// Ports that make a host answer past a router when ping is blocked.
var probePorts = []int{22, 80, 135, 139, 443, 445, 3389, 8080}

// addresses: every host address of an IPv4 subnet (/16 at most).
func addresses(subnet string) ([]net.IP, *net.IPNet, error) {
	_, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, nil, err
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return nil, nil, errors.New("IPv6 subnets aren't swept")
	}
	ones, bits := n.Mask.Size()
	if bits-ones > 16 {
		return nil, nil, errors.New("a /16 at most")
	}
	start := binary.BigEndian.Uint32(ip4)
	count := uint32(1) << uint(bits-ones)
	var out []net.IP
	for i := uint32(0); i < count; i++ {
		if count > 2 && (i == 0 || i == count-1) { // network and broadcast
			continue
		}
		b := make(net.IP, 4)
		binary.BigEndian.PutUint32(b, start+i)
		out = append(out, b)
	}
	return out, n, nil
}

// onLink: is the subnet one this machine has an address on (so ARP reaches it)?
func onLink(n *net.IPNet) bool {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if in, ok := a.(*net.IPNet); ok && in.IP.To4() != nil && (n.Contains(in.IP) || in.Contains(n.IP)) {
				return true
			}
		}
	}
	return false
}

// tcpAlive: does the address answer a TCP connection on any of the ports
// (an accept or a refusal both mean someone's there)?
func tcpAlive(ip string, ports []int, timeout time.Duration) bool {
	for _, p := range ports {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, itoa(p)), timeout)
		if err == nil {
			c.Close()
			return true
		}
		if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused") {
			return true
		}
	}
	return false
}

// parallel runs f on every item, n at a time.
func parallel[T any](items []T, n int, f func(T)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, n)
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			f(it)
		}(it)
	}
	wg.Wait()
}

// discover: who answers on a subnet - ARP on a subnet this machine is on
// (every device answers, with its MAC), ping and TCP probes past a router.
func discover(subnet string) map[string]*Host {
	ips, n, err := addresses(subnet)
	found := map[string]*Host{}
	if err != nil {
		log.Printf("%s: %v", subnet, err)
		return found
	}
	var mu sync.Mutex
	add := func(ip, mac string, rtt float64, method string) {
		mu.Lock()
		defer mu.Unlock()
		if h, ok := found[ip]; ok {
			if h.MAC == "" {
				h.MAC = mac
			}
			if h.RTT == 0 {
				h.RTT = rtt
			}
			return
		}
		found[ip] = &Host{IP: ip, MAC: mac, RTT: rtt, Method: method, Ports: []int{}}
	}
	link := onLink(n)
	if link {
		for ip, mac := range arpSweep(ips) {
			add(ip, mac, 0, "arp")
		}
	}
	// Ping (and, past a router, TCP probes) for what ARP didn't see.
	for ip, rtt := range pingSweep(ips) {
		add(ip, "", rtt, "ping")
	}
	if !link {
		var rest []net.IP
		for _, ip := range ips {
			if _, ok := found[ip.String()]; !ok {
				rest = append(rest, ip)
			}
		}
		parallel(rest, 256, func(ip net.IP) {
			if tcpAlive(ip.String(), probePorts, 700*time.Millisecond) {
				add(ip.String(), "", 0, "tcp")
			}
		})
	}
	return found
}

// openPorts: which of the top 100 TCP ports accept a connection.
func openPorts(hosts []*Host) {
	type job struct {
		h *Host
		p int
	}
	var jobs []job
	for _, h := range hosts {
		for _, p := range topPorts {
			jobs = append(jobs, job{h, p})
		}
	}
	var mu sync.Mutex
	parallel(jobs, 512, func(j job) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(j.h.IP, itoa(j.p)), 1200*time.Millisecond)
		if err == nil {
			c.Close()
			mu.Lock()
			j.h.Ports = append(j.h.Ports, j.p)
			mu.Unlock()
		}
	})
	for _, h := range hosts {
		sort.Ints(h.Ports)
	}
}

func names(hosts []*Host) {
	parallel(hosts, 32, func(h *Host) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if n, err := net.DefaultResolver.LookupAddr(ctx, h.IP); err == nil && len(n) > 0 {
			h.Hostname = strings.TrimSuffix(n[0], ".")
		}
		h.NetBIOS = netbiosName(h.IP)
	})
}

// netbiosName: the name a Windows (or Samba) machine answers a NetBIOS
// node-status query with (UDP 137) - "" if none.
func netbiosName(ip string) string {
	c, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	q := []byte{0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K'}
	q = append(q, []byte(strings.Repeat("A", 30))...)
	q = append(q, 0, 0, 0x21, 0, 1) // NBSTAT, IN
	_ = c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := c.Write(q); err != nil {
		return ""
	}
	b := make([]byte, 1024)
	n, err := c.Read(b)
	if err != nil || n < 57 {
		return ""
	}
	// header 12, answer name 34, type 2, class 2, ttl 4, length 2 -> the name count at 56
	count := int(b[56])
	for i := 0; i < count && 57+i*18+18 <= n; i++ {
		e := b[57+i*18 : 57+i*18+18]
		if e[15] == 0x00 && e[16]&0x80 == 0 { // a workstation name, not a group
			return strings.TrimSpace(string(e[:15]))
		}
	}
	return ""
}

// sweep: every subnet, then ports and names of what answered.
func sweep(subnets []string) []*Host {
	all := map[string]*Host{}
	for _, s := range subnets {
		t := time.Now()
		found := discover(s)
		log.Printf("%s: %d up (%s)", s, len(found), time.Since(t).Round(time.Second))
		for ip, h := range found {
			if _, ok := all[ip]; !ok {
				all[ip] = h
			}
		}
	}
	hosts := make([]*Host, 0, len(all))
	for _, h := range all {
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return hosts
	}
	t := time.Now()
	openPorts(hosts)
	names(hosts)
	log.Printf("ports and names: %s", time.Since(t).Round(time.Second))
	return hosts
}

func itoa(i int) string { return strconv.Itoa(i) }
