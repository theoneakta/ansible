//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"
)

// Windows' IP Helper API: SendARP and IcmpSendEcho need neither a driver
// (no Npcap) nor administrator rights.
var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP     = iphlpapi.NewProc("SendARP")
	procIcmpCreate  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose   = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho")
)

// ipv4 as SendARP / IcmpSendEcho want it: the address bytes in memory order.
func ipv4(ip net.IP) uint32 { return binary.LittleEndian.Uint32(ip.To4()) }

// arpSweep: SendARP to every address - the ones on a local subnet answer with their MAC.
func arpSweep(ips []net.IP) map[string]string {
	out := map[string]string{}
	var mu sync.Mutex
	parallel(ips, 128, func(ip net.IP) {
		var mac [8]byte
		l := uint32(len(mac))
		r, _, _ := procSendARP.Call(uintptr(ipv4(ip)), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&l)))
		if r == 0 && l == 6 {
			mu.Lock()
			out[ip.String()] = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
			mu.Unlock()
		}
	})
	return out
}

// icmpEchoReply is ICMP_ECHO_REPLY (32-bit layout).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       [8]byte
}

// pingSweep: IcmpSendEcho to every address, the ones that answer with their round trip in ms.
func pingSweep(ips []net.IP) map[string]float64 {
	out := map[string]float64{}
	var mu sync.Mutex
	parallel(ips, 128, func(ip net.IP) {
		h, _, _ := procIcmpCreate.Call()
		if h == 0 || h == ^uintptr(0) {
			return
		}
		defer procIcmpClose.Call(h)
		data := []byte("sentry-lens")
		reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(data)+64)
		n, _, _ := procIcmpSendEcho.Call(h, uintptr(ipv4(ip)), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), 1500)
		if n > 0 {
			r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
			if r.Status == 0 {
				mu.Lock()
				out[ip.String()] = float64(r.RoundTripTime)
				mu.Unlock()
			}
		}
	})
	return out
}
