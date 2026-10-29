package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// replay: the exporters' datagrams from a capture (tcpdump -w, classic pcap)
// through the same decoding and storing, each received when it was captured
// - to compare with another collector on the same traffic. UDP to the sFlow
// port is sFlow, any other NetFlow / IPFIX. Fragmented datagrams are skipped.
func replay(path string, cfg *Config, dec *Decoder, sink *Sink, stats *Stats) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, err
	}
	var bo binary.ByteOrder
	nano := false
	switch binary.LittleEndian.Uint32(hdr) {
	case 0xa1b2c3d4:
		bo = binary.LittleEndian
	case 0xa1b23c4d:
		bo, nano = binary.LittleEndian, true
	default:
		switch binary.BigEndian.Uint32(hdr) {
		case 0xa1b2c3d4:
			bo = binary.BigEndian
		case 0xa1b23c4d:
			bo, nano = binary.BigEndian, true
		default:
			return 0, errors.New("not a pcap file (pcapng: convert it with editcap -F pcap)")
		}
	}
	link := bo.Uint32(hdr[20:]) & 0xffff
	sflowPort := port(cfg.Listen.SFlow, 6343)
	rec := make([]byte, 16)
	n := 0
	for {
		if _, err := io.ReadFull(r, rec); err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		sec, frac, incl := bo.Uint32(rec), bo.Uint32(rec[4:]), bo.Uint32(rec[8:])
		data := make([]byte, incl)
		if _, err := io.ReadFull(r, data); err != nil {
			return n, err
		}
		ns := int64(frac) * 1000
		if nano {
			ns = int64(frac)
		}
		src, dport, payload, ok := udpOf(link, data)
		if !ok {
			continue
		}
		kind := "netflow"
		if dport == sflowPort {
			kind = "sflow"
		}
		handle(kind, payload, src, time.Unix(int64(sec), ns), dec, sink, stats)
		n++
	}
}

func port(addr string, def uint16) uint16 {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		if p, err := strconv.ParseUint(addr[i+1:], 10, 16); err == nil {
			return uint16(p)
		}
	}
	return def
}

// udpOf: a captured frame's UDP source, destination port and payload.
func udpOf(link uint32, b []byte) (netip.AddrPort, uint16, []byte, bool) {
	var etype uint16
	switch link {
	case 1: // Ethernet
		if len(b) < 14 {
			return netip.AddrPort{}, 0, nil, false
		}
		etype, b = binary.BigEndian.Uint16(b[12:]), b[14:]
		for (etype == 0x8100 || etype == 0x88a8) && len(b) >= 4 { // VLAN tags
			etype, b = binary.BigEndian.Uint16(b[2:]), b[4:]
		}
	case 113: // Linux cooked (SLL)
		if len(b) < 16 {
			return netip.AddrPort{}, 0, nil, false
		}
		etype, b = binary.BigEndian.Uint16(b[14:]), b[16:]
	case 276: // Linux cooked v2 (SLL2)
		if len(b) < 20 {
			return netip.AddrPort{}, 0, nil, false
		}
		etype, b = binary.BigEndian.Uint16(b), b[20:]
	case 12, 101: // raw IP
		if len(b) == 0 {
			return netip.AddrPort{}, 0, nil, false
		}
		etype = map[byte]uint16{4: 0x0800, 6: 0x86dd}[b[0]>>4]
	default:
		return netip.AddrPort{}, 0, nil, false
	}
	var src netip.Addr
	switch etype {
	case 0x0800:
		if len(b) < 20 || b[9] != 17 {
			return netip.AddrPort{}, 0, nil, false
		}
		ihl := int(b[0]&0x0f) * 4
		if binary.BigEndian.Uint16(b[6:])&0x3fff != 0 || len(b) < ihl+8 { // a fragment
			return netip.AddrPort{}, 0, nil, false
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		b = b[ihl:]
	case 0x86dd:
		if len(b) < 48 || b[6] != 17 {
			return netip.AddrPort{}, 0, nil, false
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		b = b[40:]
	default:
		return netip.AddrPort{}, 0, nil, false
	}
	sport, dport, ulen := binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:]), int(binary.BigEndian.Uint16(b[4:]))
	if ulen < 8 || ulen > len(b) {
		ulen = len(b)
	}
	return netip.AddrPortFrom(src, sport), dport, b[8:ulen], true
}
