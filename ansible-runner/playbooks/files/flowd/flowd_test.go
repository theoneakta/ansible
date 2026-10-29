package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func testConfig() *Config {
	c := &Config{DefaultSamplingRate: 1, DropUnknownExporters: true}
	c.Exporters = map[string]Exporter{
		"192.168.3.1": {Name: "opnsense", Default: Iface{Name: "other", Description: "Unknown interface", Speed: 1000},
			Interfaces: map[string]Iface{"1": {Name: "igb0", Description: "Transit: Internet", Speed: 1000},
				"2": {Name: "igb1", Description: "LAN", Speed: 1000}}},
	}
	c.Networks = map[string]Network{"192.168.3.0/24": {Name: "lan", Role: "lan"}, "224.0.0.0/4": {Name: "multicast", Role: "multicast"}}
	return c
}

// An IPFIX datagram: a template (256) and one record with it -
// 8.8.8.8:53 -> 192.168.3.10:40000, TCP flags SYN+ACK, in on ifindex 1 (the
// internet), out on 2, 420 bytes in 3 packets, source MAC 00:11:22:33:44:55.
func ipfixPacket() []byte {
	type field struct{ id, size uint16 }
	fields := []field{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {6, 1}, {10, 4}, {14, 4}, {1, 8}, {2, 8}, {56, 6}}
	tmpl := []byte{0, 2, 0, 0, 1, 0, 0, byte(len(fields))} // set 2 (templates), length later; template 256
	for _, f := range fields {
		tmpl = binary.BigEndian.AppendUint16(tmpl, f.id)
		tmpl = binary.BigEndian.AppendUint16(tmpl, f.size)
	}
	binary.BigEndian.PutUint16(tmpl[2:], uint16(len(tmpl)))
	rec := []byte{8, 8, 8, 8, 192, 168, 3, 10}
	rec = binary.BigEndian.AppendUint16(rec, 53)
	rec = binary.BigEndian.AppendUint16(rec, 40000)
	rec = append(rec, 6, 0x12)
	rec = binary.BigEndian.AppendUint32(rec, 1)
	rec = binary.BigEndian.AppendUint32(rec, 2)
	rec = binary.BigEndian.AppendUint64(rec, 420)
	rec = binary.BigEndian.AppendUint64(rec, 3)
	rec = append(rec, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
	data := append([]byte{1, 0, 0, 0}, rec...) // set 256
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
	msg := make([]byte, 16)
	binary.BigEndian.PutUint16(msg, 10)
	binary.BigEndian.PutUint32(msg[4:], uint32(time.Now().Unix()))
	msg = append(append(msg, tmpl...), data...)
	binary.BigEndian.PutUint16(msg[2:], uint16(len(msg)))
	return msg
}

// A NetFlow v9 datagram laid out as OPNsense sends them: IN_PKTS, IN_BYTES,
// then OUT_PKTS and OUT_BYTES as 0 - 1000 bytes in 7 packets.
func opnsenseV9() []byte {
	type field struct{ id, size uint16 }
	fields := []field{{8, 4}, {12, 4}, {2, 4}, {1, 4}, {24, 4}, {23, 4}, {7, 2}, {11, 2}, {4, 1}}
	tmpl := []byte{0, 0, 0, 0, 1, 0, 0, byte(len(fields))} // flowset 0 (templates); template 256
	for _, f := range fields {
		tmpl = binary.BigEndian.AppendUint16(tmpl, f.id)
		tmpl = binary.BigEndian.AppendUint16(tmpl, f.size)
	}
	binary.BigEndian.PutUint16(tmpl[2:], uint16(len(tmpl)))
	rec := []byte{192, 168, 3, 10, 1, 1, 1, 1}
	rec = binary.BigEndian.AppendUint32(rec, 7)
	rec = binary.BigEndian.AppendUint32(rec, 1000)
	rec = binary.BigEndian.AppendUint32(rec, 0)
	rec = binary.BigEndian.AppendUint32(rec, 0)
	rec = binary.BigEndian.AppendUint16(rec, 40000)
	rec = binary.BigEndian.AppendUint16(rec, 443)
	rec = append(rec, 6, 0, 0, 0) // proto, padding to 4 bytes
	data := append([]byte{1, 0, 0, 0}, rec...)
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg, 9)
	binary.BigEndian.PutUint16(msg[2:], 2) // two records: the template, the flow
	binary.BigEndian.PutUint32(msg[8:], uint32(time.Now().Unix()))
	return append(append(msg, tmpl...), data...)
}

func TestOPNsenseCounters(t *testing.T) {
	enr, _ := newEnricher(testConfig())
	dec := newDecoder(enr, newStats())
	rows, err := dec.Decode("netflow", opnsenseV9(), netip.MustParseAddrPort("192.168.3.1:5000"), time.Now())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	if rows[0].Bytes != 1000 || rows[0].Packets != 7 {
		t.Errorf("bytes %d packets %d, want 1000 and 7 (the OUT_ zeros must not win)", rows[0].Bytes, rows[0].Packets)
	}
	// No interface fields: ifindex 0 both ways - the firewall's own traffic, unnamed, internal.
	if r := rows[0]; r.InIfName != "" || r.InIfSpeed != 0 || r.InIfBoundary != 2 {
		t.Errorf("ifindex 0: name %q speed %d boundary %d, want \"\", 0, 2", r.InIfName, r.InIfSpeed, r.InIfBoundary)
	}
}

// A NetFlow v5 header: refused (v9 / IPFIX only).
func v5Packet() []byte {
	b := make([]byte, 24+48)
	binary.BigEndian.PutUint16(b[0:], 5)
	binary.BigEndian.PutUint16(b[2:], 1)
	binary.BigEndian.PutUint32(b[4:], 100000) // uptime
	binary.BigEndian.PutUint32(b[8:], uint32(time.Now().Unix()))
	r := b[24:]
	copy(r[0:], []byte{8, 8, 8, 8})
	copy(r[4:], []byte{192, 168, 3, 10})
	binary.BigEndian.PutUint16(r[12:], 1) // input
	binary.BigEndian.PutUint16(r[14:], 2) // output
	binary.BigEndian.PutUint32(r[16:], 3) // packets
	binary.BigEndian.PutUint32(r[20:], 420)
	binary.BigEndian.PutUint16(r[32:], 53)
	binary.BigEndian.PutUint16(r[34:], 40000)
	r[37] = 0x12 // TCP flags (SYN+ACK) - any value, passed through
	r[38] = 17
	return b
}

func TestDecodeIPFIX(t *testing.T) {
	enr, err := newEnricher(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	dec := newDecoder(enr, newStats())
	now := time.Unix(1_800_000_000, 0)
	rows, err := dec.Decode("netflow", ipfixPacket(), netip.MustParseAddrPort("192.168.3.1:5000"), now)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	r := rows[0]
	check := func(name string, got, want any) {
		if got != want {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	check("ExporterName", r.ExporterName, "opnsense")
	check("ExporterAddress", r.ExporterAddress, "::ffff:192.168.3.1")
	check("SrcAddr", r.SrcAddr, "::ffff:8.8.8.8")
	check("DstNetRole", r.DstNetRole, "lan")
	check("SrcNetRole", r.SrcNetRole, "")
	check("InIfName", r.InIfName, "igb0")
	check("InIfBoundary", r.InIfBoundary, uint8(1))
	check("InIfConnectivity", r.InIfConnectivity, "transit")
	check("InIfProvider", r.InIfProvider, "internet")
	check("OutIfName", r.OutIfName, "igb1")
	check("OutIfBoundary", r.OutIfBoundary, uint8(2))
	check("Proto", r.Proto, uint32(6))
	check("SrcMAC", r.SrcMAC, uint64(0x001122334455))
	check("EType", r.EType, uint32(0x800))
	check("SrcPort", r.SrcPort, uint16(53))
	check("Bytes", r.Bytes, uint64(420))
	check("Packets", r.Packets, uint64(3))
	check("TCPFlags", r.TCPFlags, uint8(0x12))
	check("SamplingRate", r.SamplingRate, uint64(1))
	check("TimeReceived", r.TimeReceived, uint32(1_800_000_000))

	// An exporter not in the list: dropped.
	rows, _ = dec.Decode("netflow", ipfixPacket(), netip.MustParseAddrPort("10.9.9.9:5000"), now)
	if len(rows) != 0 {
		t.Errorf("unknown exporter: %d rows, want 0", len(rows))
	}
	// NetFlow v5: refused.
	if _, err := dec.Decode("netflow", v5Packet(), netip.MustParseAddrPort("192.168.3.1:5000"), now); err == nil {
		t.Error("NetFlow v5 was accepted")
	}
}

func TestGeoParsing(t *testing.T) {
	if got := countryOf(map[string]any{"country": "ca"}); got != "CA" {
		t.Errorf("ipinfo country: %q", got)
	}
	if got := countryOf(map[string]any{"country": map[string]any{"iso_code": "DE"}}); got != "DE" {
		t.Errorf("MaxMind country: %q", got)
	}
	if got := asnOf(map[string]any{"asn": "AS13335"}); got != 13335 {
		t.Errorf("ipinfo asn: %d", got)
	}
	if got := asnOf(map[string]any{"autonomous_system_number": uint64(15169)}); got != 15169 {
		t.Errorf("MaxMind asn: %d", got)
	}
}

func TestUDPOf(t *testing.T) {
	// Ethernet + IPv4 + UDP 192.168.3.1:5000 -> :2055, payload "hi".
	f := make([]byte, 14+20+8+2)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:]
	ip[0], ip[9] = 0x45, 17
	copy(ip[12:], []byte{192, 168, 3, 1})
	u := ip[20:]
	binary.BigEndian.PutUint16(u, 5000)
	binary.BigEndian.PutUint16(u[2:], 2055)
	binary.BigEndian.PutUint16(u[4:], 10)
	copy(u[8:], "hi")
	src, dport, payload, ok := udpOf(1, f)
	if !ok || src != netip.MustParseAddrPort("192.168.3.1:5000") || dport != 2055 || string(payload) != "hi" {
		t.Fatalf("got %v %d %q %v", src, dport, payload, ok)
	}
}

func TestForwardPacket(t *testing.T) {
	src, dst := netip.MustParseAddr("192.168.3.1"), netip.MustParseAddr("172.18.0.5")
	p := ipv4UDP(src, 5000, dst, 2055, []byte("flow"))
	if len(p) != 32 || ipChecksum(p[:20]) != 0 { // a header with its checksum sums to 0
		t.Fatalf("len %d, header checksum check %#x", len(p), ipChecksum(p[:20]))
	}
	if got := netip.AddrFrom4([4]byte(p[12:16])); got != src {
		t.Errorf("source %v, want %v (the exporter's)", got, src)
	}
	if binary.BigEndian.Uint16(p[22:]) != 2055 || string(p[28:]) != "flow" {
		t.Errorf("port %d payload %q", binary.BigEndian.Uint16(p[22:]), p[28:])
	}
	if s, dp, payload, ok := udpOf(101, p); !ok || s != netip.MustParseAddrPort("192.168.3.1:5000") || dp != 2055 || string(payload) != "flow" {
		t.Errorf("read back: %v %d %q %v", s, dp, payload, ok)
	}
}

// Sequence numbers: v9 counts packets, IPFIX the records before each message;
// a jump is what never arrived, a step back (a restart) isn't counted.
func TestSequenceGaps(t *testing.T) {
	stats := newStats()
	st := &exporterState{next: map[seqKey]uint32{}}
	exp := netip.MustParseAddr("192.168.3.236")
	for _, seq := range []uint32{10, 11, 14, 15, 3, 4} { // 12, 13 lost; then a restart
		st.checkSeq(stats, exp, 9, 0, seq, 25)
	}
	ipfix := []struct {
		seq uint32
		n   int
	}{{100, 30}, {130, 30}, {200, 10}, {210, -1}, {500, 5}} // 160-199 lost; then one not decoded
	for _, m := range ipfix {
		st.checkSeq(stats, exp, 10, 7, m.seq, m.n)
	}
	got := stats.exporters[exp.String()]
	if got["lost_datagrams"] != 2 || got["lost_records"] != 40 {
		t.Fatalf("lost: %v, want 2 datagrams and 40 records", got)
	}
}
