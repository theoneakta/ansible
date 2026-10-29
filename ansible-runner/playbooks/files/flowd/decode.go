package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/decoders/sflow"
	"github.com/netsampler/goflow2/v2/producer"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
)

// Row: one flow as the flows table has it - Akvorado's columns (so every
// Sentry Lens query works unchanged), and what Akvorado leaves out: TCP
// flags, MACs, VLANs, ICMP type and code.
type Row struct {
	TimeReceived      uint32 `json:"TimeReceived"`
	SamplingRate      uint64 `json:"SamplingRate"`
	ExporterAddress   string `json:"ExporterAddress"`
	ExporterName      string `json:"ExporterName"`
	ExporterRole      string `json:"ExporterRole"`
	SrcAddr           string `json:"SrcAddr"`
	DstAddr           string `json:"DstAddr"`
	SrcNetMask        uint8  `json:"SrcNetMask"`
	DstNetMask        uint8  `json:"DstNetMask"`
	SrcAS             uint32 `json:"SrcAS"`
	DstAS             uint32 `json:"DstAS"`
	SrcNetName        string `json:"SrcNetName"`
	DstNetName        string `json:"DstNetName"`
	SrcNetRole        string `json:"SrcNetRole"`
	DstNetRole        string `json:"DstNetRole"`
	SrcNetSite        string `json:"SrcNetSite"`
	DstNetSite        string `json:"DstNetSite"`
	SrcNetRegion      string `json:"SrcNetRegion"`
	DstNetRegion      string `json:"DstNetRegion"`
	SrcNetTenant      string `json:"SrcNetTenant"`
	DstNetTenant      string `json:"DstNetTenant"`
	SrcCountry        string `json:"SrcCountry"`
	DstCountry        string `json:"DstCountry"`
	InIfName          string `json:"InIfName"`
	OutIfName         string `json:"OutIfName"`
	InIfDescription   string `json:"InIfDescription"`
	OutIfDescription  string `json:"OutIfDescription"`
	InIfSpeed         uint32 `json:"InIfSpeed"`
	OutIfSpeed        uint32 `json:"OutIfSpeed"`
	InIfConnectivity  string `json:"InIfConnectivity"`
	OutIfConnectivity string `json:"OutIfConnectivity"`
	InIfProvider      string `json:"InIfProvider"`
	OutIfProvider     string `json:"OutIfProvider"`
	InIfBoundary      uint8  `json:"InIfBoundary"`
	OutIfBoundary     uint8  `json:"OutIfBoundary"`
	EType             uint32 `json:"EType"`
	Proto             uint32 `json:"Proto"`
	SrcPort           uint16 `json:"SrcPort"`
	DstPort           uint16 `json:"DstPort"`
	Bytes             uint64 `json:"Bytes"`
	Packets           uint64 `json:"Packets"`
	ForwardingStatus  uint32 `json:"ForwardingStatus"`
	// Beyond Akvorado's columns.
	TCPFlags uint8  `json:"TCPFlags"`
	SrcMAC   uint64 `json:"SrcMAC"`
	DstMAC   uint64 `json:"DstMAC"`
	SrcVlan  uint16 `json:"SrcVlan"`
	DstVlan  uint16 `json:"DstVlan"`
	ICMPType uint8  `json:"ICMPType"`
	ICMPCode uint8  `json:"ICMPCode"`
}

// Decoder: IPFIX, NetFlow v9 and sFlow (goflow2's decoders and producer),
// with each exporter's own templates and sampling rates.
type Decoder struct {
	enr   *Enricher
	stats *Stats
	mu    sync.Mutex
	state map[netip.Addr]*exporterState
}

type exporterState struct {
	mu        sync.Mutex
	templates netflow.NetFlowTemplateSystem
	prod      producer.ProducerInterface
}

func newDecoder(enr *Enricher, stats *Stats) *Decoder {
	return &Decoder{enr: enr, stats: stats, state: map[netip.Addr]*exporterState{}}
}

func (d *Decoder) exporterState(a netip.Addr) (*exporterState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.state[a]; ok {
		return s, nil
	}
	cfg, err := (&protoproducer.ProducerConfig{}).Compile()
	if err != nil {
		return nil, err
	}
	p, err := protoproducer.CreateProtoProducer(cfg, protoproducer.CreateSamplingSystem)
	if err != nil {
		return nil, err
	}
	s := &exporterState{templates: netflow.CreateTemplateSystem(), prod: p}
	d.state[a] = s
	return s, nil
}

// Decode: one datagram (kind "netflow" - v9 or IPFIX by its version - or
// "sflow") from src, received at t -> its flows.
func (d *Decoder) Decode(kind string, payload []byte, src netip.AddrPort, t time.Time) ([]Row, error) {
	from := src.Addr().Unmap()
	st, err := d.exporterState(from)
	if err != nil {
		return nil, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	var msg any
	buf := bytes.NewBuffer(payload)
	switch kind {
	case "sflow":
		var p sflow.Packet
		if err := sflow.DecodeMessageVersion(buf, &p); err != nil {
			return nil, err
		}
		msg = &p
	default:
		if len(payload) < 2 {
			return nil, errors.New("short datagram")
		}
		switch binary.BigEndian.Uint16(payload) {
		case 9, 10:
			var v9 netflow.NFv9Packet
			var ipfix netflow.IPFIXPacket
			if err := netflow.DecodeMessageVersion(buf, st.templates, &v9, &ipfix); err != nil {
				return nil, err
			}
			if binary.BigEndian.Uint16(payload) == 9 {
				oneCounter(v9.FlowSets)
				msg = &v9
			} else {
				oneCounter(ipfix.FlowSets)
				msg = &ipfix
			}
		default: // v5 included: IPv4 only, fixed fields - every exporter in use does v9 or IPFIX
			return nil, errors.New("not NetFlow v9 or IPFIX")
		}
	}
	msgs, err := st.prod.Produce(msg, &producer.ProduceArgs{Src: src, SamplerAddress: from, TimeReceived: t})
	defer st.prod.Commit(msgs)
	if err != nil {
		return nil, err
	}
	rows := make([]Row, 0, len(msgs))
	for _, pm := range msgs {
		m, ok := pm.(*protoproducer.ProtoProducerMessage)
		if !ok {
			continue
		}
		exp := from
		if kind == "sflow" { // the agent, not whoever relayed the datagram
			if a, ok := netip.AddrFromSlice(m.SamplerAddress); ok {
				exp = a.Unmap()
			}
		}
		if r, ok := d.row(m, exp, t); ok {
			rows = append(rows, r)
		} else {
			d.stats.add(exp, "dropped_unknown_exporter", 1)
		}
	}
	return rows, nil
}

// oneCounter: records with both the in and the out counters - bytes 1 and 23,
// packets 2 and 24 (v9 IN_/OUT_BYTES, IPFIX octet/postOctetDeltaCount) - keep
// the in one when it counts something. goflow2 decodes both into the same
// field, the later one winning: OPNsense fills the in counters and sends the
// out ones as 0, which would leave every flow at 0 bytes.
func oneCounter(sets []any) {
	for _, s := range sets {
		ds, ok := s.(netflow.DataFlowSet)
		if !ok {
			continue
		}
		for i := range ds.Records {
			ds.Records[i].Values = dropOut(ds.Records[i].Values)
		}
	}
}

func dropOut(fields []netflow.DataField) []netflow.DataField {
	in := map[uint16]bool{}
	for _, f := range fields {
		if !f.PenProvided && (f.Type == 1 || f.Type == 2) && nonzero(f.Value) {
			in[f.Type] = true
		}
	}
	if !in[1] && !in[2] {
		return fields
	}
	out := fields[:0:0]
	for _, f := range fields {
		if !f.PenProvided && ((f.Type == 23 && in[1]) || (f.Type == 24 && in[2])) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func nonzero(v any) bool {
	b, ok := v.([]byte)
	if !ok {
		return false
	}
	for _, x := range b {
		if x != 0 {
			return true
		}
	}
	return false
}

func addr(b []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(b)
	return a
}

// mapped: an address as ClickHouse's IPv6 columns have it (IPv4 as ::ffff:a.b.c.d).
func mapped(a netip.Addr) string {
	if !a.IsValid() {
		return "::"
	}
	return netip.AddrFrom16(a.As16()).String()
}

func (d *Decoder) row(m *protoproducer.ProtoProducerMessage, exp netip.Addr, t time.Time) (Row, bool) {
	x := d.enr.exporter(exp)
	if x == nil {
		return Row{}, false
	}
	src, dst := addr(m.SrcAddr), addr(m.DstAddr)
	sn, dn := d.enr.network(src), d.enr.network(dst)
	scc, sas := d.enr.geo.lookup(src)
	dcc, das := d.enr.geo.lookup(dst)
	if m.SrcAs != 0 {
		sas = m.SrcAs
	}
	if m.DstAs != 0 {
		das = m.DstAs
	}
	in, out := x.iface(m.InIf), x.iface(m.OutIf)
	rate := m.SamplingRate
	if rate == 0 {
		rate = max(x.sampling, d.enr.defSample)
	}
	return Row{
		TimeReceived: uint32(t.Unix()), SamplingRate: rate,
		ExporterAddress: mapped(exp), ExporterName: x.name, ExporterRole: "host",
		SrcAddr: mapped(src), DstAddr: mapped(dst), SrcNetMask: uint8(m.SrcNet), DstNetMask: uint8(m.DstNet),
		SrcAS: sas, DstAS: das,
		SrcNetName: sn.Name, DstNetName: dn.Name, SrcNetRole: sn.Role, DstNetRole: dn.Role,
		SrcNetSite: sn.Site, DstNetSite: dn.Site, SrcNetRegion: sn.Region, DstNetRegion: dn.Region,
		SrcNetTenant: sn.Tenant, DstNetTenant: dn.Tenant, SrcCountry: scc, DstCountry: dcc,
		InIfName: in.Name, OutIfName: out.Name, InIfDescription: in.Description, OutIfDescription: out.Description,
		InIfSpeed: in.Speed, OutIfSpeed: out.Speed, InIfConnectivity: in.Connectivity, OutIfConnectivity: out.Connectivity,
		InIfProvider: in.Provider, OutIfProvider: out.Provider, InIfBoundary: in.Boundary, OutIfBoundary: out.Boundary,
		EType: m.Etype, Proto: m.Proto, SrcPort: uint16(m.SrcPort), DstPort: uint16(m.DstPort),
		Bytes: m.Bytes, Packets: m.Packets, ForwardingStatus: m.ForwardingStatus,
		TCPFlags: uint8(m.TcpFlags), SrcMAC: m.SrcMac, DstMAC: m.DstMac,
		SrcVlan: uint16(m.SrcVlan), DstVlan: uint16(m.DstVlan), ICMPType: uint8(m.IcmpType), ICMPCode: uint8(m.IcmpCode),
	}, true
}
