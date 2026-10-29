package main

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Enrichment - what a flow record doesn't say: the exporter's and its
// interfaces' names (static, like Akvorado's "static" metadata provider),
// whether an interface faces the internet, the networks' names and roles,
// and each address's country and AS (GeoIP files: DB-IP Lite, MaxMind or ipinfo).

type Iface struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Speed       uint32 `json:"speed"` // Mb/s
}

type Exporter struct {
	Name       string           `json:"name"`
	Default    Iface            `json:"default"`    // any interface not listed (softflowd: its only one)
	Interfaces map[string]Iface `json:"interfaces"` // by ifindex
	Sampling   uint64           `json:"sampling_rate"`
}

type Network struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Site   string `json:"site"`
	Region string `json:"region"`
	Tenant string `json:"tenant"`
}

// An interface as classified: Akvorado's interface-classifiers as Sentry
// Lens configures them - a description starting "Transit: " or "VPN: " faces
// the internet (boundary external, connectivity transit / vpn, provider its
// next word), everything else is internal.
type ifaceInfo struct {
	Iface
	Boundary     uint8 // 0 undefined, 1 external, 2 internal (Akvorado's Enum8)
	Connectivity string
	Provider     string
}

type Enricher struct {
	exporters map[netip.Addr]*exporterInfo
	dropOther bool
	networks  []netEntry // longest prefix first
	external  *regexp.Regexp
	provider  *regexp.Regexp
	geo       *geoDBs
	defSample uint64
}

type exporterInfo struct {
	name     string
	sampling uint64
	def      ifaceInfo
	ifaces   map[uint32]ifaceInfo
}

type netEntry struct {
	prefix netip.Prefix
	Network
}

func newEnricher(c *Config) (*Enricher, error) {
	e := &Enricher{exporters: map[netip.Addr]*exporterInfo{}, dropOther: c.DropUnknownExporters,
		defSample: max(c.DefaultSamplingRate, 1)}
	var err error
	if e.external, err = regexp.Compile(or(c.ExternalRegex, `^(?i)(transit|vpn): `)); err != nil {
		return nil, fmt.Errorf("external_regex: %w", err)
	}
	if e.provider, err = regexp.Compile(or(c.ProviderRegex, `^\S+?\s(\S+)`)); err != nil {
		return nil, fmt.Errorf("provider_regex: %w", err)
	}
	for a, x := range c.Exporters {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("exporter %q: %w", a, err)
		}
		info := &exporterInfo{name: or(x.Name, a), sampling: x.Sampling, def: e.classify(x.Default), ifaces: map[uint32]ifaceInfo{}}
		for idx, i := range x.Interfaces {
			n, err := strconv.ParseUint(idx, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("exporter %s: interface %q: not an ifindex", a, idx)
			}
			info.ifaces[uint32(n)] = e.classify(i)
		}
		e.exporters[addr.Unmap()] = info
	}
	for p, n := range c.Networks {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("network %q: %w", p, err)
		}
		e.networks = append(e.networks, netEntry{prefix.Masked(), n})
	}
	sort.Slice(e.networks, func(i, j int) bool { return e.networks[i].prefix.Bits() > e.networks[j].prefix.Bits() })
	e.geo = openGeo(c.GeoIP.Country, c.GeoIP.ASN)
	return e, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (e *Enricher) classify(i Iface) ifaceInfo {
	out := ifaceInfo{Iface: i, Boundary: 2}
	if m := e.external.FindStringSubmatch(i.Description); m != nil {
		out.Boundary = 1
		if len(m) > 1 {
			out.Connectivity = strings.ToLower(m[1])
		}
		if p := e.provider.FindStringSubmatch(i.Description); len(p) > 1 {
			out.Provider = strings.ToLower(p[1])
		}
	}
	return out
}

// exporter: the exporter's settings (nil: unknown, dropped if so configured).
func (e *Enricher) exporter(a netip.Addr) *exporterInfo {
	if x, ok := e.exporters[a.Unmap()]; ok {
		return x
	}
	if e.dropOther && len(e.exporters) > 0 {
		return nil
	}
	return &exporterInfo{name: a.Unmap().String(), def: ifaceInfo{Iface: Iface{Name: "unknown"}, Boundary: 2}}
}

// iface: an interface by its ifindex. 0 is no interface (the exporter's own
// traffic - a firewall's DNS answers): no name, internal, as Akvorado has it.
func (x *exporterInfo) iface(idx uint32) ifaceInfo {
	if idx == 0 {
		return ifaceInfo{Boundary: 2}
	}
	if i, ok := x.ifaces[idx]; ok {
		return i
	}
	return x.def
}

func (e *Enricher) network(a netip.Addr) Network {
	a = a.Unmap()
	for _, n := range e.networks {
		if n.prefix.Contains(a) {
			return n.Network
		}
	}
	return Network{}
}

// ------------------------------------------------------------------ GeoIP
// The country and AS of an address, from mmdb files: DB-IP Lite's or
// MaxMind's (GeoLite2) - the same layout - or ipinfo's (country, asn).
// Reopened when a file changes (flowd_stack.yml's timer replaces them weekly).

type geoDBs struct {
	mu                  sync.RWMutex
	countryPath, asPath string
	country, as         *maxminddb.Reader
	countryMod, asMod   time.Time
}

func openGeo(country, as string) *geoDBs {
	g := &geoDBs{countryPath: country, asPath: as}
	g.reload()
	go func() {
		for range time.Tick(10 * time.Minute) {
			g.reload()
		}
	}()
	return g
}

func (g *geoDBs) reload() {
	open := func(path string, cur *maxminddb.Reader, mod time.Time) (*maxminddb.Reader, time.Time) {
		if path == "" {
			return cur, mod
		}
		st, err := os.Stat(path)
		if err != nil || !st.ModTime().After(mod) {
			return cur, mod
		}
		r, err := maxminddb.Open(path)
		if err != nil {
			log.Printf("geoip %s: %v", path, err)
			return cur, mod
		}
		log.Printf("geoip: loaded %s (%s)", path, r.Metadata.DatabaseType)
		return r, st.ModTime()
	}
	c, cm := open(g.countryPath, g.country, g.countryMod)
	a, am := open(g.asPath, g.as, g.asMod)
	g.mu.Lock()
	old := []*maxminddb.Reader{}
	if c != g.country && g.country != nil {
		old = append(old, g.country)
	}
	if a != g.as && g.as != nil {
		old = append(old, g.as)
	}
	g.country, g.countryMod, g.as, g.asMod = c, cm, a, am
	g.mu.Unlock()
	for _, r := range old {
		go func(r *maxminddb.Reader) { time.Sleep(time.Minute); r.Close() }(r) // lookups in flight finish first
	}
}

// lookup: the address's two-letter country and AS number ("", 0 if unknown).
func (g *geoDBs) lookup(a netip.Addr) (string, uint32) {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return "", 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	var cc string
	var asn uint32
	if g.country != nil {
		var m map[string]any
		if g.country.Lookup(a).Decode(&m) == nil {
			cc = countryOf(m)
		}
	}
	if g.as != nil {
		var m map[string]any
		if g.as.Lookup(a).Decode(&m) == nil {
			asn = asnOf(m)
		}
	}
	return cc, asn
}

func countryOf(m map[string]any) string {
	switch v := m["country"].(type) {
	case string: // ipinfo: "country": "CA"
		return strings.ToUpper(v)
	case map[string]any: // MaxMind: "country": {"iso_code": "CA"}
		if s, ok := v["iso_code"].(string); ok {
			return s
		}
	}
	if s, ok := m["country_code"].(string); ok {
		return strings.ToUpper(s)
	}
	return ""
}

func asnOf(m map[string]any) uint32 {
	switch v := m["asn"].(type) { // ipinfo: "asn": "AS13335"
	case string:
		n, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(v), "AS"), 10, 32)
		return uint32(n)
	}
	switch v := m["autonomous_system_number"].(type) { // MaxMind
	case uint64:
		return uint32(v)
	case uint32:
		return v
	}
	return 0
}
