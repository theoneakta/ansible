package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gosnmp/gosnmp"
)

const (
	oSys      = ".1.3.6.1.2.1.1"
	oIf       = ".1.3.6.1.2.1.2.2.1"
	oIfX      = ".1.3.6.1.2.1.31.1.1.1"
	oEnt      = ".1.3.6.1.2.1.47.1.1.1.1"
	oBasePort = ".1.3.6.1.2.1.17.1.4.1.2"
	oDFdb     = ".1.3.6.1.2.1.17.4.3.1.2"
	oQFdb     = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	oArp      = ".1.3.6.1.2.1.4.22.1.2"
	oLldpLoc  = ".1.0.8802.1.1.2.1.3.7.1"
	oLldpRem  = ".1.0.8802.1.1.2.1.4.1.1"
	oLldpMan  = ".1.0.8802.1.1.2.1.4.2.1"
	oCdp      = ".1.3.6.1.4.1.9.9.23.1.2.1.1"
	oHrDescr  = ".1.3.6.1.2.1.25.3.2.1.3"
	oHrType   = ".1.3.6.1.2.1.25.3.2.1.2"
)

var authProtos = map[string]gosnmp.SnmpV3AuthProtocol{"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA-224": gosnmp.SHA224,
	"SHA-256": gosnmp.SHA256, "SHA-384": gosnmp.SHA384, "SHA-512": gosnmp.SHA512}
var privProtos = map[string]gosnmp.SnmpV3PrivProtocol{"DES": gosnmp.DES, "AES": gosnmp.AES, "AES-192": gosnmp.AES192,
	"AES-256": gosnmp.AES256}

func session(ip string, c Credential, timeout time.Duration, retries int) (*gosnmp.GoSNMP, error) {
	g := &gosnmp.GoSNMP{Target: ip, Port: 161, Timeout: timeout, Retries: retries, MaxRepetitions: 25, MaxOids: 60}
	if c.Kind == "snmp_v2c" {
		g.Version, g.Community = gosnmp.Version2c, c.Community
	} else {
		g.Version, g.SecurityModel = gosnmp.Version3, gosnmp.UserSecurityModel
		p := &gosnmp.UsmSecurityParameters{UserName: c.User}
		g.MsgFlags = gosnmp.NoAuthNoPriv
		if c.AuthPass != "" {
			p.AuthenticationProtocol, p.AuthenticationPassphrase = authProtos[c.AuthProto], c.AuthPass
			g.MsgFlags = gosnmp.AuthNoPriv
			if c.PrivPass != "" {
				p.PrivacyProtocol, p.PrivacyPassphrase = privProtos[c.PrivProto], c.PrivPass
				g.MsgFlags = gosnmp.AuthPriv
			}
		}
		g.SecurityParameters = p
	}
	return g, g.Connect()
}

func inScope(ip string, c Credential) bool {
	if len(c.Scope) == 0 {
		return true
	}
	a := net.ParseIP(ip)
	for _, s := range c.Scope {
		if _, n, err := net.ParseCIDR(s); err == nil && n.Contains(a) {
			return true
		}
	}
	return false
}

// snmpProbe: the first credential each device answers (sysObjectID), by address.
func snmpProbe(ips []string, creds []Credential) map[string]Credential {
	out := map[string]Credential{}
	var mu sync.Mutex
	parallel(ips, 32, func(ip string) {
		for _, c := range creds {
			if !inScope(ip, c) {
				continue
			}
			g, err := session(ip, c, time.Second, 0)
			if err != nil {
				continue
			}
			r, err := g.Get([]string{oSys + ".2.0"})
			g.Conn.Close()
			if err == nil && len(r.Variables) == 1 && r.Variables[0].Type == gosnmp.ObjectIdentifier {
				mu.Lock()
				out[ip] = c
				mu.Unlock()
				return
			}
		}
	})
	return out
}

// text: an SNMP value as text (printable strings as they are, other bytes as hex).
func text(v gosnmp.SnmpPDU) string {
	switch x := v.Value.(type) {
	case []byte:
		s := string(x)
		for _, r := range s {
			if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
				return fmt.Sprintf("% x", x)
			}
		}
		return strings.TrimRight(s, "\x00")
	case string:
		return strings.TrimPrefix(x, ".")
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func number(v gosnmp.SnmpPDU) uint64 {
	if v.Value == nil {
		return 0
	}
	if b := gosnmp.ToBigInt(v.Value); b != nil && b.Sign() >= 0 {
		return b.Uint64()
	}
	return 0
}

func macOf(v gosnmp.SnmpPDU) string {
	if b, ok := v.Value.([]byte); ok && len(b) == 6 {
		return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
	}
	return ""
}

// walk: a table column (or subtree), by index suffix.
func walk(g *gosnmp.GoSNMP, oid string) map[string]gosnmp.SnmpPDU {
	out := map[string]gosnmp.SnmpPDU{}
	pdus, err := g.BulkWalkAll(oid)
	if err != nil {
		return out
	}
	for _, p := range pdus {
		if strings.HasPrefix(p.Name, oid+".") && p.Type != gosnmp.NoSuchObject && p.Type != gosnmp.NoSuchInstance && p.Type != gosnmp.EndOfMibView {
			out[p.Name[len(oid)+1:]] = p
		}
	}
	return out
}

func atoi(s string) uint64 {
	var n uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + uint64(r-'0')
	}
	return n
}

// snmpRead: everything this stage reads of a device (assets/snmp.py: ingest).
func snmpRead(ip string, c Credential) map[string]any {
	g, err := session(ip, c, 2*time.Second, 1)
	if err != nil {
		return nil
	}
	defer g.Conn.Close()
	sys := map[string]any{}
	if r, err := g.Get([]string{oSys + ".1.0", oSys + ".2.0", oSys + ".3.0", oSys + ".4.0", oSys + ".5.0", oSys + ".6.0"}); err == nil {
		v := map[string]gosnmp.SnmpPDU{}
		for _, p := range r.Variables {
			v[p.Name] = p
		}
		sys = map[string]any{"descr": text(v[oSys+".1.0"]), "object_id": "." + text(v[oSys+".2.0"]), "uptime_s": number(v[oSys+".3.0"]) / 100,
			"contact": text(v[oSys+".4.0"]), "name": text(v[oSys+".5.0"]), "location": text(v[oSys+".6.0"])}
	}
	// Model, serial, firmware: the first chassis in ENTITY-MIB, else the host resources' printer (model) or processor (hardware).
	ent := map[int]map[string]gosnmp.SnmpPDU{}
	for _, col := range []int{2, 5, 8, 9, 10, 11, 12, 13} {
		ent[col] = walk(g, fmt.Sprintf("%s.%d", oEnt, col))
	}
	entity := map[string]any{}
	idx := ""
	for i, v := range ent[5] {
		if number(v) == 3 && (idx == "" || atoi(i) < atoi(idx)) {
			idx = i
		}
	}
	if idx != "" {
		model := text(ent[13][idx])
		if model == "" {
			model = text(ent[2][idx])
		}
		fw := text(ent[9][idx])
		if fw == "" {
			fw = text(ent[10][idx])
		}
		entity = map[string]any{"model": model, "serial": text(ent[11][idx]), "firmware": fw, "hardware": text(ent[8][idx]), "mfg": text(ent[12][idx])}
	}
	if entity["model"] == nil || entity["model"] == "" {
		hr, types := walk(g, oHrDescr), walk(g, oHrType)
		for i, t := range types {
			s := text(t)
			if strings.HasSuffix(s, "25.3.1.5") {
				entity["model"] = text(hr[i])
			} else if strings.HasSuffix(s, "25.3.1.3") && entity["hardware"] == nil {
				entity["hardware"] = text(hr[i])
			}
		}
	}
	// Interfaces.
	col := func(base string, n int) map[string]gosnmp.SnmpPDU { return walk(g, fmt.Sprintf("%s.%d", base, n)) }
	descr, typ, spd, phys, admin, oper := col(oIf, 2), col(oIf, 3), col(oIf, 5), col(oIf, 6), col(oIf, 7), col(oIf, 8)
	name, high, alias := col(oIfX, 1), col(oIfX, 15), col(oIfX, 18)
	ifs := []map[string]any{}
	for i, d := range descr {
		sp := number(high[i])
		if sp == 0 {
			sp = number(spd[i]) / 1_000_000
		}
		ifs = append(ifs, map[string]any{"index": atoi(i), "descr": text(d), "name": text(name[i]), "alias": text(alias[i]),
			"type": number(typ[i]), "speed_mbps": sp, "mac": macOf(phys[i]), "admin": number(admin[i]), "oper": number(oper[i])})
	}
	// The bridge's MAC table: Q-BRIDGE (per VLAN), else BRIDGE; bridge ports -> interfaces.
	base := map[string]uint64{}
	for k, v := range walk(g, oBasePort) {
		base[k] = number(v)
	}
	ifOf := func(port uint64) uint64 {
		if i, ok := base[fmt.Sprint(port)]; ok {
			return i
		}
		return port
	}
	fdb := []map[string]any{}
	for k, v := range walk(g, oQFdb) {
		p := strings.Split(k, ".")
		if len(p) == 7 && number(v) > 0 {
			fdb = append(fdb, map[string]any{"vlan": atoi(p[0]), "mac": macFromDecimal(p[1:]), "if_index": ifOf(number(v))})
		}
	}
	if len(fdb) == 0 {
		for k, v := range walk(g, oDFdb) {
			p := strings.Split(k, ".")
			if len(p) == 6 && number(v) > 0 {
				fdb = append(fdb, map[string]any{"vlan": 0, "mac": macFromDecimal(p), "if_index": ifOf(number(v))})
			}
		}
	}
	// ARP.
	arp := []map[string]any{}
	for k, v := range walk(g, oArp) {
		p := strings.Split(k, ".")
		if m := macOf(v); len(p) == 5 && m != "" {
			arp = append(arp, map[string]any{"if_index": atoi(p[0]), "ip": strings.Join(p[1:], "."), "mac": m})
		}
	}
	// LLDP neighbors (index timeMark.localPort.remIndex), then CDP's.
	nb := []map[string]any{}
	locID, locDesc := col(oLldpLoc, 3), col(oLldpLoc, 4)
	rem := map[int]map[string]gosnmp.SnmpPDU{}
	for _, c := range []int{5, 7, 8, 9, 10} {
		rem[c] = col(oLldpRem, c)
	}
	mgmt := map[string]string{}
	for k := range col(oLldpMan, 3) {
		p := strings.Split(k, ".")
		if len(p) >= 9 && p[3] == "1" && p[4] == "4" {
			mgmt[strings.Join(p[:3], ".")] = strings.Join(p[5:9], ".")
		}
	}
	for k, n := range rem[9] {
		p := strings.Split(k, ".")
		if len(p) != 3 {
			continue
		}
		lp := p[1]
		port := text(locDesc[lp])
		if port == "" {
			port = text(locID[lp])
		}
		chassis := macOf(rem[5][k])
		if chassis == "" {
			chassis = text(rem[5][k])
		}
		nb = append(nb, map[string]any{"proto": "lldp", "local_if": ifOf(atoi(lp)), "local_port": port, "remote_name": text(n),
			"remote_port": text(rem[7][k]), "remote_port_descr": text(rem[8][k]), "remote_chassis": chassis,
			"remote_mgmt": mgmt[k], "remote_descr": text(rem[10][k])})
	}
	cdpAddr, cdpDev, cdpPort, cdpPlat := col(oCdp, 4), col(oCdp, 6), col(oCdp, 7), col(oCdp, 8)
	for k, d := range cdpDev {
		addr := ""
		if b, ok := cdpAddr[k].Value.([]byte); ok && len(b) == 4 {
			addr = net.IP(b).String()
		}
		nb = append(nb, map[string]any{"proto": "cdp", "local_if": atoi(strings.Split(k, ".")[0]), "local_port": "", "remote_name": text(d),
			"remote_port": text(cdpPort[k]), "remote_port_descr": "", "remote_chassis": "", "remote_mgmt": addr, "remote_descr": text(cdpPlat[k])})
	}
	return map[string]any{"ip": ip, "cred": c.ID, "system": sys, "entity": entity, "interfaces": ifs, "fdb": fdb, "arp": arp, "neighbors": nb,
		"tables": readProfiles(g, getProfiles())}
}

// A profile from Sentry Lens (snmp.py PROFILES): an OID table, or a group of
// scalars, it wants from every SNMP device - read generically, so a new one
// needs no new collector. Columns are [name, OID]: relative to Base, or
// absolute when they start with "."; the first one tells whether the device
// has the table at all.
type Profile struct {
	ID      string      `json:"id"`
	Base    string      `json:"base"`
	Columns [][2]string `json:"columns"`
	Scalar  bool        `json:"scalar"`
}

var (
	profilesMu sync.Mutex
	profiles   []Profile // the latest from Sentry Lens (main.go)
)

func setProfiles(p []Profile) { profilesMu.Lock(); profiles = p; profilesMu.Unlock() }
func getProfiles() []Profile  { profilesMu.Lock(); defer profilesMu.Unlock(); return profiles }

func colOID(p Profile, c string) string {
	if strings.HasPrefix(c, ".") {
		return c
	}
	return p.Base + "." + c
}

// value: a number as a number (INTEGER may be negative: "unknown" in many MIBs), the rest as text.
func value(v gosnmp.SnmpPDU) any {
	switch v.Type {
	case gosnmp.Integer:
		if b := gosnmp.ToBigInt(v.Value); b != nil {
			return b.Int64()
		}
		return 0
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Counter64, gosnmp.TimeTicks, gosnmp.Uinteger32:
		return number(v)
	}
	return text(v)
}

func present(v gosnmp.SnmpPDU) bool {
	return v.Type != gosnmp.NoSuchObject && v.Type != gosnmp.NoSuchInstance && v.Type != gosnmp.EndOfMibView && v.Type != gosnmp.Null
}

// readProfiles: {profile: {row index: {column: value}}} - only what the device has.
func readProfiles(g *gosnmp.GoSNMP, ps []Profile) map[string]map[string]map[string]any {
	out := map[string]map[string]map[string]any{}
	for _, p := range ps {
		if len(p.Columns) == 0 {
			continue
		}
		rows := map[string]map[string]any{}
		if p.Scalar {
			oids := make([]string, len(p.Columns))
			for i, c := range p.Columns {
				oids[i] = colOID(p, c[1])
			}
			row := map[string]any{}
			for start := 0; start < len(oids); start += 20 {
				end := min(start+20, len(oids))
				r, err := g.Get(oids[start:end])
				if err != nil {
					continue
				}
				for _, v := range r.Variables {
					for i := start; i < end; i++ {
						if v.Name == oids[i] && present(v) {
							row[p.Columns[i][0]] = value(v)
						}
					}
				}
			}
			if len(row) > 0 {
				rows["0"] = row
			}
		} else {
			for i, c := range p.Columns {
				col := walk(g, colOID(p, c[1]))
				if i == 0 && len(col) == 0 {
					break // not on this device
				}
				for idx, v := range col {
					if rows[idx] == nil {
						// Rows come from the first column: a later one may be
						// another table (names by the same index) with more.
						if i > 0 || len(rows) >= 500 {
							continue
						}
						rows[idx] = map[string]any{}
					}
					rows[idx][c[0]] = value(v)
				}
			}
		}
		if len(rows) > 0 {
			out[p.ID] = rows
		}
	}
	return out
}

func macFromDecimal(p []string) string {
	b := make([]string, len(p))
	for i, x := range p {
		b[i] = fmt.Sprintf("%02X", atoi(x))
	}
	return strings.Join(b, ":")
}

func snmpReadAll(found map[string]Credential) []map[string]any {
	type pair struct {
		ip string
		c  Credential
	}
	var jobs []pair
	for ip, c := range found {
		jobs = append(jobs, pair{ip, c})
	}
	var mu sync.Mutex
	out := []map[string]any{}
	parallel(jobs, 8, func(j pair) {
		if r := snmpRead(j.ip, j.c); r != nil {
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}
	})
	return out
}

// snmpCounters: [[ifIndex, in, out, in errors, out errors, oper status]] - 64-bit counters where the device has them.
func snmpCounters(ip string, c Credential) [][]uint64 {
	g, err := session(ip, c, 2*time.Second, 1)
	if err != nil {
		return nil
	}
	defer g.Conn.Close()
	hin, hout := walk(g, oIfX+".6"), walk(g, oIfX+".10")
	if len(hin) == 0 {
		hin, hout = walk(g, oIf+".10"), walk(g, oIf+".16")
	}
	ie, oe, op := walk(g, oIf+".14"), walk(g, oIf+".20"), walk(g, oIf+".8")
	out := [][]uint64{}
	for i, v := range hin {
		out = append(out, []uint64{atoi(i), number(v), number(hout[i]), number(ie[i]), number(oe[i]), number(op[i])})
	}
	return out
}

func snmpCountersAll(found map[string]Credential) []map[string]any {
	type pair struct {
		ip string
		c  Credential
	}
	var jobs []pair
	for ip, c := range found {
		jobs = append(jobs, pair{ip, c})
	}
	var mu sync.Mutex
	out := []map[string]any{}
	parallel(jobs, 8, func(j pair) {
		ifs := snmpCounters(j.ip, j.c)
		mu.Lock()
		out = append(out, map[string]any{"ip": j.ip, "ifs": ifs})
		mu.Unlock()
	})
	return out
}
