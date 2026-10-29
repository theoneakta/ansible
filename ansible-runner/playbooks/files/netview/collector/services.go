package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// What an open port says about itself - read by the posture checks
// (checks.py: TLS certificates and versions, old SSH, SMBv1, old web servers).
// Read-only probes: a handshake, a banner, one HEAD request, one SMB
// negotiation - never a login.
type Service struct {
	Port         int      `json:"port"`
	Kind         string   `json:"kind"`             // tls, ssh, http, smb, ftp, telnet
	Banner       string   `json:"banner,omitempty"` // the SSH / FTP greeting, the HTTP Server header
	TLS          []string `json:"tls,omitempty"`    // the versions it accepts: 1.0 1.1 1.2 1.3
	CertSubject  string   `json:"cert_subject,omitempty"`
	CertIssuer   string   `json:"cert_issuer,omitempty"`
	CertNotAfter int64    `json:"cert_not_after,omitempty"`
	SelfSigned   bool     `json:"self_signed,omitempty"`
	SMB1         bool     `json:"smb1,omitempty"`
}

var (
	tlsPorts  = map[int]bool{443: true, 444: true, 465: true, 636: true, 990: true, 993: true, 995: true, 8443: true}
	httpPorts = map[int]bool{80: true, 81: true, 3000: true, 5000: true, 8000: true, 8008: true, 8080: true, 8081: true,
		8888: true, 10000: true}
	tlsNames = map[uint16]string{tls.VersionTLS10: "1.0", tls.VersionTLS11: "1.1", tls.VersionTLS12: "1.2", tls.VersionTLS13: "1.3"}
)

const probeTimeout = 4 * time.Second

// services: what every open port of the hosts says (the ports it knows).
func services(hosts []*Host) {
	type job struct {
		h *Host
		p int
	}
	var jobs []job
	for _, h := range hosts {
		for _, p := range h.Ports {
			if p == 21 || p == 22 || p == 23 || p == 445 || tlsPorts[p] || httpPorts[p] {
				jobs = append(jobs, job{h, p})
			}
		}
	}
	var mu sync.Mutex
	parallel(jobs, 64, func(j job) {
		if s := probe(j.h.IP, j.p); s != nil {
			mu.Lock()
			j.h.Services = append(j.h.Services, *s)
			mu.Unlock()
		}
	})
}

func probe(ip string, port int) *Service {
	addr := net.JoinHostPort(ip, itoa(port))
	switch {
	case port == 22:
		if b := greeting(addr); strings.HasPrefix(b, "SSH-") {
			return &Service{Port: port, Kind: "ssh", Banner: b}
		}
	case port == 21:
		if b := greeting(addr); strings.HasPrefix(b, "220") {
			return &Service{Port: port, Kind: "ftp", Banner: b}
		}
	case port == 23:
		return &Service{Port: port, Kind: "telnet"}
	case port == 445:
		return &Service{Port: port, Kind: "smb", SMB1: smb1(addr)}
	case tlsPorts[port]:
		return tlsProbe(addr, port)
	case httpPorts[port]:
		if s, ok := httpServer("http://" + addr + "/"); ok {
			return &Service{Port: port, Kind: "http", Banner: s}
		}
	}
	return nil
}

// greeting: the first line a server sends (SSH, FTP).
func greeting(addr string) string {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

// handshake: a TLS handshake allowing only the versions given; the
// certificate (nil if it refused).
func handshake(addr string, min, max uint16) *tls.ConnectionState {
	suites := []uint16{}
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		suites = append(suites, s.ID)
	}
	d := &net.Dialer{Timeout: probeTimeout}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: min, MaxVersion: max,
		CipherSuites: suites})
	if err != nil {
		return nil
	}
	defer c.Close()
	st := c.ConnectionState()
	return &st
}

func tlsProbe(addr string, port int) *Service {
	st := handshake(addr, tls.VersionTLS10, tls.VersionTLS13)
	if st == nil || len(st.PeerCertificates) == 0 {
		return nil
	}
	cert := st.PeerCertificates[0]
	s := &Service{Port: port, Kind: "tls", CertSubject: cert.Subject.String(), CertIssuer: cert.Issuer.String(),
		CertNotAfter: cert.NotAfter.Unix(), SelfSigned: selfSigned(cert)}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		if v == st.Version || handshake(addr, v, v) != nil {
			s.TLS = append(s.TLS, tlsNames[v])
		}
	}
	if port == 443 || port == 8443 {
		if srv, ok := httpServer("https://" + addr + "/"); ok && srv != "" {
			s.Banner = srv
		}
	}
	return s
}

func selfSigned(c *x509.Certificate) bool {
	// (not CheckSignatureFrom: it refuses a certificate that isn't a CA, as most self-signed ones)
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// httpServer: the Server header of a HEAD / (ok: it spoke HTTP).
func httpServer(url string) (string, bool) {
	cl := &http.Client{Timeout: probeTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}}
	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Set("User-Agent", "sentry-collector/"+Version)
	r, err := cl.Do(req)
	if err != nil {
		return "", false
	}
	r.Body.Close()
	return strings.TrimSpace(r.Header.Get("Server")), true
}

// smb1: does the server accept an SMB1 negotiation (NT LM 0.12 only)?
// One that has SMB1 off drops the connection.
func smb1(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	dialect := append([]byte{0x02}, []byte("NT LM 0.12\x00")...)
	smb := []byte{0xff, 'S', 'M', 'B', 0x72, 0, 0, 0, 0, 0x18, 0x01, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0x2f, 0x4b, 0, 0, 0xc5, 0x5e, 0} // header, then WordCount 0
	smb = binary.LittleEndian.AppendUint16(smb, uint16(len(dialect)))
	smb = append(smb, dialect...)
	pkt := append([]byte{0, 0, 0, 0}, smb...)
	binary.BigEndian.PutUint32(pkt, uint32(len(smb))) // NetBIOS session message: type 0, 24-bit length
	if _, err := c.Write(pkt); err != nil {
		return false
	}
	b := make([]byte, 128)
	n, _ := c.Read(b)
	// NetBIOS 4, SMB header 32 (status at 5..8), WordCount, DialectIndex
	if n < 39 || !bytes.Equal(b[4:8], []byte{0xff, 'S', 'M', 'B'}) || b[8] != 0x72 {
		return false
	}
	return binary.LittleEndian.Uint32(b[9:13]) == 0 && b[36] > 0 && binary.LittleEndian.Uint16(b[37:39]) != 0xffff
}
