package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// The SSH host keys and TLS certificates of the machines the collector signs
// in to, trusted the first time and pinned after - a machine that shows
// another one never gets the login (pins.json in the state folder). A pin is
// let go when Sentry Lens says so (Trust the new key, on the Systems tab).
type pinStore struct {
	mu   sync.Mutex
	path string // "": kept in memory only (no state folder)
	pins map[string]string
}

func loadPins(dir string) *pinStore {
	p := &pinStore{pins: map[string]string{}}
	if dir != "" {
		p.path = filepath.Join(dir, "pins.json")
		if b, err := os.ReadFile(p.path); err == nil {
			_ = json.Unmarshal(b, &p.pins)
		}
	}
	return p
}

func (p *pinStore) save() {
	if p.path == "" {
		return
	}
	b, _ := json.MarshalIndent(p.pins, "", "  ")
	tmp := p.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p.path)
	}
}

// check: nil when id ("ssh 10.0.0.5:22") shows the pinned fingerprint, or has none yet (it's pinned now).
func (p *pinStore) check(id, fp string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch old, ok := p.pins[id]; {
	case !ok:
		p.pins[id] = fp
		p.save()
		return nil
	case old == fp:
		return nil
	default:
		return fmt.Errorf("pin: %s shows another key than the one first seen (%s, was %s) - "+
			"not signed in; if it was reinstalled, Trust the new key on the Systems tab", id, fp, old)
	}
}

// replace: a certificate that changed but is valid (a public CA's renewal) becomes the pin.
func (p *pinStore) replace(id, fp string) {
	p.mu.Lock()
	p.pins[id] = fp
	p.save()
	p.mu.Unlock()
}

// forget: the pins Sentry Lens let go ("ssh 10.0.0.5:22", ...).
func (p *pinStore) forget(ids []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, id := range ids {
		if _, ok := p.pins[id]; ok {
			delete(p.pins, id)
			n++
		}
	}
	if n > 0 {
		p.save()
	}
}

// pinnedTLS: a TLS config that accepts the server's certificate when its public
// key is the pinned one (or the first seen) - or when it's valid for a public CA,
// whatever its name (an ACME renewal), which then becomes the pin.
func pinnedTLS(p *pinStore, id string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec - verified below: pinned, or a public CA's
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no certificate")
			}
			leaf := cs.PeerCertificates[0]
			s := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
			err := p.check(id, fp)
			if err == nil {
				return nil
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, verr := leaf.Verify(x509.VerifyOptions{Intermediates: inter}); verr == nil {
				p.replace(id, fp)
				return nil
			}
			return err
		},
	}
}
