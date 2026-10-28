package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type client struct {
	cfg  Config
	http *http.Client
}

func newClient(cfg Config) *client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !cfg.TLSVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec - an explicit opt-out (SENTRY_TLS_VERIFY=0)
	}
	return &client{cfg: cfg, http: &http.Client{Timeout: 2 * time.Minute, Transport: tr}}
}

func (c *client) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.cfg.URL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sentry-lens-collector/"+Version)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, data)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *client) get(path string, out any) error         { return c.do("GET", path, nil, out) }
func (c *client) post(path string, body, out any) error { return c.do("POST", path, body, out) }

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// A credential Sentry Lens sends (snmp.py: for_collector).
type Credential struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Scope     []string `json:"scope"`
	Community string   `json:"community"`
	User      string   `json:"user"`
	Level     string   `json:"level"`
	AuthProto string   `json:"auth_proto"`
	AuthPass  string   `json:"auth_pass"`
	PrivProto string   `json:"priv_proto"`
	PrivPass  string   `json:"priv_pass"`
}

// fernetOpen opens a Fernet token Sentry Lens encrypted for this collector,
// with a key derived from its own key: sha256("sentry-lens-collector-creds:"
// + key) - its first half signs, its second half is the AES-128-CBC key.
func fernetOpen(key, token string) ([]byte, error) {
	k := sha256.Sum256([]byte("sentry-lens-collector-creds:" + key))
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil || len(raw) < 1+8+16+16+32 || raw[0] != 0x80 {
		return nil, errors.New("not a token")
	}
	body, sig := raw[:len(raw)-32], raw[len(raw)-32:]
	m := hmac.New(sha256.New, k[:16])
	m.Write(body)
	if !hmac.Equal(m.Sum(nil), sig) {
		return nil, errors.New("wrong key")
	}
	iv, ct := body[9:25], body[25:]
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("bad length")
	}
	block, err := aes.NewCipher(k[16:])
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(pt) {
		return nil, errors.New("bad padding")
	}
	return pt[:len(pt)-pad], nil
}

// decryptCredentials: the SNMP credentials Sentry Lens sent.
func decryptCredentials(key, token string) []Credential {
	if token == "" {
		return nil
	}
	pt, err := fernetOpen(key, token)
	if err != nil {
		log.Printf("can't read the credentials: %v", err)
		return nil
	}
	var creds []Credential
	if err := json.Unmarshal(pt, &creds); err != nil {
		log.Printf("can't read the credentials: %v", err)
		return nil
	}
	return creds
}

// ------------------------------------------------------------------ key rotation
// A rotated key is kept in the state folder with the hash of the key it
// replaced: it's used only while the configured key is still that one, so a
// reinstall with a fresh key (a replacement) wins over an old rotation.
type keyState struct {
	Key        string `json:"key"`
	ConfigHash string `json:"config_key_sha256"`
}

func hashKey(k string) string { s := sha256.Sum256([]byte(k)); return hex.EncodeToString(s[:]) }

// stateKey: the rotated key to use instead of the configured one ("" if none applies).
func stateKey(dir, configured string) string {
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "key.json"))
	if err != nil {
		return ""
	}
	var s keyState
	if json.Unmarshal(b, &s) != nil || !strings.HasPrefix(s.Key, "slc_") {
		return ""
	}
	if s.ConfigHash != hashKey(configured) {
		_ = os.Remove(filepath.Join(dir, "key.json")) // installed with another key since: that one wins
		return ""
	}
	return s.Key
}

// saveKey: keep a rotated key (atomically, owner-only).
func saveKey(dir, configured, key string) error {
	if dir == "" {
		return errors.New("no state folder (SENTRY_STATE) to keep a rotated key in")
	}
	b, _ := json.Marshal(keyState{Key: key, ConfigHash: hashKey(configured)})
	tmp := filepath.Join(dir, "key.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "key.json"))
}
