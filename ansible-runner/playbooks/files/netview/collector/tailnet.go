package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// A Tailscale range (inside 100.64.0.0/10) is swept as the machines tailscaled
// knows - itself and its peers, from its local API - when it runs here: a few
// addresses instead of a /16's 65,536 (24 minutes), and a /10 becomes possible.
// Without it, the usual sweep.
var tailscaleRange = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

const tailscaleSocket = "/var/run/tailscale/tailscaled.sock"

// tailnet: the tailnet's IPv4 addresses and their names; ok is false when tailscaled can't be asked.
func tailnet() (names map[string]string, ok bool) {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", tailscaleSocket)
		}}}
	resp, err := c.Get("http://local-tailscaled.sock/localapi/v0/status")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, false
	}
	type node struct {
		TailscaleIPs []string `json:"TailscaleIPs"`
		DNSName      string   `json:"DNSName"`
		HostName     string   `json:"HostName"`
	}
	var st struct {
		Self *node           `json:"Self"`
		Peer map[string]node `json:"Peer"`
	}
	if json.NewDecoder(resp.Body).Decode(&st) != nil {
		return nil, false
	}
	names = map[string]string{}
	add := func(n node) {
		name := strings.TrimSuffix(n.DNSName, ".")
		if name == "" {
			name = n.HostName
		}
		for _, ip := range n.TailscaleIPs {
			if a := net.ParseIP(ip); a != nil && a.To4() != nil {
				names[a.String()] = name
			}
		}
	}
	if st.Self != nil {
		add(*st.Self)
	}
	for _, p := range st.Peer {
		add(p)
	}
	return names, true
}

// tailnetIn: the tailnet's addresses in subnet (inside the Tailscale range - any size, a /10 too)
// and their names; false when it isn't such a subnet or tailscaled can't be asked.
func tailnetIn(subnet string) ([]net.IP, *net.IPNet, map[string]string, bool) {
	_, n, err := net.ParseCIDR(subnet)
	if err != nil || n.IP.To4() == nil || !tailscaleRange.Contains(n.IP) {
		return nil, nil, nil, false
	}
	names, ok := tailnet()
	if !ok {
		return nil, nil, nil, false
	}
	var out []net.IP
	for ip := range names {
		if a := net.ParseIP(ip); n.Contains(a) {
			out = append(out, a.To4())
		}
	}
	return out, n, names, true
}
