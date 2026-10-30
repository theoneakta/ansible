package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// What the machines say when the collector signs in with the read-only
// accounts Sentry Lens gives it (readonly_accounts.yml): Linux over SSH,
// Windows by WMI over WinRM, Proxmox by its API - at most once an hour each,
// sent raw (POST /api/collector/inventory); Sentry Lens reads them
// (inventory.py). What runs is fixed here, never sent by Sentry Lens.
const inventoryEvery = time.Hour

var inventoryKinds = map[string]int{"ssh": 22, "winrm": 5986, "proxmox": 8006}

type Reading struct {
	IP    string  `json:"ip"`
	Kind  string  `json:"kind"`
	Cred  string  `json:"cred"`
	OK    bool    `json:"ok"`
	Error string  `json:"error,omitempty"`
	Took  float64 `json:"took_s"`
	Data  any     `json:"data,omitempty"`
}

// The read-only script for Linux: sections "### name", read by inventory.py.
// Pending updates on dnf systems: from a copy of root's cache (dnf won't read it
// in place without root), the repositories this account may read.
const linuxScript = `LC_ALL=C; export LC_ALL
s() { echo "### $1"; }
s hostname; hostname 2>/dev/null || cat /proc/sys/kernel/hostname
s os; cat /etc/os-release 2>/dev/null
s uname; uname -srm
s uptime; cat /proc/uptime
s cpu; grep -m1 -E '^(model name|Hardware|Processor)' /proc/cpuinfo; grep -c ^processor /proc/cpuinfo
s mem; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
s disks; df -PTk -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs -x nsfs 2>/dev/null
s addrs; ip -o addr show 2>/dev/null
s listen; ss -Hlntu 2>/dev/null
s hw; systemd-detect-virt 2>/dev/null || echo none; cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null
s packages
if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Version}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print $2 "\t" $3}'
elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null
elif command -v apk >/dev/null 2>&1; then apk info -v 2>/dev/null; fi
s updates
if command -v apt >/dev/null 2>&1; then apt list --upgradable 2>/dev/null | grep -v '^Listing'
elif command -v dnf >/dev/null 2>&1 && [ -d /var/cache/dnf ] && T=$(mktemp -d 2>/dev/null); then
  for f in /var/cache/dnf/*; do
    if [ -d "$f" ]; then [ -r "$f/repodata" ] && mkdir -p "$T/${f##*/}" && cp -r "$f/repodata" "$T/${f##*/}/" 2>/dev/null
    else cp "$f" "$T/" 2>/dev/null; fi
  done
  D="timeout 120 dnf -q -C --setopt=cachedir=$T --setopt=skip_if_unavailable=True"
  $D check-update 2>/dev/null
  s security; $D updateinfo list --updates --security 2>/dev/null
  rm -rf "$T"
fi
s reboot; [ -f /var/run/reboot-required ] && echo required
if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1; echo "needs-restarting $?"; fi
s end
`

// What WMI is asked on Windows (root/cimv2 unless the class says otherwise).
var windowsQueries = []struct{ ns, name, q string }{
	{"root/cimv2", "os", "SELECT Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, InstallDate, CSName, TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem"},
	{"root/cimv2", "computer", "SELECT Manufacturer, Model, Domain, PartOfDomain, NumberOfLogicalProcessors, TotalPhysicalMemory FROM Win32_ComputerSystem"},
	{"root/cimv2", "bios", "SELECT SerialNumber, SMBIOSBIOSVersion FROM Win32_BIOS"},
	{"root/cimv2", "cpu", "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"},
	{"root/cimv2", "disks", "SELECT DeviceID, FileSystem, Size, FreeSpace, VolumeName FROM Win32_LogicalDisk WHERE DriveType = 3"},
	{"root/cimv2", "nics", "SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True"},
	{"root/cimv2", "hotfixes", "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering"},
	{"root/cimv2", "programs", "SELECT Name, Version, Vendor FROM Win32_InstalledWin32Program"},
	{"root/StandardCimv2", "listen", "SELECT LocalAddress, LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2"},
}

// inventoryAll: the hosts swept that a read-only login is in scope for and
// whose turn it is (last: when each ip+kind was last tried).
func inventoryAll(hosts []*Host, creds []Credential, pins *pinStore, last map[string]time.Time) []Reading {
	type job struct {
		ip    string
		kind  string
		creds []Credential
	}
	var jobs []job
	for _, h := range hosts {
		for kind := range inventoryKinds {
			if t, ok := last[h.IP+" "+kind]; ok && time.Since(t) < inventoryEvery {
				continue
			}
			var cs []Credential
			for _, c := range creds {
				if c.Kind == kind && inScope(h.IP, c) {
					cs = append(cs, c)
				}
			}
			if len(cs) == 0 {
				continue
			}
			// The one meant for this host first (the narrowest scope), the "everywhere" ones last.
			sort.SliceStable(cs, func(i, j int) bool { return narrowest(cs[i]) > narrowest(cs[j]) })
			jobs = append(jobs, job{h.IP, kind, cs})
		}
	}
	var mu sync.Mutex
	var out []Reading
	parallel(jobs, 8, func(j job) {
		mu.Lock()
		last[j.ip+" "+j.kind] = time.Now()
		mu.Unlock()
		var r *Reading
		for _, c := range j.creds {
			port := c.Port
			if port == 0 {
				port = inventoryKinds[j.kind]
			}
			addr := net.JoinHostPort(j.ip, strconv.Itoa(port))
			if len(c.Scope) == 0 && !tcpAlive(j.ip, []int{port}, 1500*time.Millisecond) {
				continue // an "everywhere" login: only where its port answers
			}
			t := time.Now()
			var data any
			var err error
			switch j.kind {
			case "ssh":
				data, err = sshRead(addr, c, pins)
			case "winrm":
				data, err = winrmRead(addr, c, pins)
			case "proxmox":
				data, err = proxmoxRead(addr, c, pins)
			}
			r = &Reading{IP: j.ip, Kind: j.kind, Cred: c.ID, OK: err == nil, Data: data, Took: time.Since(t).Seconds()}
			if err != nil {
				r.Error = err.Error()
				if len(r.Error) > 400 {
					r.Error = r.Error[:400]
				}
				if !strings.HasPrefix(r.Error, "pin:") {
					continue // the next login in scope, if any
				}
			}
			break
		}
		if r != nil {
			mu.Lock()
			out = append(out, *r)
			mu.Unlock()
		}
	})
	return out
}

func narrowest(c Credential) int {
	best := -1
	for _, s := range c.Scope {
		if _, n, err := net.ParseCIDR(s); err == nil {
			if o, _ := n.Mask.Size(); o > best {
				best = o
			}
		}
	}
	return best
}

// ------------------------------------------------------------------ Linux, over SSH
func sshRead(addr string, c Credential, pins *pinStore) (any, error) {
	var auths []ssh.AuthMethod
	if c.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(c.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("the private key: %v", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if c.Password != "" {
		auths = append(auths, ssh.Password(c.Password))
	}
	cfg := &ssh.ClientConfig{User: c.User, Auth: auths, Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			return pins.check("ssh "+addr, ssh.FingerprintSHA256(k))
		}}
	cl, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	sess, err := cl.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &limited{w: &out, n: 4 << 20}
	done := make(chan error, 1)
	go func() { done <- sess.Run(linuxScript) }()
	select {
	case err = <-done:
	case <-time.After(5 * time.Minute):
		return nil, errors.New("no answer in 5 minutes")
	}
	if !strings.Contains(out.String(), "### end") {
		if err == nil {
			err = errors.New("cut short")
		}
		return nil, fmt.Errorf("the script: %v", err)
	}
	sections := map[string]string{}
	name := ""
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "### ") {
			name = strings.TrimSpace(line[4:])
			sections[name] = ""
		} else if name != "" {
			sections[name] += line + "\n"
		}
	}
	delete(sections, "end")
	return sections, nil
}

type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	k := min(len(p), l.n)
	l.n -= k
	_, err := l.w.Write(p[:k])
	return len(p), err
}

// ------------------------------------------------------------------ Windows, WMI over WinRM
func winrmRead(addr string, c Credential, pins *pinStore) (any, error) {
	if !c.HTTPS {
		return nil, errors.New("WinRM over HTTP needs message encryption, which the collector doesn't do: use HTTPS (5986)")
	}
	tr := &http.Transport{TLSClientConfig: pinnedTLS(pins, "winrm "+addr), MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}
	defer tr.CloseIdleConnections()
	w := newWsman("https://"+addr+"/wsman", c.User, c.Password, tr)
	out := map[string]any{}
	errs := map[string]string{}
	for i, q := range windowsQueries {
		rows, err := w.query(q.ns, q.q)
		if err != nil {
			if i == 0 {
				return nil, err // the sign-in itself
			}
			errs[q.name] = err.Error()
			continue
		}
		out[q.name] = rows
	}
	if len(errs) > 0 {
		out["errors"] = errs
	}
	return out, nil
}

// ------------------------------------------------------------------ Proxmox VE, its API
func proxmoxRead(addr string, c Credential, pins *pinStore) (any, error) {
	tr := &http.Transport{TLSClientConfig: pinnedTLS(pins, "proxmox "+addr)}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Timeout: 30 * time.Second, Transport: tr}
	get := func(path string) (json.RawMessage, error) {
		req, _ := http.NewRequest("GET", "https://"+addr+"/api2/json"+path, nil)
		req.Header.Set("Authorization", "PVEAPIToken="+c.User+"="+c.Secret)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s: HTTP %d %.120s", path, resp.StatusCode, b)
		}
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			return nil, err
		}
		return env.Data, nil
	}
	out := map[string]json.RawMessage{}
	v, err := get("/version")
	if err != nil {
		return nil, err
	}
	out["/version"] = v
	for _, p := range []string{"/cluster/status", "/cluster/resources", "/nodes"} {
		if d, err := get(p); err == nil {
			out[p] = d
		}
	}
	var nodes []struct {
		Node   string `json:"node"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(out["/nodes"], &nodes)
	for _, n := range nodes {
		if n.Status == "online" {
			if d, err := get("/nodes/" + n.Node + "/status"); err == nil {
				out["/nodes/"+n.Node+"/status"] = d
			}
		}
	}
	// Each guest's settings (its MACs, its OS) and, for containers that run, their addresses.
	var res []struct {
		Type   string `json:"type"`
		Node   string `json:"node"`
		VMID   int    `json:"vmid"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(out["/cluster/resources"], &res)
	n := 0
	for _, r := range res {
		if (r.Type != "qemu" && r.Type != "lxc") || n >= 300 {
			continue
		}
		n++
		base := fmt.Sprintf("/nodes/%s/%s/%d", r.Node, r.Type, r.VMID)
		if d, err := get(base + "/config"); err == nil {
			out[base+"/config"] = d
		}
		if r.Type == "lxc" && r.Status == "running" {
			if d, err := get(base + "/interfaces"); err == nil {
				out[base+"/interfaces"] = d
			}
		}
	}
	return out, nil
}
