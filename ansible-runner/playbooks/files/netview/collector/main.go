// Sentry Lens collector: sweeps its subnets, reads the devices that answer
// SNMP, signs in to the machines it has a read-only login for (SSH, WinRM,
// Proxmox), and posts what it finds to Sentry Lens - outgoing connections only.
//
//	every minute  GET  /api/collector/config     its subnets and their schedule, credentials (a heartbeat too)
//	every sweep   POST /api/collector/results    the devices found
//	              POST /api/collector/snmp       what the SNMP devices said
//	every 5 min   POST /api/collector/counters   their interface counters
//	hourly        POST /api/collector/inventory  what the machines with a read-only login say (inventory.go)
//
// One program for Linux, Windows and Docker, no dependencies: discovery with
// what each OS offers (ARP through the kernel, ping, TCP), ports by TCP
// connection, names from DNS and NetBIOS, SNMP v1/v2c/v3 with gosnmp.
//
//	sentry-collector run [--config FILE]       run in the foreground (systemd, Docker)
//	sentry-collector install --config FILE     Windows: register and start the service
//	sentry-collector uninstall                 Windows: stop and remove the service
//	sentry-collector scan SUBNET               one sweep, printed (a test)
//	sentry-collector probe ADDRESS PORT        what one port says (a test)
//	sentry-collector version
//
// Settings: SENTRY_URL, SENTRY_KEY, SENTRY_TLS_VERIFY from the environment,
// or KEY=VALUE lines in the --config file.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const Version = "2.6.0"

type Config struct {
	URL       string
	Key       string // the key in use (a rotated one, else the configured one)
	ConfigKey string // the configured key
	TLSVerify bool
	LogFile   string
	StateDir  string // where a rotated key is kept
}

// What Sentry Lens sends at every contact.
type Remote struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Subnets       []string `json:"subnets"`
	IntervalMin   int      `json:"interval_min"`
	CountersMin   int      `json:"counters_min"`
	Credentials   string   `json:"credentials"`
	CredentialCnt int      `json:"credential_count"`
	NewKey        string   `json:"new_key"`
	ForgetPins    []string `json:"forget_pins"` // pins let go: Trust the new key (pins.go)
	Update        string   `json:"update"` // the version to update to (Update on the page; update.go)
	Profiles      []Profile `json:"snmp_profiles"` // what to read beyond the basics (snmp.go)
	Schedule      []struct {
		Subnet   string `json:"subnet"`
		EveryMin int    `json:"every_min"` // 0: on demand only
	} `json:"schedule"` // each subnet's own interval (none: all of them every IntervalMin)
	SweepNow *struct {
		ID      string   `json:"id"`
		Subnets []string `json:"subnets"` // none: all of them
	} `json:"sweep_now"` // a sweep asked for on the Collectors page
}

// due: the subnets to sweep now - those whose interval has passed since
// their last sweep, and those a sweep asked for on the page covers.
func due(r Remote, last map[string]time.Time, done string) (subnets []string, forced string) {
	want := map[string]bool{}
	if r.SweepNow != nil && r.SweepNow.ID != done {
		forced = r.SweepNow.ID
		for _, s := range r.SweepNow.Subnets {
			want[s] = true
		}
		if len(r.SweepNow.Subnets) == 0 {
			for _, s := range r.Subnets {
				want[s] = true
			}
		}
	}
	if r.Schedule == nil { // an older Sentry Lens: all of them, every IntervalMin
		for _, s := range r.Subnets {
			if time.Since(last[s]) >= time.Duration(r.IntervalMin)*time.Minute {
				want[s] = true
			}
		}
	}
	for _, s := range r.Schedule {
		if s.EveryMin > 0 && time.Since(last[s.Subnet]) >= time.Duration(s.EveryMin)*time.Minute {
			want[s.Subnet] = true
		}
	}
	for _, s := range r.Subnets { // in its order
		if want[s] {
			subnets = append(subnets, s)
		}
	}
	return subnets, forced
}

// within: whether ip is in one of the subnets.
func within(ip string, subnets []string) bool {
	a := net.ParseIP(ip)
	for _, s := range subnets {
		if _, n, err := net.ParseCIDR(s); err == nil && a != nil && n.Contains(a) {
			return true
		}
	}
	return false
}

func loadConfig(path string) (Config, error) {
	c := Config{URL: os.Getenv("SENTRY_URL"), Key: os.Getenv("SENTRY_KEY"), TLSVerify: os.Getenv("SENTRY_TLS_VERIFY") != "0",
		StateDir: os.Getenv("SENTRY_STATE")}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			k, v, _ := strings.Cut(line, "=")
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.TrimSpace(k) {
			case "SENTRY_URL":
				c.URL = v
			case "SENTRY_KEY":
				c.Key = v
			case "SENTRY_TLS_VERIFY":
				c.TLSVerify = v != "0" && v != "false"
			case "SENTRY_LOG":
				c.LogFile = v
			case "SENTRY_STATE":
				c.StateDir = v
			}
		}
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if c.URL == "" || !strings.HasPrefix(c.Key, "slc_") {
		return c, fmt.Errorf("SENTRY_URL and SENTRY_KEY are needed (Sentry Lens > Assets > Collectors > Add)")
	}
	if c.StateDir == "" && path != "" && runtime.GOOS == "windows" {
		c.StateDir = filepath.Dir(path) // ProgramData\SentryLens, where the service may write
	}
	c.ConfigKey = c.Key
	if k := stateKey(c.StateDir, c.Key); k != "" {
		c.Key = k
	}
	return c, nil
}

// setupLog: stdout, or a file kept under 5 MB (the Windows service).
func setupLog(path string) {
	if path == "" {
		log.SetOutput(os.Stdout)
		return
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 5<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err == nil {
		log.SetOutput(io.MultiWriter(f))
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	cfgPath := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			cfgPath = args[i+1]
			i++
		}
	}
	switch cmd {
	case "version":
		fmt.Println("sentry-collector", Version)
	case "scan":
		if len(args) == 0 {
			fmt.Println("usage: sentry-collector scan SUBNET")
			os.Exit(2)
		}
		hosts := sweep([]string{args[0]})
		out, _ := json.MarshalIndent(hosts, "", "  ")
		fmt.Println(string(out))
	case "probe": // a test: what one port says
		if len(args) < 2 {
			fmt.Println("usage: sentry-collector probe ADDRESS PORT")
			os.Exit(2)
		}
		port, _ := strconv.Atoi(args[1])
		out, _ := json.MarshalIndent(probe(args[0], port), "", "  ")
		fmt.Println(string(out))
	case "snmp": // a test: what a device says with a v2c community
		if len(args) < 2 {
			fmt.Println("usage: sentry-collector snmp ADDRESS COMMUNITY")
			os.Exit(2)
		}
		r := snmpRead(args[0], Credential{ID: "test", Kind: "snmp_v2c", Community: args[1]})
		if r == nil {
			fmt.Println("no answer")
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(out))
	case "install", "uninstall":
		if err := serviceCommand(cmd, cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "run":
		if runAsService(cfgPath) { // Windows: started by the service manager
			return
		}
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		setupLog(cfg.LogFile)
		loop(cfg, make(chan struct{}))
	default:
		fmt.Println("commands: run, install, uninstall, scan SUBNET, probe ADDRESS PORT, snmp ADDRESS COMMUNITY, version")
		os.Exit(2)
	}
}

// loop: contact Sentry Lens every minute, sweep and read SNMP when due,
// poll counters when due - until stop closes.
func loop(cfg Config, stop chan struct{}) {
	client := newClient(cfg)
	log.Printf("Sentry Lens collector %s -> %s", Version, cfg.URL)
	var lastCounters time.Time
	lastSweep := map[string]time.Time{} // subnet -> its last sweep
	var forcedDone string               // the last sweep asked for on the page, done
	var lastRefused time.Time // a refused key is said once an hour, not every minute
	var lastUpdate time.Time  // an update asked of the updater: again after 30 minutes if it didn't happen
	how := updater(cfg)
	var agentsMu sync.Mutex
	agents := map[string]Credential{} // ip -> the credential it answered, from the last sweep
	pins := loadPins(cfg.StateDir)
	lastInventory := map[string]time.Time{} // "ip kind" -> when it was last read (inventory.go)
	var inventoryMu sync.Mutex              // guards lastInventory
	var inventoryRunning atomic.Bool        // one round at a time, beside the minute loop
	for {
		var r Remote
		if err := client.get("/api/collector/config?version="+Version+"&updater="+how, &r); err != nil {
			if strings.HasPrefix(err.Error(), "HTTP 401") {
				if time.Since(lastRefused) >= time.Hour {
					log.Printf("Sentry Lens refuses this collector's key (%v): it was replaced, or the collector deleted - "+
						"run the install line from Assets > Collectors again (it keeps asking every minute)", err)
					lastRefused = time.Now()
				}
			} else {
				log.Printf("can't reach Sentry Lens: %v", err)
			}
		} else {
			used := client.cfg.Key // what this answer was encrypted for
			if r.NewKey != "" { // Sentry Lens rotated our key: keep it, then use it
				if nk, err := fernetOpen(client.cfg.Key, r.NewKey); err != nil {
					log.Printf("can't read the rotated key: %v", err)
				} else if err := saveKey(cfg.StateDir, cfg.ConfigKey, string(nk)); err != nil {
					log.Printf("can't keep the rotated key: %v", err)
				} else {
					client.cfg.Key, cfg.Key = string(nk), string(nk)
					log.Printf("key rotated")
				}
			}
			if r.Update != "" && r.Update != Version && time.Since(lastUpdate) >= 30*time.Minute {
				lastUpdate = time.Now()
				switch err := requestUpdate(cfg, r.Update); {
				case errors.Is(err, errRestart):
					log.Printf("updating to %s: restarting (the container fetches it)", r.Update)
					return
				case err != nil:
					log.Printf("can't update to %s: %v", r.Update, err)
				default:
					log.Printf("updating to %s: asked the updater", r.Update)
				}
			}
			creds := decryptCredentials(used, r.Credentials)
			if len(r.ForgetPins) > 0 {
				pins.forget(r.ForgetPins)
				for _, id := range r.ForgetPins { // read again at the next sweep: "ssh 10.0.0.5:22" -> "10.0.0.5 ssh"
					if kind, addr, ok := strings.Cut(id, " "); ok {
						if host, _, err := net.SplitHostPort(addr); err == nil {
							inventoryMu.Lock()
							delete(lastInventory, host+" "+kind)
							inventoryMu.Unlock()
						}
					}
				}
			}
			if r.Profiles != nil {
				setProfiles(r.Profiles)
			}
			if r.IntervalMin <= 0 {
				r.IntervalMin = 30
			}
			if subnets, forced := due(r, lastSweep, forcedDone); len(subnets) > 0 {
				started := time.Now()
				hosts := sweep(subnets)
				var res struct {
					Hosts int `json:"hosts"`
				}
				if err := client.post("/api/collector/results", map[string]any{"scan": newID(), "started": started.Unix(),
					"finished": time.Now().Unix(), "hosts": hosts, "subnets": subnets, "forced": forced}, &res); err != nil {
					log.Printf("couldn't send the results (next try in a minute): %v", err)
				} else {
					why := ""
					if forced != "" {
						why = ", asked for on the page"
					}
					log.Printf("sent %d devices from %s (%s%s)", res.Hosts, strings.Join(subnets, " "), time.Since(started).Round(time.Second), why)
					for _, s := range subnets {
						lastSweep[s] = started
					}
					if forced != "" {
						forcedDone = forced
					}
				}
				if len(creds) > 0 && len(hosts) > 0 {
					t := time.Now()
					ips := make([]string, 0, len(hosts))
					for _, h := range hosts {
						ips = append(ips, h.IP)
					}
					found := snmpProbe(ips, creds)
					readings := snmpReadAll(found)
					if err := client.post("/api/collector/snmp", map[string]any{"devices": readings}, nil); err != nil {
						log.Printf("couldn't send the SNMP readings: %v", err)
					} else {
						log.Printf("SNMP: %d devices read (%s)", len(readings), time.Since(t).Round(time.Second))
					}
					// The swept subnets' agents are now these; the others' stay (their own schedule).
					agentsMu.Lock()
					next := map[string]Credential{}
					for ip, c := range agents {
						if !within(ip, subnets) {
							next[ip] = c
						}
					}
					for ip, c := range found {
						next[ip] = c
					}
					agents = next
					agentsMu.Unlock()
				}
				// The machines it has a read-only login for, beside the minute loop (a round can take minutes).
				if len(creds) > 0 && len(hosts) > 0 && inventoryRunning.CompareAndSwap(false, true) {
					go func(hosts []*Host, creds []Credential) {
						defer inventoryRunning.Store(false)
						started := time.Now()
						inventoryMu.Lock()
						last := make(map[string]time.Time, len(lastInventory))
						for k, v := range lastInventory {
							last[k] = v
						}
						inventoryMu.Unlock()
						readings := inventoryAll(hosts, creds, pins, last)
						inventoryMu.Lock()
						for k, v := range last {
							if !v.Before(started) { // tried in this round (a pin let go meanwhile stays let go)
								lastInventory[k] = v
							}
						}
						inventoryMu.Unlock()
						if len(readings) == 0 {
							return
						}
						if err := client.post("/api/collector/inventory", map[string]any{"readings": readings}, nil); err != nil {
							log.Printf("couldn't send the inventory: %v", err)
						} else {
							ok := 0
							for _, r := range readings {
								if r.OK {
									ok++
								}
							}
							log.Printf("inventory: %d of %d machines read (%s)", ok, len(readings), time.Since(started).Round(time.Second))
						}
					}(hosts, creds)
				}
			}
			every := time.Duration(max(r.CountersMin, 1)) * time.Minute
			agentsMu.Lock()
			current := agents
			agentsMu.Unlock()
			if len(current) > 0 && time.Since(lastCounters) >= every {
				lastCounters = time.Now()
				if err := client.post("/api/collector/counters", map[string]any{"devices": snmpCountersAll(current)}, nil); err != nil {
					log.Printf("couldn't send the counters: %v", err)
				}
			}
		}
		select {
		case <-stop:
			return
		case <-time.After(time.Minute):
		}
	}
}
