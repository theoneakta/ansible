// flowd: Sentry Lens's flow collector - IPFIX, NetFlow v9 and sFlow in,
// enriched flows into ClickHouse's flows table (Akvorado's columns, so
// Sentry Lens reads it unchanged, plus TCP flags, MACs, VLANs). No Kafka:
// it batches in memory and keeps rows ClickHouse couldn't take yet.
//
//	flowd run --config FILE             receive and store (the service)
//	flowd replay --config FILE PCAP...  a capture of exporter datagrams through the
//	                                    same path, timed by the capture (a test)
//	flowd version
//
// GET /metrics (Prometheus) and /healthz on the metrics address.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Version = "0.1.0"

type ClickHouseConfig struct {
	URL          string `json:"url"` // http://clickhouse:8123
	User         string `json:"user"`
	Password     string `json:"password"`
	Database     string `json:"database"`
	Table        string `json:"table"`
	ManageSchema bool   `json:"manage_schema"` // make the table if missing, add flowd's columns
	TTLDays      int    `json:"ttl_days"`
	BatchSize    int    `json:"batch_size"`
	FlushSeconds int    `json:"flush_seconds"`
	MaxBuffered  int    `json:"max_buffered"`
}

func (c ClickHouseConfig) table() string { return c.Database + "." + c.Table }

type Config struct {
	Listen struct {
		NetFlow string `json:"netflow"` // NetFlow v9 and IPFIX, e.g. ":2055"
		IPFIX   string `json:"ipfix"`   // a second NetFlow/IPFIX port, e.g. ":4739"
		SFlow   string `json:"sflow"`   // ":6343"
		Metrics string `json:"metrics"` // ":8080"
	} `json:"listen"`
	ClickHouse           ClickHouseConfig    `json:"clickhouse"`
	DefaultSamplingRate  uint64              `json:"default_sampling_rate"`
	Exporters            map[string]Exporter `json:"exporters"`
	DropUnknownExporters bool                `json:"drop_unknown_exporters"`
	Networks             map[string]Network  `json:"networks"`
	GeoIP                struct {
		Country string `json:"country"`
		ASN     string `json:"asn"`
	} `json:"geoip"`
	ExternalRegex string `json:"external_regex"`
	ProviderRegex string `json:"provider_regex"`
	// Every datagram also passed on to another collector (running flowd in front of it).
	Forward *ForwardConfig `json:"forward"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.ClickHouse.URL == "" {
		c.ClickHouse.URL = "http://clickhouse:8123"
	}
	c.ClickHouse.Database = or(c.ClickHouse.Database, "default")
	c.ClickHouse.Table = or(c.ClickHouse.Table, "flows")
	if c.ClickHouse.TTLDays <= 0 {
		c.ClickHouse.TTLDays = 7
	}
	if p := os.Getenv("CLICKHOUSE_PASSWORD"); p != "" {
		c.ClickHouse.Password = p
	}
	return c, nil
}

// ------------------------------------------------------------------ counters
type Stats struct {
	mu        sync.Mutex
	exporters map[string]map[string]int // exporter -> counter -> n
	totals    map[string]int
	lastErr   string
	started   time.Time
}

func newStats() *Stats {
	return &Stats{exporters: map[string]map[string]int{}, totals: map[string]int{}, started: time.Now()}
}

func (s *Stats) add(exp netip.Addr, k string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.exporters[exp.String()]
	if m == nil {
		m = map[string]int{}
		s.exporters[exp.String()] = m
	}
	m[k] += n
}

func (s *Stats) global(k string, n int) {
	s.mu.Lock()
	s.totals[k] += n
	s.mu.Unlock()
}

func (s *Stats) setError(e string) {
	s.mu.Lock()
	s.lastErr = e
	s.mu.Unlock()
}

func (s *Stats) metrics(buffered int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "flowd_up 1\nflowd_buffered_rows %d\nflowd_uptime_seconds %.0f\n", buffered, time.Since(s.started).Seconds())
	keys := make([]string, 0, len(s.totals))
	for k := range s.totals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "flowd_%s_total %d\n", k, s.totals[k])
	}
	exps := make([]string, 0, len(s.exporters))
	for e := range s.exporters {
		exps = append(exps, e)
	}
	sort.Strings(exps)
	for _, e := range exps {
		ks := make([]string, 0, len(s.exporters[e]))
		for k := range s.exporters[e] {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Fprintf(&b, "flowd_exporter_%s_total{exporter=%q} %d\n", k, e, s.exporters[e][k])
		}
	}
	return b.String()
}

// ------------------------------------------------------------------ main
func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	cfgPath, rest := "/etc/flowd/flowd.json", []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			cfgPath = args[i+1]
			i++
		} else {
			rest = append(rest, args[i])
		}
	}
	if cmd == "version" {
		fmt.Println("flowd", Version)
		return
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	enr, err := newEnricher(cfg)
	if err != nil {
		log.Fatal(err)
	}
	stats := newStats()
	dec := newDecoder(enr, stats)
	sink := newSink(cfg.ClickHouse, stats)
	if err := sink.EnsureSchema(cfg.ClickHouse.TTLDays); err != nil {
		log.Fatalf("the flows table: %v", err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { sink.Run(stop); close(done) }()

	switch cmd {
	case "replay":
		if len(rest) == 0 {
			log.Fatal("usage: flowd replay --config FILE CAPTURE.pcap...")
		}
		for _, f := range rest {
			n, err := replay(f, cfg, dec, sink, stats)
			if err != nil {
				log.Fatalf("%s: %v", f, err)
			}
			log.Printf("%s: %d datagrams", f, n)
		}
	case "run":
		var fwd *Forwarder
		if cfg.Forward != nil && cfg.Forward.Host != "" {
			if fwd, err = newForwarder(*cfg.Forward, stats); err != nil {
				log.Fatal(err)
			}
			log.Printf("forwarding every datagram to %s (exporter addresses kept: %v)", cfg.Forward.Host, cfg.Forward.PreserveSource)
		}
		if cfg.Listen.Metrics != "" {
			go serveMetrics(cfg.Listen.Metrics, stats, sink)
		}
		for kind, a := range map[string]string{"netflow": cfg.Listen.NetFlow, "ipfix": cfg.Listen.IPFIX, "sflow": cfg.Listen.SFlow} {
			if a == "" {
				continue
			}
			k := kind
			if k == "ipfix" {
				k = "netflow" // the same decoder: the version says which
			}
			if err := listen(a, k, dec, sink, stats, fwd); err != nil {
				log.Fatalf("%s: %v", a, err)
			}
		}
		log.Printf("flowd %s -> %s", Version, cfg.ClickHouse.table())
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
	default:
		log.Fatalf("commands: run, replay, version")
	}
	close(stop)
	<-done
	if n := sink.Buffered(); n > 0 {
		log.Printf("%d rows couldn't be stored", n)
		os.Exit(1)
	}
}

// listen: one UDP socket, its datagrams decoded as they come.
func listen(addr, kind string, dec *Decoder, sink *Sink, stats *Stats, fwd *Forwarder) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	if u, ok := pc.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(8 << 20)
	}
	lport := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	log.Printf("listening for %s on %s", kind, addr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			src := from.(*net.UDPAddr).AddrPort()
			if fwd != nil {
				fwd.Send(src, lport, buf[:n])
			}
			handle(kind, buf[:n], src, time.Now(), dec, sink, stats)
		}
	}()
	return nil
}

func handle(kind string, payload []byte, src netip.AddrPort, t time.Time, dec *Decoder, sink *Sink, stats *Stats) {
	exp := src.Addr().Unmap()
	stats.add(exp, "datagrams", 1)
	rows, err := dec.Decode(kind, payload, src, t)
	if err != nil {
		stats.add(exp, "decode_errors", 1) // (a v9 / IPFIX template not seen yet among them)
		return
	}
	stats.add(exp, "flows", len(rows))
	sink.Add(rows)
}

func serveMetrics(addr string, stats *Stats, sink *Sink) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, stats.metrics(sink.Buffered()))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		stats.mu.Lock()
		e := stats.lastErr
		stats.mu.Unlock()
		if e != "" {
			http.Error(w, e, http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	log.Printf("metrics on %s", addr)
	log.Print(http.ListenAndServe(addr, mux))
}
