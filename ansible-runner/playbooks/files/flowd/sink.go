package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Sink: flows into ClickHouse in batches (its HTTP interface, JSONEachRow) -
// every FlushSeconds or BatchSize rows. ClickHouse away: the rows wait and
// are sent again, up to MaxBuffered (then the oldest go, counted).
type Sink struct {
	cfg    ClickHouseConfig
	stats  *Stats
	client *http.Client
	mu     sync.Mutex
	buf    []Row
	kick   chan struct{}
}

func newSink(cfg ClickHouseConfig, stats *Stats) *Sink {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50000
	}
	if cfg.FlushSeconds <= 0 {
		cfg.FlushSeconds = 5
	}
	if cfg.MaxBuffered <= 0 {
		cfg.MaxBuffered = 2_000_000
	}
	return &Sink{cfg: cfg, stats: stats, client: &http.Client{Timeout: 60 * time.Second}, kick: make(chan struct{}, 1)}
}

func (s *Sink) Add(rows []Row) {
	if len(rows) == 0 {
		return
	}
	s.mu.Lock()
	s.buf = append(s.buf, rows...)
	if over := len(s.buf) - s.cfg.MaxBuffered; over > 0 {
		s.buf = s.buf[over:]
		s.stats.global("rows_dropped_buffer_full", over)
	}
	full := len(s.buf) >= s.cfg.BatchSize
	s.mu.Unlock()
	if full {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

func (s *Sink) Run(stop <-chan struct{}) {
	t := time.NewTicker(time.Duration(s.cfg.FlushSeconds) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			s.flush()
			return
		case <-t.C:
		case <-s.kick:
		}
		s.flush()
	}
}

func (s *Sink) flush() {
	for {
		s.mu.Lock()
		n := min(len(s.buf), s.cfg.BatchSize)
		batch := s.buf[:n:n]
		s.mu.Unlock()
		if n == 0 {
			return
		}
		if err := s.insert(batch); err != nil {
			s.stats.global("insert_errors", 1)
			s.stats.setError(err.Error())
			log.Printf("ClickHouse insert of %d rows failed (kept, retried): %v", n, err)
			return
		}
		s.mu.Lock()
		s.buf = s.buf[n:]
		s.mu.Unlock()
		s.stats.global("rows_inserted", n)
		s.stats.setError("")
	}
}

func (s *Sink) insert(rows []Row) error {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for i := range rows {
		if err := enc.Encode(&rows[i]); err != nil {
			return err
		}
	}
	_, err := s.exec(fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", s.cfg.table()), &body)
	return err
}

func (s *Sink) Buffered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}

// exec: one statement; with a body, the statement goes in the URL and the body is its data.
func (s *Sink) exec(query string, body io.Reader) (string, error) {
	u, err := url.Parse(s.cfg.URL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if body != nil {
		q.Set("query", query)
	} else {
		body = strings.NewReader(query)
	}
	q.Set("date_time_input_format", "best_effort")
	q.Set("allow_suspicious_low_cardinality_types", "1") // ExporterAddress LowCardinality(IPv6), as Akvorado has it
	u.RawQuery = q.Encode()
	req, err := http.NewRequest("POST", u.String(), body)
	if err != nil {
		return "", err
	}
	if s.cfg.User != "" {
		req.Header.Set("X-ClickHouse-User", s.cfg.User)
		req.Header.Set("X-ClickHouse-Key", s.cfg.Password)
	}
	r, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.StatusCode != 200 {
		return "", fmt.Errorf("ClickHouse: %s", strings.TrimSpace(string(out[:min(len(out), 400)])))
	}
	return string(out), nil
}

// ------------------------------------------------------------------ the table
// Akvorado's flows columns (Sentry Lens reads these), partitioned by day and
// kept TTLDays, plus the extra ones (Row). Made if missing; extra columns
// added to an existing table (Akvorado's, once flowd replaces it).
func (s *Sink) EnsureSchema(ttlDays int) error {
	if !s.cfg.ManageSchema {
		return nil
	}
	db := s.cfg.Database
	stmts := []string{
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", db),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    TimeReceived DateTime CODEC(DoubleDelta, LZ4),
    SamplingRate UInt64,
    ExporterAddress LowCardinality(IPv6), ExporterName LowCardinality(String),
    ExporterGroup LowCardinality(String), ExporterRole LowCardinality(String),
    ExporterSite LowCardinality(String), ExporterRegion LowCardinality(String), ExporterTenant LowCardinality(String),
    SrcAddr IPv6, DstAddr IPv6, SrcNetMask UInt8, DstNetMask UInt8, SrcAS UInt32, DstAS UInt32,
    SrcNetName LowCardinality(String), DstNetName LowCardinality(String),
    SrcNetRole LowCardinality(String), DstNetRole LowCardinality(String),
    SrcNetSite LowCardinality(String), DstNetSite LowCardinality(String),
    SrcNetRegion LowCardinality(String), DstNetRegion LowCardinality(String),
    SrcNetTenant LowCardinality(String), DstNetTenant LowCardinality(String),
    SrcCountry FixedString(2), DstCountry FixedString(2),
    SrcGeoCity LowCardinality(String), DstGeoCity LowCardinality(String),
    SrcGeoState LowCardinality(String), DstGeoState LowCardinality(String),
    DstASPath Array(UInt32), Dst1stAS UInt32, Dst2ndAS UInt32, Dst3rdAS UInt32,
    DstCommunities Array(UInt32), DstLargeCommunities Array(UInt128),
    InIfName LowCardinality(String), OutIfName LowCardinality(String),
    InIfDescription LowCardinality(String), OutIfDescription LowCardinality(String),
    InIfSpeed UInt32, OutIfSpeed UInt32,
    InIfConnectivity LowCardinality(String), OutIfConnectivity LowCardinality(String),
    InIfProvider LowCardinality(String), OutIfProvider LowCardinality(String),
    InIfBoundary Enum8('undefined' = 0, 'external' = 1, 'internal' = 2),
    OutIfBoundary Enum8('undefined' = 0, 'external' = 1, 'internal' = 2),
    EType UInt32, Proto UInt32, SrcPort UInt16, DstPort UInt16,
    Bytes UInt64, Packets UInt64,
    PacketSize UInt64 ALIAS intDiv(Bytes, Packets),
    ForwardingStatus UInt32,
    FlowDirection Enum8('undefined' = 0, 'ingress' = 1, 'egress' = 2)
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(TimeReceived)
ORDER BY (toStartOfFiveMinutes(TimeReceived), ExporterAddress, InIfName, OutIfName)
TTL TimeReceived + INTERVAL %d DAY`, s.cfg.table(), ttlDays),
	}
	for _, c := range []string{"TCPFlags UInt8", "SrcMAC UInt64", "DstMAC UInt64", "SrcVlan UInt16", "DstVlan UInt16",
		"ICMPType UInt8", "ICMPCode UInt8"} {
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s", s.cfg.table(), c))
	}
	for _, q := range stmts {
		if _, err := s.exec(q, nil); err != nil {
			return err
		}
	}
	return nil
}
