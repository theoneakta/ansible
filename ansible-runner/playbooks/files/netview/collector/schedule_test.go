package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func remote(t *testing.T, s string) Remote {
	var r Remote
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDueSchedule(t *testing.T) {
	r := remote(t, `{"subnets":["10.0.0.0/24","10.0.1.0/24","10.0.2.0/24"],"interval_min":30,
		"schedule":[{"subnet":"10.0.0.0/24","every_min":30},{"subnet":"10.0.1.0/24","every_min":240},{"subnet":"10.0.2.0/24","every_min":0}]}`)
	// First contact: all but the on-demand one.
	if got, f := due(r, map[string]time.Time{}, ""); !reflect.DeepEqual(got, []string{"10.0.0.0/24", "10.0.1.0/24"}) || f != "" {
		t.Fatalf("first: %v %q", got, f)
	}
	// An hour later: only the 30-minute one.
	ago := time.Now().Add(-time.Hour)
	last := map[string]time.Time{"10.0.0.0/24": ago, "10.0.1.0/24": ago}
	if got, _ := due(r, last, ""); !reflect.DeepEqual(got, []string{"10.0.0.0/24"}) {
		t.Fatalf("an hour later: %v", got)
	}
}

func TestDueSweepNow(t *testing.T) {
	now := map[string]time.Time{"10.0.0.0/24": time.Now(), "10.0.1.0/24": time.Now()}
	r := remote(t, `{"subnets":["10.0.0.0/24","10.0.1.0/24"],"interval_min":30,"schedule":[],
		"sweep_now":{"id":"ab12","subnets":["10.0.1.0/24"]}}`)
	if got, f := due(r, now, ""); !reflect.DeepEqual(got, []string{"10.0.1.0/24"}) || f != "ab12" {
		t.Fatalf("one subnet: %v %q", got, f)
	}
	if got, _ := due(r, now, "ab12"); len(got) != 0 { // done: not again
		t.Fatalf("done: %v", got)
	}
	r = remote(t, `{"subnets":["10.0.0.0/24","10.0.1.0/24"],"interval_min":30,"schedule":[],"sweep_now":{"id":"cd34","subnets":[]}}`)
	if got, _ := due(r, now, "ab12"); len(got) != 2 {
		t.Fatalf("all: %v", got)
	}
}

func TestDueOlderServer(t *testing.T) {
	r := remote(t, `{"subnets":["10.0.0.0/24","10.0.1.0/24"],"interval_min":30}`)
	if got, _ := due(r, map[string]time.Time{"10.0.0.0/24": time.Now()}, ""); !reflect.DeepEqual(got, []string{"10.0.1.0/24"}) {
		t.Fatalf("older server: %v", got)
	}
}

func TestWithin(t *testing.T) {
	if !within("10.0.1.7", []string{"10.0.0.0/24", "10.0.1.0/24"}) || within("10.0.2.7", []string{"10.0.0.0/24"}) {
		t.Fatal("within")
	}
}
