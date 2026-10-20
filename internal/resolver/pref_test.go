package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakePrefBackend is an in-memory PrefBackend for tests.
type fakePrefBackend struct {
	entries map[string]*PrefEntry
	ttls    map[string]time.Duration
	bumps   map[string]int64
}

func newFakePrefBackend() *fakePrefBackend {
	return &fakePrefBackend{
		entries: make(map[string]*PrefEntry),
		ttls:    make(map[string]time.Duration),
		bumps:   make(map[string]int64),
	}
}

func (f *fakePrefBackend) LoadPref(_ context.Context, key string) (*PrefEntry, error) {
	e, ok := f.entries[key]
	if !ok {
		return nil, nil
	}
	cp := *e
	return &cp, nil
}

func (f *fakePrefBackend) StorePref(_ context.Context, key string, e *PrefEntry, ttl time.Duration) error {
	cp := *e
	f.entries[key] = &cp
	f.ttls[key] = ttl
	return nil
}

func (f *fakePrefBackend) BumpPref(_ context.Context, key string) error {
	if e, ok := f.entries[key]; ok {
		e.Hits++
		f.bumps[key]++
	}
	return nil
}

func (f *fakePrefBackend) seed(e *PrefEntry) string {
	key := prefKey("example.com.", dns.TypeA)
	f.entries[key] = e
	return key
}

func (f *fakePrefBackend) only(t *testing.T) (*PrefEntry, time.Duration) {
	t.Helper()
	if len(f.entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(f.entries))
	}
	for key, e := range f.entries {
		return e, f.ttls[key]
	}
	return nil, 0
}

// prefResolver builds a Resolver with racing and the pref cache on.
// The scripted dialer would crown 192.0.2.1 if a race actually ran, so
// tests can tell a pref hit (winner 192.0.2.2) from a race (.1).
func prefResolver(b PrefBackend, recheckHits int64) *Resolver {
	d := scriptedDialer{delays: map[string]time.Duration{
		addr("192.0.2.1", 443): 10 * time.Millisecond,
	}}
	r := &Resolver{race: &raceConfig{
		ports: []int{443, 80}, timeout: 500 * time.Millisecond,
		tcpDeadline: 200 * time.Millisecond, dial: d.dial,
	}}
	r.EnablePref(b, time.Hour, time.Minute, recheckHits, 6*time.Hour)
	return r
}

func twoIPMsg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{
		aAnswer("example.com", "192.0.2.1"),
		aAnswer("example.com", "192.0.2.2"),
	}
	return m
}

func TestPrefHitSkipsRace(t *testing.T) {
	b := newFakePrefBackend()
	key := b.seed(&PrefEntry{IP: net.ParseIP("192.0.2.2"), Via: "tcp/443", Hits: 5, Updated: time.Now()})
	out := prefResolver(b, 100).applyRace(twoIPMsg(), dns.TypeA)
	ips := answerIPs(out, dns.TypeA)
	if len(ips) != 1 || ips[0].String() != "192.0.2.2" {
		t.Fatalf("ips=%v, want [192.0.2.2] from pref, not the race winner", ips)
	}
	if b.bumps[key] != 1 {
		t.Fatalf("bumps=%d, want 1", b.bumps[key])
	}
}

func TestPrefNegativeSkipsRace(t *testing.T) {
	b := newFakePrefBackend()
	b.seed(&PrefEntry{IP: nil, Hits: 1, Updated: time.Now()})
	m := twoIPMsg()
	out := prefResolver(b, 100).applyRace(m, dns.TypeA)
	if out != m {
		t.Fatal("negative pref should return the upstream answer untouched")
	}
}

func TestPrefRotatedOutRaces(t *testing.T) {
	b := newFakePrefBackend()
	b.seed(&PrefEntry{IP: net.ParseIP("192.0.2.9"), Via: "tcp/443", Hits: 5, Updated: time.Now()})
	out := prefResolver(b, 100).applyRace(twoIPMsg(), dns.TypeA)
	ips := answerIPs(out, dns.TypeA)
	if len(ips) != 1 || ips[0].String() != "192.0.2.1" {
		t.Fatalf("ips=%v, want [192.0.2.1] from a fresh race", ips)
	}
	e, _ := b.only(t)
	if e.IP.String() != "192.0.2.1" || e.Hits != 1 {
		t.Fatalf("stored pref=%+v, want ip=192.0.2.1 hits=1", e)
	}
}

func TestPrefStaleByHitsRaces(t *testing.T) {
	b := newFakePrefBackend()
	b.seed(&PrefEntry{IP: net.ParseIP("192.0.2.2"), Via: "tcp/443", Hits: 3, Updated: time.Now()})
	out := prefResolver(b, 3).applyRace(twoIPMsg(), dns.TypeA)
	ips := answerIPs(out, dns.TypeA)
	if len(ips) != 1 || ips[0].String() != "192.0.2.1" {
		t.Fatalf("ips=%v, want [192.0.2.1]: hit limit should force a revalidation race", ips)
	}
}

func TestPrefStaleByAgeRaces(t *testing.T) {
	b := newFakePrefBackend()
	b.seed(&PrefEntry{IP: net.ParseIP("192.0.2.2"), Via: "tcp/443", Hits: 1, Updated: time.Now().Add(-7 * time.Hour)})
	out := prefResolver(b, 100).applyRace(twoIPMsg(), dns.TypeA)
	ips := answerIPs(out, dns.TypeA)
	if len(ips) != 1 || ips[0].String() != "192.0.2.1" {
		t.Fatalf("ips=%v, want [192.0.2.1]: aged entry should force a revalidation race", ips)
	}
}

func TestRaceStoresWinnerPref(t *testing.T) {
	b := newFakePrefBackend()
	out := prefResolver(b, 100).applyRace(twoIPMsg(), dns.TypeA)
	if len(answerIPs(out, dns.TypeA)) != 1 {
		t.Fatal("expected a narrowed answer")
	}
	e, ttl := b.only(t)
	if e.IP.String() != "192.0.2.1" || e.Via != "tcp/443" || e.Hits != 1 {
		t.Fatalf("stored pref=%+v, want ip=192.0.2.1 via=tcp/443 hits=1", e)
	}
	if ttl != time.Hour {
		t.Fatalf("ttl=%s, want 1h positive TTL", ttl)
	}
}

func TestRaceStoresNegativePref(t *testing.T) {
	b := newFakePrefBackend()
	d := scriptedDialer{delays: map[string]time.Duration{}}
	r := &Resolver{race: &raceConfig{
		ports: []int{443, 80}, timeout: 100 * time.Millisecond,
		tcpDeadline: 50 * time.Millisecond, dial: d.dial,
	}}
	r.EnablePref(b, time.Hour, time.Minute, 100, 6*time.Hour)
	m := twoIPMsg()
	if out := r.applyRace(m, dns.TypeA); out != m {
		t.Fatal("no-finisher race should return the upstream answer untouched")
	}
	e, ttl := b.only(t)
	if e.IP != nil {
		t.Fatalf("stored pref ip=%v, want negative entry", e.IP)
	}
	if ttl != time.Minute {
		t.Fatalf("ttl=%s, want 1m negative TTL", ttl)
	}
}
