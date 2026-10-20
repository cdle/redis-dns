package server

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCountMemberRoundTrip(t *testing.T) {
	m := countMember("WWW.Example.COM", dns.TypeA)
	if m != "www.example.com.|A" {
		t.Fatalf("member=%q, want www.example.com.|A", m)
	}
	name, qtype, ok := parseMember(m)
	if !ok || name != "www.example.com." || qtype != dns.TypeA {
		t.Fatalf("parse=%q,%d,%v, want www.example.com.,A,true", name, qtype, ok)
	}
	m = countMember("example.com.", dns.TypeAAAA)
	if _, qtype, ok := parseMember(m); !ok || qtype != dns.TypeAAAA {
		t.Fatalf("AAAA roundtrip failed for %q", m)
	}
}

func TestParseMemberBad(t *testing.T) {
	for _, m := range []string{"", "no-pipe", "|A", "example.com.|", "example.com.|BOGUS"} {
		if _, _, ok := parseMember(m); ok {
			t.Fatalf("parseMember(%q) ok, want false", m)
		}
	}
}

func TestDecayFactor(t *testing.T) {
	half := 24 * time.Hour
	if f := decayFactor(half, half); math.Abs(f-0.5) > 1e-9 {
		t.Fatalf("factor(half-life)=%v, want 0.5", f)
	}
	if f := decayFactor(half, 48*time.Hour); math.Abs(f-0.25) > 1e-9 {
		t.Fatalf("factor(2 half-lives)=%v, want 0.25", f)
	}
	if f := decayFactor(half, time.Minute); f < 0.999 || f > 1 {
		t.Fatalf("factor(1m)=%v, want just under 1", f)
	}
	if f := decayFactor(0, time.Hour); f != 1 {
		t.Fatalf("factor(no half-life)=%v, want 1 (no decay)", f)
	}
}

func TestPrefetchNextDelay(t *testing.T) {
	sweep := time.Minute
	cases := []struct {
		ttl  time.Duration
		want time.Duration
	}{
		{0, sweep},                             // no cache TTL: refresh every sweep
		{30 * time.Second, sweep},              // short TTL: floored at the sweep
		{300 * time.Second, 240 * time.Second}, // 80% of TTL
		{2 * time.Hour, time.Hour},             // capped at 1h
	}
	for _, c := range cases {
		if got := prefetchNextDelay(c.ttl, sweep); got != c.want {
			t.Fatalf("prefetchNextDelay(%s)=%s, want %s", c.ttl, got, c.want)
		}
	}
}

// fakeRankStore records increments and serves a canned ranking.
type fakeRankStore struct {
	top []scoredMember
}

func (f *fakeRankStore) Top(_ context.Context, n int, minScore float64) ([]scoredMember, error) {
	var out []scoredMember
	for _, m := range f.top {
		if m.Score >= minScore {
			out = append(out, m)
		}
	}
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (f *fakeRankStore) Decay(_ context.Context, _ float64) error { return nil }

func TestCountQueryEnqueuesMember(t *testing.T) {
	s := &Server{countCh: make(chan string, 4)}
	s.countQuery(context.Background(), "WWW.Example.COM", dns.TypeAAAA)
	select {
	case m := <-s.countCh:
		if m != "www.example.com.|AAAA" {
			t.Fatalf("member=%q, want www.example.com.|AAAA", m)
		}
	default:
		t.Fatal("countQuery should have enqueued a member")
	}
}

func TestCountQueryDropsWhenFull(t *testing.T) {
	s := &Server{countCh: make(chan string, 1)}
	s.countQuery(context.Background(), "a.example.com", dns.TypeA)
	// The queue is full: this call must drop, not block.
	s.countQuery(context.Background(), "b.example.com", dns.TypeA)
	if len(s.countCh) != 1 {
		t.Fatalf("queue len=%d, want 1 (second count dropped)", len(s.countCh))
	}
}

func TestDueDynamic(t *testing.T) {
	now := time.Now()
	next := map[string]time.Time{
		"dyn|later.example.com.|A": now.Add(time.Hour), // scheduled: skip
	}
	top := []scoredMember{
		{Member: "hot.example.com.|A", Score: 120},
		{Member: "later.example.com.|A", Score: 50},
		{Member: "warm.example.com.|AAAA", Score: 3},
		{Member: "garbage", Score: 9},
	}
	due := dueDynamic(top, next, now)
	if len(due) != 2 || due[0].Member != "hot.example.com.|A" || due[1].Member != "warm.example.com.|AAAA" {
		t.Fatalf("due=%v, want [hot.example.com.|A warm.example.com.|AAAA]", due)
	}
}
