package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// scriptedDialer returns per-address fake probe results: an address present
// in delays succeeds after that delay; any other address fails at once.
type scriptedDialer struct {
	delays map[string]time.Duration
}

func (s scriptedDialer) dial(ctx context.Context, address string) (time.Duration, error) {
	d, ok := s.delays[address]
	if !ok {
		return 0, errors.New("connection refused")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(d):
		return d, nil
	}
}

func addr(ip string, port int) string {
	return net.JoinHostPort(ip, fmt.Sprint(port))
}

func racingResolver(dial dialFunc, timeout time.Duration) *Resolver {
	return &Resolver{race: &raceConfig{ports: []int{443, 80}, timeout: timeout, dial: dial}}
}

func TestPickFastestPrimaryWins(t *testing.T) {
	d := scriptedDialer{delays: map[string]time.Duration{
		addr("192.0.2.1", 443): 60 * time.Millisecond,
		addr("192.0.2.2", 443): 15 * time.Millisecond,
	}}
	winner, port, _ := pickFastest([]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
		[]int{443, 80}, 500*time.Millisecond, d.dial)
	if winner == nil || winner.String() != "192.0.2.2" || port != 443 {
		t.Fatalf("winner=%v port=%d, want 192.0.2.2:443", winner, port)
	}
}

func TestPickFastestPrimaryBeatsFasterSecondary(t *testing.T) {
	// A quick port-80 answer must not preempt a port-443 success that lands
	// within the budget: 443 is the port real traffic will use.
	d := scriptedDialer{delays: map[string]time.Duration{
		addr("192.0.2.1", 80):  5 * time.Millisecond,
		addr("192.0.2.2", 443): 40 * time.Millisecond,
	}}
	winner, port, _ := pickFastest([]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
		[]int{443, 80}, 600*time.Millisecond, d.dial)
	if winner == nil || winner.String() != "192.0.2.2" || port != 443 {
		t.Fatalf("winner=%v port=%d, want 192.0.2.2:443", winner, port)
	}
}

func TestPickFastestFallsBackToSecondaryAtDeadline(t *testing.T) {
	d := scriptedDialer{delays: map[string]time.Duration{
		addr("192.0.2.1", 80): 20 * time.Millisecond,
		addr("192.0.2.2", 80): 35 * time.Millisecond,
	}}
	winner, port, _ := pickFastest([]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
		[]int{443, 80}, 200*time.Millisecond, d.dial)
	if winner == nil || winner.String() != "192.0.2.1" || port != 80 {
		t.Fatalf("winner=%v port=%d, want 192.0.2.1:80", winner, port)
	}
}

func TestPickFastestNoFinisher(t *testing.T) {
	d := scriptedDialer{delays: map[string]time.Duration{}}
	winner, _, _ := pickFastest([]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
		[]int{443, 80}, 200*time.Millisecond, d.dial)
	if winner != nil {
		t.Fatalf("winner=%v, want nil", winner)
	}
}

func aAnswer(name, ip string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(ip),
	}
}

func TestApplyRaceNarrowsToWinner(t *testing.T) {
	name := "www.example.com"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: dns.Fqdn("cdn.example.net"),
		},
		aAnswer("cdn.example.net", "192.0.2.1"),
		aAnswer("cdn.example.net", "192.0.2.2"),
	}
	d := scriptedDialer{delays: map[string]time.Duration{
		addr("192.0.2.1", 443): 80 * time.Millisecond,
		addr("192.0.2.2", 443): 10 * time.Millisecond,
	}}
	out := racingResolver(d.dial, 500*time.Millisecond).applyRace(m, dns.TypeA)
	if len(out.Answer) != 2 {
		t.Fatalf("answers=%d, want 2 (CNAME + winner)", len(out.Answer))
	}
	if _, ok := out.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("first answer = %T, want CNAME preserved", out.Answer[0])
	}
	if a, ok := out.Answer[1].(*dns.A); !ok || a.A.String() != "192.0.2.2" {
		t.Fatalf("second answer = %v, want A 192.0.2.2", out.Answer[1])
	}
	// The input message must not be mutated.
	if len(m.Answer) != 3 {
		t.Fatalf("input mutated: answers=%d, want 3", len(m.Answer))
	}
}

func TestApplyRaceLeavesSingleIPAlone(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{aAnswer("example.com", "192.0.2.1")}
	d := scriptedDialer{delays: map[string]time.Duration{}}
	out := racingResolver(d.dial, 100*time.Millisecond).applyRace(m, dns.TypeA)
	if out != m {
		t.Fatal("single-IP answer should pass through untouched")
	}
}

func TestApplyRaceKeepsOriginalWhenNobodyAnswers(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{aAnswer("example.com", "192.0.2.1"), aAnswer("example.com", "192.0.2.2")}
	d := scriptedDialer{delays: map[string]time.Duration{}}
	out := racingResolver(d.dial, 100*time.Millisecond).applyRace(m, dns.TypeA)
	if out != m {
		t.Fatal("answer with no race finisher should pass through untouched")
	}
}

func TestApplyRaceAAAA(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeAAAA)
	m.Response = true
	for _, ip := range []string{"2001:db8::1", "2001:db8::2"} {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP(ip),
		})
	}
	d := scriptedDialer{delays: map[string]time.Duration{
		addr("2001:db8::1", 443): 70 * time.Millisecond,
		addr("2001:db8::2", 443): 10 * time.Millisecond,
	}}
	out := racingResolver(d.dial, 500*time.Millisecond).applyRace(m, dns.TypeAAAA)
	if len(out.Answer) != 1 {
		t.Fatalf("answers=%d, want 1", len(out.Answer))
	}
	if a, ok := out.Answer[0].(*dns.AAAA); !ok || a.AAAA.String() != "2001:db8::2" {
		t.Fatalf("answer=%v, want AAAA 2001:db8::2", out.Answer[0])
	}
}

// TestResolveRacesEndToEnd runs Resolve against a fake upstream whose
// answer lists a dead loopback address first and a live one second, with
// real TCP probes: the answer must come back narrowed to the live address.
func TestResolveRacesEndToEnd(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	accept := func(ip string) net.Listener {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		return ln
	}
	// Only 127.0.0.1 listens; 127.0.0.2 refuses instantly.
	live := accept("127.0.0.1")
	defer live.Close()

	mux := dns.NewServeMux()
	mux.HandleFunc("example.com.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			aAnswer("example.com", "127.0.0.2"), // dead, listed first
			aAnswer("example.com", "127.0.0.1"), // live
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	r := New(pc.LocalAddr().String(), "udp", 3*time.Second)
	r.EnableRace([]int{port}, time.Second)
	resp, err := r.Resolve("example.com", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	ips := answerIPs(resp, dns.TypeA)
	if len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatalf("raced answer IPs = %v, want [127.0.0.1]", ips)
	}
}

func TestAnswerIPsDedup(t *testing.T) {
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		aAnswer("example.com", "192.0.2.1"),
		aAnswer("example.com", "192.0.2.2"),
		aAnswer("example.com", "192.0.2.1"),
	}
	ips := answerIPs(m, dns.TypeA)
	if len(ips) != 2 || ips[0].String() != "192.0.2.1" || ips[1].String() != "192.0.2.2" {
		t.Fatalf("ips=%v, want [192.0.2.1 192.0.2.2]", ips)
	}
}
