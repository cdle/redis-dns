package resolver

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Answer racing: when the upstream returns several IPs for one name, the
// server probes them concurrently from the exit itself and narrows the
// answer to the fastest-responding IP, so clients always connect to the
// best address this exit can reach — instead of whichever address the
// upstream happened to list first.
//
// Ports are probed in priority order (default 443, then 80): a success on
// the first port wins immediately; successes on later ports only count if
// no first-port success arrives within the timeout. If nothing responds in
// time the upstream answer is returned unchanged: racing may narrow an
// answer, never break one.

// dialFunc probes one TCP address and reports how long connecting took.
type dialFunc func(ctx context.Context, address string) (time.Duration, error)

func tcpDial(ctx context.Context, address string) (time.Duration, error) {
	var d net.Dialer
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return rtt, nil
}

// raceConfig holds the racing parameters of a Resolver.
type raceConfig struct {
	ports   []int
	timeout time.Duration
	dial    dialFunc
}

// EnableRace turns on answer racing with the given probe ports (in priority
// order) and overall time budget.
func (r *Resolver) EnableRace(ports []int, timeout time.Duration) {
	if len(ports) == 0 {
		ports = []int{443, 80}
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	r.race = &raceConfig{ports: ports, timeout: timeout, dial: tcpDial}
}

// applyRace narrows msg to the fastest-responding IP when the answer holds
// two or more addresses of the queried type. Anything else — single-IP
// answers, non-address queries, errors, a race with no finisher — returns
// msg untouched.
func (r *Resolver) applyRace(msg *dns.Msg, qtype uint16) *dns.Msg {
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		return msg
	}
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return msg
	}
	ips := answerIPs(msg, qtype)
	if len(ips) < 2 {
		return msg
	}
	name := ""
	if len(msg.Question) > 0 {
		name = msg.Question[0].Name
	}
	winner, port, rtt := pickFastest(ips, r.race.ports, r.race.timeout, r.race.dial)
	if winner == nil {
		log.Printf("resolver: race name=%s type=%d candidates=%d no winner within %s, keeping upstream answer",
			name, qtype, len(ips), r.race.timeout)
		return msg
	}
	log.Printf("resolver: race name=%s type=%d candidates=%d winner=%s port=%d rtt=%s",
		name, qtype, len(ips), winner, port, rtt)
	return narrow(msg, qtype, winner)
}

// answerIPs returns the distinct IPs carried by records of type qtype in the
// answer section, in answer order.
func answerIPs(msg *dns.Msg, qtype uint16) []net.IP {
	var ips []net.IP
	seen := make(map[string]bool)
	for _, rr := range msg.Answer {
		ip, ok := recordIP(rr, qtype)
		if !ok {
			continue
		}
		if key := ip.String(); !seen[key] {
			seen[key] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// recordIP extracts the address from an A or AAAA record when its type
// matches the query type.
func recordIP(rr dns.RR, qtype uint16) (net.IP, bool) {
	switch qtype {
	case dns.TypeA:
		if a, ok := rr.(*dns.A); ok {
			return a.A, true
		}
	case dns.TypeAAAA:
		if aaaa, ok := rr.(*dns.AAAA); ok {
			return aaaa.AAAA, true
		}
	}
	return nil, false
}

// pickFastest dials every (ip, port) pair concurrently. A success on the
// first (highest-priority) port wins at once; a success on a later port is
// remembered and used only if the deadline passes with no first-port
// success. Returns the winning IP, the port it answered on, and its connect
// time — or nil when nothing answered within timeout.
func pickFastest(ips []net.IP, ports []int, timeout time.Duration, dial dialFunc) (net.IP, int, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		ip      net.IP
		portIdx int
		port    int
		rtt     time.Duration
		ok      bool
	}
	// Every probe reports back, success or failure, so a race where all
	// candidates refuse at once ends immediately instead of idling until
	// the deadline. The channel is fully buffered: probes never block on
	// send after an early return.
	results := make(chan result, len(ips)*len(ports))
	for _, ip := range ips {
		for i, port := range ports {
			go func(ip net.IP, idx, port int) {
				rtt, err := dial(ctx, net.JoinHostPort(ip.String(), fmt.Sprint(port)))
				results <- result{ip: ip, portIdx: idx, port: port, rtt: rtt, ok: err == nil}
			}(ip, i, port)
		}
	}

	var fallback *result
	remaining := len(ips) * len(ports)
	for remaining > 0 {
		select {
		case r := <-results:
			remaining--
			if !r.ok {
				continue
			}
			if r.portIdx == 0 {
				return r.ip, r.port, r.rtt
			}
			if fallback == nil || r.rtt < fallback.rtt {
				b := r
				fallback = &b
			}
		case <-ctx.Done():
			if fallback != nil {
				return fallback.ip, fallback.port, fallback.rtt
			}
			return nil, 0, 0
		}
	}
	if fallback != nil {
		return fallback.ip, fallback.port, fallback.rtt
	}
	return nil, 0, 0
}

// narrow returns a copy of msg whose answer keeps only the records that are
// not addresses of the queried type, plus the winner's own record(s).
// CNAMEs and other record types pass through untouched.
func narrow(msg *dns.Msg, qtype uint16, winner net.IP) *dns.Msg {
	out := msg.Copy()
	kept := out.Answer[:0]
	for _, rr := range out.Answer {
		if ip, ok := recordIP(rr, qtype); ok && !ip.Equal(winner) {
			continue
		}
		kept = append(kept, rr)
	}
	out.Answer = kept
	return out
}
