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
// answer to the best-responding IP, so clients always connect to the best
// address this exit can reach — instead of whichever address the upstream
// happened to list first.
//
// Three probe kinds run at once: TCP connects on the configured ports
// (default 443, then 80) and one ICMP echo per IP. The TCP probes are the
// authoritative ones — a connect proves the service port is really open —
// but they only get a short deadline (default 200ms):
//
//   - A TCP success on the first port within the deadline wins at once.
//   - A TCP success on a later port within the deadline is held, and wins
//     when the deadline passes with no first-port success.
//   - Once the deadline passes — or every TCP probe has finished without a
//     success — TCP is out and the fastest ICMP reply wins instead. This
//     is the only signal available for hosts that serve no web port at
//     all (IMAP, SMTP, …), which otherwise burned the whole budget.
//
// If nothing usable responds within the overall budget the upstream
// answer is returned unchanged: racing may narrow an answer, never break
// one. Winners are remembered in the preferred-IP cache (see pref.go), so
// repeat resolutions skip the race entirely.

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

// pingFunc measures the ICMP echo round-trip to one IP.
type pingFunc func(ctx context.Context, ip net.IP) (time.Duration, error)

// raceConfig holds the racing parameters of a Resolver.
type raceConfig struct {
	ports       []int
	timeout     time.Duration // overall probe budget
	tcpDeadline time.Duration // window TCP gets before ICMP takes over
	dial        dialFunc
	ping        pingFunc // nil = ICMP probing disabled
}

// EnableRace turns on answer racing with the given probe ports (in
// priority order), overall time budget, TCP deadline and ICMP toggle.
func (r *Resolver) EnableRace(ports []int, timeout, tcpDeadline time.Duration, icmp bool) {
	if len(ports) == 0 {
		ports = []int{443, 80}
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	cfg := &raceConfig{ports: ports, timeout: timeout, tcpDeadline: tcpDeadline, dial: tcpDial}
	if icmp {
		cfg.ping = icmpPing
	}
	r.race = cfg
}

// applyRace narrows msg to the best-responding IP when the answer holds
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
	// A still-valid preferred IP from an earlier race short-circuits this
	// one; the counter on the entry decides when a fresh race is due.
	if out, done := r.applyPref(msg, qtype, name, ips); done {
		return out
	}
	winner, via, rtt := pickWinner(ips, r.race.ports, r.race.timeout, r.race.tcpDeadline, r.race.dial, r.race.ping)
	if winner == nil {
		log.Printf("resolver: race name=%s type=%d candidates=%d no winner (tcp deadline %s, budget %s), keeping upstream answer",
			name, qtype, len(ips), r.race.tcpDeadline, r.race.timeout)
		r.storePref(name, qtype, nil, "", 0)
		return msg
	}
	log.Printf("resolver: race name=%s type=%d candidates=%d winner=%s via=%s rtt=%s",
		name, qtype, len(ips), winner, via, rtt)
	r.storePref(name, qtype, winner, via, rtt)
	return narrow(msg, qtype, winner)
}

// answerIPs returns the distinct IPs carried by records of type qtype in
// the answer section, in answer order.
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

func ipIn(ips []net.IP, want net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(want) {
			return true
		}
	}
	return false
}

// pickWinner runs the concurrent probe described at the top of this file
// and returns the winning IP, how it won ("tcp/443", "tcp/80", "icmp")
// and the winning probe's round-trip — or nil when nothing usable
// responded within timeout.
func pickWinner(ips []net.IP, ports []int, timeout, tcpDeadline time.Duration, dial dialFunc, ping pingFunc) (net.IP, string, time.Duration) {
	if timeout <= 0 {
		timeout = time.Second
	}
	if tcpDeadline <= 0 || tcpDeadline >= timeout {
		if ping != nil {
			// The handover must land inside the budget.
			tcpDeadline = timeout / 2
		} else {
			// Without ICMP there is nobody to hand over to: TCP keeps
			// the whole budget (the original behaviour).
			tcpDeadline = timeout
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type tcpResult struct {
		ip      net.IP
		portIdx int
		port    int
		rtt     time.Duration
		ok      bool
	}
	type icmpResult struct {
		ip  net.IP
		rtt time.Duration
		ok  bool
	}
	// Every probe reports back, success or failure, and the channels are
	// fully buffered: probes never block on send after an early return,
	// and a race where everything refuses at once ends immediately.
	tcpCh := make(chan tcpResult, len(ips)*len(ports))
	for _, ip := range ips {
		for i, port := range ports {
			go func(ip net.IP, idx, port int) {
				rtt, err := dial(ctx, net.JoinHostPort(ip.String(), fmt.Sprint(port)))
				tcpCh <- tcpResult{ip: ip, portIdx: idx, port: port, rtt: rtt, ok: err == nil}
			}(ip, i, port)
		}
	}
	icmpCh := make(chan icmpResult, len(ips))
	icmpPending := 0
	if ping != nil {
		icmpPending = len(ips)
		for _, ip := range ips {
			go func(ip net.IP) {
				rtt, err := ping(ctx, ip)
				icmpCh <- icmpResult{ip: ip, rtt: rtt, ok: err == nil}
			}(ip)
		}
	}

	tcpPending := len(ips) * len(ports)
	tcpLive := true // TCP results still count
	var fallback *tcpResult
	var bestICMP *icmpResult
	deadline := time.NewTimer(tcpDeadline)
	defer deadline.Stop()

	tcpWin := func(r *tcpResult) (net.IP, string, time.Duration) {
		return r.ip, fmt.Sprintf("tcp/%d", r.port), r.rtt
	}
	icmpWin := func() (net.IP, string, time.Duration) {
		return bestICMP.ip, "icmp", bestICMP.rtt
	}

	for {
		// Terminal states reachable without waiting for another event.
		if tcpPending == 0 && fallback != nil {
			return tcpWin(fallback)
		}
		if (tcpPending == 0 || !tcpLive) && bestICMP != nil {
			return icmpWin()
		}
		if tcpPending == 0 && icmpPending == 0 {
			return nil, "", 0
		}
		if !tcpLive && icmpPending == 0 {
			return nil, "", 0
		}
		select {
		case r := <-tcpCh:
			tcpPending--
			if tcpLive && r.ok {
				if r.portIdx == 0 {
					return tcpWin(&r)
				}
				if fallback == nil || r.rtt < fallback.rtt {
					c := r
					fallback = &c
				}
			}
			if tcpPending == 0 && fallback == nil && bestICMP == nil && icmpPending > 0 {
				// TCP is conclusively dead — every dial came back
				// without a success — so hand over to ICMP now
				// instead of idling until the deadline.
				tcpLive = false
			}
		case p := <-icmpCh:
			icmpPending--
			if p.ok && (bestICMP == nil || p.rtt < bestICMP.rtt) {
				c := p
				bestICMP = &c
			}
		case <-deadline.C:
			tcpLive = false
			if fallback != nil {
				return tcpWin(fallback)
			}
			if bestICMP != nil {
				return icmpWin()
			}
			if icmpPending == 0 {
				return nil, "", 0
			}
			// Keep waiting for ICMP until the overall budget ends.
		case <-ctx.Done():
			if bestICMP != nil {
				return icmpWin()
			}
			if fallback != nil {
				return tcpWin(fallback)
			}
			return nil, "", 0
		}
	}
}

// narrow returns a copy of msg whose answer keeps only the records that
// are not addresses of the queried type, plus the winner's own record(s).
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
