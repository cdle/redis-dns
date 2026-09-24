// Package resolver performs upstream DNS resolution on behalf of the server
// and extracts cache TTLs from answers.
package resolver

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Resolver resolves names through a configured upstream recursive resolver.
type Resolver struct {
	upstream string
	network  string
	timeout  time.Duration
}

// New builds a Resolver.
func New(upstream, network string, timeout time.Duration) *Resolver {
	return &Resolver{upstream: upstream, network: network, timeout: timeout}
}

// Resolve queries the upstream and returns the full response message.
func (r *Resolver) Resolve(name string, qtype uint16) (*dns.Msg, error) {
	c := &dns.Client{Net: r.network, Timeout: r.timeout}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	resp, _, err := c.Exchange(m, r.upstream)
	if err != nil {
		return nil, fmt.Errorf("exchange: %w", err)
	}
	return resp, nil
}

// MinTTL returns the smallest cacheable TTL in the message, in seconds. It
// scans answer records and, for negative responses, the SOA in the authority
// section (RFC 2308: negative-caching TTL = min(SOA TTL, SOA.Minttl)).
// A zero result means no TTL could be determined.
func MinTTL(m *dns.Msg) uint32 {
	var min uint32
	consider := func(ttl uint32) {
		if ttl > 0 && (min == 0 || ttl < min) {
			min = ttl
		}
	}
	for _, rr := range m.Answer {
		consider(rr.Header().Ttl)
	}
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			consider(soa.Hdr.Ttl)
			consider(soa.Minttl)
		} else {
			consider(rr.Header().Ttl)
		}
	}
	return min
}
