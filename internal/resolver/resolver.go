// Package resolver performs upstream DNS resolution on behalf of the server.
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
