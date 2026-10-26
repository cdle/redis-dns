package client

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Reverse lookup: given IPs, return the domains already present in the local
// cache whose answers contain them. This is a pure cache scan -- it never
// triggers an upstream resolution, so it is cheap and side-effect free.
//
// The local cache is keyed by "dns:cache:<name>:<type>", so a scan has to
// unpack every cached wire message and look at its answer records. That is
// acceptable because the cache is bounded by traffic, not by the internet.

// ReverseResult maps one queried IP to the cached domains that answer it.
type ReverseResult struct {
	IP      string            `json:"ip"`
	Domains []string          `json:"domains"` // sorted, unique, lower-case
	Records map[string]string `json:"records"` // domain -> "A 1.2.3.4"
}

// ReverseResponse is the batch reply. Elapsed is the scan wall time.
type ReverseResponse struct {
	Results []ReverseResult `json:"results"`
	Elapsed string          `json:"elapsed"`
	Scanned int             `json:"scanned"` // cache entries examined
}

// maxReverseBody bounds the request body.
const maxReverseBody = 64 << 10

// maxReverseIPs bounds how many IPs one request may ask about.
const maxReverseIPs = 256

// reverseHandler serves POST /reverse with a JSON body that is either
// {"ips":["1.2.3.4", ...]} or a bare JSON array ["1.2.3.4", ...], or a plain
// text body with one IP per line. It answers from the local cache only.
func (c *Client) reverseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ips, err := parseReverseBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	start := time.Now()
	results, scanned := c.reverseLookup(ips)
	resp := ReverseResponse{
		Results: results,
		Elapsed: time.Since(start).String(),
		Scanned: scanned,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// parseReverseBody accepts three shapes: a JSON object with "ips", a bare JSON
// array of strings, or newline/whitespace separated plain text.
func parseReverseBody(r *http.Request) ([]string, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxReverseBody))
	if err != nil {
		return nil, err
	}
	body := strings.TrimSpace(string(b))
	if body == "" {
		return nil, io.ErrUnexpectedEOF
	}

	var ips []string
	switch body[0] {
	case '{':
		var in struct {
			IPs []string `json:"ips"`
		}
		if err := json.Unmarshal([]byte(body), &in); err != nil {
			return nil, err
		}
		ips = in.IPs
	case '[':
		if err := json.Unmarshal([]byte(body), &ips); err != nil {
			return nil, err
		}
	default:
		ips = strings.Fields(body)
	}

	// Validate, normalise, and de-duplicate while preserving order.
	seen := make(map[string]bool, len(ips))
	out := make([]string, 0, len(ips))
	for _, s := range ips {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, &net.ParseError{Type: "IP address", Text: s}
		}
		key := ip.String()
		if seen[key] || len(out) >= maxReverseIPs {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return out, nil
}

// reverseLookup scans the local cache once and matches every queried IP
// against the answer records of every cached message.
func (c *Client) reverseLookup(ips []string) ([]ReverseResult, int) {
	// Snapshot the cache under the read lock, then work lock-free.
	c.mu.RLock()
	type snap struct {
		key  string
		wire []byte
	}
	entries := make([]snap, 0, len(c.local))
	now := time.Now()
	for k, e := range c.local {
		if now.After(e.expire) {
			continue
		}
		entries = append(entries, snap{key: k, wire: e.wire})
	}
	c.mu.RUnlock()

	// want[ip] = domain -> record text
	want := make(map[string]map[string]string, len(ips))
	for _, ip := range ips {
		want[ip] = make(map[string]string)
	}

	for _, e := range entries {
		msg := new(dns.Msg)
		if err := msg.Unpack(e.wire); err != nil {
			continue
		}
		for _, rr := range msg.Answer {
			var ipStr string
			switch v := rr.(type) {
			case *dns.A:
				ipStr = v.A.String()
			case *dns.AAAA:
				ipStr = v.AAAA.String()
			default:
				continue
			}
			m, ok := want[ipStr]
			if !ok {
				continue
			}
			// Prefer the record's own owner name (CNAME chains end at the
			// final A/AAAA, which is what the IP actually belongs to).
			owner := strings.ToLower(dns.Fqdn(rr.Header().Name))
			if owner == "" {
				owner = cacheKeyName(e.key)
			}
			if owner == "" {
				continue
			}
			m[owner] = dns.Type(rr.Header().Rrtype).String() + " " + ipStr
		}
	}

	results := make([]ReverseResult, 0, len(ips))
	for _, ip := range ips {
		m := want[ip]
		domains := make([]string, 0, len(m))
		for d := range m {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		records := make(map[string]string, len(domains))
		for _, d := range domains {
			records[d] = m[d]
		}
		results = append(results, ReverseResult{IP: ip, Domains: domains, Records: records})
	}
	return results, len(entries)
}

// cacheKeyName extracts "<name>" from a "dns:cache:<name>:<type>" key.
func cacheKeyName(key string) string {
	const prefix = "dns:cache:"
	if !strings.HasPrefix(key, prefix) {
		return ""
	}
	rest := key[len(prefix):]
	i := strings.LastIndex(rest, ":")
	if i <= 0 {
		return ""
	}
	return strings.ToLower(dns.Fqdn(rest[:i]))
}

// reverseStats returns the current local-cache size.
func (c *Client) reverseStats() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.local)
}

// reverseStatsHandler serves GET /reverse/stats: how many live entries the
// local cache currently holds.
func (c *Client) reverseStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"cached_entries": c.reverseStats()})
}
