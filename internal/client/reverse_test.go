package client

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aRR(name, ip string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   parseIP(ip),
	}
}

func aaaaRR(name, ip string, ttl uint32) dns.RR {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: parseIP(ip),
	}
}

func parseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad ip " + s)
	}
	return ip
}

func newTestClient() *Client {
	return New(nil, 5*time.Second, 300*time.Second)
}

// seed packs a message and stores it in the local cache.
func (c *Client) seed(t *testing.T, m *dns.Msg) {
	t.Helper()
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	c.localSet("dns:cache:"+dns.Fqdn(m.Question[0].Name)+":"+dns.Type(m.Question[0].Qtype).String(), wire, time.Now().UnixNano())
}

func TestReverseLookupBasic(t *testing.T) {
	c := newTestClient()

	m := new(dns.Msg)
	m.SetQuestion("a.example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{aRR("a.example.com", "1.2.3.4", 300), aRR("a.example.com", "5.6.7.8", 300)}
	c.seed(t, m)

	m2 := new(dns.Msg)
	m2.SetQuestion("b.example.com.", dns.TypeA)
	m2.Response = true
	m2.Answer = []dns.RR{aRR("b.example.com", "1.2.3.4", 300)}
	c.seed(t, m2)

	results, scanned := c.reverseLookup([]string{"1.2.3.4", "9.9.9.9"})
	if scanned != 2 {
		t.Fatalf("scanned=%d, want 2", scanned)
	}
	if len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}

	// 1.2.3.4 must map to both domains, sorted.
	got := results[0]
	if got.IP != "1.2.3.4" {
		t.Fatalf("ip=%s", got.IP)
	}
	want := []string{"a.example.com.", "b.example.com."}
	if len(got.Domains) != 2 || got.Domains[0] != want[0] || got.Domains[1] != want[1] {
		t.Fatalf("domains=%v, want %v", got.Domains, want)
	}
	if got.Records["a.example.com."] != "A 1.2.3.4" {
		t.Fatalf("record=%q", got.Records["a.example.com."])
	}

	// Unknown IP yields an empty result, not nil.
	if len(results[1].Domains) != 0 {
		t.Fatalf("unknown ip domains=%v, want empty", results[1].Domains)
	}
}

func TestReverseLookupCNAMEChain(t *testing.T) {
	c := newTestClient()

	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "cdn.example.net.",
		},
		aRR("cdn.example.net", "1.2.3.4", 300),
	}
	c.seed(t, m)

	results, _ := c.reverseLookup([]string{"1.2.3.4"})
	if len(results) != 1 {
		t.Fatalf("results=%d", len(results))
	}
	// The IP belongs to the CNAME target, not the queried name.
	if len(results[0].Domains) != 1 || results[0].Domains[0] != "cdn.example.net." {
		t.Fatalf("domains=%v, want [cdn.example.net.]", results[0].Domains)
	}
}

func TestReverseLookupIgnoresExpired(t *testing.T) {
	c := newTestClient()

	m := new(dns.Msg)
	m.SetQuestion("old.example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{aRR("old.example.com", "1.2.3.4", 1)}
	c.seed(t, m)
	// Force expiry by rewriting the entry's deadline.
	c.mu.Lock()
	for k, e := range c.local {
		e.expire = time.Now().Add(-time.Minute)
		c.local[k] = e
	}
	c.mu.Unlock()

	results, scanned := c.reverseLookup([]string{"1.2.3.4"})
	if scanned != 0 {
		t.Fatalf("scanned=%d, want 0 (expired entries skipped)", scanned)
	}
	if len(results[0].Domains) != 0 {
		t.Fatalf("domains=%v, want empty", results[0].Domains)
	}
}

func TestReverseHandlerJSONObject(t *testing.T) {
	c := newTestClient()
	m := new(dns.Msg)
	m.SetQuestion("a.example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{aRR("a.example.com", "1.2.3.4", 300)}
	c.seed(t, m)

	body := `{"ips":["1.2.3.4","8.8.8.8"]}`
	req := httptest.NewRequest(http.MethodPost, "/reverse", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	c.reverseHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp ReverseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("results=%d", len(resp.Results))
	}
	if len(resp.Results[0].Domains) != 1 || resp.Results[0].Domains[0] != "a.example.com." {
		t.Fatalf("domains=%v", resp.Results[0].Domains)
	}
	if len(resp.Results[1].Domains) != 0 {
		t.Fatalf("second should be empty: %v", resp.Results[1].Domains)
	}
}

func TestReverseHandlerPlainTextAndArray(t *testing.T) {
	c := newTestClient()
	m := new(dns.Msg)
	m.SetQuestion("a.example.com.", dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{aRR("a.example.com", "1.2.3.4", 300)}
	c.seed(t, m)

	for _, body := range []string{"1.2.3.4", `["1.2.3.4"]`, "1.2.3.4\n8.8.8.8\n"} {
		req := httptest.NewRequest(http.MethodPost, "/reverse", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		c.reverseHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("body=%q code=%d", body, rec.Code)
		}
		var resp ReverseResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("body=%q: %v", body, err)
		}
		if len(resp.Results[0].Domains) != 1 {
			t.Fatalf("body=%q domains=%v", body, resp.Results[0].Domains)
		}
	}
}

func TestReverseHandlerRejectsBadIP(t *testing.T) {
	c := newTestClient()
	req := httptest.NewRequest(http.MethodPost, "/reverse", bytes.NewBufferString(`{"ips":["not-an-ip"]}`))
	rec := httptest.NewRecorder()
	c.reverseHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d, want 400", rec.Code)
	}
}

func TestReverseHandlerRejectsGet(t *testing.T) {
	c := newTestClient()
	req := httptest.NewRequest(http.MethodGet, "/reverse", nil)
	rec := httptest.NewRecorder()
	c.reverseHandler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, want 405", rec.Code)
	}
}

func TestReverseHandlerDedup(t *testing.T) {
	c := newTestClient()
	// Same IP repeated; must collapse to one result.
	req := httptest.NewRequest(http.MethodPost, "/reverse",
		bytes.NewBufferString(`{"ips":["1.2.3.4","1.2.3.4","1.2.3.4"]}`))
	rec := httptest.NewRecorder()
	c.reverseHandler(rec, req)
	var resp ReverseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results=%d, want 1 (deduped)", len(resp.Results))
	}
	if resp.Results[0].IP != "1.2.3.4" {
		t.Fatalf("ip=%s, want normalised 1.2.3.4", resp.Results[0].IP)
	}
}

func TestCacheKeyName(t *testing.T) {
	cases := map[string]string{
		"dns:cache:a.example.com.:A":  "a.example.com.",
		"dns:cache:example.com.:AAAA": "example.com.",
		"dns:cache::A":                "",
		"nonsense":                    "",
	}
	for in, want := range cases {
		if got := cacheKeyName(in); got != want {
			t.Errorf("cacheKeyName(%q)=%q, want %q", in, got, want)
		}
	}
}
