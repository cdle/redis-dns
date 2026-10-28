package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/imdraw/redis-dns/internal/redisx"
)

// Test panel: an HTML page served on the DoH listener that runs real lookups
// through the client's own path (local cache -> redis -> upstream) and shows
// the numbers the logs do: latency, cache hit/miss, rcode, answers, TTLs.

// panelPreset is one domain to test (also used as the request item type).
type panelPreset struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Tag  string `json:"tag,omitempty"`
}

// panelPresets feed the UI checkboxes.
var panelPresets = []panelPreset{
	{Name: "www.baidu.com", Type: "A", Tag: "国内"},
	{Name: "www.qq.com", Type: "A", Tag: "国内"},
	{Name: "www.bilibili.com", Type: "A", Tag: "国内"},
	{Name: "www.douyin.com", Type: "A", Tag: "国内"},
	{Name: "www.zhihu.com", Type: "A", Tag: "国内"},
	{Name: "github.com", Type: "A", Tag: "国外"},
	{Name: "www.google.com", Type: "A", Tag: "国外"},
	{Name: "openai.com", Type: "A", Tag: "国外"},
	{Name: "www.youtube.com", Type: "A", Tag: "国外"},
	{Name: "netflix.com", Type: "A", Tag: "国外"},
	{Name: "www.baidu.com", Type: "AAAA", Tag: "国内"},
	{Name: "github.com", Type: "AAAA", Tag: "国外"},
}

// panelTestResult is one query's outcome.
type panelTestResult struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Tag       string   `json:"tag,omitempty"`
	LatencyMs float64  `json:"latency_ms"`
	Path      string   `json:"path"` // local | upstream
	Rcode     string   `json:"rcode"`
	Answers   []string `json:"answers"`
	TTLMin    int      `json:"ttl_min_sec"` // min TTL across answers
	Error     string   `json:"error,omitempty"`
}

// panelRunRequest / panelRunResponse.
type panelRunRequest struct {
	Queries []panelPreset `json:"queries"`
}
type panelRunResponse struct {
	Results   []panelTestResult `json:"results"`
	ElapsedMs float64           `json:"elapsed_ms"`
}

// panelRunHandler runs the requested lookups concurrently.
func (c *Client) panelRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in panelRunRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&in); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(in.Queries) == 0 {
		in.Queries = panelPresets
	}
	if len(in.Queries) > 64 {
		in.Queries = in.Queries[:64]
	}

	// 预热连接池：清缓存后并发测试想测的是解析路径而非建连成本。
	// 用与查询数相同的 ping 数把池撑起来（幂等，池已热时 <1ms）。
	warmCtx, warmCancel := context.WithTimeout(r.Context(), 8*time.Second)
	var warmWG sync.WaitGroup
	need := len(in.Queries)
	if need > 16 {
		need = 16
	}
	for i := 0; i < need; i++ {
		warmWG.Add(1)
		go func() {
			defer warmWG.Done()
			_ = c.rdb.Ping(warmCtx).Err()
		}()
	}
	warmWG.Wait()
	warmCancel()

	start := time.Now()
	results := make([]panelTestResult, len(in.Queries))
	var wg sync.WaitGroup
	for i, q := range in.Queries {
		wg.Add(1)
		go func(i int, q panelPreset) {
			defer wg.Done()
			results[i] = c.panelRunOne(q)
		}(i, q)
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(panelRunResponse{
		Results:   results,
		ElapsedMs: float64(time.Since(start).Microseconds()) / 1000.0,
	})
}

// panelRunOne executes one lookup through the normal client path.
func (c *Client) panelRunOne(q panelPreset) panelTestResult {
	out := panelTestResult{Name: q.Name, Type: strings.ToUpper(q.Type), Tag: q.Tag}
	qtype := dns.StringToType[out.Type]
	if qtype == 0 {
		qtype = dns.TypeA
	}
	name := strings.ToLower(dns.Fqdn(q.Name))
	_, wasCached := c.localGet(redisx.CacheKey(name, qtype))

	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	start := time.Now()
	wire, rcode := c.resolveQuery("panel", m)
	out.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	out.Rcode = dns.RcodeToString[rcode]
	out.Path = "upstream"
	if wasCached {
		out.Path = "local"
	} else if out.LatencyMs < 5 && out.Rcode != "SERVFAIL" {
		// Warmed by a push between the two checks; still a cache hit.
		out.Path = "local"
	}

	if wire == nil {
		out.Error = "no answer"
		return out
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(wire); err != nil {
		out.Error = "unpack: " + err.Error()
		return out
	}
	out.TTLMin = -1
	for _, rr := range resp.Answer {
		out.Answers = append(out.Answers, rr.String())
		ttl := int(rr.Header().Ttl)
		if out.TTLMin == -1 || ttl < out.TTLMin {
			out.TTLMin = ttl
		}
	}
	if len(resp.Answer) == 0 {
	}
	return out
}

// panelCacheClearHandler wipes the local cache (test cold paths).
func (c *Client) panelCacheClearHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	n := c.reverseStats()
	c.mu.Lock()
	c.local = make(map[string]localEntry)
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"cleared": n})
}

// panelCacheListHandler dumps the live cache.
func (c *Client) panelCacheListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	type item struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		TTL     int    `json:"ttl_sec"`
		Rcode   string `json:"rcode"`
		Answers int    `json:"answers"`
	}
	now := time.Now()
	c.mu.RLock()
	items := make([]item, 0, len(c.local))
	for k, e := range c.local {
		if now.After(e.expire) {
			continue
		}
		// 键形如 "dns:cache:<fqdn>:<TYPE>"（fqdn 自身也含点但不含冒号，
		// TYPE 是已知类型字符串），取最后一个冒号之后即是类型。
		rest := strings.TrimPrefix(k, "dns:cache:")
		typ := "OTHER"
		if i := strings.LastIndex(rest, ":"); i > 0 {
			if t, ok := dns.StringToType[rest[i+1:]]; ok {
				typ = dns.Type(t).String()
			}
		}
		name := cacheKeyName(k)
		rc := ""
		ans := 0
		if msg := new(dns.Msg); msg.Unpack(e.wire) == nil {
			rc = dns.RcodeToString[msg.Rcode]
			ans = len(msg.Answer)
		}
		items = append(items, item{
			Name: name, Type: typ,
			TTL:   int(e.expire.Sub(now).Seconds()),
			Rcode: rc, Answers: ans,
		})
	}
	c.mu.RUnlock()
	sort.Slice(items, func(a, b int) bool { return items[a].Name < items[b].Name })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

// panelPageData feeds the HTML template.
type panelPageData struct {
	Presets       []panelPreset
	CachedEntries int
}

// panelHandler serves the HTML page.
func (c *Client) panelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = panelTmpl.Execute(w, panelPageData{Presets: panelPresets, CachedEntries: c.reverseStats()})
}
