package client

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/imdraw/redis-dns/internal/config"
	"github.com/imdraw/redis-dns/internal/redisx"
)

// RunFollow watches the proxy policy group on the mihomo external-controller
// API and keeps the redis backend pinned to the node that is actually in
// use: whichever node serves the proxy traffic also serves DNS resolution.
// Backends are hot-swapped in place (listeners never go down) and the local
// cache is cleared on every switch.
func RunFollow(ctx context.Context, cfg config.Follow, password string, db int, c *Client) {
	interval := time.Duration(cfg.Interval) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	hc := &http.Client{Timeout: 3 * time.Second}

	now := func(group string) string {
		req, _ := http.NewRequest("GET", cfg.API+"/proxies/"+url.PathEscape(group), nil)
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		resp, err := hc.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		var out struct {
			Now string `json:"now"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		return out.Now
	}

	current := ""
	for ctx.Err() == nil {
		node := now(cfg.Group)
		if node == "自动选择" || node == "故障转移" {
			node = now(node) // nested group: resolve one more level
		}
		if be, ok := cfg.Backends[node]; ok && be.Addr != current {
			rdb := redisx.New(be.Addr, "", password, db, 8, true, be.SNI)
			if err := rdb.Ping(ctx).Err(); err != nil {
				log.Printf("follow: ping %s (%s) failed, keeping %s: %v", node, be.Addr, current, err)
				rdb.Close()
			} else {
				c.SwapRedis(rdb)
				current = be.Addr
				log.Printf("follow: node=%s -> backend=%s sni=%s, local cache cleared", node, be.Addr, be.SNI)
			}
		}
		time.Sleep(interval)
	}
}
