// Package redisx centralizes the Redis key layout, stream/channel names, and
// client construction shared by both the server and the client binaries.
package redisx

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/net/proxy"
)

// Stream, channel, and key names.
const (
	// ChannelRequests is the pub/sub channel the client PUBLISHes resolution
	// requests on and the server SUBSCRIBEs to. Pub/sub beats streams for
	// latency: no consumer-group bookkeeping and no polling round-trips.
	ChannelRequests = "dns:req:ps"

	// ChannelResponses is the pub/sub channel the server PUBLISHes answers
	// on; clients receive them instantly (PUBLISH is push, no RTT for poll).
	// Loss tolerance: a missed response only costs the client a retry, and
	// the answer is cached server-side so the retry hits the cache.
	ChannelResponses = "dns:resp:ps"

	// ChannelUpdates is the pub/sub channel on which the server broadcasts
	// freshly resolved answers so clients can warm their local caches.
	ChannelUpdates = "dns:updates"

	// PrefixCache is prepended to cached-answer keys: dns:cache:<name>:<type>.
	PrefixCache = "dns:cache:"

	// HashHotDomains holds fixed domains the server should refresh on a
	// schedule: field = fqdn, value = refresh interval in seconds.
	HashHotDomains = "dns:hot:domains"

	// SetQueryCounts is the sorted set ranking queried names by
	// demand: member = <fqdn>|<type string>, score = decayed query
	// count. The server increments it per client request and keeps
	// the top members prefetched (see internal/server).
	SetQueryCounts = "dns:count:q"
)

// CacheKey returns the Redis key holding a cached DNS answer.
func CacheKey(name string, qtype uint16) string {
	return PrefixCache + name + ":" + strconv.Itoa(int(qtype))
}

// New builds a Redis client from connection parameters. It maintains a
// small pool of long-lived connections and pings them in the background
// so dead connections are detected and replaced before a query hits them.
// poolSize controls how many connections the pool holds; servers running
// concurrent handlers need a larger pool than clients (each blocking
// XReadGroup/XRead consumes one connection for its whole duration).
// If socks5Addr is non-empty, all Redis connections are dialed through
// that SOCKS5 proxy. If useTLS is true, connections are wrapped in TLS
// with serverName as SNI (for a terminator such as stunnel in front of Redis).
func New(addr, username, password string, db, poolSize int, socks5Addr string, useTLS bool, serverName string) *redis.Client {
	if poolSize < 1 {
		poolSize = 4
	}
	opts := &redis.Options{
		Addr:         addr,
		Username:     username,
		Password:     password,
		DB:           db,
		PoolSize:     poolSize,
		MinIdleConns: poolSize / 2,
		// 跨公网 TLS 链路上新建连接的握手要几百毫秒，且 go-redis 每次从
		// 池里取连接都会做健康检查（syscall.Read 探测）。空闲连接被回收
		// 后重建就是 400ms 级的成本，所以这里禁止按空闲时间回收连接，
		// 只依赖 keepalive ping 检测断链。
		PoolTimeout:     2 * time.Second,
		ConnMaxIdleTime: -1, // 永不因空闲回收
		ConnMaxLifetime: 0,  // 永不过期
	}
	if socks5Addr != "" {
		dialer, err := proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
		if err != nil {
			log.Fatalf("redisx: socks5 dialer %s: %v", socks5Addr, err)
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			log.Fatalf("redisx: socks5 dialer %s does not support DialContext", socks5Addr)
		}
		opts.Dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return contextDialer.DialContext(ctx, network, addr)
		}
	}
	if useTLS {
		if serverName == "" {
			if h, _, err := net.SplitHostPort(addr); err == nil {
				serverName = h
			}
		}
		opts.TLSConfig = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	return redis.NewClient(opts)
}

// StartKeepalive pings the Redis client every interval on a background
// goroutine until ctx is cancelled. This keeps idle NAT/firewall state
// open and forces broken connections to be re-established ahead of
// real queries. It returns immediately.
func StartKeepalive(ctx context.Context, c *redis.Client, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pingCtx, cancel := context.WithTimeout(ctx, interval)
				err := c.Ping(pingCtx).Err()
				cancel()
				if err != nil && ctx.Err() == nil {
					if strings.Contains(err.Error(), "client is closed") {
						return // this pool was hot-swapped away; stop pinging it
					}
					log.Printf("redisx: keepalive ping: %v", err)
				}
			}
		}
	}()
}

// WarmPool dials n idle connections ahead of time by issuing cheap PINGs
// through the pool. Called at startup (and after backend swaps) so the first
// burst of concurrent queries does not pay the TLS handshake cost itself.
func WarmPool(ctx context.Context, c *redis.Client, n int) {
	if n < 1 {
		return
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_ = c.Ping(wctx).Err()
		}()
	}
	wg.Wait()
}
