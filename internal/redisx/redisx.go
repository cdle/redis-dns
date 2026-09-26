// Package redisx centralizes the Redis key layout, stream/channel names, and
// client construction shared by both the server and the client binaries.
package redisx

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Stream, channel, and key names.
const (
	// StreamRequests is the Redis stream the client publishes resolution
	// requests to and the server consumes from (via a consumer group).
	StreamRequests = "dns:req"

	// StreamResponses is the Redis stream the server publishes answers to and
	// every client reads from, matching messages by request ID. Capped with
	// MAXLEN so stale responses for timed-out requests cannot accumulate.
	StreamResponses = "dns:resp"

	// ChannelUpdates is the pub/sub channel on which the server broadcasts
	// freshly resolved answers so clients can warm their local caches.
	ChannelUpdates = "dns:updates"

	// PrefixCache is prepended to cached-answer keys: dns:cache:<name>:<type>.
	PrefixCache = "dns:cache:"

	// HashHotDomains holds fixed domains the server should refresh on a
	// schedule: field = fqdn, value = refresh interval in seconds.
	HashHotDomains = "dns:hot:domains"
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
// If serverName is non-empty and tls is true, connections are wrapped in
// TLS with that SNI (for a terminator such as stunnel in front of Redis).
func New(addr, username, password string, db, poolSize int, useTLS bool, serverName string) *redis.Client {
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
	}
	if useTLS {
		if serverName == "" {
			if h, _, err := net.SplitHostPort(addr); err == nil {
				serverName = h
			}
		}
		tlsCfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
		opts.TLSConfig = tlsCfg
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
				if err := c.Ping(pingCtx).Err(); err != nil && ctx.Err() == nil {
					log.Printf("redisx: keepalive ping: %v", err)
				}
				cancel()
			}
		}
	}()
}
