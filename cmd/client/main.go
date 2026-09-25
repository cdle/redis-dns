// Command client runs a LAN-side DNS server that answers from a local,
// expiry-aware cache and a Redis cache first, and only falls back to an
// on-demand resolution request to the server-side resolver when the answer is
// not cached. It also subscribes to pushed updates to warm its local cache.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/imdraw/redis-dns/internal/client"
	"github.com/imdraw/redis-dns/internal/config"
	"github.com/imdraw/redis-dns/internal/redisx"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to YAML config file")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	pool := cfg.Redis.PoolSize
	if pool == 0 {
		pool = 8
	}
	rdb := redisx.New(cfg.Redis.Addr, cfg.Redis.Username, cfg.Redis.Password, cfg.Redis.DB, pool)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := ping(ctx, rdb); err != nil {
		log.Fatalf("redis: %v", err)
	}

	// Keep the pooled connections alive so idle NAT/firewall state does not
	// silently drop them; this removes the first-query-after-idle spike.
	redisx.StartKeepalive(ctx, rdb, 15*time.Second)

	c := client.New(
		rdb,
		time.Duration(cfg.BlockTime)*time.Second,
		time.Duration(cfg.LocalTTL)*time.Second,
	)
	log.Printf("client: starting listen=%s doh=%s redis=%s block=%ds local_ttl=%ds",
		cfg.Listen, cfg.DOHListen, cfg.Redis.Addr, cfg.BlockTime, cfg.LocalTTL)

	if err := c.ListenAndServe(ctx, cfg.Listen, cfg.DOHListen); err != nil {
		log.Fatalf("client: %v", err)
	}
	log.Println("client: stopped")
}

func ping(ctx context.Context, rdb *redis.Client) error {
	for i := 0; i < 10; i++ {
		if err := rdb.Ping(ctx).Err(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("redis unreachable after 10 attempts")
}
