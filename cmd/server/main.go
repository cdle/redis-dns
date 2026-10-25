// Command server is the server-side resolver: it consumes DNS resolution
// requests from a Redis stream with a pool of workers, resolves them via an
// upstream resolver, caches answers, delivers responses on a response stream,
// and broadcasts freshly resolved answers on a pub/sub channel.
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

	"github.com/imdraw/redis-dns/internal/config"
	"github.com/imdraw/redis-dns/internal/redisx"
	"github.com/imdraw/redis-dns/internal/resolver"
	"github.com/imdraw/redis-dns/internal/server"
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
		pool = 32 // concurrent handlers need headroom beyond the blocking workers
	}
	rdb := redisx.New(cfg.Redis.Addr, cfg.Redis.Username, cfg.Redis.Password, cfg.Redis.DB, pool, "", false, "")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("cfg redis debug: %+v", cfg.Redis)
	if err := ping(ctx, rdb); err != nil {
		log.Fatalf("redis: %v", err)
	}

	res := resolver.New(
		cfg.Upstream.Addr,
		cfg.Upstream.Network,
		time.Duration(cfg.Upstream.Timeout)*time.Second,
	)
	if cfg.Race.IsEnabled() {
		res.EnableRace(cfg.Race.PortList(), cfg.Race.TimeoutDur(), cfg.Race.TCPDeadlineDur(), cfg.Race.ICMPEnabled())
		res.EnablePref(resolver.NewRedisPrefBackend(rdb),
			cfg.Race.PrefTTLDur(), cfg.Race.PrefNegTTLDur(), cfg.Race.RecheckHitsN(), cfg.Race.RecheckAgeDur())
	}
	srv := server.New(
		rdb,
		res,
		cfg.Group,
		cfg.Consumer,
		time.Duration(cfg.CacheTTL)*time.Second,
		time.Duration(cfg.NegTTL)*time.Second,
		cfg.RespMax,
		cfg.Workers,
		time.Duration(cfg.Prefetch.Interval)*time.Second,
		cfg.Prefetch.TopNN(),
		cfg.Prefetch.DecayDur(),
	)

	log.Printf("server: starting upstream=%s/%s timeout=%ds workers=%d cache_ttl=%ds neg_ttl=%ds resp_max=%d prefetch=%ds race=%v ports=%v budget=%s tcp_deadline=%s icmp=%v pref_ttl=%s pref_neg_ttl=%s recheck=%d/%s topn=%d count_halflife=%s",
		cfg.Upstream.Addr, cfg.Upstream.Network, cfg.Upstream.Timeout, cfg.Workers, cfg.CacheTTL, cfg.NegTTL, cfg.RespMax, cfg.Prefetch.Interval,
		cfg.Race.IsEnabled(), cfg.Race.PortList(), cfg.Race.TimeoutDur(), cfg.Race.TCPDeadlineDur(), cfg.Race.ICMPEnabled(),
		cfg.Race.PrefTTLDur(), cfg.Race.PrefNegTTLDur(), cfg.Race.RecheckHitsN(), cfg.Race.RecheckAgeDur(), cfg.Prefetch.TopNN(), cfg.Prefetch.DecayDur())

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Println("server: stopped")
}

func ping(ctx context.Context, rdb *redis.Client) error {
	for i := 0; i < 10; i++ {
		if err := rdb.Ping(ctx).Err(); err == nil {
			return nil
		} else {
			log.Printf("redis ping attempt %d failed: %v", i+1, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("redis unreachable after 10 attempts")
}
