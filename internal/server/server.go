// Package server implements the server-side resolver: it consumes requests
// from a Redis stream with a pool of concurrent workers, resolves them
// through an upstream resolver, caches the answer (including negative
// answers), delivers the response on a response stream, and broadcasts the
// freshly resolved answer on a pub/sub channel so clients can warm their
// local caches.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"

	"github.com/imdraw/redis-dns/internal/proto"
	"github.com/imdraw/redis-dns/internal/redisx"
	"github.com/imdraw/redis-dns/internal/resolver"
)

// Server consumes resolution requests and answers them.
type Server struct {
	rdb      *redis.Client
	res      *resolver.Resolver
	group    string
	consumer string // base consumer name; workers append -<i>
	cacheTTL time.Duration
	negTTL   time.Duration
	respMax  int64
	workers  int
	prefetch time.Duration
}

// New builds a Server. Non-positive respMax is forced to 1000.
func New(rdb *redis.Client, res *resolver.Resolver, group, consumer string, cacheTTL, negTTL time.Duration, respMax int64, workers int, prefetch time.Duration) *Server {
	if respMax <= 0 {
		respMax = 1000
	}
	if workers <= 0 {
		workers = 1
	}
	return &Server{
		rdb:      rdb,
		res:      res,
		group:    group,
		consumer: consumer,
		cacheTTL: cacheTTL,
		negTTL:   negTTL,
		respMax:  respMax,
		workers:  workers,
		prefetch: prefetch,
	}
}

// Run blocks, processing requests until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.ensureGroup(ctx); err != nil {
		return err
	}
	log.Printf("server: consuming stream %q as group %q with %d workers", redisx.StreamRequests, s.group, s.workers)

	if s.prefetch > 0 {
		go s.runPrefetch(ctx)
	}

	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.worker(ctx, fmt.Sprintf("%s-%d", s.consumer, i))
		}(i)
	}
	wg.Wait()
	return nil
}

func (s *Server) worker(ctx context.Context, consumer string) {
	for {
		if ctx.Err() != nil {
			return
		}

		streams, err := s.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    s.group,
			Consumer: consumer,
			Streams:  []string{redisx.StreamRequests, ">"},
			Count:    16,
			Block:    2 * time.Second,
		}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) || ctx.Err() != nil {
				continue
			}
			log.Printf("server: xreadgroup: %v", err)
			time.Sleep(time.Second)
			continue
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {
				s.handle(ctx, msg)
				// Ack regardless so malformed messages never loop forever.
				s.rdb.XAck(ctx, redisx.StreamRequests, s.group, msg.ID)
			}
		}
	}
}

func (s *Server) ensureGroup(ctx context.Context) error {
	err := s.rdb.XGroupCreateMkStream(ctx, redisx.StreamRequests, s.group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

func (s *Server) handle(ctx context.Context, msg redis.XMessage) {
	data, ok := msg.Values["data"].(string)
	if !ok {
		log.Printf("server: message %s missing data field", msg.ID)
		return
	}

	var req proto.Request
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		log.Printf("server: malformed request: %v", err)
		return
	}

	start := time.Now()
	resp := &proto.Response{ID: req.ID, Name: req.Name, Type: req.Type}

	answer, err := s.res.Resolve(req.Name, req.Type)
	if err != nil {
		resp.Err = err.Error()
		log.Printf("server: resolve name=%s type=%d error=%v took=%s", req.Name, req.Type, err, time.Since(start))
	} else {
		wire, perr := answer.Pack()
		if perr != nil {
			resp.Err = perr.Error()
			log.Printf("server: resolve name=%s type=%d pack_error=%v took=%s", req.Name, req.Type, perr, time.Since(start))
		} else {
			resp.Wire = wire
			resp.Rcode = answer.Rcode
			resp.ResolvedAt = time.Now().UnixNano()
			ttl := s.cache(ctx, req.Name, req.Type, wire, answer)
			s.publish(ctx, req.Name, req.Type, wire, answer, resp.ResolvedAt)
			log.Printf("server: resolve name=%s type=%d rcode=%s answers=%d ttl=%s took=%s", req.Name, req.Type, dns.RcodeToString[answer.Rcode], len(answer.Answer), ttl, time.Since(start))
		}
	}

	payload, _ := json.Marshal(resp)
	if err := s.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: redisx.StreamResponses,
		MaxLen: s.respMax,
		Approx: true,
		Values: map[string]interface{}{"data": string(payload)},
	}).Err(); err != nil {
		log.Printf("server: xadd response: %v", err)
	}
}

// cache stores the answer wire verbatim with a TTL bounded by the record TTLs
// (and by negTTL for negative answers), so the Redis cache never outlives the
// real records it holds.
func (s *Server) cache(ctx context.Context, name string, qtype uint16, wire []byte, answer *dns.Msg) time.Duration {
	ttl := s.cacheTTL
	if answer.Rcode == dns.RcodeNameError {
		ttl = s.negTTL
	}
	if ttl <= 0 {
		return 0
	}
	if min := resolver.MinTTL(answer); min > 0 && time.Duration(min)*time.Second < ttl {
		ttl = time.Duration(min) * time.Second
	}
	key := redisx.CacheKey(name, qtype)
	if err := s.rdb.Set(ctx, key, wire, ttl).Err(); err != nil {
		log.Printf("server: cache %s: %v", key, err)
	}
	return ttl
}

// publish broadcasts a freshly resolved answer on the updates channel.
func (s *Server) publish(ctx context.Context, name string, qtype uint16, wire []byte, answer *dns.Msg, resolvedAt int64) {
	upd := &proto.Update{Name: name, Type: qtype, Rcode: answer.Rcode, ResolvedAt: resolvedAt, Wire: wire}
	payload, err := json.Marshal(upd)
	if err != nil {
		return
	}
	if err := s.rdb.Publish(ctx, redisx.ChannelUpdates, payload).Err(); err != nil {
		log.Printf("server: publish: %v", err)
	}
}

// runPrefetch periodically refreshes the fixed domains listed in the
// dns:hot:domains hash (field=fqdn, value=refresh interval seconds), caches
// the result, and broadcasts it so clients stay warm without querying.
func (s *Server) runPrefetch(ctx context.Context) {
	log.Printf("server: prefetching hot domains every %s", s.prefetch)
	next := make(map[string]time.Time)
	ticker := time.NewTicker(s.prefetch)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.prefetchSweep(ctx, next)
		}
	}
}

func (s *Server) prefetchSweep(ctx context.Context, next map[string]time.Time) {
	domains, err := s.rdb.HGetAll(ctx, redisx.HashHotDomains).Result()
	if err != nil {
		log.Printf("server: prefetch hgetall: %v", err)
		return
	}
	for fqdn, intervalStr := range domains {
		interval, err := strconv.Atoi(strings.TrimSpace(intervalStr))
		if err != nil || interval <= 0 {
			interval = int(s.prefetch.Seconds())
		}
		name := strings.ToLower(dns.Fqdn(fqdn))
		if t, ok := next[name]; ok && time.Now().Before(t) {
			continue
		}

		answer, err := s.res.Resolve(name, dns.TypeA)
		if err != nil {
			log.Printf("server: prefetch %s: %v", name, err)
			continue
		}
		wire, err := answer.Pack()
		if err != nil {
			continue
		}
		s.cache(ctx, name, dns.TypeA, wire, answer)
		s.publish(ctx, name, dns.TypeA, wire, answer, time.Now().UnixNano())
		next[name] = time.Now().Add(time.Duration(interval) * time.Second)
	}
}
