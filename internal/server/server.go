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
	topN     int                                               // dynamic prefetch breadth (top-queried names)
	halfLife time.Duration                                     // query-count decay half-life
	rank     rankStore                                         // query-count ranking storage
	countCh  chan string                                       // query-count queue feeding runCounter
	jobs     chan string                                       // request payloads for the worker pool
	resolve  func(name string, qtype uint16) (*dns.Msg, error) // prefetch resolve path
}

// New builds a Server. Non-positive respMax is forced to 1000.
func New(rdb *redis.Client, res *resolver.Resolver, group, consumer string, cacheTTL, negTTL time.Duration, respMax int64, workers int, prefetch time.Duration, topN int, halfLife time.Duration) *Server {
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
		topN:     topN,
		halfLife: halfLife,
		rank:     &redisRankStore{rdb: rdb},
		countCh:  make(chan string, countQueueSize),
		jobs:     make(chan string, 256),
		resolve:  res.Resolve,
	}
}

// Run blocks, processing requests until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	log.Printf("server: subscribing %q with %d workers", redisx.ChannelRequests, s.workers)

	go s.runCounter(ctx)
	if s.prefetch > 0 {
		go s.runPrefetch(ctx)
	}

	var wg sync.WaitGroup
	// 订阅者（单一）：接收 pub/sub，分发到 jobs
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.worker(ctx, s.consumer)
	}()
	// 处理者池：并发 resolve
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case payload := <-s.jobs:
					s.handlePayload(ctx, payload)
				}
			}
		}(i)
	}
	wg.Wait()
	return nil
}

func (s *Server) worker(ctx context.Context, consumer string) {
	backoff := time.Second
	for ctx.Err() == nil {
		func() {
			// 单一订阅连接：Redis pub/sub 是广播，如果每个 worker 都
			// SUBSCRIBE，同一条请求会被处理 N 次。所以只有这个 goroutine
			// 订阅，收到后交给共享任务池（s.jobs）并发处理。
			pubsub := s.rdb.Subscribe(ctx, redisx.ChannelRequests)
			defer pubsub.Close()
			ch := pubsub.Channel(redis.WithChannelSize(256))
			for {
				select {
				case <-ctx.Done():
					return
				case <-s.jobs:
					// drain signal（不应发生）
				case msg, ok := <-ch:
					if !ok {
						return // 连接断开，外层重连
					}
					select {
					case s.jobs <- msg.Payload:
					default:
						log.Printf("server: job queue full, dropping request")
					}
				}
			}
		}()
		if ctx.Err() != nil {
			return
		}
		log.Printf("server: %s pubsub disconnected (retry in %s)", consumer, backoff)
		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

// handlePayload parses one request payload and resolves it.
func (s *Server) handlePayload(ctx context.Context, data string) {
	var req proto.Request
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		log.Printf("server: malformed request: %v", err)
		return
	}
	s.handle(ctx, req)
}

func (s *Server) handle(ctx context.Context, req proto.Request) {
	s.countQuery(ctx, req.Name, req.Type)

	start := time.Now()
	resp := &proto.Response{ID: req.ID, Name: req.Name, Type: req.Type}

	// Cache-first: check the shared Redis cache locally (sub-ms on the same
	// host) before hitting the upstream resolver. A cached hit skips the
	// upstream round-trip entirely.
	key := redisx.CacheKey(req.Name, req.Type)
	if wire, err := s.rdb.Get(ctx, key).Bytes(); err == nil && len(wire) > 0 {
		resp.Wire = wire
		var m dns.Msg
		if err := m.Unpack(wire); err == nil {
			resp.Rcode = m.Rcode
		}
		resp.ResolvedAt = time.Now().UnixNano()
		log.Printf("server: cache-hit name=%s type=%d took=%s", req.Name, req.Type, time.Since(start))
		payload, _ := json.Marshal(resp)
		s.rdb.Publish(ctx, redisx.ChannelResponses, payload)
		return
	}

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
	// Fire-and-forget PUBLISH: push semantics deliver the response to every
	// subscriber immediately; no confirmation round-trip on the hot path.
	go func() {
		if err := s.rdb.Publish(ctx, redisx.ChannelResponses, payload).Err(); err != nil {
			log.Printf("server: publish response: %v", err)
		}
	}()
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
	log.Printf("server: prefetch sweep: %d hot domains", len(domains))
	defer func() {
		if r := recover(); r != nil {
			log.Printf("server: prefetch sweep panic: %v", r)
		}
	}()
	for fqdn, intervalStr := range domains {
		interval, err := strconv.Atoi(strings.TrimSpace(intervalStr))
		if err != nil || interval <= 0 {
			interval = int(s.prefetch.Seconds())
		}
		name := strings.ToLower(dns.Fqdn(fqdn))
		if t, ok := next[name]; ok && time.Now().Before(t) {
			continue
		}

		answer, err := s.resolve(name, dns.TypeA)
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
		log.Printf("server: prefetch ok name=%s interval=%ds answers=%d", name, interval, len(answer.Answer))
	}

	s.prefetchDynamic(ctx, next)
	if s.rank != nil && s.halfLife > 0 {
		if err := s.rank.Decay(ctx, decayFactor(s.halfLife, s.prefetch)); err != nil {
			log.Printf("server: prefetch decay: %v", err)
		}
	}
}

// prefetchDynamic refreshes the top-queried names from the ranking
// set: whatever clients actually ask for stays warm, without anyone
// maintaining a fixed list. Entries are rescheduled by answer TTL
// (see prefetchNextDelay), so a hot name never lapses while ranked.
func (s *Server) prefetchDynamic(ctx context.Context, next map[string]time.Time) {
	if s.topN <= 0 || s.rank == nil {
		return
	}
	top, err := s.rank.Top(ctx, s.topN, minPrefetchScore)
	if err != nil {
		log.Printf("server: prefetch top: %v", err)
		return
	}
	refreshed := 0
	for _, m := range dueDynamic(top, next, time.Now()) {
		name, qtype, _ := parseMember(m.Member)
		key := "dyn|" + m.Member
		answer, err := s.resolve(name, qtype)
		if err != nil {
			log.Printf("server: prefetch dyn %s type=%d: %v", name, qtype, err)
			next[key] = time.Now().Add(s.prefetch)
			continue
		}
		wire, err := answer.Pack()
		if err != nil {
			continue
		}
		ttl := s.cache(ctx, name, qtype, wire, answer)
		s.publish(ctx, name, qtype, wire, answer, time.Now().UnixNano())
		next[key] = time.Now().Add(prefetchNextDelay(ttl, s.prefetch))
		refreshed++
	}
	if refreshed > 0 {
		log.Printf("server: prefetch dynamic: refreshed %d of top %d", refreshed, len(top))
	}
}
