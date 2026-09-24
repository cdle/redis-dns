// Package server implements the server-side resolver loop: it consumes
// requests from a Redis stream, resolves them through an upstream resolver,
// caches the answer, and delivers the response back to the requesting client.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
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
	consumer string
	cacheTTL time.Duration
	respTTL  time.Duration
}

// New builds a Server. A non-positive respTTL is forced to 30s so that
// orphaned response lists cannot leak.
func New(rdb *redis.Client, res *resolver.Resolver, group, consumer string, cacheTTL, respTTL time.Duration) *Server {
	if respTTL <= 0 {
		respTTL = 30 * time.Second
	}
	return &Server{
		rdb:      rdb,
		res:      res,
		group:    group,
		consumer: consumer,
		cacheTTL: cacheTTL,
		respTTL:  respTTL,
	}
}

// Run blocks, processing requests until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.ensureGroup(ctx); err != nil {
		return err
	}
	log.Printf("server: consuming stream %q as %q/%q", redisx.StreamRequests, s.group, s.consumer)

	for {
		if ctx.Err() != nil {
			return nil
		}

		streams, err := s.rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    s.group,
			Consumer: s.consumer,
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

	resp := &proto.Response{ID: req.ID, Name: req.Name, Type: req.Type}

	answer, err := s.res.Resolve(req.Name, req.Type)
	if err != nil {
		resp.Err = err.Error()
		log.Printf("server: resolve %s/%d: %v", req.Name, req.Type, err)
	} else {
		resp.Rcode = answer.Rcode
		if wire, perr := answer.Pack(); perr != nil {
			resp.Err = perr.Error()
		} else {
			resp.Wire = wire
			if answer.Rcode == dns.RcodeSuccess {
				s.cache(ctx, req, wire, answer)
			}
		}
	}

	payload, _ := json.Marshal(resp)
	key := redisx.RespKey(req.ID)
	if err := s.rdb.LPush(ctx, key, payload).Err(); err != nil {
		log.Printf("server: lpush %s: %v", key, err)
		return
	}
	s.rdb.Expire(ctx, key, s.respTTL)
}

func (s *Server) cache(ctx context.Context, req proto.Request, wire []byte, answer *dns.Msg) {
	if s.cacheTTL <= 0 {
		return
	}
	ttl := s.cacheTTL
	if min := minTTLSeconds(answer); min > 0 && time.Duration(min)*time.Second < ttl {
		ttl = time.Duration(min) * time.Second
	}
	key := redisx.CacheKey(req.Name, req.Type)
	if err := s.rdb.Set(ctx, key, wire, ttl).Err(); err != nil {
		log.Printf("server: cache %s: %v", key, err)
	}
}

// minTTLSeconds returns the smallest answer-record TTL so the cache never
// outlives the real records it holds.
func minTTLSeconds(m *dns.Msg) uint32 {
	var min uint32
	for _, rr := range m.Answer {
		ttl := rr.Header().Ttl
		if min == 0 || ttl < min {
			min = ttl
		}
	}
	return min
}
