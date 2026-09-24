// Package client runs a LAN-side DNS server that answers from local and Redis
// caches first, and only falls back to an on-demand resolution request to the
// server-side resolver when the answer is not cached.
package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"

	"github.com/imdraw/redis-dns/internal/proto"
	"github.com/imdraw/redis-dns/internal/redisx"
)

// Client is a DNS server that answers LAN queries, backed by a Redis cache and
// an on-demand resolution channel to the server-side resolver.
type Client struct {
	rdb      *redis.Client
	block    time.Duration
	localTTL time.Duration

	mu    sync.RWMutex
	local map[string]localEntry
}

type localEntry struct {
	wire   []byte
	expire time.Time
}

// New builds a Client. Non-positive timeouts are forced to sane defaults.
func New(rdb *redis.Client, block, localTTL time.Duration) *Client {
	if block <= 0 {
		block = 5 * time.Second
	}
	if localTTL <= 0 {
		localTTL = 300 * time.Second
	}
	return &Client{
		rdb:      rdb,
		block:    block,
		localTTL: localTTL,
		local:    make(map[string]localEntry),
	}
}

// ListenAndServe runs the DNS server on addr for both UDP and TCP until ctx is
// cancelled.
func (c *Client) ListenAndServe(ctx context.Context, addr string) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", c.handle)

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()

	log.Printf("client: serving DNS on %s (udp+tcp)", addr)

	select {
	case err := <-errCh:
		udp.Shutdown()
		tcp.Shutdown()
		return err
	case <-ctx.Done():
		udp.Shutdown()
		tcp.Shutdown()
		return nil
	}
}

func (c *Client) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.ToLower(dns.Fqdn(q.Name))
	key := redisx.CacheKey(name, q.Qtype)

	// 1. Local in-memory cache.
	if wire, ok := c.localGet(key); ok {
		c.reply(w, r, wire)
		return
	}

	// 2. Redis cache.
	if b, err := c.rdb.Get(context.Background(), key).Bytes(); err == nil && len(b) > 0 {
		c.localSet(key, b)
		c.reply(w, r, b)
		return
	}

	// 3. On-demand resolution via the server.
	wire, err := c.resolve(context.Background(), name, q.Qtype)
	if err != nil {
		log.Printf("client: resolve %s/%d: %v", name, q.Qtype, err)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	c.localSet(key, wire)
	c.reply(w, r, wire)
}

// reply unpacks a wire-format answer and echoes it to the requester.
func (c *Client) reply(w dns.ResponseWriter, r *dns.Msg, wire []byte) {
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		n := new(dns.Msg)
		n.SetReply(r)
		n.Rcode = dns.RcodeServerFailure
		w.WriteMsg(n)
		return
	}
	m.Id = r.Id
	w.WriteMsg(m)
}

// resolve publishes a request to the stream and blocks on the per-request
// response list.
func (c *Client) resolve(ctx context.Context, name string, qtype uint16) ([]byte, error) {
	req := proto.Request{ID: newID(), Name: name, Type: qtype}
	payload, _ := json.Marshal(req)

	if err := c.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: redisx.StreamRequests,
		Values: map[string]interface{}{"data": string(payload)},
	}).Err(); err != nil {
		return nil, err
	}

	key := redisx.RespKey(req.ID)
	vals, err := c.rdb.BLPop(ctx, c.block, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errors.New("resolution timed out")
		}
		return nil, err
	}
	if len(vals) < 2 {
		return nil, errors.New("empty response")
	}

	var resp proto.Response
	if err := json.Unmarshal([]byte(vals[1]), &resp); err != nil {
		return nil, err
	}
	if resp.Err != "" {
		return nil, errors.New(resp.Err)
	}
	if len(resp.Wire) == 0 {
		return nil, errors.New("empty answer")
	}
	return resp.Wire, nil
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func (c *Client) localGet(key string) ([]byte, bool) {
	c.mu.RLock()
	e, ok := c.local[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expire) {
		c.mu.Lock()
		delete(c.local, key)
		c.mu.Unlock()
		return nil, false
	}
	return e.wire, true
}

func (c *Client) localSet(key string, wire []byte) {
	c.mu.Lock()
	c.local[key] = localEntry{wire: wire, expire: time.Now().Add(c.localTTL)}
	c.mu.Unlock()
}
