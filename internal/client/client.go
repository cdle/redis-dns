// Package client runs a LAN-side DNS server that answers from a local,
// expiry-aware cache and a Redis cache first, and only falls back to an
// on-demand resolution request when the answer is not cached. It also
// subscribes to the server's updates channel to warm its local cache from
// pushed answers.
package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"

	"github.com/imdraw/redis-dns/internal/proto"
	"github.com/imdraw/redis-dns/internal/redisx"
	"github.com/imdraw/redis-dns/internal/resolver"
)

// Client is a DNS server that answers LAN queries, backed by a Redis cache, an
// on-demand resolution channel, and pushed updates from the server.
type Client struct {
	rdb      *redis.Client
	block    time.Duration
	localTTL time.Duration // fallback TTL when the wire carries no usable TTL

	sf singleflight.Group

	mu    sync.RWMutex
	local map[string]localEntry

	wmu   sync.Mutex
	waits map[string]chan proto.Response
}

type localEntry struct {
	wire       []byte
	expire     time.Time
	resolvedAt int64
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
		waits:    make(map[string]chan proto.Response),
	}
}

// ListenAndServe runs the DNS server on addr for both UDP and TCP, plus the
// response dispatcher and update subscriber, until ctx is cancelled.
func (c *Client) ListenAndServe(ctx context.Context, addr, dohAddr string) error {
	go c.runDispatcher(ctx)
	go c.runSubscriber(ctx)

	if dohAddr != "" {
		go c.serveDoH(ctx, dohAddr)
	}

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
	src := "udp"
	if w.RemoteAddr() != nil && w.RemoteAddr().Network() == "tcp" {
		src = "tcp"
	}
	wire, rcode := c.resolveQuery(src, r)
	if wire == nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = rcode
		w.WriteMsg(m)
		return
	}
	c.reply(w, r, wire)
}

// resolveQuery answers a single-question DNS message and returns the
// wire-format answer plus the RCODE to use when no answer was produced. It is
// shared by the DNS (UDP/TCP) and DoH (HTTP) frontends.
func (c *Client) resolveQuery(src string, r *dns.Msg) ([]byte, int) {
	if len(r.Question) != 1 {
		return nil, dns.RcodeFormatError
	}

	q := r.Question[0]
	name := strings.ToLower(dns.Fqdn(q.Name))
	key := redisx.CacheKey(name, q.Qtype)
	start := time.Now()

	// 1. Local expiry-aware cache.
	if wire, ok := c.localGet(key); ok {
		log.Printf("client: query src=%s name=%s type=%d path=local took=%s", src, name, q.Qtype, time.Since(start))
		return wire, dns.RcodeSuccess
	}

	// 2. Redis cache.
	if b, err := c.rdb.Get(context.Background(), key).Bytes(); err == nil && len(b) > 0 {
		c.localSet(key, b, time.Now().UnixNano())
		log.Printf("client: query src=%s name=%s type=%d path=redis took=%s", src, name, q.Qtype, time.Since(start))
		return b, dns.RcodeSuccess
	}

	// 3. On-demand resolution, coalesced across concurrent identical queries.
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		return c.resolve(context.Background(), name, q.Qtype)
	})
	if err != nil {
		log.Printf("client: query src=%s name=%s type=%d path=upstream error=%v took=%s", src, name, q.Qtype, err, time.Since(start))
		return nil, dns.RcodeServerFailure
	}
	resp := v.(proto.Response)
	c.localSet(key, resp.Wire, resp.ResolvedAt)
	log.Printf("client: query src=%s name=%s type=%d path=upstream rcode=%d took=%s", src, name, q.Qtype, resp.Rcode, time.Since(start))
	return resp.Wire, dns.RcodeSuccess
}

// dohHandler serves DNS-over-HTTPS (RFC 8484) on /dns-query.
func (c *Client) dohHandler(w http.ResponseWriter, r *http.Request) {
	var msg *dns.Msg
	switch r.Method {
	case http.MethodGet:
		b, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(b); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(b); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	wire, rcode := c.resolveQuery("doh", msg)
	if wire == nil {
		m := new(dns.Msg)
		m.SetReply(msg)
		m.Rcode = rcode
		wire, _ = m.Pack()
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(wire)
}

// serveDoH runs the DoH HTTP frontend on addr until ctx is cancelled.
func (c *Client) serveDoH(ctx context.Context, addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", c.dohHandler)
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Printf("client: serving DoH on http://%s/dns-query", addr)
	if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
		log.Printf("client: DoH server: %v", err)
	}
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

// resolve publishes a request to the stream and waits for the matching
// response to arrive on the response stream (delivered via the dispatcher).
func (c *Client) resolve(ctx context.Context, name string, qtype uint16) (proto.Response, error) {
	req := proto.Request{ID: newID(), Name: name, Type: qtype}
	payload, _ := json.Marshal(req)

	ch := make(chan proto.Response, 1)
	c.register(req.ID, ch)
	defer c.unregister(req.ID)

	// Fire the XADD and do not wait for its round-trip confirmation: the
	// server only needs the message to land in the stream, and the blocking
	// XRead below delivers the answer as soon as it is ready. Skipping the
	// confirmation round-trip saves one full RTT on every cold query.
	xaddErr := make(chan error, 1)
	go func() {
		xaddErr <- c.rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: redisx.StreamRequests,
			Values: map[string]interface{}{"data": string(payload)},
		}).Err()
	}()

	select {
	case resp := <-ch:
		if resp.Err != "" {
			return resp, errors.New(resp.Err)
		}
		if len(resp.Wire) == 0 {
			return resp, errors.New("empty answer")
		}
		return resp, nil
	case err := <-xaddErr:
		// The XADD confirmation only means the request landed in the stream —
		// the response is still on its way. Only a real XADD failure aborts.
		if err != nil {
			return proto.Response{}, err
		}
		// Confirmation received, keep waiting for the response below.
		select {
		case resp := <-ch:
			if resp.Err != "" {
				return resp, errors.New(resp.Err)
			}
			if len(resp.Wire) == 0 {
				return resp, errors.New("empty answer")
			}
			return resp, nil
		case <-time.After(c.block):
			return proto.Response{}, errors.New("resolution timed out")
		case <-ctx.Done():
			return proto.Response{}, ctx.Err()
		}
	case <-time.After(c.block):
		return proto.Response{}, errors.New("resolution timed out")
	case <-ctx.Done():
		return proto.Response{}, ctx.Err()
	}
}

// runDispatcher reads the response stream and routes each response to the
// pending request waiting on it. A single blocking reader serves all pending
// requests, so the Redis connection pool is not exhausted by per-request
// blocking reads.
func (c *Client) runDispatcher(ctx context.Context) {
	lastID := "$"
	backoff := time.Second
	for ctx.Err() == nil {
		streams, err := c.rdb.XRead(ctx, &redis.XReadArgs{
			Streams: []string{redisx.StreamResponses, lastID},
			Count:   100,
			Block:   0,
		}).Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, redis.Nil) {
				continue
			}
			log.Printf("client: xread responses: %v (retry in %s)", err, backoff)
			time.Sleep(backoff)
			if backoff < 5*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for _, st := range streams {
			for _, msg := range st.Messages {
				lastID = msg.ID
				data, ok := msg.Values["data"].(string)
				if !ok {
					continue
				}
				var resp proto.Response
				if err := json.Unmarshal([]byte(data), &resp); err != nil {
					continue
				}
				c.dispatch(resp)
			}
		}
	}
}

// runSubscriber subscribes to the updates channel and warms the local cache
// from every pushed answer. Missed pushes are harmless: the local cache simply
// falls back to on-demand resolution.
func (c *Client) runSubscriber(ctx context.Context) {
	pubsub := c.rdb.Subscribe(ctx, redisx.ChannelUpdates)
	defer pubsub.Close()
	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			var upd proto.Update
			if err := json.Unmarshal([]byte(msg.Payload), &upd); err != nil || len(upd.Wire) == 0 {
				continue
			}
			c.localSet(redisx.CacheKey(upd.Name, upd.Type), upd.Wire, upd.ResolvedAt)
		}
	}
}

func (c *Client) register(id string, ch chan proto.Response) {
	c.wmu.Lock()
	c.waits[id] = ch
	c.wmu.Unlock()
}

func (c *Client) unregister(id string) {
	c.wmu.Lock()
	delete(c.waits, id)
	c.wmu.Unlock()
}

func (c *Client) dispatch(resp proto.Response) {
	c.wmu.Lock()
	ch, ok := c.waits[resp.ID]
	c.wmu.Unlock()
	if ok {
		ch <- resp
	}
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

// localSet writes the local cache with a TTL derived from the real record TTLs
// (falling back to localTTL), and version-orders competing writes so a stale
// answer never overwrites a fresher one.
func (c *Client) localSet(key string, wire []byte, resolvedAt int64) {
	ttl := c.localTTL
	if m := new(dns.Msg); m.Unpack(wire) == nil {
		if min := resolver.MinTTL(m); min > 0 {
			ttl = time.Duration(min) * time.Second
		}
	}
	c.mu.Lock()
	if e, ok := c.local[key]; ok && e.resolvedAt > resolvedAt {
		c.mu.Unlock()
		return
	}
	c.local[key] = localEntry{wire: wire, expire: time.Now().Add(ttl), resolvedAt: resolvedAt}
	c.mu.Unlock()
}
