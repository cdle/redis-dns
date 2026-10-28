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

	// 2. On-demand resolution, coalesced across concurrent identical queries.
	// NOTE: no synchronous Redis GET here — on a cold key it costs a full
	// public-internet round trip (~1 RTT) just to learn "not cached". The
	// server is cache-first anyway (it checks Redis before resolving), so a
	// client-side GET only duplicates that check at 10x the latency.
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		return c.resolve(context.Background(), name, q.Qtype)
	})
	if err != nil {
		log.Printf("client: query src=%s name=%s type=%d path=upstream error=%v took=%s", src, name, q.Qtype, err, time.Since(start))
		return nil, dns.RcodeServerFailure
	}
	resp := v.(proto.Response)
	if len(resp.Wire) == 0 {
		// 合法的空答案（如无 AAAA 记录的 NOERROR）：立即返回 NODATA 形式的空应答，不挂超时。
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = resp.Rcode
		log.Printf("client: query src=%s name=%s type=%d path=upstream rcode=%d empty-answer took=%s", src, name, q.Qtype, resp.Rcode, time.Since(start))
		wire, _ := m.Pack()
		return wire, resp.Rcode
	}
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
	mux.HandleFunc("/reverse", c.reverseHandler)
	mux.HandleFunc("/reverse/stats", c.reverseStatsHandler)
	mux.HandleFunc("/panel", c.panelHandler)
	mux.HandleFunc("/panel/run", c.panelRunHandler)
	mux.HandleFunc("/panel/cache", c.panelCacheListHandler)
	mux.HandleFunc("/panel/cache/clear", c.panelCacheClearHandler)
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

	// Fire the PUBLISH and do not wait for its confirmation: the response is
	// pushed to the dispatcher's subscription the instant the server publishes
	// it. Skipping the confirmation round-trip saves one full RTT.
	pubErr := make(chan error, 1)
	go func() {
		started := time.Now()
		err := c.rdb.Publish(ctx, redisx.ChannelRequests, payload).Err()
		log.Printf("client: pub-req id=%s confirm_after_start=%.1fms", shortID(req.ID), float64(time.Since(started).Microseconds())/1000)
		pubErr <- err
	}()

	// pub/sub 推送偶发丢失（跨公网链路抖动时 PUBLISH 确认延迟、订阅
	// 连接闪断），在 block_time 内重发一次请求即可恢复——服务端
	// cache-first，重发命中的是缓存，幂等且便宜。
	deadline := time.Now().Add(c.block)
	for attempt := 0; ; attempt++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return proto.Response{}, errors.New("resolution timed out")
		}
		waitCtx, cancel := context.WithTimeout(ctx, remaining)
		pubErr := make(chan error, 1)
		go func() {
			started := time.Now()
			err := c.rdb.Publish(waitCtx, redisx.ChannelRequests, payload).Err()
			log.Printf("client: pub-req id=%s attempt=%d confirm_after_start=%.1fms",
				shortID(req.ID), attempt, float64(time.Since(started).Microseconds())/1000)
			pubErr <- err
		}()
		select {
		case resp := <-ch:
			cancel()
			if resp.Err != "" {
				return resp, errors.New(resp.Err)
			}
			return resp, nil
		case err := <-pubErr:
			if err != nil {
				cancel()
				// 发布失败：若还有时间则重试，否则放弃
				continue
			}
			// 已发布；在剩余时间内等推送
			select {
			case resp := <-ch:
				cancel()
				if resp.Err != "" {
					return resp, errors.New(resp.Err)
				}
				return resp, nil
			case <-time.After(remaining / 2):
				cancel()
				// 一半时间没响应：回到循环顶重发（attempt+1）
			case <-ctx.Done():
				cancel()
				return proto.Response{}, ctx.Err()
			}
		case <-time.After(remaining / 2):
			cancel()
			// 确认和响应都没等到（连接慢）：重发
		case <-ctx.Done():
			cancel()
			return proto.Response{}, ctx.Err()
		}
	}
}

// runDispatcher reads the response stream and routes each response to the
// pending request waiting on it. A single blocking reader serves all pending
// requests, so the Redis connection pool is not exhausted by per-request
// blocking reads.
func (c *Client) runDispatcher(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		func() {
			// 响应经 PUBLISH 即时推送，无需轮询；一个订阅连接服务所有请求。
			pubsub := c.rdb.Subscribe(ctx, redisx.ChannelResponses)
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
					var resp proto.Response
					if err := json.Unmarshal([]byte(msg.Payload), &resp); err != nil {
						continue
					}
					log.Printf("client: resp-recv id=%s", shortID(resp.ID))
					c.dispatch(resp)
				}
			}
		}()
		if ctx.Err() != nil {
			return
		}
		log.Printf("client: dispatcher pubsub disconnected (retry in %s)", backoff)
		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

// runSubscriber subscribes to the updates channel and warms the local cache
// from every pushed answer. Missed pushes are harmless: the local cache simply
// falls back to on-demand resolution.
func (c *Client) runSubscriber(ctx context.Context) {
	for ctx.Err() == nil {
		func() {
			pubsub := c.rdb.Subscribe(ctx, redisx.ChannelUpdates)
			defer pubsub.Close()
			ch := pubsub.Channel()
			for {
				select {
				case <-ctx.Done():
					return
				case msg, ok := <-ch:
					if !ok {
						return // connection lost; reconnect with current backend
					}
					var upd proto.Update
					if err := json.Unmarshal([]byte(msg.Payload), &upd); err != nil || len(upd.Wire) == 0 {
						continue
					}
					c.localSet(redisx.CacheKey(upd.Name, upd.Type), upd.Wire, upd.ResolvedAt)
					log.Printf("client: warm name=%s type=%d", upd.Name, upd.Type)
				}
			}
		}()
		time.Sleep(time.Second) // reconnect (possibly to a hot-swapped backend)
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
	if !ok {
		return // 迟到的响应：等待者已超时离开
	}
	// 非阻塞发送：waits 的 channel 容量为1且等待者必然在 select 消费，
	// 这里若满说明是重复投递（pubsub 广播/重连重放），直接丢弃。
	// 绝不能阻塞 dispatcher——否则 pubsub 缓冲堆积、消息开始被丢弃，
	// 所有后续查询都会超时（实测踩过：channel full for 1m0s）。
	select {
	case ch <- resp:
	default:
	}
}

// shortID returns the first 8 hex chars of an ID for compact log pairing.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
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
