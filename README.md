# redis-dns

DNS resolution relayed through Redis. It moves recursive lookups off the open
internet path and onto a trusted server, so a home network no longer hammers a
public resolver with a high-frequency DoH pattern.

## Problem

A home network (router / OpenClash) that forwards every query to a self-hosted
DoH endpoint produces a very distinctive traffic shape: many short TLS
connections with the `application/dns-message` content type. That pattern is
easy to fingerprint and flag.

This project replaces the "every device → DoH endpoint" fan-out with a
two-tier design:

1. A **server-side resolver** runs next to a Redis instance on a trusted host
   (bwg). It is the only component that actually talks to upstream DNS over
   that host's own clean network path.
2. A **LAN-side client** runs a normal DNS server (UDP+TCP port 53). It
   answers from a local, expiry-aware cache and the Redis cache first, and only
   sends a resolution request to the server through Redis when the answer is
   not cached.

The LAN client never speaks DNS to the public internet, and the server never
speaks DNS to the LAN. Redis is the only bridge, and it can travel over an SSH
tunnel so no plaintext Redis is ever exposed.

## Architecture

```
 LAN device ──UDP/TCP 53──> redis-dns-client (local cache, real TTL)
                                │
                                │  Redis (over SSH tunnel)
                                │   ├─ dns:req      (request stream)
                                │   ├─ dns:resp     (response stream)
                                │   ├─ dns:cache:*  (cached answers)
                                │   └─ dns:updates  (pub/sub pushes)
                                ▼
                   bwg: redis-dns-server ──> upstream DNS
```

### Request–response (Redis Streams)

The query path is a reliable, point-to-point request/response carried by two
streams:

1. Cache miss: the client publishes a `proto.Request` to the `dns:req` stream
   and waits on a pending-request channel keyed by a random ID.
2. The server's worker pool consumes `dns:req` through a consumer group (each
   message delivered to exactly one worker), resolves via upstream, caches the
   wire-format answer, and XADDs a `proto.Response` to the `dns:resp` stream
   (capped with MAXLEN so stale responses cannot accumulate).
3. The client's single dispatcher goroutine reads `dns:resp`, matches each
   response to its pending request by ID, and delivers it. One blocking reader
   serves all pending requests, so the connection pool is never exhausted by
   per-request blocking reads.

### Update push (Redis pub/sub)

Whenever the server freshly resolves a name (on demand, or via prefetch), it
also PUBLISHes the answer on the `dns:updates` channel. Every subscribing
client warms its local cache from the push without issuing its own request.
Losing a push is harmless: the client simply falls back to on-demand
resolution, so the push path can be best-effort.

### Caching

- **Local cache** (client, in-memory): expiry derived from the real record TTLs
  in the answer, not a fixed timeout. Falls back to `local_ttl` only when the
  wire carries no usable TTL.
- **Redis cache** (`dns:cache:<name>:<type>`): written by the server, TTL
  bounded by the smallest answer-record TTL so it never outlives the records it
  holds.
- **Negative caching**: NXDOMAIN answers are cached too (RFC 2308: TTL =
  min(SOA TTL, SOA.Minttl), capped at `neg_ttl`), so nonexistent names don't
  trigger repeated upstream lookups.
- **Coalescing**: concurrent identical queries are merged with singleflight,
  so a burst of devices resolving the same cold name produces a single upstream
  request.
- **Versioning**: the local cache stores each answer's `resolved_at` and drops
  any write older than the current entry, so a stale pushed answer can never
  overwrite a fresher one.

### Prefetch (hot domains)

The server can refresh fixed domains on a schedule. Populate the Redis hash
`dns:hot:domains` (field = fqdn, value = refresh interval in seconds), e.g.:

```sh
redis-cli HSET dns:hot:domains "google.com" 300 "www.youtube.com" 300
```

The prefetch loop resolves each domain when its interval elapses, caches the
result, and broadcasts it, keeping clients warm without them querying.

## Why Redis

- Redis Streams give a durable work queue with consumer-group semantics, and
  pub/sub gives best-effort broadcast for cache warming — each channel matched
  to its natural semantics (reliable point-to-point vs. fire-and-forget).
- Wire-format DNS answers (the raw `dns.Msg` bytes) are stored verbatim, so
  the client replays exactly what upstream returned (rcode, TTLs, all
  sections) with no lossy re-encoding.
- Plaintext RESP has no TLS handshake and no SNI, so it is not subject to the
  TLS-handshake interference that hits port 443.

## Security

Redis is **not** exposed to the public internet. On the server host it binds
to `127.0.0.1` only and requires a password (see `deploy/redis.conf`). The LAN
client reaches it through an SSH local-forward tunnel:

```sh
autossh -M 0 -N -L 6379:127.0.0.1:6379 bwg
```

With the tunnel up, the client's Redis address is `127.0.0.1:6379`.

## Quick start

### Server side (bwg)

```sh
# 1. run redis
cd deploy && docker compose up -d

# 2. build & run the resolver
go build -o redis-dns-server ./cmd/server
./redis-dns-server -config config.server.example.yaml
```

### Client side (LAN)

```sh
# 1. open the SSH tunnel (see Security above)
# 2. build & run the DNS server
go build -o redis-dns-client ./cmd/client
./redis-dns-client -config config.client.example.yaml
# 3. point your LAN's DNS (or OpenClash upstream) at this host's :53
```

## Configuration

See `config.server.example.yaml` and `config.client.example.yaml`. Common
fields can be overridden with environment variables: `REDIS_ADDR`,
`REDIS_PASSWORD`, `UPSTREAM_ADDR`, `LISTEN`.

## Build

```sh
make build   # go build ./...
make vet     # go vet ./...
```

## License

MIT
