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
   (bwg). It is the only component that actually talks to upstream DNS
   (`8.8.8.8`, `1.1.1.1`, …) over that host's own clean network path.
2. A **LAN-side client** runs a normal DNS server (UDP+TCP port 53). It
   answers from local and Redis caches first, and only sends a resolution
   request to the server through Redis when the answer is not cached.

The LAN client never speaks DNS to the public internet, and the server never
speaks DNS to the LAN. Redis is the only bridge, and it can travel over an SSH
tunnel so no plaintext Redis is ever exposed.

## Architecture

```
 LAN device ──UDP/TCP 53──> redis-dns-client (local cache)
                                  │
                                  │  Redis (over SSH tunnel)
                                  ▼
                     bwg: redis-dns-server ──> upstream DNS (8.8.8.8)
                            ▲
                            └──── Redis cache (dns:cache:*)
```

### Request flow

1. Client receives a query; checks the in-memory cache, then the Redis cache.
2. Cache miss: client publishes a request to the `dns:req` stream and blocks
   on a per-request list key.
3. Server consumes the stream, resolves via upstream, caches the wire-format
   answer, and LPUSHes the response back.
4. Client unpacks the answer and replies to the original query.

## Why Redis

- Redis Streams give a durable work queue with consumer-group semantics.
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
