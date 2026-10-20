package resolver

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisPrefBackend stores preferred-IP entries as Redis hashes, one per
// (name, qtype): fields ip ("" = negative), via, rtt_us, hits, updated.
type redisPrefBackend struct {
	rdb *redis.Client
}

// NewRedisPrefBackend returns a PrefBackend over the given Redis client.
// Entries live in the server-local Redis, which is the point: "fastest"
// is a property of this exit's position in the network.
func NewRedisPrefBackend(rdb *redis.Client) PrefBackend {
	return &redisPrefBackend{rdb: rdb}
}

func (b *redisPrefBackend) LoadPref(ctx context.Context, key string) (*PrefEntry, error) {
	vals, err := b.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		return nil, nil
	}
	e := &PrefEntry{Via: vals["via"]}
	if s := vals["ip"]; s != "" {
		e.IP = net.ParseIP(s)
	}
	if v, err := strconv.ParseInt(vals["rtt_us"], 10, 64); err == nil {
		e.RTT = time.Duration(v) * time.Microsecond
	}
	if v, err := strconv.ParseInt(vals["hits"], 10, 64); err == nil {
		e.Hits = v
	}
	if v, err := strconv.ParseInt(vals["updated"], 10, 64); err == nil {
		e.Updated = time.Unix(v, 0)
	}
	return e, nil
}

func (b *redisPrefBackend) StorePref(ctx context.Context, key string, e *PrefEntry, ttl time.Duration) error {
	ipStr := ""
	if e.IP != nil {
		ipStr = e.IP.String()
	}
	pipe := b.rdb.Pipeline()
	pipe.HSet(ctx, key, map[string]interface{}{
		"ip":      ipStr,
		"via":     e.Via,
		"rtt_us":  e.RTT.Microseconds(),
		"hits":    e.Hits,
		"updated": e.Updated.Unix(),
	})
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (b *redisPrefBackend) BumpPref(ctx context.Context, key string) error {
	return b.rdb.HIncrBy(ctx, key, "hits", 1).Err()
}
