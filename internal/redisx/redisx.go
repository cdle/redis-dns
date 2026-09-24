// Package redisx centralizes the Redis key layout and client construction
// shared by both the server and the client binaries.
package redisx

import (
	"strconv"

	"github.com/redis/go-redis/v9"
)

// Stream names and key prefixes.
const (
	// StreamRequests is the Redis stream the client publishes resolution
	// requests to and the server consumes from.
	StreamRequests = "dns:req"

	// PrefixCache is prepended to cached-answer keys: dns:cache:<name>:<type>.
	PrefixCache = "dns:cache:"
	// PrefixResp is prepended to per-request response list keys: dns:resp:<id>.
	PrefixResp = "dns:resp:"
)

// CacheKey returns the Redis key holding a cached DNS answer.
func CacheKey(name string, qtype uint16) string {
	return PrefixCache + name + ":" + strconv.Itoa(int(qtype))
}

// RespKey returns the per-request list key the server LPUSHes a response to.
func RespKey(id string) string {
	return PrefixResp + id
}

// New builds a Redis client from connection parameters.
func New(addr, username, password string, db int) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: username,
		Password: password,
		DB:       db,
	})
}
