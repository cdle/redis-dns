// Package config loads runtime configuration from a YAML file, flags, and
// environment variables.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the shared runtime configuration for both binaries.
type Config struct {
	Redis    Redis    `yaml:"redis"`
	Upstream Upstream `yaml:"upstream"`

	// Client settings.
	Listen    string `yaml:"listen"`     // DNS listen address (client only)
	DOHListen string `yaml:"doh_listen"` // DoH HTTP listen address (client only); empty disables
	LocalTTL  int    `yaml:"local_ttl"`  // fallback local-cache TTL when wire has no TTL, seconds
	BlockTime int    `yaml:"block_time"` // wait timeout for a resolution response, seconds

	// Server settings.
	Group    string   `yaml:"group"`
	Consumer string   `yaml:"consumer"`
	CacheTTL int      `yaml:"cache_ttl"` // Redis cache TTL ceiling, seconds; 0 disables caching
	NegTTL   int      `yaml:"neg_ttl"`   // negative (NXDOMAIN) cache TTL ceiling, seconds; 0 disables
	RespMax  int64    `yaml:"resp_max"`  // response stream MAXLEN cap
	Workers  int      `yaml:"workers"`   // number of concurrent consumer workers; 0 = GOMAXPROCS
	Prefetch Prefetch `yaml:"prefetch"`
	Race     Race     `yaml:"race"`

	// Client settings.
	Follow Follow `yaml:"follow"` // empty API disables node following
}

// Redis holds the Redis connection parameters.
type Redis struct {
	Addr       string `yaml:"addr"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	DB         int    `yaml:"db"`
	PoolSize   int    `yaml:"pool_size"`   // connection pool size; 0 = small default (4)
	TLS        bool   `yaml:"tls"`         // enable TLS (e.g. stunnel terminator in front of Redis)
	ServerName string `yaml:"server_name"` // TLS SNI / certificate hostname; empty = derive from addr
}

// Upstream is the recursive resolver the server queries.
type Upstream struct {
	Addr    string `yaml:"addr"`
	Network string `yaml:"network"` // udp, tcp, tcp-tls
	Timeout int    `yaml:"timeout"` // seconds
}

// Follow is the optional proxy-node-following configuration (client only):
// watch a mihomo policy group and keep the redis backend pinned to the node
// that is actually in use.
type Follow struct {
	API      string                   `yaml:"api"`      // mihomo external-controller URL
	Token    string                   `yaml:"token"`    // bearer token
	Group    string                   `yaml:"group"`    // policy group to watch
	Interval int                      `yaml:"interval"` // seconds between polls
	Backends map[string]FollowBackend `yaml:"backends"` // node name -> redis-dns backend
}

// FollowBackend points at the redis-dns server of one proxy node.
type FollowBackend struct {
	Addr string `yaml:"addr"`
	SNI  string `yaml:"sni"`
}

// Prefetch configures scheduled refresh of fixed domains. Interval of 0
// disables prefetching. Domains and their per-domain refresh interval live in
// the Redis hash dns:hot:domains (field=fqdn, value=interval seconds).
type Prefetch struct {
	Interval int `yaml:"interval"` // seconds between refresh sweeps; 0 disables
}

// Race configures server-side answer racing (see internal/resolver): when an
// upstream answer carries several IPs, the server probes them concurrently
// (TCP on Ports plus ICMP echo) and narrows the answer to the
// best-responding one. Racing is enabled unless the config explicitly
// disables it.
type Race struct {
	Enabled     *bool `yaml:"enabled"`         // nil = enabled; set false to disable
	Ports       []int `yaml:"ports"`           // probe ports in priority order; empty = [443 80]
	Timeout     int   `yaml:"timeout_ms"`      // overall probe budget, ms; <=0 = 1000
	TCPDeadline int   `yaml:"tcp_deadline_ms"` // window TCP gets before ICMP takes over, ms; <=0 = 200
	ICMP        *bool `yaml:"icmp"`            // nil = enabled; set false to disable ICMP probing
	PrefTTL     int   `yaml:"pref_ttl"`        // preferred-IP entry lifetime, seconds; <=0 = 86400
	PrefNegTTL  int   `yaml:"pref_neg_ttl"`    // negative preferred-IP entry lifetime, seconds; <=0 = 600
	RecheckHits int   `yaml:"recheck_hits"`    // pref hits before a revalidation race; <=0 = 100
	RecheckAge  int   `yaml:"recheck_age"`     // pref age before a revalidation race, seconds; <=0 = 21600
}

// IsEnabled reports whether answer racing is on.
func (r Race) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// PortList returns the probe ports, defaulting to [443 80].
func (r Race) PortList() []int {
	if len(r.Ports) > 0 {
		return r.Ports
	}
	return []int{443, 80}
}

// TimeoutDur returns the probe budget, defaulting to one second.
func (r Race) TimeoutDur() time.Duration {
	if r.Timeout > 0 {
		return time.Duration(r.Timeout) * time.Millisecond
	}
	return time.Second
}

// TCPDeadlineDur returns the window TCP probes get before the race
// falls back to ICMP results, defaulting to 200ms.
func (r Race) TCPDeadlineDur() time.Duration {
	if r.TCPDeadline > 0 {
		return time.Duration(r.TCPDeadline) * time.Millisecond
	}
	return 200 * time.Millisecond
}

// ICMPEnabled reports whether ICMP echo probing joins the race.
func (r Race) ICMPEnabled() bool { return r.ICMP == nil || *r.ICMP }

// PrefTTLDur returns the lifetime of a positive preferred-IP entry,
// defaulting to 24h.
func (r Race) PrefTTLDur() time.Duration {
	if r.PrefTTL > 0 {
		return time.Duration(r.PrefTTL) * time.Second
	}
	return 24 * time.Hour
}

// PrefNegTTLDur returns the lifetime of a negative preferred-IP
// entry, defaulting to 10 minutes.
func (r Race) PrefNegTTLDur() time.Duration {
	if r.PrefNegTTL > 0 {
		return time.Duration(r.PrefNegTTL) * time.Second
	}
	return 10 * time.Minute
}

// RecheckHitsN returns how many pref hits trigger a revalidation
// race, defaulting to 100.
func (r Race) RecheckHitsN() int64 {
	if r.RecheckHits > 0 {
		return int64(r.RecheckHits)
	}
	return 100
}

// RecheckAgeDur returns the pref age that triggers a revalidation
// race, defaulting to 6h.
func (r Race) RecheckAgeDur() time.Duration {
	if r.RecheckAge > 0 {
		return time.Duration(r.RecheckAge) * time.Second
	}
	return 6 * time.Hour
}

// Default returns a configuration with sensible defaults.
func Default() *Config {
	return &Config{
		Redis: Redis{Addr: "127.0.0.1:6379", DB: 0},
		Upstream: Upstream{
			Addr:    "8.8.8.8:53",
			Network: "udp",
			Timeout: 5,
		},
		Listen:    "0.0.0.0:53",
		DOHListen: "127.0.0.1:5354",
		LocalTTL:  300,
		BlockTime: 5,
		Group:     "dns",
		Consumer:  "resolver",
		CacheTTL:  300,
		NegTTL:    60,
		RespMax:   1000,
		Workers:   0,
	}
}

// Load reads the YAML file at path (if non-empty) over the defaults, then
// applies environment-variable overrides and finalizes the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	applyEnv(cfg)
	finalize(cfg)
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		cfg.Redis.Addr = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("UPSTREAM_ADDR"); v != "" {
		cfg.Upstream.Addr = v
	}
	if v := os.Getenv("LISTEN"); v != "" {
		cfg.Listen = v
	}
}

func finalize(cfg *Config) {
	if cfg.LocalTTL <= 0 {
		cfg.LocalTTL = 300
	}
	if cfg.BlockTime <= 0 {
		cfg.BlockTime = 5
	}
	if cfg.NegTTL < 0 {
		cfg.NegTTL = 0
	}
	if cfg.RespMax <= 0 {
		cfg.RespMax = 1000
	}
	if cfg.Upstream.Timeout <= 0 {
		cfg.Upstream.Timeout = 5
	}
	if cfg.Upstream.Network == "" {
		cfg.Upstream.Network = "udp"
	}
	if cfg.Group == "" {
		cfg.Group = "dns"
	}
	if cfg.Consumer == "" {
		cfg.Consumer = "resolver"
	}
}
