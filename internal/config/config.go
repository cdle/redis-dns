// Package config loads runtime configuration from a YAML file, flags, and
// environment variables.
package config

import (
	"fmt"
	"os"

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
}

// Redis holds the Redis connection parameters.
type Redis struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	PoolSize int    `yaml:"pool_size"` // connection pool size; 0 = small default (4)
}

// Upstream is the recursive resolver the server queries.
type Upstream struct {
	Addr    string `yaml:"addr"`
	Network string `yaml:"network"` // udp, tcp, tcp-tls
	Timeout int    `yaml:"timeout"` // seconds
}

// Prefetch configures scheduled refresh of fixed domains. Interval of 0
// disables prefetching. Domains and their per-domain refresh interval live in
// the Redis hash dns:hot:domains (field=fqdn, value=interval seconds).
type Prefetch struct {
	Interval int `yaml:"interval"` // seconds between refresh sweeps; 0 disables
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
