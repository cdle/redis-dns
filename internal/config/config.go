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
	LocalTTL  int    `yaml:"local_ttl"`  // local cache TTL, seconds
	BlockTime int    `yaml:"block_time"` // BLPOP block timeout, seconds

	// Server settings.
	Group    string `yaml:"group"`
	Consumer string `yaml:"consumer"`
	CacheTTL int    `yaml:"cache_ttl"` // Redis cache TTL, seconds; 0 disables caching
	RespTTL  int    `yaml:"resp_ttl"`  // response list entry TTL, seconds
}

// Redis holds the Redis connection parameters.
type Redis struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// Upstream is the recursive resolver the server queries.
type Upstream struct {
	Addr    string `yaml:"addr"`
	Network string `yaml:"network"` // udp, tcp, tcp-tls
	Timeout int    `yaml:"timeout"` // seconds
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
		LocalTTL:  300,
		BlockTime: 5,
		Group:     "dns",
		Consumer:  "resolver-1",
		CacheTTL:  300,
		RespTTL:   30,
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
	if cfg.RespTTL <= 0 {
		cfg.RespTTL = 30
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
		cfg.Consumer = "resolver-1"
	}
}
