package jwtblacklist

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Config holds the configuration for the JWT blacklist plugin
type Config struct {
	// Redis connection settings
	RedisAddr     string     `json:"redis_addr,omitempty"`
	RedisPassword string     `json:"redis_password,omitempty"`
	RedisDB       int        `json:"redis_db,omitempty"`
	RedisTLS      *TLSConfig `json:"redis_tls,omitempty"`

	// JWT settings
	JWTSecret string `json:"jwt_secret,omitempty"`

	// Blacklist settings
	BlacklistPrefix string `json:"blacklist_prefix,omitempty"`

	// Behavior settings
	FailOpen   bool           `json:"fail_open,omitempty"`
	Timeout    caddy.Duration `json:"timeout,omitempty"`
	LogBlocked bool           `json:"log_blocked,omitempty"`
}

// setDefaults sets default values for the configuration
func (c *Config) setDefaults() {
	if c.RedisAddr == "" {
		c.RedisAddr = "localhost:6379"
	}
	if c.RedisDB == 0 {
		c.RedisDB = 0
	}
	if c.BlacklistPrefix == "" {
		c.BlacklistPrefix = "BLACKLIST:key:"
	}
	if c.Timeout == 0 {
		c.Timeout = caddy.Duration(50 * time.Millisecond)
	}
	if !c.FailOpen {
		c.FailOpen = true // Fail open by default for safety
	}
}

// validate ensures the configuration is valid
func (c *Config) validate() error {
	if c.JWTSecret == "" {
		return fmt.Errorf("jwt_secret is required")
	}
	if c.RedisAddr == "" {
		return fmt.Errorf("redis_addr is required")
	}
	if time.Duration(c.Timeout) < time.Millisecond {
		return fmt.Errorf("timeout must be at least 1ms")
	}
	return nil
}

// parseCaddyfile parses the Caddyfile configuration
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var jb JWTBlacklist
	err := jb.UnmarshalCaddyfile(h.Dispenser)
	return &jb, err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (jb *JWTBlacklist) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	config := &Config{}

	// Parse the directive arguments
	if !d.Next() {
		return d.ArgErr()
	}

	// Parse the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "redis_addr":
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.RedisAddr = d.Val()

		case "redis_password":
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.RedisPassword = d.Val()

		case "redis_db":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var db int
			if _, err := fmt.Sscanf(d.Val(), "%d", &db); err != nil {
				return d.Errf("invalid redis_db value: %s", d.Val())
			}
			config.RedisDB = db

		case "jwt_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.JWTSecret = d.Val()

		case "blacklist_prefix":
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.BlacklistPrefix = d.Val()

		case "fail_open":
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.FailOpen = d.Val() == "true"

		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := time.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid timeout duration: %s", d.Val())
			}
			config.Timeout = caddy.Duration(dur)

		case "log_blocked":
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.LogBlocked = d.Val() == "true"

		// TLS configuration block
		case "tls":
			tlsConfig := &TLSConfig{}
			for d.NextBlock(1) {
				switch d.Val() {
				case "enabled":
					if !d.NextArg() {
						return d.ArgErr()
					}
					tlsConfig.Enabled = d.Val() == "true"

				case "insecure_skip_verify":
					if !d.NextArg() {
						return d.ArgErr()
					}
					tlsConfig.InsecureSkipVerify = d.Val() == "true"

				case "server_name":
					if !d.NextArg() {
						return d.ArgErr()
					}
					tlsConfig.ServerName = d.Val()

				case "min_version":
					if !d.NextArg() {
						return d.ArgErr()
					}
					tlsConfig.MinVersion = d.Val()

				case "cert_file":
					if !d.NextArg() {
						return d.ArgErr()
					}
					tlsConfig.CertFile = d.Val()

				case "key_file":
					if !d.NextArg() {
						return d.ArgErr()
					}
					tlsConfig.KeyFile = d.Val()

				case "ca_file":
					if !d.NextArg() {
						return d.ArgErr()
					}
					tlsConfig.CAFile = d.Val()

				default:
					return d.Errf("unknown TLS directive: %s", d.Val())
				}
			}
			config.RedisTLS = tlsConfig

		default:
			return d.Errf("unknown directive: %s", d.Val())
		}
	}

	jb.Config = config
	return nil
}
