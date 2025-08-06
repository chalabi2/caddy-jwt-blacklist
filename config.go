package jwtblacklist

import (
	"fmt"
	"strings"
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

	// JWT settings (for backward compatibility)
	JWTSecret string `json:"jwt_secret,omitempty"`

	// Advanced JWT configuration
	JWT *JWTConfig `json:"jwt,omitempty"`

	// Blacklist settings
	BlacklistPrefix string `json:"blacklist_prefix,omitempty"`

	// Behavior settings
	FailOpen   bool           `json:"fail_open,omitempty"`
	Timeout    caddy.Duration `json:"timeout,omitempty"`
	LogBlocked bool           `json:"log_blocked,omitempty"`
}

// setDefaults sets default values for the configuration
func (c *Config) setDefaults() {
	// RedisAddr is required and has no default
	if c.RedisDB == 0 {
		c.RedisDB = 0
	}
	if c.BlacklistPrefix == "" {
		c.BlacklistPrefix = "BLACKLIST:key:"
	}
	if c.Timeout == 0 {
		c.Timeout = caddy.Duration(50 * time.Millisecond)
	}
	// FailOpen defaults to false (fail closed for security)
	// No need to set it explicitly since bool zero value is false

	// Initialize JWT config if not provided
	if c.JWT == nil {
		c.JWT = &JWTConfig{}
	}

	// Set JWT defaults
	c.JWT.setJWTDefaults()

	// For backward compatibility, use simple JWT secret if advanced config is empty
	if c.JWTSecret != "" && c.JWT.SignKey == "" {
		c.JWT.SignKey = c.JWTSecret
	}
}

// validate ensures the configuration is valid
func (c *Config) validate() error {
	// Validate basic configuration
	if c.RedisAddr == "" {
		return fmt.Errorf("redis_addr is required")
	}
	if time.Duration(c.Timeout) < time.Millisecond {
		return fmt.Errorf("timeout must be at least 1ms")
	}

	// Validate JWT configuration
	if c.JWT == nil {
		return fmt.Errorf("JWT configuration is required")
	}
	if c.JWT.SignKey == "" && c.JWT.JWKURL == "" && c.JWTSecret == "" {
		return fmt.Errorf("either jwt_secret, sign_key, or jwk_url is required")
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

		// JWT configuration options (simple)
		case "sign_key":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.JWT.SignKey = d.Val()

		case "sign_alg":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.JWT.SignAlgorithm = d.Val()

		case "jwk_url":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			config.JWT.JWKURL = d.Val()

		case "skip_verification":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			config.JWT.SkipVerification = true

		case "from_query":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			config.JWT.FromQuery = d.RemainingArgs()

		case "from_header":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			config.JWT.FromHeader = d.RemainingArgs()

		case "from_cookies":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			config.JWT.FromCookies = d.RemainingArgs()

		case "issuer_whitelist":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			config.JWT.IssuerWhitelist = d.RemainingArgs()

		case "audience_whitelist":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			config.JWT.AudienceWhitelist = d.RemainingArgs()

		case "user_claims":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			config.JWT.UserClaims = d.RemainingArgs()

		case "meta_claims":
			if config.JWT == nil {
				config.JWT = &JWTConfig{}
			}
			if config.JWT.MetaClaims == nil {
				config.JWT.MetaClaims = make(map[string]string)
			}
			for _, metaClaim := range d.RemainingArgs() {
				claim, placeholder, err := parseMetaClaim(metaClaim)
				if err != nil {
					return d.Errf("invalid meta_claims: %v", err)
				}
				if _, ok := config.JWT.MetaClaims[claim]; ok {
					return d.Errf("invalid meta_claims: duplicate claim: %s", claim)
				}
				config.JWT.MetaClaims[claim] = placeholder
			}

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

// parseMetaClaim parses key to get the claim and corresponding placeholder
// e.g "IsAdmin -> is_admin" as { Claim: "IsAdmin", Placeholder: "is_admin" }
func parseMetaClaim(key string) (claim, placeholder string, err error) {
	parts := strings.Split(key, "->")
	if len(parts) == 1 {
		claim = strings.TrimSpace(parts[0])
		placeholder = strings.TrimSpace(parts[0])
	} else if len(parts) == 2 {
		claim = strings.TrimSpace(parts[0])
		placeholder = strings.TrimSpace(parts[1])
	} else {
		return "", "", fmt.Errorf("too many delimiters (->) in key %q", key)
	}

	if claim == "" {
		return "", "", fmt.Errorf("empty claim in key %q", key)
	}
	if placeholder == "" {
		return "", "", fmt.Errorf("empty placeholder in key %q", key)
	}
	return
}
