package jwtblacklist

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RedisClient wraps the Redis client with blacklist-specific functionality
type RedisClient struct {
	client *redis.Client
	logger *zap.Logger
}

// NewRedisClient creates a new Redis client with optional TLS support
func NewRedisClient(addr, password string, db int, tlsConfig *TLSConfig, logger *zap.Logger) (*RedisClient, error) {
	opts := &redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	}

	// Configure TLS if provided
	if tlsConfig != nil && tlsConfig.Enabled {
		config, err := buildTLSConfig(tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts.TLSConfig = config
	}

	client := redis.NewClient(opts)

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClient{
		client: client,
		logger: logger,
	}, nil
}

// TLSConfig holds TLS configuration options
type TLSConfig struct {
	Enabled            bool   `json:"enabled,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
	MinVersion         string `json:"min_version,omitempty"`
	CertFile           string `json:"cert_file,omitempty"`
	KeyFile            string `json:"key_file,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
}

// buildTLSConfig creates a tls.Config from TLSConfig
func buildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, // #nosec G402 - User configurable for dev environments
		ServerName:         cfg.ServerName,
	}

	// Set minimum TLS version
	switch cfg.MinVersion {
	case "1.0":
		tlsConfig.MinVersion = tls.VersionTLS10
	case "1.1":
		tlsConfig.MinVersion = tls.VersionTLS11
	case "1.2":
		tlsConfig.MinVersion = tls.VersionTLS12
	case "1.3":
		tlsConfig.MinVersion = tls.VersionTLS13
	default:
		tlsConfig.MinVersion = tls.VersionTLS12 // Default to TLS 1.2
	}

	// Load client certificate if provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// IsBlacklisted checks if an API key is blacklisted
func (rc *RedisClient) IsBlacklisted(ctx context.Context, apiKeyID string, prefix string) (bool, error) {
	key := fmt.Sprintf("%s%s", prefix, apiKeyID)

	// Handle case where Redis client is not properly initialized
	if rc.client == nil {
		return false, fmt.Errorf("redis client not initialized")
	}

	exists, err := rc.client.Exists(ctx, key).Result()
	if err != nil {
		rc.logger.Error("Redis blacklist check failed",
			zap.String("api_key_id", apiKeyID),
			zap.String("key", key),
			zap.Error(err))
		return false, err
	}

	if exists > 0 {
		// Log the blacklist hit for debugging
		rc.logger.Debug("API key found in blacklist",
			zap.String("api_key_id", apiKeyID),
			zap.String("key", key))
		return true, nil
	}

	return false, nil
}

// GetBlacklistInfo retrieves additional information about a blacklisted key
func (rc *RedisClient) GetBlacklistInfo(ctx context.Context, apiKeyID string, prefix string) (string, time.Duration, error) {
	key := fmt.Sprintf("%s%s", prefix, apiKeyID)

	// Get the value (reason for blacklisting)
	value, err := rc.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", 0, nil // Not blacklisted
	}
	if err != nil {
		return "", 0, err
	}

	// Get the TTL
	ttl, err := rc.client.TTL(ctx, key).Result()
	if err != nil {
		return value, 0, err
	}

	return value, ttl, nil
}

// Close closes the Redis connection
func (rc *RedisClient) Close() error {
	return rc.client.Close()
}
