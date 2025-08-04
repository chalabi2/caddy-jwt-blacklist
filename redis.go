package jwtblacklist

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// RedisClient wraps the Redis client with blacklist-specific functionality
type RedisClient struct {
	client *redis.Client
	logger *zap.Logger
}

// NewRedisClient creates a new Redis client
func NewRedisClient(addr, password string, db int, logger *zap.Logger) (*RedisClient, error) {
	opts := &redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
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

// IsBlacklisted checks if an API key is blacklisted
func (rc *RedisClient) IsBlacklisted(ctx context.Context, apiKeyID string, prefix string) (bool, error) {
	key := fmt.Sprintf("%s%s", prefix, apiKeyID)

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
