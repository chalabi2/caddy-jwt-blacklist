package jwtblacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// JWTBlacklist is the main middleware struct
type JWTBlacklist struct {
	Config *Config `json:"config,omitempty"`

	redis  *RedisClient
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information
func (JWTBlacklist) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jwt_blacklist",
		New: func() caddy.Module { return new(JWTBlacklist) },
	}
}

// Provision sets up the module
func (jb *JWTBlacklist) Provision(ctx caddy.Context) error {
	jb.logger = ctx.Logger(jb)

	if jb.Config == nil {
		jb.Config = &Config{}
	}

	// Set defaults
	jb.Config.setDefaults()

	// Replace environment variables
	repl := caddy.NewReplacer()
	jb.Config.RedisAddr = repl.ReplaceAll(jb.Config.RedisAddr, "")
	jb.Config.RedisPassword = repl.ReplaceAll(jb.Config.RedisPassword, "")
	jb.Config.JWTSecret = repl.ReplaceAll(jb.Config.JWTSecret, "")

	// Initialize Redis client
	var err error
	jb.redis, err = NewRedisClient(
		jb.Config.RedisAddr,
		jb.Config.RedisPassword,
		jb.Config.RedisDB,
		jb.logger,
	)
	if err != nil {
		return err
	}

	jb.logger.Info("JWT blacklist middleware provisioned",
		zap.String("redis_addr", jb.Config.RedisAddr),
		zap.Int("redis_db", jb.Config.RedisDB),
		zap.String("blacklist_prefix", jb.Config.BlacklistPrefix),
		zap.Duration("timeout", time.Duration(jb.Config.Timeout)),
		zap.Bool("fail_open", jb.Config.FailOpen),
	)

	return nil
}

// Validate ensures the configuration is valid
func (jb *JWTBlacklist) Validate() error {
	if jb.Config == nil {
		return fmt.Errorf("JWT blacklist configuration is required")
	}
	return jb.Config.validate()
}

// Cleanup closes the Redis connection
func (jb *JWTBlacklist) Cleanup() error {
	if jb.redis != nil {
		return jb.redis.Close()
	}
	return nil
}

// ServeHTTP implements the middleware logic
func (jb *JWTBlacklist) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 1. Extract token from request
	token := extractToken(r)
	if token == "" {
		// No token found, let the next handler (jwtauth) deal with it
		return next.ServeHTTP(w, r)
	}

	// 2. Parse JWT to get API key ID
	claims, err := parseJWT(token, jb.Config.JWTSecret)
	if err != nil {
		// Invalid JWT, let the next handler (jwtauth) deal with it
		jb.logger.Debug("JWT parsing failed, passing to next handler",
			zap.Error(err))
		return next.ServeHTTP(w, r)
	}

	// 3. Check Redis blacklist with timeout
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(jb.Config.Timeout))
	defer cancel()

	isBlacklisted, err := jb.redis.IsBlacklisted(ctx, claims.ApiKeyID, jb.Config.BlacklistPrefix)

	if err != nil {
		if jb.Config.FailOpen {
			// Log the error but continue processing
			jb.logger.Warn("Redis blacklist check failed, failing open",
				zap.String("api_key_id", claims.ApiKeyID),
				zap.String("user_id", claims.UserID),
				zap.String("client_ip", getClientIP(r)),
				zap.Error(err))
			return next.ServeHTTP(w, r)
		} else {
			// Fail closed - return internal server error
			jb.logger.Error("Redis blacklist check failed, failing closed",
				zap.String("api_key_id", claims.ApiKeyID),
				zap.String("user_id", claims.UserID),
				zap.String("client_ip", getClientIP(r)),
				zap.Error(err))
			return jb.respondError(w, http.StatusInternalServerError, "internal_error", "Blacklist check failed")
		}
	}

	if isBlacklisted {
		// Get additional blacklist info for logging
		reason, ttl, _ := jb.redis.GetBlacklistInfo(ctx, claims.ApiKeyID, jb.Config.BlacklistPrefix)

		if jb.Config.LogBlocked {
			jb.logger.Info("Blocked blacklisted API key",
				zap.String("api_key_id", claims.ApiKeyID),
				zap.String("user_id", claims.UserID),
				zap.String("client_ip", getClientIP(r)),
				zap.String("reason", reason),
				zap.Duration("ttl", ttl),
				zap.String("uri", r.RequestURI))
		}

		// Set error type header for specific error handling
		w.Header().Set("X-Error-Type", "api_key_blacklisted")
		w.Header().Set("WWW-Authenticate", "Bearer")

		return jb.respondError(w, http.StatusUnauthorized, "api_key_blacklisted",
			"API key has been disabled due to subscription changes")
	}

	// 4. Token is valid and not blacklisted, continue to next handler
	return next.ServeHTTP(w, r)
}

// respondError sends a JSON error response
func (jb *JWTBlacklist) respondError(w http.ResponseWriter, statusCode int, errorType, message string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":   errorType,
		"message": message,
		"code":    statusCode,
	}

	if errorType == "api_key_blacklisted" {
		response["details"] = "Please check your subscription status or generate a new API key"
	}

	return json.NewEncoder(w).Encode(response)
}
