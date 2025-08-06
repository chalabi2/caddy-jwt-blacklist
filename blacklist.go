// Package jwtblacklist provides a Caddy middleware for integrated JWT authentication and blacklist validation using Redis.
// This module combines JWT token validation with Redis-based blacklist checking in a single middleware.
package jwtblacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lestrrat-go/jwx/v2/jwt"
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

	// Process TLS config environment variables if present
	if jb.Config.RedisTLS != nil {
		if jb.Config.RedisTLS.ServerName != "" {
			jb.Config.RedisTLS.ServerName = repl.ReplaceAll(jb.Config.RedisTLS.ServerName, "")
		}
		if jb.Config.RedisTLS.CertFile != "" {
			jb.Config.RedisTLS.CertFile = repl.ReplaceAll(jb.Config.RedisTLS.CertFile, "")
		}
		if jb.Config.RedisTLS.KeyFile != "" {
			jb.Config.RedisTLS.KeyFile = repl.ReplaceAll(jb.Config.RedisTLS.KeyFile, "")
		}
		if jb.Config.RedisTLS.CAFile != "" {
			jb.Config.RedisTLS.CAFile = repl.ReplaceAll(jb.Config.RedisTLS.CAFile, "")
		}
	}

	// Validate and initialize JWT configuration first (always required)
	if err := validateJWTConfig(jb.Config.JWT, jb.logger); err != nil {
		return fmt.Errorf("JWT configuration error: %w", err)
	}

	// Initialize Redis client with optional TLS support
	var err error
	jb.redis, err = NewRedisClient(
		jb.Config.RedisAddr,
		jb.Config.RedisPassword,
		jb.Config.RedisDB,
		jb.Config.RedisTLS, // Pass TLS config (nil for non-TLS)
		jb.logger,
	)
	if err != nil {
		if jb.Config.FailOpen {
			// Log the error but continue - Redis will be handled as unavailable
			jb.logger.Warn("Redis connection failed during provision, will fail open",
				zap.String("redis_addr", jb.Config.RedisAddr),
				zap.Error(err))
			jb.redis = nil
		} else {
			return fmt.Errorf("Redis connection failed: %w", err)
		}
	}

	jb.logger.Info("JWT authentication + blacklist middleware provisioned",
		zap.String("redis_addr", jb.Config.RedisAddr),
		zap.Int("redis_db", jb.Config.RedisDB),
		zap.String("blacklist_prefix", jb.Config.BlacklistPrefix),
		zap.Duration("timeout", time.Duration(jb.Config.Timeout)),
		zap.Bool("fail_open", jb.Config.FailOpen),
		zap.Bool("tls_enabled", jb.Config.RedisTLS != nil && jb.Config.RedisTLS.Enabled),
		zap.String("jwt_sign_alg", jb.Config.JWT.SignAlgorithm),
		zap.Bool("jwt_skip_verification", jb.Config.JWT.SkipVerification),
		zap.Strings("jwt_user_claims", jb.Config.JWT.UserClaims),
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

// ServeHTTP implements the integrated JWT authentication and blacklist validation
// CRITICAL: Blacklist check happens BEFORE full JWT authentication for performance and security
func (jb *JWTBlacklist) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 1. Extract token candidates from request (lightweight operation)
	candidates := extractTokens(r, jb.Config.JWT.FromQuery, jb.Config.JWT.FromHeader, jb.Config.JWT.FromCookies)
	if len(candidates) == 0 {
		// No token found - require authentication
		w.Header().Set("WWW-Authenticate", "Bearer")
		return jb.respondError(w, http.StatusUnauthorized, "missing_token", "Authentication required")
	}

	// 2. Lightweight JWT parsing to extract jti (API key ID) for blacklist check
	// We parse WITHOUT verification to get the jti quickly
	var apiKeyID string
	for _, candidateToken := range candidates {
		tokenString := normToken(candidateToken)
		if token, err := jwt.ParseString(tokenString, jwt.WithVerify(false)); err == nil {
			if jti, ok := token.Get("jti"); ok {
				if jtiStr, ok := jti.(string); ok {
					apiKeyID = jtiStr
					break
				}
			}
		}
	}

	if apiKeyID == "" {
		// No valid jti found in any token
		w.Header().Set("WWW-Authenticate", "Bearer")
		return jb.respondError(w, http.StatusUnauthorized, "invalid_token", "Invalid token format")
	}

	// 3. Check Redis blacklist FIRST (fast O(1) operation)
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(jb.Config.Timeout))
	defer cancel()

	var isBlacklisted bool
	var err error

	if jb.redis == nil {
		// Redis client not available - handle based on FailOpen policy
		err = fmt.Errorf("Redis client not initialized")
	} else {
		isBlacklisted, err = jb.redis.IsBlacklisted(ctx, apiKeyID, jb.Config.BlacklistPrefix)
	}

	if err != nil {
		if jb.Config.FailOpen {
			// Log the error but continue processing
			jb.logger.Warn("Redis blacklist check failed, failing open",
				zap.String("api_key_id", apiKeyID),
				zap.String("client_ip", getClientIP(r)),
				zap.Error(err))
		} else {
			// Fail closed - return internal server error
			jb.logger.Error("Redis blacklist check failed, failing closed",
				zap.String("api_key_id", apiKeyID),
				zap.String("client_ip", getClientIP(r)),
				zap.Error(err))
			return jb.respondError(w, http.StatusInternalServerError, "internal_error", "Authentication service unavailable")
		}
	} else if isBlacklisted {
		// Token is blacklisted
		reason, ttl, _ := jb.redis.GetBlacklistInfo(ctx, apiKeyID, jb.Config.BlacklistPrefix)

		if jb.Config.LogBlocked {
			jb.logger.Info("Blocked blacklisted API key",
				zap.String("api_key_id", apiKeyID),
				zap.String("client_ip", getClientIP(r)),
				zap.String("reason", reason),
				zap.Duration("ttl", ttl),
				zap.String("uri", r.RequestURI))
		}

		w.Header().Set("X-Error-Type", "api_key_blacklisted")
		w.Header().Set("WWW-Authenticate", "Bearer")
		return jb.respondError(w, http.StatusUnauthorized, "api_key_blacklisted",
			"API key has been disabled due to subscription changes")
	}

	// 4. Blacklist check passed - now perform full JWT authentication
	claims, err := authenticateJWT(r, jb.Config.JWT, jb.logger)
	if err != nil {
		// Authentication failed after blacklist check passed
		jb.logger.Debug("JWT authentication failed",
			zap.Error(err),
			zap.String("api_key_id", apiKeyID),
			zap.String("client_ip", getClientIP(r)))
		w.Header().Set("WWW-Authenticate", "Bearer")
		return jb.respondError(w, http.StatusUnauthorized, "invalid_token", "Invalid authentication token")
	}

	// 5. Both blacklist and authentication checks passed - set user context
	jb.setUserContext(r, claims)

	// 6. Continue to next handler
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

// setUserContext populates the request context with authenticated user information
// This makes user data available to downstream handlers via Caddy placeholders
func (jb *JWTBlacklist) setUserContext(r *http.Request, claims *Claims) {
	// Get the replacer from the request context
	replVal := r.Context().Value(caddy.ReplacerCtxKey)
	if replVal == nil {
		// No replacer in context - this can happen in tests or non-Caddy contexts
		jb.logger.Debug("No Caddy replacer found in request context, skipping placeholder population")
		return
	}
	repl := replVal.(*caddy.Replacer)

	// Set user authentication data that downstream handlers can access
	repl.Set("http.auth.user.id", claims.UserID)
	repl.Set("http.auth.user.tier", claims.Tier)
	repl.Set("http.auth.user.scope", claims.Scope)
	repl.Set("http.auth.user.jti", claims.APIKeyID)

	// Also set some additional useful context
	repl.Set("http.auth.user.api_key_id", claims.APIKeyID) // Alias for jti
	repl.Set("http.auth.user.authenticated", "true")

	// Set metadata from JWT claims if configured
	if jb.Config.JWT != nil && len(jb.Config.JWT.MetaClaims) > 0 {
		// We need to re-extract the token to get metadata
		candidates := extractTokens(r, jb.Config.JWT.FromQuery, jb.Config.JWT.FromHeader, jb.Config.JWT.FromCookies)
		if len(candidates) > 0 {
			tokenString := normToken(candidates[0])
			if token, err := jwt.ParseString(tokenString, jwt.WithVerify(false)); err == nil {
				metadata := getUserMetadata(token, jb.Config.JWT.MetaClaims)
				for key, value := range metadata {
					repl.Set("http.auth.user."+key, value)
				}
			}
		}
	}

	jb.logger.Debug("User authentication successful",
		zap.String("user_id", claims.UserID),
		zap.String("api_key_id", claims.APIKeyID),
		zap.String("tier", claims.Tier),
		zap.String("scope", claims.Scope),
		zap.String("client_ip", getClientIP(r)))
}
