package jwtblacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
)

// testRedisContainer manages a Redis container for testing
type testRedisContainer struct {
	client *redis.Client
	addr   string
}

func setupTestRedis() (*testRedisContainer, error) {
	// For testing, assume Redis is running on localhost:6379
	// In a real test environment, you'd use testcontainers-go
	addr := "localhost:6379"
	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   15, // Use a different DB for testing
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis not available for testing (start Redis on localhost:6379): %w", err)
	}

	// Clean the test database
	client.FlushDB(ctx)

	return &testRedisContainer{
		client: client,
		addr:   addr,
	}, nil
}

func (tc *testRedisContainer) cleanup() {
	if tc.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tc.client.FlushDB(ctx)
		_ = tc.client.Close()
	}
}

// Helper function to create test JWT tokens using our new JWT library
func createTestToken(claims map[string]interface{}) string {
	tb := jwt.NewBuilder()

	// Set default required claims
	if _, ok := claims["sub"]; !ok {
		tb = tb.Subject("test-user")
	}
	if _, ok := claims["jti"]; !ok {
		tb = tb.JwtID("test-api-key-id")
	}

	// Add all custom claims
	for k, v := range claims {
		tb = tb.Claim(k, v)
	}

	token, err := tb.Build()
	if err != nil {
		panic(err)
	}

	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, RawTestSignKey))
	if err != nil {
		panic(err)
	}

	return string(tokenBytes)
}

func TestJWTBlacklistModule(t *testing.T) {
	// Setup test Redis
	testRedis, err := setupTestRedis()
	if err != nil {
		t.Skipf("Skipping integration test: %v", err)
		return
	}
	defer testRedis.cleanup()

	// Create module instance
	module := &JWTBlacklist{
		Config: &Config{
			RedisAddr:       testRedis.addr,
			RedisDB:         15,
			BlacklistPrefix: "TEST:BLACKLIST:key:",
			FailOpen:        false,
			Timeout:         caddy.Duration(100 * time.Millisecond),
			LogBlocked:      true,
			JWT: &JWTConfig{
				SignKey:       TestSignKey,
				SignAlgorithm: "HS256",
				FromHeader:    []string{"Authorization"},
				UserClaims:    []string{"sub"},
			},
		},
	}

	// Setup context
	ctx := caddy.Context{}

	// Provision the module
	err = module.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision module: %v", err)
	}
	defer func() { _ = module.Cleanup() }()

	t.Run("ValidToken_NotBlacklisted_ShouldPass", func(t *testing.T) {
		apiKeyID := "valid-api-key-123" // #nosec G101 - Test API key, not a real credential
		token := createTestToken(map[string]interface{}{
			"sub": "test-user",
			"jti": apiKeyID,
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Add replacer context
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()

		nextCalled := false
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			nextCalled = true
			// Verify that user context was set
			userID, _ := repl.Get("http.auth.user.id")
			if userID != "test-user" {
				t.Errorf("Expected user ID 'test-user', got '%v'", userID)
			}
			apiKeyIDCtx, _ := repl.Get("http.auth.user.api_key_id")
			if apiKeyIDCtx != apiKeyID {
				t.Errorf("Expected API key ID '%s', got '%v'", apiKeyID, apiKeyIDCtx)
			}
			w.WriteHeader(http.StatusOK)
			return nil
		})

		err := module.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if !nextCalled {
			t.Error("Next handler should have been called")
		}

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
	})

	t.Run("ValidToken_Blacklisted_ShouldBlock", func(t *testing.T) {
		apiKeyID := "blacklisted-api-key-456"
		token := createTestToken(map[string]interface{}{
			"sub": "test-user",
			"jti": apiKeyID,
		})

		// Blacklist the API key
		ctx := context.Background()
		blacklistKey := module.Config.BlacklistPrefix + apiKeyID
		err := testRedis.client.Set(ctx, blacklistKey, "revoked", time.Hour).Err()
		if err != nil {
			t.Fatalf("Failed to blacklist key: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Add replacer context
		repl := caddy.NewReplacer()
		ctx = context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()

		nextCalled := false
		next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error {
			nextCalled = true
			return nil
		})

		err = module.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("Expected no error from ServeHTTP, got: %v", err)
		}

		if nextCalled {
			t.Error("Next handler should not have been called for blacklisted token")
		}

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}

		// Check response body
		var response map[string]interface{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "api_key_blacklisted" {
			t.Errorf("Expected error 'api_key_blacklisted', got '%v'", response["error"])
		}
	})

	t.Run("InvalidToken_ShouldBlock", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token")

		// Add replacer context
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()

		nextCalled := false
		next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error {
			nextCalled = true
			return nil
		})

		err := module.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("Expected no error from ServeHTTP, got: %v", err)
		}

		if nextCalled {
			t.Error("Next handler should not have been called for invalid token")
		}

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}
	})

	t.Run("MissingToken_ShouldBlock", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		// Add replacer context
		repl := caddy.NewReplacer()
		ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()

		nextCalled := false
		next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error {
			nextCalled = true
			return nil
		})

		err := module.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("Expected no error from ServeHTTP, got: %v", err)
		}

		if nextCalled {
			t.Error("Next handler should not have been called for missing token")
		}

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}

		// Check response body
		var response map[string]interface{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response["error"] != "missing_token" {
			t.Errorf("Expected error 'missing_token', got '%v'", response["error"])
		}
	})

	t.Run("RedisFailure_FailOpen_ShouldPass", func(t *testing.T) {
		// Create module with fail_open enabled
		failOpenModule := &JWTBlacklist{
			Config: &Config{
				RedisAddr:       "invalid:9999", // Invalid Redis address
				RedisDB:         15,
				BlacklistPrefix: "TEST:BLACKLIST:key:",
				FailOpen:        true, // Key difference
				Timeout:         caddy.Duration(100 * time.Millisecond),
				LogBlocked:      true,
				JWT: &JWTConfig{
					SignKey:       TestSignKey,
					SignAlgorithm: "HS256",
					FromHeader:    []string{"Authorization"},
					UserClaims:    []string{"sub"},
				},
			},
		}

		// Provision the module (this will fail to connect to Redis, but that's expected)
		ctx := caddy.Context{}
		_ = failOpenModule.Provision(ctx) // Ignore Redis connection error

		apiKeyID := "test-api-key-789"
		token := createTestToken(map[string]interface{}{
			"sub": "test-user",
			"jti": apiKeyID,
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Add replacer context
		repl := caddy.NewReplacer()
		ctx2 := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
		req = req.WithContext(ctx2)

		rec := httptest.NewRecorder()

		nextCalled := false
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
			return nil
		})

		err := failOpenModule.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("Expected no error from ServeHTTP, got: %v", err)
		}

		if !nextCalled {
			t.Error("Next handler should have been called when failing open")
		}

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}

		_ = failOpenModule.Cleanup()
	})
}

func TestJWTBlacklistConfiguration(t *testing.T) {
	t.Run("ValidateRequiredFields", func(t *testing.T) {
		config := &Config{}
		config.setDefaults()

		err := config.validate()
		if err == nil {
			t.Error("Expected validation error for missing redis_addr")
		}

		config.RedisAddr = "localhost:6379"
		err = config.validate()
		if err == nil {
			t.Error("Expected validation error for missing JWT configuration")
		}

		config.JWT = &JWTConfig{SignKey: TestSignKey}
		config.JWT.setJWTDefaults()
		err = config.validate()
		if err != nil {
			t.Errorf("Expected no validation error, got: %v", err)
		}
	})

	t.Run("DefaultValues", func(t *testing.T) {
		config := &Config{}
		config.setDefaults()

		if config.BlacklistPrefix != "BLACKLIST:key:" {
			t.Errorf("Expected default blacklist prefix 'BLACKLIST:key:', got '%s'", config.BlacklistPrefix)
		}

		if config.Timeout != caddy.Duration(50*time.Millisecond) {
			t.Errorf("Expected default timeout 50ms, got %v", config.Timeout)
		}

		if config.FailOpen {
			t.Error("Expected default fail_open to be false")
		}

		if config.JWT == nil {
			t.Error("Expected JWT config to be initialized")
		} else {
			if config.JWT.SignAlgorithm != "HS256" {
				t.Errorf("Expected default sign algorithm 'HS256', got '%s'", config.JWT.SignAlgorithm)
			}
		}
	})
}

// Integration test with multiple token sources
func TestMultipleTokenSources(t *testing.T) {
	testRedis, err := setupTestRedis()
	if err != nil {
		t.Skipf("Skipping integration test: %v", err)
		return
	}
	defer testRedis.cleanup()

	module := &JWTBlacklist{
		Config: &Config{
			RedisAddr:       testRedis.addr,
			RedisDB:         15,
			BlacklistPrefix: "TEST:BLACKLIST:key:",
			FailOpen:        false,
			Timeout:         caddy.Duration(100 * time.Millisecond),
			JWT: &JWTConfig{
				SignKey:       TestSignKey,
				SignAlgorithm: "HS256",
				FromQuery:     []string{"access_token", "token"},
				FromHeader:    []string{"Authorization", "X-Api-Token"},
				FromCookies:   []string{"session_token"},
				UserClaims:    []string{"sub"},
			},
		},
	}

	ctx := caddy.Context{}
	err = module.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision module: %v", err)
	}
	defer func() { _ = module.Cleanup() }()

	apiKeyID := "multi-source-token"
	token := createTestToken(map[string]interface{}{
		"sub": "test-user",
		"jti": apiKeyID,
	})

	tests := []struct {
		name     string
		setToken func(*http.Request)
	}{
		{
			name: "FromQuery",
			setToken: func(req *http.Request) {
				q := req.URL.Query()
				q.Set("access_token", token)
				req.URL.RawQuery = q.Encode()
			},
		},
		{
			name: "FromHeader",
			setToken: func(req *http.Request) {
				req.Header.Set("X-Api-Token", token)
			},
		},
		{
			name: "FromCookie",
			setToken: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_token", Value: token})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setToken(req)

			// Add replacer context
			repl := caddy.NewReplacer()
			ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()

			nextCalled := false
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				return nil
			})

			err := module.ServeHTTP(rec, req, next)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			if !nextCalled {
				t.Error("Next handler should have been called")
			}

			if rec.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rec.Code)
			}
		})
	}
}
