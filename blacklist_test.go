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
	"github.com/golang-jwt/jwt/v4"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
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

func (tr *testRedisContainer) cleanup() {
	if tr.client != nil {
		tr.client.FlushDB(context.Background())
		_ = tr.client.Close()
	}
}

// generateTestJWT creates a JWT token for testing
func generateTestJWT(apiKeyID, userID, tier, scope, secret string) (string, error) {
	claims := &Claims{
		UserID:   userID,
		ApiKeyID: apiKeyID,
		Tier:     tier,
		Scope:    scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// TestJWTBlacklistMiddleware tests the main middleware functionality
func TestJWTBlacklistMiddleware(t *testing.T) {
	// Setup test Redis
	testRedis, err := setupTestRedis()
	if err != nil {
		t.Skipf("Skipping test: %v", err)
		return
	}
	defer testRedis.cleanup()

	// Test JWT secret
	jwtSecret := "test-jwt-secret-key-for-testing"

	// Create middleware instance
	jb := &JWTBlacklist{
		Config: &Config{
			RedisAddr:       testRedis.addr,
			RedisDB:         15,
			JWTSecret:       jwtSecret,
			BlacklistPrefix: "BLACKLIST:key:",
			FailOpen:        true,
			Timeout:         caddy.Duration(100 * time.Millisecond),
			LogBlocked:      true,
		},
	}

	// Provision the middleware
	ctx := caddy.Context{Context: context.Background()}
	if err := jb.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision middleware: %v", err)
	}
	defer func() { _ = jb.Cleanup() }()

	tests := []struct {
		name           string
		apiKeyID       string
		userID         string
		tier           string
		blacklisted    bool
		blacklistValue string
		expectStatus   int
		expectError    string
		authHeader     string
	}{
		{
			name:         "Valid token not blacklisted",
			apiKeyID:     "api-key-123",
			userID:       "user-123",
			tier:         "BASIC",
			blacklisted:  false,
			expectStatus: 200,
		},
		{
			name:           "Valid token but blacklisted (cancelled subscription)",
			apiKeyID:       "api-key-cancelled",
			userID:         "user-456",
			tier:           "BASIC",
			blacklisted:    true,
			blacklistValue: "cancelled",
			expectStatus:   401,
			expectError:    "api_key_blacklisted",
		},
		{
			name:           "Valid token but blacklisted (expired payment)",
			apiKeyID:       "api-key-expired",
			userID:         "user-789",
			tier:           "PREMIUM",
			blacklisted:    true,
			blacklistValue: "expired",
			expectStatus:   401,
			expectError:    "api_key_blacklisted",
		},
		{
			name:           "Valid token but blacklisted (downgraded)",
			apiKeyID:       "api-key-downgraded",
			userID:         "user-101",
			tier:           "ENTERPRISE",
			blacklisted:    true,
			blacklistValue: "downgraded",
			expectStatus:   401,
			expectError:    "api_key_blacklisted",
		},
		{
			name:         "No token provided",
			expectStatus: 200, // Should pass through to next handler
		},
		{
			name:         "Invalid JWT token",
			expectStatus: 200, // Should pass through to next handler
			authHeader:   "Bearer invalid-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup blacklist if needed
			if tt.blacklisted {
				blacklistKey := fmt.Sprintf("BLACKLIST:key:%s", tt.apiKeyID)
				var ttl time.Duration
				switch tt.blacklistValue {
				case "cancelled":
					ttl = 86400 * 7 * time.Second // 7 days
				case "expired":
					ttl = 86400 * 30 * time.Second // 30 days
				case "downgraded":
					ttl = 86400 * 1 * time.Second // 1 day
				}
				err := testRedis.client.SetEx(context.Background(), blacklistKey, tt.blacklistValue, ttl).Err()
				if err != nil {
					t.Fatalf("Failed to setup blacklist: %v", err)
				}
			}

			// Create test request
			req := httptest.NewRequest("GET", "/cosmos/status", nil)

			// Add JWT token if provided
			if tt.apiKeyID != "" {
				token, err := generateTestJWT(tt.apiKeyID, tt.userID, tt.tier, "api_access", jwtSecret)
				if err != nil {
					t.Fatalf("Failed to generate test JWT: %v", err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
			} else if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create next handler that returns 200 OK
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})

			// Execute the middleware
			err := jb.ServeHTTP(w, req, wrapHandler(nextHandler))
			if err != nil {
				t.Fatalf("Middleware returned error: %v", err)
			}

			// Check response status
			if w.Code != tt.expectStatus {
				t.Errorf("Expected status %d, got %d", tt.expectStatus, w.Code)
			}

			// Check error response for blacklisted tokens
			if tt.expectError != "" {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to parse error response: %v", err)
				}

				if response["error"] != tt.expectError {
					t.Errorf("Expected error %s, got %s", tt.expectError, response["error"])
				}

				// Check that error headers are set
				if w.Header().Get("X-Error-Type") != "api_key_blacklisted" {
					t.Errorf("Expected X-Error-Type header to be set")
				}
			}

			// Cleanup blacklist entry
			if tt.blacklisted {
				blacklistKey := fmt.Sprintf("BLACKLIST:key:%s", tt.apiKeyID)
				testRedis.client.Del(context.Background(), blacklistKey)
			}
		})
	}
}

// TestTokenExtraction tests various token sources
func TestTokenExtraction(t *testing.T) {
	tests := []struct {
		name     string
		setupReq func(*http.Request)
		expected string
	}{
		{
			name: "Authorization Bearer header",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer test-token-123")
			},
			expected: "test-token-123",
		},
		{
			name: "X-API-Key header",
			setupReq: func(req *http.Request) {
				req.Header.Set("X-API-Key", "test-token-456")
			},
			expected: "test-token-456",
		},
		{
			name: "X-Api-Token header",
			setupReq: func(req *http.Request) {
				req.Header.Set("X-Api-Token", "test-token-789")
			},
			expected: "test-token-789",
		},
		{
			name: "Query parameter api_key",
			setupReq: func(req *http.Request) {
				req.URL.RawQuery = "api_key=test-token-query"
			},
			expected: "test-token-query",
		},
		{
			name: "Query parameter access_token",
			setupReq: func(req *http.Request) {
				req.URL.RawQuery = "access_token=test-token-access"
			},
			expected: "test-token-access",
		},
		{
			name: "Cookie session_token",
			setupReq: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: "session_token", Value: "test-token-cookie"})
			},
			expected: "test-token-cookie",
		},
		{
			name: "No token",
			setupReq: func(req *http.Request) {
				// No token setup
			},
			expected: "",
		},
		{
			name: "Priority test - Authorization header wins",
			setupReq: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer priority-token")
				req.Header.Set("X-API-Key", "lower-priority")
				req.URL.RawQuery = "api_key=lowest-priority"
			},
			expected: "priority-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupReq(req)

			result := extractToken(req)
			if result != tt.expected {
				t.Errorf("Expected token %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestJWTParsing tests JWT parsing functionality
func TestJWTParsing(t *testing.T) {
	secret := "test-secret-key"

	tests := []struct {
		name      string
		token     string
		expectErr bool
		claims    *Claims
	}{
		{
			name: "Valid token",
			claims: &Claims{
				UserID:   "user-123",
				ApiKeyID: "api-key-456",
				Tier:     "BASIC",
				Scope:    "api_access",
			},
			expectErr: false,
		},
		{
			name:      "Empty token",
			token:     "",
			expectErr: true,
		},
		{
			name:      "Invalid token format",
			token:     "invalid-token",
			expectErr: true,
		},
		{
			name: "Missing jti claim",
			claims: &Claims{
				UserID: "user-123",
				Tier:   "BASIC",
				Scope:  "api_access",
				// ApiKeyID missing
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token string
			var err error

			if tt.claims != nil {
				// Generate token from claims
				jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, tt.claims)
				token, err = jwtToken.SignedString([]byte(secret))
				if err != nil {
					t.Fatalf("Failed to generate test token: %v", err)
				}
			} else if tt.token != "" {
				token = tt.token
			}

			claims, err := parseJWT(token, secret)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if claims.UserID != tt.claims.UserID {
				t.Errorf("Expected UserID %s, got %s", tt.claims.UserID, claims.UserID)
			}

			if claims.ApiKeyID != tt.claims.ApiKeyID {
				t.Errorf("Expected ApiKeyID %s, got %s", tt.claims.ApiKeyID, claims.ApiKeyID)
			}
		})
	}
}

// TestRedisFailure tests behavior when Redis is unavailable
func TestRedisFailure(t *testing.T) {
	jwtSecret := "test-jwt-secret-key"

	// Create middleware with invalid Redis address
	jb := &JWTBlacklist{
		Config: &Config{
			RedisAddr:       "localhost:9999", // Invalid port
			RedisDB:         0,
			JWTSecret:       jwtSecret,
			BlacklistPrefix: "BLACKLIST:key:",
			FailOpen:        true, // Should continue processing
			Timeout:         caddy.Duration(100 * time.Millisecond),
		},
		logger: zap.NewNop(),
	}

	// Initialize Redis client (this will fail, but we handle it gracefully)
	redis, err := NewRedisClient("localhost:9999", "", 0, jb.logger)
	if err != nil {
		// Expected - Redis not available
		// For this test, we'll simulate the scenario in the middleware
		t.Log("Redis connection failed as expected")
	} else {
		_ = redis.Close()
		t.Skip("Redis available on port 9999 - skipping failure test")
	}

	// Create a valid JWT token
	token, err := generateTestJWT("api-key-123", "user-123", "BASIC", "api_access", jwtSecret)
	if err != nil {
		t.Fatalf("Failed to generate test JWT: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Mock Redis client that always fails
	jb.redis = &RedisClient{
		client: nil, // Will cause connection errors
		logger: zap.NewNop(),
	}

	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return nil
	})

	// Test that the middleware handles Redis failures gracefully when fail_open is true
	// The request should continue to the next handler
	err = jb.ServeHTTP(w, req, nextHandler)
	if err != nil {
		t.Errorf("ServeHTTP should not return error when fail_open=true, got: %v", err)
	}

	// Should get successful response from next handler despite Redis failure
	if w.Code != 200 {
		t.Errorf("Expected status 200 with fail_open=true, got %d", w.Code)
	}
}
