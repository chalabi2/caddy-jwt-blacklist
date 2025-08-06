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
	"go.uber.org/zap"
)

// TestIntegrationWithExistingSetup tests integration with the existing Caddy setup
func TestIntegrationWithExistingSetup(t *testing.T) {
	// Setup test Redis
	testRedis, err := setupTestRedis()
	if err != nil {
		t.Skipf("Skipping integration test: %v", err)
		return
	}
	defer testRedis.cleanup()

	// Use the test JWT secret (base64 encoded for proper validation)
	jwtSecret := TestSignKey

	// Create middleware with configuration matching the spec
	jb := &JWTBlacklist{
		Config: &Config{
			RedisAddr:       testRedis.addr,
			RedisPassword:   "",
			RedisDB:         15,
			JWTSecret:       jwtSecret,
			BlacklistPrefix: "BLACKLIST:key:",
			FailOpen:        true,
			Timeout:         caddy.Duration(50 * time.Millisecond),
			LogBlocked:      true,
		},
	}

	// Provision the middleware
	ctx := caddy.Context{Context: context.Background()}
	if err := jb.Provision(ctx); err != nil {
		t.Fatalf("Failed to provision middleware: %v", err)
	}
	defer func() { _ = jb.Cleanup() }()

	// Test scenarios that match the webapp behavior
	scenarios := []struct {
		name           string
		apiKeyID       string
		userID         string
		tier           string
		scenario       string
		blacklistValue string
		ttlDays        int
		expectBlocked  bool
	}{
		{
			name:          "FREE tier user - not blacklisted",
			apiKeyID:      "ak_1234567890abcdef",
			userID:        "user_free_123",
			tier:          "FREE",
			scenario:      "active_subscription",
			expectBlocked: false,
		},
		{
			name:           "BASIC tier - subscription cancelled",
			apiKeyID:       "ak_basic_cancelled",
			userID:         "user_basic_456",
			tier:           "BASIC",
			scenario:       "subscription_cancelled",
			blacklistValue: "cancelled",
			ttlDays:        7,
			expectBlocked:  true,
		},
		{
			name:           "PREMIUM tier - one-time payment expired",
			apiKeyID:       "ak_premium_expired",
			userID:         "user_premium_789",
			tier:           "PREMIUM",
			scenario:       "one_time_expired",
			blacklistValue: "expired",
			ttlDays:        30,
			expectBlocked:  true,
		},
		{
			name:           "ENTERPRISE tier - downgraded to FREE",
			apiKeyID:       "ak_enterprise_downgraded",
			userID:         "user_enterprise_101",
			tier:           "ENTERPRISE",
			scenario:       "tier_downgraded",
			blacklistValue: "downgraded",
			ttlDays:        1,
			expectBlocked:  true,
		},
		{
			name:          "UNLIMITED tier - test account",
			apiKeyID:      "ak_unlimited_test",
			userID:        "user_unlimited_999",
			tier:          "UNLIMITED",
			scenario:      "test_account",
			expectBlocked: false,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Setup blacklist if needed (simulating webapp behavior)
			if scenario.expectBlocked {
				blacklistKey := fmt.Sprintf("BLACKLIST:key:%s", scenario.apiKeyID)
				ttl := time.Duration(scenario.ttlDays) * 24 * time.Hour

				err := testRedis.client.SetEx(context.Background(), blacklistKey, scenario.blacklistValue, ttl).Err()
				if err != nil {
					t.Fatalf("Failed to setup blacklist for scenario %s: %v", scenario.scenario, err)
				}

				// Verify blacklist was set correctly
				exists, err := testRedis.client.Exists(context.Background(), blacklistKey).Result()
				if err != nil || exists == 0 {
					t.Fatalf("Blacklist key not set correctly: %v", err)
				}
			}

			// Create JWT token matching webapp format
			token := createTestToken(map[string]interface{}{
				"sub":   scenario.userID,
				"jti":   scenario.apiKeyID,
				"tier":  scenario.tier,
				"scope": "api_access",
			})

			// Test different token passing methods (as used in production)
			tokenTests := []struct {
				method string
				setup  func(*http.Request)
			}{
				{
					method: "Authorization_Bearer",
					setup: func(req *http.Request) {
						req.Header.Set("Authorization", "Bearer "+token)
					},
				},
				{
					method: "X-API-Key",
					setup: func(req *http.Request) {
						req.Header.Set("X-API-Key", token)
					},
				},
				{
					method: "query_param",
					setup: func(req *http.Request) {
						req.URL.RawQuery = "api_key=" + token
					},
				},
			}

			for _, tokenTest := range tokenTests {
				t.Run(fmt.Sprintf("%s_%s", scenario.name, tokenTest.method), func(t *testing.T) {
					// Create request for various endpoints (matching chain configs)
					endpoints := []string{
						"/cosmos/status",
						"/ethereum/",
						"/base/",
						"/status",
					}

					for _, endpoint := range endpoints {
						req := httptest.NewRequest("GET", endpoint, nil)
						tokenTest.setup(req)

						w := httptest.NewRecorder()

						// Mock next handler (simulating jwtauth + rate_limit + reverse_proxy)
						nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							w.WriteHeader(200)
							response := map[string]interface{}{
								"status":    "ok",
								"service":   "chandra-station-private",
								"timestamp": time.Now().Unix(),
								"user_id":   scenario.userID,
								"tier":      scenario.tier,
							}
							_ = json.NewEncoder(w).Encode(response)
						})

						// Execute middleware
						err := jb.ServeHTTP(w, req, wrapHandler(nextHandler))
						if err != nil {
							t.Fatalf("Middleware error for %s: %v", endpoint, err)
						}

						// Verify response
						if scenario.expectBlocked {
							if w.Code != 401 {
								t.Errorf("Expected 401 for blocked token at %s, got %d", endpoint, w.Code)
							}

							// Verify error response format matches spec
							var errorResponse map[string]interface{}
							if err := json.Unmarshal(w.Body.Bytes(), &errorResponse); err != nil {
								t.Fatalf("Failed to parse error response: %v", err)
							}

							expectedError := "api_key_blacklisted"
							if errorResponse["error"] != expectedError {
								t.Errorf("Expected error %s, got %s", expectedError, errorResponse["error"])
							}

							// Verify headers are set for error handling
							if w.Header().Get("X-Error-Type") != "api_key_blacklisted" {
								t.Errorf("Missing X-Error-Type header")
							}

							if w.Header().Get("WWW-Authenticate") != "Bearer" {
								t.Errorf("Missing WWW-Authenticate header")
							}
						} else {
							if w.Code != 200 {
								t.Errorf("Expected 200 for valid token at %s, got %d", endpoint, w.Code)
							}

							// Verify successful response
							var response map[string]interface{}
							if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
								t.Fatalf("Failed to parse success response: %v", err)
							}

							if response["status"] != "ok" {
								t.Errorf("Expected status ok, got %s", response["status"])
							}
						}
					}
				})
			}

			// Cleanup blacklist entry
			if scenario.expectBlocked {
				blacklistKey := fmt.Sprintf("BLACKLIST:key:%s", scenario.apiKeyID)
				testRedis.client.Del(context.Background(), blacklistKey)
			}
		})
	}
}

// TestWebappBlacklistPatterns tests the exact patterns used by the webapp
func TestWebappBlacklistPatterns(t *testing.T) {
	testRedis, err := setupTestRedis()
	if err != nil {
		t.Skipf("Skipping webapp pattern test: %v", err)
		return
	}
	defer testRedis.cleanup()

	// Test the exact blacklist patterns from the webapp
	patterns := []struct {
		reason   string
		ttlDays  int
		expected string
	}{
		{"cancelled", 7, "cancelled"},   // subscription cancelled
		{"expired", 30, "expired"},      // one-time payment expired
		{"downgraded", 1, "downgraded"}, // subscription downgraded
	}

	for _, pattern := range patterns {
		t.Run(fmt.Sprintf("webapp_pattern_%s", pattern.reason), func(t *testing.T) {
			apiKeyID := fmt.Sprintf("test-key-%s", pattern.reason)
			blacklistKey := fmt.Sprintf("BLACKLIST:key:%s", apiKeyID)
			ttl := time.Duration(pattern.ttlDays) * 24 * time.Hour

			// Set blacklist entry with webapp pattern
			err := testRedis.client.SetEx(context.Background(), blacklistKey, pattern.expected, ttl).Err()
			if err != nil {
				t.Fatalf("Failed to set blacklist: %v", err)
			}

			// Verify the pattern is detected correctly
			redis, err := NewRedisClient(testRedis.addr, "", 15, nil, zap.NewNop())
			if err != nil {
				t.Fatalf("Failed to create Redis client: %v", err)
			}
			defer func() { _ = redis.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			isBlacklisted, err := redis.IsBlacklisted(ctx, apiKeyID, "BLACKLIST:key:")
			if err != nil {
				t.Fatalf("Failed to check blacklist: %v", err)
			}

			if !isBlacklisted {
				t.Errorf("Expected key %s to be blacklisted", apiKeyID)
			}

			// Get additional info
			value, ttlRemaining, err := redis.GetBlacklistInfo(ctx, apiKeyID, "BLACKLIST:key:")
			if err != nil {
				t.Fatalf("Failed to get blacklist info: %v", err)
			}

			if value != pattern.expected {
				t.Errorf("Expected blacklist value %s, got %s", pattern.expected, value)
			}

			if ttlRemaining <= 0 {
				t.Errorf("Expected positive TTL, got %v", ttlRemaining)
			}

			// Cleanup
			testRedis.client.Del(context.Background(), blacklistKey)
		})
	}
}

// TestRateLimitingIntegration tests that the blacklist works with tier-based rate limiting
func TestRateLimitingIntegration(t *testing.T) {
	testRedis, err := setupTestRedis()
	if err != nil {
		t.Skipf("Skipping rate limiting integration test: %v", err)
		return
	}
	defer testRedis.cleanup()

	jwtSecret := TestSignKey

	// Test that blacklisted tokens are blocked before rate limiting
	tiers := []string{"FREE", "BASIC", "PREMIUM", "ENTERPRISE", "UNLIMITED"}

	for _, tier := range tiers {
		t.Run(fmt.Sprintf("tier_%s_blacklisted", tier), func(t *testing.T) {
			apiKeyID := fmt.Sprintf("ak_%s_test", tier)
			userID := fmt.Sprintf("user_%s_123", tier)

			// Blacklist the key
			blacklistKey := fmt.Sprintf("BLACKLIST:key:%s", apiKeyID)
			err := testRedis.client.SetEx(context.Background(), blacklistKey, "test_blacklist", time.Hour).Err()
			if err != nil {
				t.Fatalf("Failed to blacklist key: %v", err)
			}

			// Create middleware
			jb := &JWTBlacklist{
				Config: &Config{
					RedisAddr:       testRedis.addr,
					RedisDB:         15,
					JWTSecret:       jwtSecret,
					BlacklistPrefix: "BLACKLIST:key:",
					FailOpen:        true,
					Timeout:         caddy.Duration(50 * time.Millisecond),
				},
			}

			ctx := caddy.Context{Context: context.Background()}
			if err := jb.Provision(ctx); err != nil {
				t.Fatalf("Failed to provision middleware: %v", err)
			}
			defer func() { _ = jb.Cleanup() }()

			// Generate token
			token := createTestToken(map[string]interface{}{
				"sub":   userID,
				"jti":   apiKeyID,
				"tier":  tier,
				"scope": "api_access",
			})

			req := httptest.NewRequest("GET", "/cosmos/status", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			// Mock rate limiting handler that should NOT be reached
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				// If we reach here, the blacklist check failed
				t.Error("Rate limiting handler should not be reached for blacklisted tokens")
				w.WriteHeader(200)
			})

			// Execute middleware
			err = jb.ServeHTTP(w, req, wrapHandler(nextHandler))
			if err != nil {
				t.Fatalf("Middleware error: %v", err)
			}

			// Should be blocked before reaching rate limiting
			if w.Code != 401 {
				t.Errorf("Expected 401 for blacklisted %s tier token, got %d", tier, w.Code)
			}

			// Cleanup
			testRedis.client.Del(context.Background(), blacklistKey)
		})
	}
}
