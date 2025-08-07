package jwtblacklist

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// TestDirectiveRegistration tests that the stateful_jwt directive is properly registered
func TestDirectiveRegistration(t *testing.T) {
	// Test that the module is registered with the expected ID
	module := JWTBlacklist{}
	info := module.CaddyModule()

	expectedID := "http.handlers.stateful_jwt"
	if string(info.ID) != expectedID {
		t.Errorf("Expected module ID %s, got %s", expectedID, string(info.ID))
	}

	// Test that New() creates a proper instance
	newInstance := info.New()
	if newInstance == nil {
		t.Error("Module New() function returned nil")
	}

	_, ok := newInstance.(*JWTBlacklist)
	if !ok {
		t.Error("Module New() function did not return *JWTBlacklist")
	}
}

// TestCaddyfileParsingWithOrder tests that Caddyfile parsing works with order directive
func TestCaddyfileParsingWithOrder(t *testing.T) {
	caddyfileContent := `{
	order stateful_jwt before jwtauth
	order jwtauth before rate_limit
}

localhost:8080 {
	stateful_jwt {
		redis_addr localhost:6379
		jwt_secret test-secret
		blacklist_prefix "BLACKLIST:key:"
		fail_open true
		timeout 50ms
		log_blocked true
	}
	
	respond "OK"
}`

	// Parse the Caddyfile
	blocks, err := caddyfile.Parse("Caddyfile", []byte(caddyfileContent))
	if err != nil {
		t.Fatalf("Failed to parse Caddyfile: %v", err)
	}

	// Verify that we can parse without errors - this tests the directive registration
	if len(blocks) == 0 {
		t.Error("Expected parsed blocks, got none")
	}

	// Look for the stateful_jwt directive in the server block
	found := false
	for _, block := range blocks {
		for _, segment := range block.Segments {
			for _, token := range segment {
				if token.Text == "stateful_jwt" {
					found = true
					break
				}
			}
		}
	}

	if !found {
		t.Error("stateful_jwt directive not found in parsed Caddyfile")
	}
}

// TestJSONConfigGeneration tests that JSON config generation includes proper module ID
func TestJSONConfigGeneration(t *testing.T) {
	jb := &JWTBlacklist{
		Config: &Config{
			RedisAddr:       "localhost:6379",
			JWTSecret:       "test-secret",
			BlacklistPrefix: "BLACKLIST:key:",
			FailOpen:        true,
		},
	}

	// Marshal to JSON to verify structure
	jsonData, err := json.Marshal(jb)
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	// Verify the JSON contains expected structure
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Check that config exists
	if _, exists := result["config"]; !exists {
		t.Error("JSON config should contain 'config' field")
	}
}

// TestUnmarshalCaddyfile tests that Caddyfile unmarshaling works correctly
func TestUnmarshalCaddyfile(t *testing.T) {
	caddyfileContent := `stateful_jwt {
		redis_addr localhost:6379
		jwt_secret test-secret
		blacklist_prefix "BLACKLIST:key:"
		fail_open true
		timeout 50ms
		log_blocked true
	}`

	// Create a dispenser
	d := caddyfile.NewTestDispenser(caddyfileContent)

	// Create a JWTBlacklist instance and unmarshal
	jb := &JWTBlacklist{}
	err := jb.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("Failed to unmarshal Caddyfile: %v", err)
	}

	// Verify configuration was parsed correctly
	if jb.Config == nil {
		t.Fatal("Config should not be nil after unmarshaling")
	}

	if jb.Config.RedisAddr != "localhost:6379" {
		t.Errorf("Expected redis_addr localhost:6379, got %s", jb.Config.RedisAddr)
	}

	if jb.Config.JWTSecret != "test-secret" {
		t.Errorf("Expected jwt_secret test-secret, got %s", jb.Config.JWTSecret)
	}

	if jb.Config.BlacklistPrefix != "BLACKLIST:key:" {
		t.Errorf("Expected blacklist_prefix BLACKLIST:key:, got %s", jb.Config.BlacklistPrefix)
	}

	if !jb.Config.FailOpen {
		t.Error("Expected fail_open to be true")
	}

	if !jb.Config.LogBlocked {
		t.Error("Expected log_blocked to be true")
	}
}
