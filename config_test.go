package jwtblacklist

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalCaddyfileNormalCase(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		redis_addr "localhost:6379"
		redis_password "secret"
		redis_db 1
		blacklist_prefix "BLACKLIST:key:"
		fail_open true
		timeout 100ms
		log_blocked true
		sign_key "TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk="
		sign_alg HS256
		from_query access_token token _tok
		from_header X-Api-Key
		from_cookies user_session SESSID
		issuer_whitelist https://api.example.com
		audience_whitelist https://api.example.io https://learn.example.com
		user_claims uid user_id login username
		meta_claims "IsAdmin -> is_admin" "gender"
	}
	`),
	}

	expectedConfig := &Config{
		RedisAddr:       "localhost:6379",
		RedisPassword:   "secret",
		RedisDB:         1,
		BlacklistPrefix: "BLACKLIST:key:",
		FailOpen:        true,
		Timeout:         100000000, // 100ms in nanoseconds
		LogBlocked:      true,
		JWT: &JWTConfig{
			SignKey:           TestSignKey,
			SignAlgorithm:     "HS256",
			FromQuery:         []string{"access_token", "token", "_tok"},
			FromHeader:        []string{"X-Api-Key"},
			FromCookies:       []string{"user_session", "SESSID"},
			IssuerWhitelist:   []string{"https://api.example.com"},
			AudienceWhitelist: []string{"https://api.example.io", "https://learn.example.com"},
			UserClaims:        []string{"uid", "user_id", "login", "username"},
			MetaClaims:        map[string]string{"IsAdmin": "is_admin", "gender": "gender"},
		},
	}

	jb := &JWTBlacklist{}
	err := jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.Nil(t, err)

	// Set defaults to match expected config
	jb.Config.setDefaults()

	assert.Equal(t, expectedConfig.RedisAddr, jb.Config.RedisAddr)
	assert.Equal(t, expectedConfig.RedisPassword, jb.Config.RedisPassword)
	assert.Equal(t, expectedConfig.RedisDB, jb.Config.RedisDB)
	assert.Equal(t, expectedConfig.BlacklistPrefix, jb.Config.BlacklistPrefix)
	assert.Equal(t, expectedConfig.FailOpen, jb.Config.FailOpen)
	assert.Equal(t, expectedConfig.Timeout, jb.Config.Timeout)
	assert.Equal(t, expectedConfig.LogBlocked, jb.Config.LogBlocked)
	assert.Equal(t, expectedConfig.JWT.SignKey, jb.Config.JWT.SignKey)
	assert.Equal(t, expectedConfig.JWT.SignAlgorithm, jb.Config.JWT.SignAlgorithm)
	assert.Equal(t, expectedConfig.JWT.FromQuery, jb.Config.JWT.FromQuery)
	assert.Equal(t, expectedConfig.JWT.FromHeader, jb.Config.JWT.FromHeader)
	assert.Equal(t, expectedConfig.JWT.FromCookies, jb.Config.JWT.FromCookies)
	assert.Equal(t, expectedConfig.JWT.IssuerWhitelist, jb.Config.JWT.IssuerWhitelist)
	assert.Equal(t, expectedConfig.JWT.AudienceWhitelist, jb.Config.JWT.AudienceWhitelist)
	assert.Equal(t, expectedConfig.JWT.UserClaims, jb.Config.JWT.UserClaims)
	assert.Equal(t, expectedConfig.JWT.MetaClaims, jb.Config.JWT.MetaClaims)
}

func TestUnmarshalCaddyfileError(t *testing.T) {
	// invalid sign_key: missing
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		sign_key
	}
	`),
	}

	jb := &JWTBlacklist{}
	err := jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sign_key")

	// invalid sign_alg: missing
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		sign_alg
	}`),
	}

	jb = &JWTBlacklist{}
	err = jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sign_alg")

	// invalid jwk_url: missing
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		jwk_url
	}`),
	}

	jb = &JWTBlacklist{}
	err = jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "jwk_url")

	// invalid meta_claims: parse error
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		redis_addr "localhost:6379"
		sign_key "TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk="
		meta_claims IsAdmin->is_admin->
	}
	`),
	}
	jb = &JWTBlacklist{}
	err = jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "meta_claims")

	// invalid meta_claims: duplicate
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		redis_addr "localhost:6379"
		sign_key "TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk="
		meta_claims IsAdmin->is_admin Gender->gender IsAdmin->admin
	}
	`),
	}
	jb = &JWTBlacklist{}
	err = jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "meta_claims")

	// unrecognized option
	helper = httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		redis_addr "localhost:6379"
		sign_key "TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk="
		upstream http://192.168.1.4
	}
	`),
	}
	jb = &JWTBlacklist{}
	err = jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unknown directive")
}

func TestParseMetaClaim(t *testing.T) {
	var testCases = []struct {
		Key         string
		Claim       string
		Placeholder string
		Pass        bool
	}{
		{"username", "username", "username", true},
		{"registerYear->register_year", "registerYear", "register_year", true},
		{"IsAdmin -> is_admin", "IsAdmin", "is_admin", true},
		{"Gender", "Gender", "Gender", true},
		{"->slot", "", "", false},
		{"IsMember->", "", "", false},
		{"Favorite -> favorite->fav", "", "", false},
	}

	for _, c := range testCases {
		claim, placeholder, err := parseMetaClaim(c.Key)
		assert.Equal(t, claim, c.Claim)
		assert.Equal(t, placeholder, c.Placeholder)
		if c.Pass == true {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Contains(t, err.Error(), c.Key)
		}
	}
}

func TestUnmarshalCaddyfileWithSkipVerification(t *testing.T) {
	helper := httpcaddyfile.Helper{
		Dispenser: caddyfile.NewTestDispenser(`
	jwt_blacklist {
		redis_addr "localhost:6379"
		skip_verification
		from_query access_token token _tok
		from_header X-Api-Key
		from_cookies user_session SESSID
		issuer_whitelist https://api.example.com
		audience_whitelist https://api.example.io https://learn.example.com
		user_claims uid user_id login username
		meta_claims "IsAdmin -> is_admin" "gender"
	}
	`),
	}

	jb := &JWTBlacklist{}
	err := jb.UnmarshalCaddyfile(helper.Dispenser)
	assert.Nil(t, err)

	jb.Config.setDefaults()

	assert.Equal(t, "localhost:6379", jb.Config.RedisAddr)
	assert.True(t, jb.Config.JWT.SkipVerification)
	assert.Equal(t, []string{"access_token", "token", "_tok"}, jb.Config.JWT.FromQuery)
	assert.Equal(t, []string{"X-Api-Key"}, jb.Config.JWT.FromHeader)
	assert.Equal(t, []string{"user_session", "SESSID"}, jb.Config.JWT.FromCookies)
	assert.Equal(t, []string{"https://api.example.com"}, jb.Config.JWT.IssuerWhitelist)
	assert.Equal(t, []string{"https://api.example.io", "https://learn.example.com"}, jb.Config.JWT.AudienceWhitelist)
	assert.Equal(t, []string{"uid", "user_id", "login", "username"}, jb.Config.JWT.UserClaims)
	assert.Equal(t, map[string]string{"IsAdmin": "is_admin", "gender": "gender"}, jb.Config.JWT.MetaClaims)
}

func TestConfigValidation(t *testing.T) {
	// Valid config
	config := &Config{
		RedisAddr: "localhost:6379",
		JWT: &JWTConfig{
			SignKey: TestSignKey,
		},
	}
	config.setDefaults()
	assert.Nil(t, config.validate())

	// Missing Redis address
	config = &Config{
		// RedisAddr is empty - this should cause validation error
		JWT: &JWTConfig{
			SignKey: TestSignKey,
		},
	}
	config.setDefaults()
	err := config.validate()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "redis_addr")
	}

	// Missing JWT configuration
	config = &Config{
		RedisAddr: "localhost:6379",
		JWT:       nil, // Explicitly set to nil
	}
	config.setDefaults() // This should initialize JWT to empty config
	err = config.validate()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "sign_key")
	}
}
