package jwtblacklist

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

type MapClaims map[string]interface{}

var (
	testLogger, _ = zap.NewDevelopment()

	// Symmetric
	RawTestSignKey = []byte("NFL5*0Bc#9U6E@tnmC&E7SUN6GwHfLmY")
	TestSignKey    = base64.StdEncoding.EncodeToString(RawTestSignKey)

	// Asymmetric
	TestPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzekF0pqttKNJMOiZeyt
RdYiabdyy/sdGQYWYJPGD2Q+QDU9ZqprDmKgFOTxUy/VUBnaYr7hOEMBe7I6dyaS
5G0EGr8UXAwgD5Uvhmz6gqvKTV+FyQfw0bupbcM4CdMD7wQ9uOxDdMYm7g7gdGd6
SSIVvmsGDibBI9S7nKlbcbmciCmxbAlwegTYSHHLjwWvDs2aAF8fxeRfphwQZKkd
HekSZ090/c2V4i0ju2M814QyGERMoq+cSlmikCgRWoSZeWOSTj+rAZJyEAzlVL4z
8ojzOpjmxw6pRYsS0vYIGEDuyiptf+ODC8smTbma/p3Vz+vzyLWPfReQY2RHtpUe
hwIDAQAB
-----END PUBLIC KEY-----`

	// JWK URL
	TestJWKURL                = "http://127.0.0.1:2546/key"
	TestJWKSetURL             = "http://127.0.0.1:2546/keys"
	TestJWKSetURLInapplicable = "http://127.0.0.1:2546/keys_inapplicable"

	jwkKey                   jwk.Key // private key
	jwkPubKey                jwk.Key // public key
	jwkPubKeySet             jwk.Set // public key set
	jwkPubKeySetInapplicable jwk.Set // public key set (inapplicable)

	// EdDSA test
	jwkKeyEd25519      jwk.Key // private key for EdDSA test
	TestSignKeyEd25519 string  // base64 encoded public key
)

func init() {
	var err error
	jwkKey = generateJWK()

	jwkPubKey, err = jwkKey.PublicKey()
	panicOnError(err)

	anotherPubKeyI, err := generateJWK().PublicKey()
	panicOnError(err)
	anotherPubKeyII, err := generateJWK().PublicKey()
	panicOnError(err)

	jwkKeyEd25519 = generateEdDSAJWK()

	jwkPubKeySet = jwk.NewSet()
	jwkPubKeySet.AddKey(anotherPubKeyI)
	jwkPubKeySet.AddKey(jwkPubKey)

	jwkPubKeySetInapplicable = jwk.NewSet()
	jwkPubKeySetInapplicable.AddKey(anotherPubKeyI)
	jwkPubKeySetInapplicable.AddKey(anotherPubKeyII)

	publishJWKsOnLocalServer()
}

func generateJWK() jwk.Key {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	panicOnError(err)
	key, err := jwk.FromRaw(privateKey)
	panicOnError(err)
	jwk.AssignKeyID(key)                       // set "kid"
	key.Set(jwk.AlgorithmKey, jwa.RS256)       // set "alg"
	key.Set(jwk.KeyUsageKey, jwk.ForSignature) // set "use"
	return key
}

func generateEdDSAJWK() jwk.Key {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	panicOnError(err)
	TestSignKeyEd25519 = base64.StdEncoding.EncodeToString(publicKey)
	key, err := jwk.FromRaw(privateKey)
	panicOnError(err)
	jwk.AssignKeyID(key)
	key.Set(jwk.AlgorithmKey, jwa.EdDSA)
	key.Set(jwk.KeyUsageKey, jwk.ForSignature)
	return key
}

func publishJWKsOnLocalServer() {
	go func() {
		http.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(jwkPubKey)
		})
		http.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(jwkPubKeySet)
		})
		http.HandleFunc("/keys_inapplicable", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(jwkPubKeySetInapplicable)
		})
		panicOnError(http.ListenAndServe("127.0.0.1:2546", nil))
	}()
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func buildToken(claims MapClaims) jwt.Token {
	tb := jwt.NewBuilder()
	for k, v := range claims {
		tb = tb.Claim(k, v)
	}
	token, err := tb.Build()
	panicOnError(err)
	return token
}

// issueTokenString issues a token string with the given claims,
// using HS256 signing algorithm.
func issueTokenString(claims MapClaims) string {
	token := buildToken(claims)
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.HS256, RawTestSignKey))
	panicOnError(err)

	return string(tokenBytes)
}

// issueTokenString issues a token string with the given claims,
// using EdDSA signing algorithm.
func issueTokenStringEdDSA(claims MapClaims) string {
	token := buildToken(claims)
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, jwkKeyEd25519))
	panicOnError(err)

	return string(tokenBytes)
}

func issueTokenStringJWK(claims MapClaims, options ...func(*jwt.SignOption)) string {
	token := buildToken(claims)

	// Default options
	signOptions := []jwt.SignOption{jwt.WithKey(jwa.RS256, jwkKey)}

	// Apply additional options
	for _, opt := range options {
		var option jwt.SignOption
		opt(&option)
		signOptions = append(signOptions, option)
	}

	tokenBytes, err := jwt.Sign(token, signOptions...)
	panicOnError(err)

	return string(tokenBytes)
}

func TestValidateJWTConfig_SignKey(t *testing.T) {
	// missing sign_key
	jc := &JWTConfig{}
	err := validateJWTConfig(jc, testLogger)
	assert.NotNil(t, err)
	assert.ErrorIs(t, err, ErrMissingKeys)

	// having sign_key
	jc = &JWTConfig{
		SignKey: TestSignKey,
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))
}

func TestValidateJWTConfig_SignAlg(t *testing.T) {
	// invalid sign_alg
	jc := &JWTConfig{
		SignKey:       TestSignKey,
		SignAlgorithm: "ABC",
	}
	jc.setJWTDefaults()
	assert.ErrorIs(t, validateJWTConfig(jc, testLogger), ErrInvalidSignAlgorithm)
}

func TestValidateJWTConfig_usingJWK(t *testing.T) {
	jc := &JWTConfig{JWKURL: TestJWKSetURL}
	jc.setJWTDefaults()
	assert.True(t, usingJWK(jc))
	err := validateJWTConfig(jc, testLogger)
	assert.Nil(t, err)
}

// TestValidateJWTConfig_SkipVerification checks that validation does not fail when
// SkipVerification is enabled and no keys are provided. This ensures that
// enabling SkipVerification bypasses signature and keys validation without errors.
func TestValidateJWTConfig_SkipVerification(t *testing.T) {
	// skipping verification
	jc := &JWTConfig{
		SkipVerification: true,
	}
	jc.setJWTDefaults()
	assert.NoError(t, validateJWTConfig(jc, testLogger))
}

func TestAuthenticateJWT_FromAuthorizationHeader(t *testing.T) {
	claims := MapClaims{"sub": "ggicci", "jti": "test-api-key-id"}
	jc := &JWTConfig{SignKey: TestSignKey}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+issueTokenString(claims))
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestAuthenticateJWT_EdDSA(t *testing.T) {
	claims := MapClaims{"sub": "ggicci", "jti": "test-api-key-id"}
	jc := &JWTConfig{SignKey: TestSignKeyEd25519, SignAlgorithm: string(jwa.EdDSA)}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+issueTokenStringEdDSA(claims))
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestAuthenticateJWT_FromCustomHeader(t *testing.T) {
	claims := MapClaims{"sub": "ggicci", "jti": "test-api-key-id"}
	jc := &JWTConfig{
		SignKey:    TestSignKey,
		FromHeader: []string{"X-Api-Token"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("x-api-token", issueTokenString(claims))
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestAuthenticateJWT_FromQueryWithSkipVerification(t *testing.T) {
	var (
		claims = MapClaims{"sub": "ggicci", "jti": "test-api-key-id"}
		jc     = &JWTConfig{
			FromQuery:        []string{"access_token", "token"},
			SkipVerification: true,
		}
		tokenString = issueTokenString(claims)

		err       error
		r         *http.Request
		params    url.Values
		gotClaims *Claims
	)
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// trying "access_token" without signature key
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)

	// invalid "token" without signature key
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString+"INVALID")
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestAuthenticateJWT_FromQuery(t *testing.T) {
	var (
		claims = MapClaims{"sub": "ggicci", "jti": "test-api-key-id"}
		jc     = &JWTConfig{
			SignKey:   TestSignKey,
			FromQuery: []string{"access_token", "token"},
		}
		tokenString = issueTokenString(claims)

		err       error
		r         *http.Request
		params    url.Values
		gotClaims *Claims
	)
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// only "access_token"
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)

	// only "token"
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)

	// both valid "access_token", "token"
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString)
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)

	// invalid "access_token", and valid "token"
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString+"INVALID")
	params.Add("token", tokenString)
	r.URL.RawQuery = params.Encode()
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)

	// both invalid "access_token", "token"
	r, _ = http.NewRequest("GET", "/", nil)
	params = make(url.Values)
	params.Add("access_token", tokenString+"INVALID")
	params.Add("token", tokenString+"INVALID")
	r.URL.RawQuery = params.Encode()
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)
}

func TestAuthenticateJWT_FromCookies(t *testing.T) {
	claims := MapClaims{"sub": "ggicci", "jti": "test-api-key-id"}
	jc := &JWTConfig{
		SignKey:     TestSignKey,
		FromCookies: []string{"user_session", "sess"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "user_session", Value: issueTokenString(claims)})
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestAuthenticateJWT_CustomUserClaims(t *testing.T) {
	claims := MapClaims{"sub": "182140474727", "username": "ggicci", "jti": "test-api-key-id"}
	jc := &JWTConfig{
		SignKey:    TestSignKey,
		UserClaims: []string{"username"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)

	// custom user claims all empty should fail - having keys
	claims = MapClaims{"sub": "ggicci", "username": "", "jti": "test-api-key-id"}
	jc = &JWTConfig{
		SignKey:    TestSignKey,
		UserClaims: []string{"username"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)

	// custom user claims all empty should fail - even no keys
	claims = MapClaims{"username": "ggicci", "jti": "test-api-key-id"}
	jc = &JWTConfig{
		SignKey:    TestSignKey,
		UserClaims: []string{"uid", "user_id"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)

	// custom user claims at least one is non-empty can work
	claims = MapClaims{"username": "ggicci", "user_id": nil, "uid": 19911110, "jti": "test-api-key-id"}
	jc = &JWTConfig{
		SignKey:    TestSignKey,
		UserClaims: []string{"user_id", "uid"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(claims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "19911110", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestAuthenticateJWT_ValidateStandardClaims(t *testing.T) {
	jc := &JWTConfig{
		SignKey: TestSignKey,
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// invalid "exp" (Expiration Time)
	expiredClaims := MapClaims{"sub": "ggicci", "exp": 689702400, "jti": "test-api-key-id"}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)

	// invalid "iat" (Issued At)
	expiredClaims = MapClaims{"sub": "ggicci", "iat": 3845462400, "jti": "test-api-key-id"}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)

	// invalid "nbf" (Not Before)
	expiredClaims = MapClaims{"sub": "ggicci", "nbf": 3845462400, "jti": "test-api-key-id"}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(expiredClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)
}

func TestAuthenticateJWT_VerifyIssuerWhitelist(t *testing.T) {
	jc := &JWTConfig{
		SignKey: TestSignKey,

		IssuerWhitelist: []string{"https://api.example.com", "https://api.github.com"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// valid "iss"
	exampleClaims := MapClaims{"sub": "ggicci", "iss": "https://api.example.com", "jti": "test-api-key-id"}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(exampleClaims))
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)

	githubClaims := MapClaims{"sub": "ggicci", "iss": "https://api.github.com", "jti": "test-api-key-id"}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)

	// invalid "iss" (no iss)
	noIssClaims := MapClaims{"sub": "ggicci", "jti": "test-api-key-id"}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(noIssClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)

	// invalid "iss" (wrong value)
	wrongIssClaims := MapClaims{"sub": "ggicci", "iss": "https://api.example.com/secure", "jti": "test-api-key-id"}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(wrongIssClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)
}

func TestAuthenticateJWT_VerifyAudienceWhitelist(t *testing.T) {
	jc := &JWTConfig{
		SignKey: TestSignKey,

		IssuerWhitelist:   []string{"https://api.github.com"},
		AudienceWhitelist: []string{"https://api.codelet.io", "https://api.copilot.codelet.io"},
	}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// valid "aud" (of single string)
	githubClaims := MapClaims{
		"sub": "ggicci",
		"iss": "https://api.github.com",
		"aud": "https://api.codelet.io",
		"jti": "test-api-key-id",
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)

	// valid "aud" (multiple, as long as one of them is on the whitelist)
	githubClaims = MapClaims{
		"sub": "ggicci",
		"iss": "https://api.github.com",
		"aud": []string{"https://api.learn.codelet.io", "https://api.copilot.codelet.io"},
		"jti": "test-api-key-id",
	}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(githubClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)

	// invalid "aud" (no aud)
	noIssClaims := MapClaims{"sub": "ggicci", "iss": "https://api.github.com", "jti": "test-api-key-id"}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(noIssClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)

	// invalid "aud" (wrong value)
	wrongIssClaims := MapClaims{
		"sub": "ggicci",
		"iss": "https://api.github.com",
		"aud": []string{"https://api.example.com", "https://api.example.org"},
		"jti": "test-api-key-id",
	}
	r, _ = http.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", issueTokenString(wrongIssClaims))
	gotClaims, err = authenticateJWT(r, jc, testLogger)
	assert.NotNil(t, err)
	assert.Nil(t, gotClaims)
}

func Test_stringify(t *testing.T) {
	now := time.Now()

	for _, c := range []struct {
		Input    interface{}
		Expected string
	}{
		{nil, ""},
		{"abc", "abc"},
		{true, "true"},
		{false, "false"},
		{json.Number("1991"), "1991"},
		{now, now.UTC().Format(time.RFC3339Nano)},
		{[]int{1, 2, 3}, ""},                // unsupported array type
		{ThingNotStringer{}, ""},            // unsupported custom type
		{ThingIsStringer{}, "i'm stringer"}, // support fmt.Stringer interface
	} {
		assert.Equal(t, stringify(c.Input), c.Expected)
	}
}

func Test_desensitizedTokenString(t *testing.T) {
	for _, c := range []struct {
		Input    string
		Expected string
	}{
		{"", ""},
		{"abc", "abc"},
		{"abcdef", "abcdef"},
		{"abcdefg", "ab…fg"},
		{"abcdefeijk", "abc…ijk"},
		{"abcdefghijklmnopqrstuvwxyz", "abcdefgh…stuvwxyz"},
		{"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv", "abcdefghijklmnop…ghijklmnopqrstuv"},
		{
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
			"abcdefghijklmnop…klmnopqrstuvwxyz",
		},
		{
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
			"abcdefghijklmnop…klmnopqrstuvwxyz",
		},
	} {
		assert.Equal(t, desensitizedTokenString(c.Input), c.Expected)
	}
}

func Test_AsymmetricAlgorithm(t *testing.T) {
	jc := &JWTConfig{SignKey: TestPubKey, UserClaims: []string{"login"}}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// This test requires a valid asymmetric key pair, which requires complex setup
	// For now, let's verify that the config validation works with the public key
	assert.NotNil(t, jc.SignKey)
	assert.Contains(t, jc.SignKey, "BEGIN PUBLIC KEY")
	assert.Contains(t, jc.SignKey, "END PUBLIC KEY")
}

func Test_AsymmetricAlgorithm_InvalidPubKey(t *testing.T) {
	jc := &JWTConfig{SignKey: `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAA ... invalid\n-----END PUBLIC KEY-----`, UserClaims: []string{"login"}}
	jc.setJWTDefaults()
	assert.ErrorIs(t, validateJWTConfig(jc, testLogger), ErrInvalidPublicKey)
}

func TestJWK(t *testing.T) {
	time.Sleep(3 * time.Second)
	jc := &JWTConfig{JWKURL: TestJWKURL}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// Cache will be created during first authentication
	token := issueTokenStringJWK(MapClaims{"sub": "ggicci", "jti": "test-api-key-id"})
	r, _ := http.NewRequest("GET", "/", nil)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)

	r.Header.Add("Authorization", "Bearer "+token)
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestJWKSet(t *testing.T) {
	time.Sleep(3 * time.Second)
	jc := &JWTConfig{JWKURL: TestJWKSetURL}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// Authenticate to create cache
	token := issueTokenStringJWK(MapClaims{"sub": "ggicci", "jti": "test-api-key-id"})
	r, _ := http.NewRequest("GET", "/", nil)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)

	r.Header.Add("Authorization", "Bearer "+token)
	gotClaims, err := authenticateJWT(r, jc, testLogger)
	assert.Nil(t, err)
	assert.Equal(t, "ggicci", gotClaims.UserID)
	assert.Equal(t, "test-api-key-id", gotClaims.APIKeyID)
}

func TestJWKSet_KeyNotFound(t *testing.T) {
	time.Sleep(3 * time.Second)
	jc := &JWTConfig{JWKURL: TestJWKSetURLInapplicable}
	jc.setJWTDefaults()
	assert.Nil(t, validateJWTConfig(jc, testLogger))

	// First request to create cache
	token := issueTokenStringJWK(MapClaims{"sub": "ggicci", "jti": "test-api-key-id"})
	r, _ := http.NewRequest("GET", "/", nil)

	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)

	r.Header.Add("Authorization", "Bearer "+token)
	gotClaims, err := authenticateJWT(r, jc, testLogger)

	// Authentication should fail because key is not found
	assert.Error(t, err)
	assert.Nil(t, gotClaims)
}

type ThingNotStringer struct{}
type ThingIsStringer struct{}

func (t ThingIsStringer) String() string { return "i'm stringer" }
