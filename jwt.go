package jwtblacklist

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

// JWT error constants
var (
	ErrMissingKeys          = errors.New("missing sign_key and jwk_url")
	ErrInvalidPublicKey     = errors.New("invalid PEM-formatted public key")
	ErrInvalidSignAlgorithm = errors.New("invalid sign_alg")
	ErrInvalidIssuer        = errors.New("invalid issuer")
	ErrInvalidAudience      = errors.New("invalid audience")
	ErrEmptyUserClaim       = errors.New("user claim is empty")
)

// Claims represents the JWT claims we're interested in
type Claims struct {
	UserID   string `json:"sub"`
	APIKeyID string `json:"jti"` // This is the API key ID we check against blacklist
	Tier     string `json:"tier"`
	Scope    string `json:"scope"`
}

// Token represents a JWT token
type Token = jwt.Token

// jwkCacheEntry stores the JWK cache information for a specific URL
type jwkCacheEntry struct {
	URL       string
	Cache     *jwk.Cache
	CachedSet jwk.Set
}

// refresh refreshes the JWK cache for this entry
func (entry *jwkCacheEntry) refresh(ctx context.Context, logger *zap.Logger) error {
	_, err := entry.Cache.Refresh(ctx, entry.URL)
	if err != nil {
		logger.Warn("failed to refresh JWK cache", zap.Error(err), zap.String("url", entry.URL))
		return err
	}
	return nil
}

// JWTConfig holds the JWT authentication configuration
type JWTConfig struct {
	// SignKey is the key used by the signing algorithm to verify the signature
	SignKey string `json:"sign_key"`

	// JWKURL is the URL where a provider publishes their JWKs
	JWKURL string `json:"jwk_url"`

	// SignAlgorithm is the signing algorithm used
	SignAlgorithm string `json:"sign_alg"`

	// SkipVerification disables the verification of the JWT token signature
	SkipVerification bool `json:"skip_verification"`

	// FromQuery defines a list of names to get tokens from query parameters
	FromQuery []string `json:"from_query"`

	// FromHeader defines a list of names to get tokens from HTTP headers
	FromHeader []string `json:"from_header"`

	// FromCookies defines a list of names to get tokens from HTTP cookies
	FromCookies []string `json:"from_cookies"`

	// IssuerWhitelist defines a list of allowed issuers
	IssuerWhitelist []string `json:"issuer_whitelist"`

	// AudienceWhitelist defines a list of allowed audiences
	AudienceWhitelist []string `json:"audience_whitelist"`

	// UserClaims defines a list of names to find the ID of the authenticated user
	UserClaims []string `json:"user_claims"`

	// MetaClaims defines a map to populate user metadata placeholders
	MetaClaims map[string]string `json:"meta_claims"`

	// Internal fields for JWT processing
	parsedSignKey interface{}
	jwkCaches     map[string]*jwkCacheEntry
	mutex         sync.RWMutex
}

// setJWTDefaults sets default values for JWT configuration
func (jc *JWTConfig) setJWTDefaults() {
	if jc.SignAlgorithm == "" {
		jc.SignAlgorithm = "HS256"
	}
	if len(jc.FromQuery) == 0 {
		jc.FromQuery = []string{"api_key", "access_token", "token"}
	}
	if len(jc.FromHeader) == 0 {
		jc.FromHeader = []string{"Authorization", "X-API-Key", "X-Api-Token"}
	}
	if len(jc.FromCookies) == 0 {
		jc.FromCookies = []string{"session_token"}
	}
	if len(jc.UserClaims) == 0 {
		jc.UserClaims = []string{"sub"}
	}
}

// extractTokens extracts JWT tokens from request using multiple sources
func extractTokens(r *http.Request, fromQuery, fromHeader, fromCookies []string) []string {
	var candidates []string

	// Priority: from_query > from_header > from_cookies
	candidates = append(candidates, getTokensFromQuery(r, fromQuery)...)
	candidates = append(candidates, getTokensFromHeader(r, fromHeader)...)
	candidates = append(candidates, getTokensFromCookies(r, fromCookies)...)

	return candidates
}

func getTokensFromQuery(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	query := r.URL.Query()
	for _, key := range names {
		token := query.Get(key)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func getTokensFromHeader(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	for _, key := range names {
		token := r.Header.Get(key)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func getTokensFromCookies(r *http.Request, names []string) []string {
	tokens := make([]string, 0)
	for _, key := range names {
		if ck, err := r.Cookie(key); err == nil && ck.Value != "" {
			tokens = append(tokens, ck.Value)
		}
	}
	return tokens
}

// normToken normalizes a token by removing Bearer prefix and trimming whitespace
func normToken(token string) string {
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = token[len("bearer "):]
	}
	return strings.TrimSpace(token)
}

// validateJWTConfig validates the JWT configuration
func validateJWTConfig(jc *JWTConfig, logger *zap.Logger) error {
	if !jc.SkipVerification {
		if err := validateSignatureKeys(jc, logger); err != nil {
			return err
		}
	}

	for claim, placeholder := range jc.MetaClaims {
		if claim == "" || placeholder == "" {
			return fmt.Errorf("invalid meta claim: %s -> %s", claim, placeholder)
		}
	}
	return nil
}

func validateSignatureKeys(jc *JWTConfig, logger *zap.Logger) error {
	if usingJWK(jc) {
		setupJWKLoader(jc, logger)
	} else {
		if keyBytes, asymmetric, err := parseSignKey(jc.SignKey); err != nil {
			return fmt.Errorf("invalid sign_key: %w", err)
		} else {
			if !asymmetric {
				jc.parsedSignKey = keyBytes
			} else if jc.parsedSignKey, err = x509.ParsePKIXPublicKey(keyBytes); err != nil {
				return fmt.Errorf("invalid sign_key (asymmetric): %w", err)
			}

			if jc.SignAlgorithm != "" {
				var alg jwa.SignatureAlgorithm
				if err := alg.Accept(jc.SignAlgorithm); err != nil {
					return fmt.Errorf("%w: %v", ErrInvalidSignAlgorithm, err)
				}
			}
		}
	}
	return nil
}

func usingJWK(jc *JWTConfig) bool {
	return jc.SignKey == "" && jc.JWKURL != ""
}

func setupJWKLoader(jc *JWTConfig, logger *zap.Logger) {
	jc.mutex.Lock()
	jc.jwkCaches = make(map[string]*jwkCacheEntry)
	jc.mutex.Unlock()
	logger.Info("JWK cache initialized for JWK URL", zap.String("jwk_url", jc.JWKURL))
}

// parseSignKey parses the given key and returns the key bytes
func parseSignKey(signKey string) (keyBytes []byte, asymmetric bool, err error) {
	repl := caddy.NewReplacer()
	resolvedSignKey := repl.ReplaceAll(signKey, "")
	if len(resolvedSignKey) == 0 {
		return nil, false, ErrMissingKeys
	}
	if strings.Contains(resolvedSignKey, "-----BEGIN PUBLIC KEY-----") {
		keyBytes, err = parsePEMFormattedPublicKey(resolvedSignKey)
		return keyBytes, true, err
	}
	keyBytes, err = base64.StdEncoding.DecodeString(resolvedSignKey)
	return keyBytes, false, err
}

func parsePEMFormattedPublicKey(pubKey string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubKey))
	if block != nil && block.Type == "PUBLIC KEY" {
		return block.Bytes, nil
	}
	return nil, ErrInvalidPublicKey
}

// authenticateJWT performs comprehensive JWT authentication
func authenticateJWT(r *http.Request, jc *JWTConfig, logger *zap.Logger) (*Claims, error) {
	var (
		gotToken   Token
		candidates []string
		err        error
	)

	// Extract tokens from multiple sources
	candidates = extractTokens(r, jc.FromQuery, jc.FromHeader, jc.FromCookies)
	if len(candidates) == 0 {
		return nil, errors.New("no JWT token found in request")
	}

	checked := make(map[string]struct{})

	for _, candidateToken := range candidates {
		tokenString := normToken(candidateToken)
		if _, ok := checked[tokenString]; ok {
			continue
		}

		jwtOptions := []jwt.ParseOption{
			jwt.WithVerify(!jc.SkipVerification),
		}
		if !jc.SkipVerification {
			jwtOptions = append(jwtOptions, jwt.WithKeyProvider(keyProvider(jc, r, logger)))
		}
		gotToken, err = jwt.ParseString(tokenString, jwtOptions...)

		checked[tokenString] = struct{}{}

		logContext := logger.With(zap.String("token_string", desensitizedTokenString(tokenString)))
		if err != nil {
			logContext.Debug("invalid token", zap.Error(err))
			continue
		}

		// Validate issuer whitelist
		if len(jc.IssuerWhitelist) > 0 {
			isValidIssuer := false
			for _, issuer := range jc.IssuerWhitelist {
				if jwt.Validate(gotToken, jwt.WithIssuer(issuer)) == nil {
					isValidIssuer = true
					break
				}
			}
			if !isValidIssuer {
				err = ErrInvalidIssuer
				logContext.Debug("invalid issuer", zap.Error(err))
				continue
			}
		}

		// Validate audience whitelist
		if len(jc.AudienceWhitelist) > 0 {
			isValidAudience := false
			for _, audience := range jc.AudienceWhitelist {
				if jwt.Validate(gotToken, jwt.WithAudience(audience)) == nil {
					isValidAudience = true
					break
				}
			}
			if !isValidAudience {
				err = ErrInvalidAudience
				logContext.Debug("invalid audience", zap.Error(err))
				continue
			}
		}

		// Extract user ID from claims
		claimName, gotUserID := getUserID(gotToken, jc.UserClaims)
		if gotUserID == "" {
			err = ErrEmptyUserClaim
			logContext.Debug("empty user claim", zap.Strings("user_claims", jc.UserClaims), zap.Error(err))
			continue
		}

		// Extract our specific claims
		claims := &Claims{
			UserID: gotUserID,
		}

		// Extract jti (API key ID)
		if jti, ok := gotToken.Get("jti"); ok {
			if jtiStr, ok := jti.(string); ok {
				claims.APIKeyID = jtiStr
			}
		}
		if claims.APIKeyID == "" {
			err = errors.New("missing jti (API key ID) claim")
			logContext.Debug("missing jti claim", zap.Error(err))
			continue
		}

		// Extract tier and scope
		if tier, ok := gotToken.Get("tier"); ok {
			if tierStr, ok := tier.(string); ok {
				claims.Tier = tierStr
			}
		}
		if scope, ok := gotToken.Get("scope"); ok {
			if scopeStr, ok := scope.(string); ok {
				claims.Scope = scopeStr
			}
		}

		logger.Info("JWT authentication successful",
			zap.String("user_claim", claimName),
			zap.String("user_id", gotUserID),
			zap.String("api_key_id", claims.APIKeyID),
			zap.String("tier", claims.Tier),
			zap.String("scope", claims.Scope))

		return claims, nil
	}

	return nil, err
}

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (most common)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}
	return ip
}

// keyProvider creates a JWT key provider function
func keyProvider(jc *JWTConfig, request *http.Request, logger *zap.Logger) jws.KeyProviderFunc {
	return func(curContext context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
		if usingJWK(jc) {
			resolvedURL := resolveJWKURL(jc.JWKURL, request)
			logger.Debug("JWK URL", zap.String("unresolved", jc.JWKURL), zap.String("resolved", resolvedURL))

			// Get or create the cache for this URL
			cacheEntry, err := getOrCreateJWKCache(jc, resolvedURL, logger)
			if err != nil {
				return fmt.Errorf("failed to get JWK cache: %w", err)
			}

			// Use the key set associated with this URL
			kid := sig.ProtectedHeaders().KeyID()
			key, found := cacheEntry.CachedSet.LookupKeyID(kid)
			if !found {
				// Trigger an asynchronous refresh if the key is not found
				go cacheEntry.refresh(context.Background(), logger)

				if kid == "" {
					return fmt.Errorf("missing kid in JWT header")
				}
				return fmt.Errorf("key specified by kid %q not found in JWKs from %s", kid, resolvedURL)
			}
			sink.Key(determineSigningAlgorithm(jc, key.Algorithm(), sig.ProtectedHeaders().Algorithm()), key)
		} else if jc.SignAlgorithm == string(jwa.EdDSA) {
			if signKey, ok := jc.parsedSignKey.([]byte); !ok {
				return fmt.Errorf("EdDSA key must be base64 encoded bytes")
			} else if len(signKey) != ed25519.PublicKeySize {
				return fmt.Errorf("key is not a proper ed25519 length")
			} else {
				sink.Key(jwa.EdDSA, ed25519.PublicKey(signKey))
			}
		} else {
			sink.Key(determineSigningAlgorithm(jc, sig.ProtectedHeaders().Algorithm()), jc.parsedSignKey)
		}
		return nil
	}
}

func resolveJWKURL(jwkURL string, request *http.Request) string {
	replacer := request.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	return replacer.ReplaceAll(jwkURL, "")
}

func getOrCreateJWKCache(jc *JWTConfig, resolvedURL string, logger *zap.Logger) (*jwkCacheEntry, error) {
	if resolvedURL == "" {
		return nil, fmt.Errorf("resolved JWK URL is empty")
	}

	jc.mutex.RLock()
	entry, ok := jc.jwkCaches[resolvedURL]
	jc.mutex.RUnlock()

	if ok {
		return entry, nil
	}

	jc.mutex.Lock()
	defer jc.mutex.Unlock()

	if entry, ok := jc.jwkCaches[resolvedURL]; ok {
		return entry, nil
	}

	cache := jwk.NewCache(context.Background())
	err := cache.Register(resolvedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to register JWK URL: %w", err)
	}

	entry = &jwkCacheEntry{
		URL:       resolvedURL,
		Cache:     cache,
		CachedSet: jwk.NewCachedSet(cache, resolvedURL),
	}

	err = entry.refresh(context.Background(), logger)
	if err != nil {
		logger.Warn("failed to refresh JWK cache during initialization", zap.Error(err), zap.String("url", resolvedURL))
	}

	jc.jwkCaches[resolvedURL] = entry
	logger.Info("new JWK cache created", zap.String("url", resolvedURL), zap.Int("loaded_keys", entry.CachedSet.Len()))

	return entry, nil
}

func determineSigningAlgorithm(jc *JWTConfig, alg ...jwa.KeyAlgorithm) jwa.SignatureAlgorithm {
	for _, a := range alg {
		if a.String() != "" {
			return jwa.SignatureAlgorithm(a.String())
		}
	}
	return jwa.SignatureAlgorithm(jc.SignAlgorithm)
}

func getUserID(token Token, names []string) (string, string) {
	for _, name := range names {
		if userClaim, ok := token.Get(name); ok {
			switch val := userClaim.(type) {
			case string:
				return name, val
			case float64:
				return name, strconv.FormatFloat(val, 'f', -1, 64)
			}
		}
	}
	return "", ""
}

func getUserMetadata(token Token, placeholdersMap map[string]string) map[string]string {
	if len(placeholdersMap) == 0 {
		return nil
	}

	claims, _ := token.AsMap(context.Background())
	metadata := make(map[string]string)
	for claim, placeholder := range placeholdersMap {
		claimValue, ok := token.Get(claim)

		if !ok && strings.Contains(claim, ".") {
			claimValue, ok = queryNested(claims, strings.Split(claim, "."))
		}
		if !ok {
			metadata[placeholder] = ""
			continue
		}
		metadata[placeholder] = stringify(claimValue)
	}

	return metadata
}

func queryNested(claims map[string]interface{}, path []string) (interface{}, bool) {
	var (
		object = claims
		ok     bool
	)
	for i := 0; i < len(path)-1; i++ {
		if object, ok = object[path[i]].(map[string]interface{}); !ok || object == nil {
			return nil, false
		}
	}

	lastKey := path[len(path)-1]
	return object[lastKey], true
}

func stringify(val interface{}) string {
	if val == nil {
		return ""
	}

	switch uv := val.(type) {
	case string:
		return uv
	case bool:
		return strconv.FormatBool(uv)
	case json.Number:
		return uv.String()
	case time.Time:
		return uv.UTC().Format(time.RFC3339Nano)
	}

	if stringer, ok := val.(fmt.Stringer); ok {
		return stringer.String()
	}

	if slice, ok := val.([]interface{}); ok {
		return stringifySlice(slice)
	}

	return ""
}

func stringifySlice(slice []interface{}) string {
	var result []string
	for _, val := range slice {
		result = append(result, stringify(val))
	}
	return strings.Join(result, ",")
}

func desensitizedTokenString(token string) string {
	if len(token) <= 6 {
		return token
	}
	mask := len(token) / 3
	if mask > 16 {
		mask = 16
	}
	return token[:mask] + "…" + token[len(token)-mask:]
}
