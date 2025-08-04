package jwtblacklist

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// Claims represents the JWT claims we're interested in
type Claims struct {
	UserID   string `json:"sub"`
	APIKeyID string `json:"jti"` // This is the API key ID we check against blacklist
	Tier     string `json:"tier"`
	Scope    string `json:"scope"`
	jwt.RegisteredClaims
}

// extractToken extracts JWT token from request using multiple sources
// Priority order: Authorization header, X-API-Key, X-Api-Token, query params, cookies
func extractToken(r *http.Request) string {
	// 1. Check Authorization header (Bearer token)
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.Split(auth, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// 2. Check X-API-Key header
	if token := r.Header.Get("X-API-Key"); token != "" {
		return token
	}

	// 3. Check X-Api-Token header
	if token := r.Header.Get("X-Api-Token"); token != "" {
		return token
	}

	// 4. Check query parameters
	if token := r.URL.Query().Get("api_key"); token != "" {
		return token
	}
	if token := r.URL.Query().Get("access_token"); token != "" {
		return token
	}
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	// 5. Check cookies
	if cookie, err := r.Cookie("session_token"); err == nil {
		return cookie.Value
	}

	return ""
}

// parseJWT parses and validates a JWT token
func parseJWT(tokenString, secret string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	if secret == "" {
		return nil, errors.New("JWT secret not configured")
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Validate required claims
	if claims.APIKeyID == "" {
		return nil, errors.New("missing jti (API key ID) claim")
	}

	return claims, nil
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
