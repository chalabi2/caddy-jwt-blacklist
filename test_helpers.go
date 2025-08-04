package jwtblacklist

import (
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// testHandler wraps a standard http.Handler to implement caddyhttp.Handler
type testHandler struct {
	handler http.Handler
}

func (th testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	th.handler.ServeHTTP(w, r)
	return nil
}

// wrapHandler wraps a standard http.Handler to work with Caddy tests
func wrapHandler(h http.Handler) caddyhttp.Handler {
	return testHandler{handler: h}
}
