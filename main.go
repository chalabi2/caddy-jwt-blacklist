package jwtblacklist

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(JWTBlacklist{})
	httpcaddyfile.RegisterHandlerDirective("stateful_jwt", parseCaddyfile)
	// Register default ordering - stateful_jwt handles both authentication and token state management
	// Place it early in the middleware chain to ensure authentication happens before other handlers
	// We use "rewrite" as anchor since it's reliably early in the middleware chain
	httpcaddyfile.RegisterDirectiveOrder("stateful_jwt", httpcaddyfile.After, "rewrite")
}

// Interface guards
var (
	_ caddy.Provisioner           = (*JWTBlacklist)(nil)
	_ caddy.Validator             = (*JWTBlacklist)(nil)
	_ caddyhttp.MiddlewareHandler = (*JWTBlacklist)(nil)
	_ caddyfile.Unmarshaler       = (*JWTBlacklist)(nil)
)
