package jwtblacklist

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(JWTBlacklist{})
	httpcaddyfile.RegisterHandlerDirective("jwt_blacklist", parseCaddyfile)
	// Register default ordering - jwt_blacklist handles both authentication and blacklist checking
	// Place it early in the middleware chain to ensure authentication happens before other handlers
	// We use "rewrite" as anchor since it's reliably early in the middleware chain
	httpcaddyfile.RegisterDirectiveOrder("jwt_blacklist", httpcaddyfile.After, "rewrite")
}

// Interface guards
var (
	_ caddy.Provisioner           = (*JWTBlacklist)(nil)
	_ caddy.Validator             = (*JWTBlacklist)(nil)
	_ caddyhttp.MiddlewareHandler = (*JWTBlacklist)(nil)
	_ caddyfile.Unmarshaler       = (*JWTBlacklist)(nil)
)
