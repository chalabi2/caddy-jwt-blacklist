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
	// Register default ordering - jwt_blacklist should run early in the chain
	httpcaddyfile.RegisterDirectiveOrder("jwt_blacklist", httpcaddyfile.Before, "header")
}

// Interface guards
var (
	_ caddy.Provisioner           = (*JWTBlacklist)(nil)
	_ caddy.Validator             = (*JWTBlacklist)(nil)
	_ caddyhttp.MiddlewareHandler = (*JWTBlacklist)(nil)
	_ caddyfile.Unmarshaler       = (*JWTBlacklist)(nil)
)
