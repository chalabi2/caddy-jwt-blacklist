# Stateful JWT Auth

[![codecov](https://codecov.io/gh/chalabi2/caddy-stateful-jwt-auth/graph/badge.svg?token=LSORQKOL2R)](https://codecov.io/gh/chalabi2/caddy-stateful-jwt-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/chalabi2/caddy-stateful-jwt-auth)](https://goreportcard.com/report/github.com/chalabi2/caddy-stateful-jwt-auth)
[![Go Reference](https://pkg.go.dev/badge/github.com/chalabi2/caddy-stateful-jwt-auth.svg)](https://pkg.go.dev/github.com/chalabi2/caddy-stateful-jwt-auth)

A comprehensive **stateful JWT authentication middleware** for Caddy that provides immediate token revocation capabilities using Redis. This plugin transforms traditional stateless JWT into a stateful system, enabling real-time token invalidation while maintaining JWT's distributed benefits.

> [!NOTE]
> This plugin integrates JWT authentication functionality from [ggicci/caddy-jwt](https://github.com/ggicci/caddy-jwt) with Redis-based state management, providing a stateful JWT solution that enables immediate token revocation while eliminating the need for separate JWT auth plugins.

> [!NOTE]  
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

## Features

### 🔐 **Integrated JWT Authentication**

- **Full JWT validation** - Signature verification, expiration, issuer/audience validation
- **Multiple signing algorithms** - HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, EdDSA
- **JWK support** - Fetch public keys from JWK URLs with caching and refresh
- **Flexible token extraction** - Authorization header, custom headers, query parameters, cookies
- **Custom claims mapping** - Extract user metadata from JWT claims
- **Skip verification mode** - For development and testing

### 🚫 **Redis-Based Token State Management**

- **Immediate token revocation** - O(1) Redis lookups for invalidated tokens
- **State-first architecture** - Check token state before expensive JWT validation
- **TTL support** - Automatic expiration of revoked token entries
- **Detailed revocation metadata** - Store revocation reason and context

### 🛡️ **Production-Ready Features**

- **Fail-open/fail-closed** - Configurable behavior when Redis is unavailable
- **Low latency** - Optimized request processing (~0.1-0.5ms overhead)
- **Comprehensive logging** - Detailed request and error logging
- **Graceful error handling** - Specific error responses for different failure modes
- **User context population** - Set Caddy placeholders for downstream handlers

## Installation

Build Caddy with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/chalabi2/caddy-stateful-jwt-auth
```

> **Migration Note:** This repository was renamed from `caddy-jwt-blacklist` to `caddy-stateful-jwt-auth` and the directive was changed from `jwt_blacklist` to `stateful_jwt` to better reflect its functionality as a stateful JWT authentication system.

Or add to your `xcaddy.json`:

```json
{
  "dependencies": [
    {
      "module": "github.com/chalabi2/caddy-stateful-jwt-auth",
      "version": "latest"
    }
  ]
}
```

## Quick Start

Basic Caddyfile configuration:

```caddy
{
    admin localhost:2019
}

localhost:8080 {
    stateful_jwt {
        # Redis configuration
        redis_addr {env.REDIS_URL}
        redis_password {env.REDIS_PASSWORD}
        redis_db 0
        blacklist_prefix "BLACKLIST:key:"

        # JWT authentication
        sign_key {env.JWT_SECRET}
        sign_alg HS256
        from_header Authorization X-API-Key
        from_query api_key access_token
        user_claims sub
        meta_claims "tier" "scope"

        # Optional settings
        timeout 50ms
        fail_open true
        log_blocked true
    }

    respond "Hello {http.auth.user.id}! Your tier: {http.auth.user.tier}"
}
```

## Configuration

> **Note:** Complete example configurations are available in the [`example-configs/`](example-configs/) directory.

### Configuration Patterns

The plugin supports three main usage patterns:

#### 1. **Full Stateful JWT Auth** (Recommended for critical APIs)

```caddy
stateful_jwt {
    # Redis configuration for token state management
    redis_addr {env.REDIS_URL}
    redis_password {env.REDIS_PASSWORD}
    redis_db 0
    blacklist_prefix "BLACKLIST:key:"
    fail_open true
    timeout 500ms
    log_blocked true

    # TLS configuration for Redis (if using TLS like Upstash)
    tls {
        enabled true
        server_name {env.REDIS_TLS_SERVER_NAME}
        min_version "1.2"
    }

    # JWT authentication configuration
    sign_key {env.JWT_SECRET}
    sign_alg HS256
    from_query api_key access_token token
    from_header Authorization X-Api-Token X-API-Key
    from_cookies session_token
    user_claims sub jti uid user_id
    meta_claims "tier" "scope"
}
```

#### 2. **JWT-Only** (Authentication without state management)

```caddy
stateful_jwt {
    # JWT authentication configuration
    sign_key {env.JWT_SECRET}
    sign_alg HS256
    from_query api_key access_token token
    from_header Authorization X-Api-Token X-API-Key
    from_cookies session_token
    user_claims sub jti uid user_id
    meta_claims "tier" "scope"

    # Disable Redis (stateless JWT mode)
    redis_addr "disabled"
    fail_open true
    timeout 100ms
}
```

#### 3. **Advanced Configuration with JWK Support**

```caddy
stateful_jwt {
    # Redis with TLS
    redis_addr {env.REDIS_URL}
    redis_password {env.REDIS_PASSWORD}
    redis_db 0
    tls {
        enabled true
        server_name {env.REDIS_TLS_SERVER_NAME}
        min_version "1.2"
    }

    # JWK for asymmetric keys
    jwk_url https://auth.example.com/.well-known/jwks.json
    sign_alg RS256

    # Validation rules
    issuer_whitelist https://auth.example.com
    audience_whitelist https://api.example.com

    # Custom token sources
    from_header Authorization X-Custom-Token
    from_query access_token

    # Advanced claims mapping
    user_claims sub email username
    meta_claims "role->user_role" "permissions->access_permissions"
}
```

### ⚠️ **Important: Token State Behavior**

**Pattern 1 (Full Stateful JWT)**: ✅ **Enforces token state** - Tokens are checked against Redis state before authentication.

**Pattern 2 (JWT-Only)**: ❌ **No state management** - Only JWT authentication is performed. Use `redis_addr "disabled"` and `fail_open true` to skip Redis operations.

**Pattern 3 (Advanced)**: ✅ **Enforces token state** - Same as Pattern 1 with additional JWT features.

**Recommendation**: Use **Pattern 1** for your main API and **Pattern 2** for services that only need JWT authentication (like gRPC endpoints) to maintain consistent authentication while avoiding Redis dependency.

## Configuration Options

### Redis Settings

| Option             | Description                         | Default          | Required |
| ------------------ | ----------------------------------- | ---------------- | -------- |
| `redis_addr`       | Redis server address                | -                | ✅       |
| `redis_password`   | Redis password                      | _(empty)_        | ❌       |
| `redis_db`         | Redis database number               | `0`              | ❌       |
| `blacklist_prefix` | Redis key prefix for revoked tokens | `BLACKLIST:key:` | ❌       |
| `timeout`          | Redis operation timeout             | `50ms`           | ❌       |
| `fail_open`        | Continue processing if Redis fails  | `false`          | ❌       |
| `log_blocked`      | Log blocked requests                | `false`          | ❌       |

### TLS Settings (for Redis)

| Option        | Description         | Default | Required |
| ------------- | ------------------- | ------- | -------- |
| `enabled`     | Enable TLS          | `false` | ❌       |
| `server_name` | TLS server name     | -       | ❌       |
| `cert_file`   | Client certificate  | -       | ❌       |
| `key_file`    | Client private key  | -       | ❌       |
| `ca_file`     | CA certificate      | -       | ❌       |
| `min_version` | Minimum TLS version | `1.2`   | ❌       |

### JWT Authentication Settings

| Option               | Description                       | Default                                         | Required |
| -------------------- | --------------------------------- | ----------------------------------------------- | -------- |
| `sign_key`           | JWT signing key (base64 for HMAC) | -                                               | ✅\*     |
| `jwk_url`            | JWK endpoint URL                  | -                                               | ✅\*     |
| `sign_alg`           | Signing algorithm                 | `HS256`                                         | ❌       |
| `skip_verification`  | Skip signature verification       | `false`                                         | ❌       |
| `from_query`         | Query parameter names             | `["api_key", "access_token", "token"]`          | ❌       |
| `from_header`        | Header names                      | `["Authorization", "X-API-Key", "X-Api-Token"]` | ❌       |
| `from_cookies`       | Cookie names                      | `["session_token"]`                             | ❌       |
| `user_claims`        | JWT claims for user ID            | `["sub"]`                                       | ❌       |
| `meta_claims`        | Additional claims mapping         | `{}`                                            | ❌       |
| `issuer_whitelist`   | Allowed issuers                   | `[]`                                            | ❌       |
| `audience_whitelist` | Allowed audiences                 | `[]`                                            | ❌       |

_\* Either `sign_key` or `jwk_url` is required_

## JWT Claims

The plugin expects JWT tokens with standard claims:

```json
{
  "sub": "user_123", // Subject (user ID)
  "jti": "api_key_abc123", // JWT ID (used for blacklist lookup)
  "iss": "https://auth.example.com", // Issuer
  "aud": ["https://api.example.com"], // Audience
  "exp": 1640995200, // Expiration timestamp
  "iat": 1640991600, // Issued at timestamp
  "tier": "PREMIUM", // Custom: user tier
  "scope": "api_access", // Custom: access scope
  "org_id": "org_456" // Custom: organization ID
}
```

**Critical:** The `jti` (JWT ID) claim is used as the token identifier for state management and revocation checks.

## Redis Token State Format

Revoked tokens are stored in Redis with this key pattern:

```
{blacklist_prefix}{jti}
```

Example:

```
BLACKLIST:key:api_key_abc123
```

> **Note:** The prefix name "BLACKLIST" is maintained for backward compatibility. In future versions, this may be renamed to "REVOKED" or "INVALID".

The value stores the revocation reason:

- `cancelled` - Subscription cancelled
- `expired` - Payment/subscription expired
- `downgraded` - Subscription downgraded
- `security` - Security incident
- `abuse` - Terms of service violation

### TTL Examples

```redis
# Temporary revocation for downgrade (24 hours)
SETEX BLACKLIST:key:api_key_123 86400 "downgraded"

# Subscription cancelled (7 days)
SETEX BLACKLIST:key:api_key_456 604800 "cancelled"

# Permanent revocation (security incident)
SET BLACKLIST:key:api_key_789 "security"
```

## User Context & Placeholders

After successful authentication, the plugin populates Caddy placeholders:

```caddy
# Basic user information
{http.auth.user.id}              # User ID from JWT
{http.auth.user.jti}             # JWT ID (API key ID)
{http.auth.user.authenticated}   # "true"

# Custom metadata (from meta_claims)
{http.auth.user.tier}            # User tier
{http.auth.user.scope}           # Access scope
{http.auth.user.organization}    # Organization ID
```

Example usage:

```caddy
stateful_jwt {
    user_claims sub username
    meta_claims "tier" "role->user_role" "org->organization"
}

# Use in responses
respond "Welcome {http.auth.user.username} (Role: {http.auth.user.user_role})"

# Use in logging
log {
    output file /var/log/api.log
    format single_field common_log
    level INFO
}
```

## Error Responses

### Revoked/Invalid Token

```json
{
  "error": "api_key_blacklisted",
  "message": "API key has been disabled due to subscription changes",
  "code": 401,
  "details": "Please check your subscription status or generate a new API key"
}
```

### Invalid/Missing Token

```json
{
  "error": "invalid_token",
  "message": "Invalid authentication token",
  "code": 401
}
```

### Redis Unavailable (Fail Closed)

```json
{
  "error": "internal_error",
  "message": "Authentication service unavailable",
  "code": 500
}
```

## Integration Examples

### Backend Integration (TypeScript/Node.js)

```typescript
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL);

// Revoke API key immediately on subscription cancellation
async function revokeApiKey(
  apiKeyId: string,
  reason: string,
  ttlDays: number = 7
) {
  const ttlSeconds = ttlDays * 24 * 60 * 60;
  await redis.setex(`BLACKLIST:key:${apiKeyId}`, ttlSeconds, reason);
  console.log(`Revoked API key ${apiKeyId} for ${reason}`);
}

// Usage examples
await revokeApiKey("api_key_123", "cancelled", 7); // 7 days
await revokeApiKey("api_key_456", "expired", 30); // 30 days
await revokeApiKey("api_key_789", "downgraded", 1); // 1 day

// Restore token validity (e.g., subscription reactivated)
async function restoreApiKey(apiKeyId: string) {
  await redis.del(`BLACKLIST:key:${apiKeyId}`);
}
```

### Webhook Integration

```typescript
// Subscription cancelled webhook
app.post("/webhooks/subscription-cancelled", async (req, res) => {
  const { userId, subscriptionId } = req.body;

  // Get all API keys for user
  const apiKeys = await db.apiKeys.findMany({ where: { userId } });

  // Revoke all API keys
  const revokePromises = apiKeys.map((key) =>
    redis.setex(`BLACKLIST:key:${key.jti}`, 86400 * 7, "cancelled")
  );

  await Promise.all(revokePromises);
  res.json({ success: true, revoked: apiKeys.length });
});
```

## Architecture

This plugin implements a **state-first architecture** for optimal performance:

```
1. Extract JWT token from request
2. Parse JWT (without verification) to get `jti`
3. Check Redis token state (O(1) lookup)
4. If revoked → return 401 immediately
5. If valid state → perform full JWT validation
6. If valid → populate user context and continue
```

This design ensures:

- **Fast rejection** of revoked tokens (~0.1ms)
- **Expensive validation** only for valid tokens
- **Security** - no way to bypass revocation with valid signatures
- **Statefulness** - immediate token invalidation across all services

## Performance

- **Latency**: ~0.1-0.5ms per request
- **Memory**: Minimal overhead with connection pooling
- **Redis operations**: Single `EXISTS` check per request
- **Throughput**: Tested at >10,000 RPS with negligible impact

## Development & Testing

### Setup Development Environment

```bash
git clone https://github.com/chalabi2/caddy-stateful-jwt-auth
cd caddy-stateful-jwt-auth
make deps
```

### Run Tests

```bash
# Start Redis for testing
make redis-start

# Run all tests
make test-all

# Run with coverage
make test-coverage

# Run benchmarks
make benchmark

# Stop Redis
make redis-stop
```

### Integration Testing

```bash
# Build custom Caddy binary
make xcaddy-build

# Run integration test script
./test.sh

# Test with example configs
./caddy run --config example-configs/Caddyfile
```

## Migration from Separate Modules

If you're currently using `ggicci/caddy-jwt` + a separate token revocation system:

### Before (Two Modules)

```caddy
{
    order stateful_jwt before jwtauth
}

api.example.com {
    stateful_jwt {
        redis_addr {env.REDIS_URL}
        # ... blacklist config
    }

    jwtauth {
        sign_key {env.JWT_SECRET}
        # ... jwt config
    }
}
```

### After (Unified Module)

```caddy
api.example.com {
    stateful_jwt {
        # Redis settings
        redis_addr {env.REDIS_URL}

        # JWT settings (integrated)
        sign_key {env.JWT_SECRET}
        sign_alg HS256
        from_header Authorization
        user_claims sub
    }
}
```

**Benefits:**

- ✅ Single module to manage
- ✅ Better performance (blacklist-first)
- ✅ No middleware ordering issues
- ✅ Simplified configuration
- ✅ Reduced build dependencies

## Requirements

- **Caddy:** v2.8.0 or higher
- **Go:** 1.22 or higher
- **Redis:** 6.0 or higher

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

This plugin integrates JWT authentication functionality from [ggicci/caddy-jwt](https://github.com/ggicci/caddy-jwt) by @ggicci with our Redis-based blacklist system. We extend our gratitude to the original authors for their excellent JWT implementation.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Bug Reports

When reporting bugs, please include:

- Caddy version (`./caddy version`)
- Plugin version
- Configuration (Caddyfile or JSON)
- Redis version and setup
- JWT token format and claims
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs with `debug` level enabled
