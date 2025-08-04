# Caddy JWT Blacklist Plugin

[![codecov](https://codecov.io/gh/chalabi2/caddy-jwt-blacklist/graph/badge.svg)](https://codecov.io/gh/chalabi2/caddy-jwt-blacklist)
[![Go Report Card](https://goreportcard.com/badge/github.com/chalabi2/caddy-jwt-blacklist)](https://goreportcard.com/report/github.com/chalabi2/caddy-jwt-blacklist)
[![Go Reference](https://pkg.go.dev/badge/github.com/chalabi2/caddy-jwt-blacklist.svg)](https://pkg.go.dev/github.com/chalabi2/caddy-jwt-blacklist)

A comprehensive JWT-based API key blacklist middleware for Caddy that provides immediate token revocation capabilities using Redis. This plugin extends existing JWT authentication to block API keys when subscriptions are cancelled, expired, or downgraded.

> [!NOTE]
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

## Features

- **Redis-based blacklist checking** - Fast O(1) lookups using Redis
- **Multiple token sources** - Supports Authorization header, custom headers, query parameters, and cookies
- **Fail-open behavior** - Continues processing if Redis is unavailable (configurable)
- **Detailed logging** - Logs blocked requests with context
- **Low latency** - Adds ~0.1-0.5ms per request
- **Graceful error handling** - Specific error responses for blacklisted keys

## Installation

Build Caddy with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/chalabi2/caddy-jwt-blacklist
```

Or add to your `xcaddy.json`:

```json
{
  "dependencies": [
    {
      "module": "github.com/chalabi2/caddy-jwt-blacklist",
      "version": "latest"
    }
  ]
}
```

## Configuration

> **Note:** Complete example configurations are available in the [`example-configs/`](example-configs/) directory.

### Caddyfile

Basic usage - add the `jwt_blacklist` directive before JWT authentication:

```caddy
{
    # CRITICAL: Plugin execution order
    order jwt_blacklist before jwtauth
    order jwtauth before rate_limit
}

api.example.com {
    # Step 1: JWT Blacklist Check
    jwt_blacklist {
        redis_addr {env.REDIS_URL}
        redis_password {env.REDIS_PASSWORD}
        redis_db 0
        jwt_secret {env.JWT_SECRET}
        blacklist_prefix "BLACKLIST:key:"
        fail_open true
        timeout 50ms
        log_blocked true
    }

    # Step 2: JWT Authentication (existing)
    jwtauth {
        sign_key {env.JWT_SECRET}
        sign_alg HS256
        from_query api_key access_token token
        from_header Authorization X-Api-Token X-API-Key
        from_cookies session_token
        user_claims sub jti uid user_id
        meta_claims "tier" "scope"
    }

    # Your existing configuration...
}
```

### JSON Configuration

```json
{
  "admin": {
    "listen": "localhost:2019"
  },
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":8080"],
          "routes": [
            {
              "match": [
                {
                  "host": ["api.example.com"],
                  "path": ["/api*"]
                }
              ],
              "handle": [
                {
                  "handler": "jwt_blacklist",
                  "config": {
                    "redis_addr": "{env.REDIS_URL}",
                    "redis_password": "{env.REDIS_PASSWORD}",
                    "redis_db": 0,
                    "jwt_secret": "{env.JWT_SECRET}",
                    "blacklist_prefix": "BLACKLIST:key:",
                    "fail_open": true,
                    "timeout": "50ms",
                    "log_blocked": true
                  }
                },
                {
                  "handler": "jwtauth",
                  "sign_key": "{env.JWT_SECRET}",
                  "sign_alg": "HS256",
                  "from_query": ["api_key", "access_token", "token"],
                  "from_header": ["Authorization", "X-Api-Token", "X-API-Key"],
                  "from_cookies": ["session_token"],
                  "user_claims": ["sub", "jti", "uid", "user_id"],
                  "meta_claims": ["tier", "scope"]
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

## Configuration Options

| Option             | Description                           | Default          |
| ------------------ | ------------------------------------- | ---------------- |
| `redis_addr`       | Redis server address                  | `localhost:6379` |
| `redis_password`   | Redis password                        | _(empty)_        |
| `redis_db`         | Redis database number                 | `0`              |
| `jwt_secret`       | JWT signing secret _(required)_       | _(none)_         |
| `blacklist_prefix` | Redis key prefix for blacklisted keys | `BLACKLIST:key:` |
| `fail_open`        | Continue processing if Redis fails    | `true`           |
| `timeout`          | Redis operation timeout               | `50ms`           |
| `log_blocked`      | Log blocked requests                  | `false`          |

## Token Sources

The plugin checks for JWT tokens in the following order:

1. **Authorization header**: `Authorization: Bearer <token>`
2. **X-API-Key header**: `X-API-Key: <token>`
3. **X-Api-Token header**: `X-Api-Token: <token>`
4. **Query parameters**: `?api_key=<token>`, `?access_token=<token>`, `?token=<token>`
5. **Cookies**: `session_token=<token>`

## JWT Claims

The plugin expects JWT tokens with the following claims:

```json
{
  "sub": "user_id", // User ID
  "jti": "api_key_id", // API Key ID (used for blacklist lookup)
  "tier": "BASIC", // User tier
  "scope": "api_access", // Token scope
  "exp": 1640995200, // Expiration timestamp
  "iat": 1640991600 // Issued at timestamp
}
```

The `jti` (JWT ID) claim is used as the API key identifier for blacklist checks.

## Redis Key Format

Blacklisted API keys are stored in Redis using this pattern:

```
BLACKLIST:key:{api_key_id}
```

The value can be a reason code like:

- `cancelled` - Subscription cancelled (7 days TTL)
- `expired` - One-time payment expired (30 days TTL)
- `downgraded` - Subscription downgraded (1 day TTL)

### Sample Error Response

When an API key is blacklisted, the plugin returns:

```json
{
  "error": "api_key_blacklisted",
  "message": "API key has been disabled due to subscription changes",
  "code": 401,
  "details": "Please check your subscription status or generate a new API key"
}
```

**Headers Set:**

- `X-Error-Type: api_key_blacklisted`
- `WWW-Authenticate: Bearer`

## Integration with Webapp

This plugin is designed to work with the existing Chandra Station webapp blacklist management:

### Subscription Cancellation

```typescript
// Blacklist immediately when subscription is cancelled
const blacklistPromises = apiKeys.map((key) =>
  redis.setEx(`BLACKLIST:key:${key.id}`, 86400 * 7, "cancelled")
);
```

### One-Time Payment Expiration

```typescript
// Background job for expired payments
const blacklistPromises = apiKeys.map((key) =>
  redis.setEx(`BLACKLIST:key:${key.id}`, 86400 * 30, "expired")
);
```

### Subscription Downgrades

```typescript
// Temporary blacklist for tier changes
const blacklistPromises = apiKeys.map((key) =>
  redis.setEx(`BLACKLIST:key:${key.id}`, 86400 * 1, "downgraded")
);
```

## Testing

Run tests with Redis available on localhost:6379:

```bash
# Start Redis for testing
docker run -d -p 6379:6379 redis:alpine

# Run tests
cd caddy-jwt-blacklist
go test -v ./...
```

The tests include:

- Unit tests for token extraction and JWT parsing
- Integration tests with Redis
- Webapp blacklist pattern testing
- Error handling and failover scenarios

## Requirements

- **Caddy:** v2.8.0 or higher
- **Go:** 1.21 or higher
- **Redis:** 6.0 or higher
- **JWT Secret:** Shared secret for token validation

## Building from Source

```bash
git clone https://github.com/chalabi2/caddy-jwt-blacklist
cd caddy-jwt-blacklist
make deps
make xcaddy-build
```

## Testing

Run the test suite:

```bash
make test        # Run unit tests
make test-all    # Run all tests including integration
make benchmark   # Run benchmarks
make ci          # Run all CI checks
```

### Integration Testing

```bash
# Start Redis for testing
make redis-start

# Run integration tests
make xcaddy-test

# Run the demo test script
./test.sh

# Stop Redis when done
make redis-stop
```

## Performance

- **Latency**: ~0.1-0.5ms per request
- **Memory**: Minimal overhead (connection pooling)
- **Redis operations**: Single EXISTS check per request
- **Fail-open**: Requests continue if Redis is unavailable

## Monitoring

The plugin logs important events at different levels:

```bash
# View plugin logs
./caddy run --config example-configs/Caddyfile 2>&1 | grep jwt_blacklist

# Sample log output:
INFO: JWT blacklist middleware provisioned
INFO: Blocked blacklisted API key api_key_id=ak_123 user_id=user_456
WARN: Redis blacklist check failed, failing open
```

## License

MIT License

## Bug Reports

When reporting bugs, include:

- Caddy version
- Plugin version
- Configuration (Caddyfile or JSON)
- Redis version and configuration
- JWT token format and claims
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs
