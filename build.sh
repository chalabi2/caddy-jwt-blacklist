#!/bin/bash

# Script to build Caddy with unified JWT authentication and blacklist module
# This script builds from the local codebase with integrated JWT functionality

set -e

echo "🚀 Building Caddy with unified JWT authentication and blacklist module..."
echo "📋 Including modules:"
echo "   - Cloudflare DNS provider (for TLS challenges)"
echo "   - chalabi2/caddy-ratelimit (for rate limiting)"
echo "   - chalabi2/caddy-usage (for usage tracking)"
echo "   - chalabi2/caddy-jwt-blacklist (LOCAL - unified JWT auth + blacklist)"
echo "   - Standard Caddy modules"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    echo "Visit: https://golang.org/doc/install"
    exit 1
fi

# Check if xcaddy is installed
if ! command -v xcaddy &> /dev/null; then
    echo "📦 Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
fi

# Create build directory
BUILD_DIR="./build"
mkdir -p "$BUILD_DIR"

echo "🔨 Building Caddy with unified JWT + blacklist module..."

# Build Caddy with the unified JWT authentication and blacklist module
# Note: No longer need separate ggicci/caddy-jwt module - functionality is integrated
xcaddy build \
    --output "$BUILD_DIR/caddy" \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/chalabi2/caddy-ratelimit@v0.1.3 \
    --with github.com/chalabi2/caddy-usage@v0.1.2 \
    --with github.com/chalabi2/caddy-jwt-blacklist=.

# Make the binary executable
chmod +x "$BUILD_DIR/caddy"

echo "✅ Caddy built successfully!"
echo "📍 Binary location: $BUILD_DIR/caddy"
echo ""

# Test the build with our configurations
echo "🧪 Testing configuration validation..."

# Test unified JWT + blacklist config
echo "  Testing unified JWT + blacklist configuration..."
if "$BUILD_DIR/caddy" validate --config example-configs/Caddyfile --adapter caddyfile > /dev/null 2>&1; then
    echo "  ✅ Caddyfile configuration is valid!"
else
    echo "  ⚠️  Caddyfile configuration has warnings (check environment variables)"
fi

# Test JSON config
echo "  Testing JSON configuration..."
if "$BUILD_DIR/caddy" validate --config example-configs/caddy.json > /dev/null 2>&1; then
    echo "  ✅ JSON configuration is valid!"
else
    echo "  ⚠️  JSON configuration has warnings (check environment variables)"
fi

# Check that our module is properly loaded
echo "  Checking module registration..."
if "$BUILD_DIR/caddy" list-modules | grep -q "http.handlers.jwt_blacklist"; then
    echo "  ✅ Unified JWT + blacklist module registered correctly!"
else
    echo "  ❌ JWT blacklist module not found in loaded modules"
    echo "  Available modules:"
    "$BUILD_DIR/caddy" list-modules | grep "http.handlers"
    exit 1
fi

# Verify no conflicting JWT modules
echo "  Checking for JWT module conflicts..."
JWT_MODULES=$("$BUILD_DIR/caddy" list-modules | grep -E "(jwt|auth)" | grep -v "jwt_blacklist" || true)
if [ -n "$JWT_MODULES" ]; then
    echo "  ℹ️  Other JWT/auth modules found:"
    echo "$JWT_MODULES" | sed 's/^/    /'
else
    echo "  ✅ No conflicting JWT modules found!"
fi

echo ""
echo "🎯 To use the custom Caddy binary:"
echo "  1. Copy it to your system: sudo cp $BUILD_DIR/caddy /usr/local/bin/"
echo "  2. Or run directly: $BUILD_DIR/caddy run --config example-configs/Caddyfile"
echo ""
echo "📝 Required environment variables:"
echo "   1. Set the JWT_SECRET environment variable:"
echo "      export JWT_SECRET='your-base64-encoded-jwt-secret'"
echo "   2. Set up Redis environment variables:"
echo "      export REDIS_URL='localhost:6379'"
echo "      export REDIS_PASSWORD='your-redis-password'"
echo "   3. Optional: Cloudflare API token (for TLS challenges):"
echo "      export CLOUDFLARE_API_TOKEN='your-cloudflare-token'"
echo ""
echo "💡 JWT Secret generation:"
echo "   # Generate a secure base64-encoded secret:"
echo "   openssl rand -base64 32"
echo ""
echo "🔧 Your modules included:"
echo "   ✅ Cloudflare DNS (for TLS certificates)"
echo "   ✅ chalabi2/caddy-ratelimit (for rate limiting)" 
echo "   ✅ chalabi2/caddy-usage (for usage tracking)"
echo "   ✅ Unified JWT Authentication + Blacklist (LOCAL BUILD)"
echo "      - Integrated JWT validation (replaces ggicci/caddy-jwt)"
echo "      - Redis-based token revocation"
echo "      - Blacklist-first architecture for optimal performance"
echo "      - Multiple signing algorithms (HS256, RS256, ES256, EdDSA)"
echo "      - JWK support with automatic refresh"

# Optional: Run integration tests if Redis is available
if [ "$1" = "test" ]; then
    echo ""
    echo "🔍 Running integration tests..."
    
    # Check if Redis is available
    if command -v redis-cli &> /dev/null && redis-cli ping > /dev/null 2>&1; then
        echo "  ✅ Redis is available, running full test suite..."
        make redis-start > /dev/null 2>&1 || true
        go test -v ./...
        make redis-stop > /dev/null 2>&1 || true
    else
        echo "  ⚠️  Redis not available, running unit tests only..."
        go test -v ./... -short
        echo "  To run full integration tests: start Redis and run: $0 test"
    fi
elif [ "$1" = "demo" ]; then
    echo ""
    echo "🎮 Starting demo server..."
    echo "  Server will start on http://localhost:8080"
    echo "  Press Ctrl+C to stop"
    export JWT_SECRET="TkZMNSowQmMjOVU2RUB0bm1DJkU3U1VONkd3SGZMbVk="
    export REDIS_URL="localhost:6379" 
    "$BUILD_DIR/caddy" run --config example-configs/Caddyfile
fi

echo ""
echo "🚀 Build complete! Your unified JWT + blacklist module is ready."
echo "   Run: $0 test    # To run tests"
echo "   Run: $0 demo    # To start demo server"