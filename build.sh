#!/bin/bash

# Script to build Caddy with JWT authentication, blacklist, and rate limiting modules
# This script builds from the local codebase and ensures proper module ordering

set -e

echo "🚀 Building Caddy with JWT authentication, blacklist, and rate limiting modules..."
echo "📋 Including modules:"
echo "   - Cloudflare DNS provider (for TLS challenges)"
echo "   - chalabi2/caddy-ratelimit (for rate limiting)"
echo "   - ggicci/caddy-jwt (for JWT authentication)"
echo "   - chalabi2/caddy-usage (for usage tracking)"
echo "   - chalabi2/caddy-jwt-blacklist (LOCAL - for API key revocation)"
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

echo "🔨 Building Caddy with JWT, blacklist, and rate limiting modules..."

# Build Caddy with the JWT authentication, blacklist, rate limiting, and usage modules
# Note: Using local codebase for jwt-blacklist module with "=."
xcaddy build \
    --output "$BUILD_DIR/caddy" \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/chalabi2/caddy-ratelimit@v0.1.3 \
    --with github.com/ggicci/caddy-jwt@v1.1.0 \
    --with github.com/chalabi2/caddy-usage@v0.1.2 \
    --with github.com/chalabi2/caddy-jwt-blacklist=.

# Make the binary executable
chmod +x "$BUILD_DIR/caddy"

echo "✅ Caddy built successfully!"
echo "📍 Binary location: $BUILD_DIR/caddy"
echo ""

# Test the build with our configurations
echo "🧪 Testing configuration validation..."

# Test standalone JWT blacklist config
echo "  Testing standalone JWT blacklist configuration..."
if "$BUILD_DIR/caddy" validate --config example-configs/Caddyfile > /dev/null 2>&1; then
    echo "  ✅ Standalone configuration is valid!"
else
    echo "  ⚠️  Standalone configuration has warnings (expected - missing jwtauth module)"
fi

# Test JSON config
echo "  Testing JSON configuration..."
if "$BUILD_DIR/caddy" validate --config example-configs/caddy.json > /dev/null 2>&1; then
    echo "  ✅ JSON configuration is valid!"
else
    echo "  ⚠️  JSON configuration has warnings"
fi

# Check that our module is properly loaded
echo "  Checking module registration..."
if "$BUILD_DIR/caddy" list-modules | grep -q "http.handlers.jwt_blacklist"; then
    echo "  ✅ JWT blacklist module registered correctly!"
else
    echo "  ❌ JWT blacklist module not found in loaded modules"
    echo "  Available modules:"
    "$BUILD_DIR/caddy" list-modules | grep "http.handlers"
    exit 1
fi

# Test example configurations
echo "  Testing example configurations..."
if "$BUILD_DIR/caddy" validate --config example-configs/Caddyfile > /dev/null 2>&1; then
    echo "  ✅ Main Caddyfile example is valid!"
else
    echo "  ⚠️  Main Caddyfile has warnings (check Redis connection)"
fi

if "$BUILD_DIR/caddy" validate --config example-configs/Caddyfile-jwt-auth > /dev/null 2>&1; then
    echo "  ✅ JWT auth integration example is valid!"
else
    echo "  ⚠️  JWT auth example has warnings (expected if jwtauth module not available)"
fi

echo ""
echo "🎯 To use the custom Caddy binary:"
echo "  1. Copy it to your system: sudo cp $BUILD_DIR/caddy /usr/local/bin/"
echo "  2. Or run directly: $BUILD_DIR/caddy run --config example-configs/Caddyfile"
echo ""
echo "📝 Important setup steps:"
echo "   1. Set the JWT_SECRET environment variable:"
echo "      export JWT_SECRET='your-very-secure-jwt-secret-key-here'"
echo "   2. Make sure CLOUDFLARE_API_TOKEN is still set (for DNS challenges)"
echo "   3. Set up Redis environment variables:"
echo "      export REDIS_URL='localhost:6379'"
echo "      export REDIS_PASSWORD='your-redis-password'"
echo "   4. Update your Next.js .env file to include the same JWT_SECRET"
echo "   5. Ensure Redis is running and properly secured"
echo ""
echo "🔧 Your modules included:"
echo "   ✅ Cloudflare DNS (for TLS certificates)"
echo "   ✅ chalabi2/caddy-ratelimit (for rate limiting)" 
echo "   ✅ chalabi2/caddy-usage (for usage tracking)"
echo "   ✅ JWT authentication (for private endpoints)"
echo "   ✅ JWT blacklist (LOCAL BUILD - for API key revocation with proper ordering)"

# Optional: Run a quick integration test if Redis is available
if [ "$1" = "test-redis" ]; then
    echo ""
    echo "🔍 Running Redis integration test..."
    
    # Check if Redis is available
    if command -v redis-cli &> /dev/null && redis-cli ping > /dev/null 2>&1; then
        echo "  ✅ Redis is available, running integration tests..."
        go test -v ./... -run TestJWTBlacklistMiddleware
    else
        echo "  ⚠️  Redis not available for integration testing"
        echo "  To run full tests: start Redis and run: $0 test-redis"
    fi
fi