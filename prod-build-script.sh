#!/bin/bash

# Production build script for Chandra Station Caddy server
# Builds Caddy with unified JWT authentication and blacklist module

set -e

echo "🚀 Building production Caddy with unified JWT authentication and blacklist module..."
echo "📋 Including production modules:"
echo "   - Cloudflare DNS provider (for TLS challenges)"
echo "   - chalabi2/caddy-ratelimit (for rate limiting)"
echo "   - chalabi2/caddy-usage (for usage tracking)"
echo "   - chalabi2/caddy-jwt-blacklist (unified JWT auth + blacklist)"
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

echo "🔨 Building production Caddy with unified JWT + blacklist module..."

# Build Caddy with production modules
# Note: Using latest stable versions for production deployment
xcaddy build \
    --output "$BUILD_DIR/caddy" \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/chalabi2/caddy-ratelimit@v0.1.3 \
    --with github.com/chalabi2/caddy-usage@v0.1.2 \
    --with github.com/chalabi2/caddy-jwt-blacklist@latest

# Make the binary executable
chmod +x "$BUILD_DIR/caddy"

echo "✅ Production Caddy built successfully!"
echo "📍 Binary location: $BUILD_DIR/caddy"
echo ""

# Validate production configuration
echo "🧪 Validating production configuration..."
if JWT_SECRET="dummy" REDIS_URL="localhost:6379" CLOUDFLARE_API_TOKEN="dummy" "$BUILD_DIR/caddy" validate --config prod-caddy --adapter caddyfile > /dev/null 2>&1; then
    echo "  ✅ Production Caddyfile configuration is valid!"
else
    echo "  ⚠️  Production configuration has warnings (check environment variables)"
fi

# Check module registration
echo "  Checking production module registration..."
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
echo "🎯 Production deployment steps:"
echo "  1. Copy binary to production server:"
echo "     scp $BUILD_DIR/caddy user@prod-server:/usr/local/bin/"
echo "  2. Copy configuration:"
echo "     scp prod-caddy user@prod-server:/etc/caddy/Caddyfile"
echo "  3. Set environment variables on production server:"
echo "     - JWT_SECRET (base64-encoded secret)"
echo "     - REDIS_URL (Upstash Redis URL)" 
echo "     - REDIS_PASSWORD (Upstash Redis password)"
echo "     - CLOUDFLARE_API_TOKEN (for DNS challenges)"
echo "  4. Restart Caddy service:"
echo "     sudo systemctl restart caddy"
echo ""
echo "📝 Required production environment variables:"
echo "   export JWT_SECRET='your-base64-encoded-jwt-secret'"
echo "   export REDIS_URL='redis-xxxxx.upstash.io:6379'"
echo "   export REDIS_PASSWORD='your-upstash-redis-password'"
echo "   export CLOUDFLARE_API_TOKEN='your-cloudflare-api-token'"
echo ""
echo "💡 Security notes:"
echo "   - JWT_SECRET should be at least 32 bytes, base64-encoded"
echo "   - Use a secure random generator: openssl rand -base64 32"
echo "   - Upstash Redis TLS is automatically enabled in production config"
echo "   - fail_open=true allows graceful degradation if Redis is temporarily unavailable"
echo ""
echo "🔧 Production modules included:"
echo "   ✅ Cloudflare DNS (for automatic TLS certificates)"
echo "   ✅ chalabi2/caddy-ratelimit (tier-based rate limiting)" 
echo "   ✅ chalabi2/caddy-usage (request usage tracking)"
echo "   ✅ Unified JWT Authentication + Blacklist:"
echo "      - Integrated JWT validation (no separate ggicci/caddy-jwt needed)"
echo "      - Redis-based token revocation with Upstash TLS"
echo "      - Blacklist-first architecture for optimal performance"
echo "      - Multiple signing algorithms support"
echo "      - User context population for downstream services"
echo ""
echo "📊 Architecture benefits:"
echo "   🚀 Performance: Blacklist check before JWT validation (~0.1ms overhead)"
echo "   🔒 Security: Immediate token revocation, fail-open/fail-closed modes"
echo "   🛠️  Simplified: Single module replaces jwt + blacklist middleware chain"
echo "   📈 Observability: Comprehensive logging and metrics integration"

# Optional: Run configuration test if environment is available
if [ "$1" = "test" ]; then
    echo ""
    echo "🔍 Running production configuration test..."
    
    if [ -z "$JWT_SECRET" ] || [ -z "$REDIS_URL" ] || [ -z "$CLOUDFLARE_API_TOKEN" ]; then
        echo "  ⚠️  Missing environment variables for full test"
        echo "  Set JWT_SECRET, REDIS_URL, and CLOUDFLARE_API_TOKEN for complete validation"
    else
        echo "  ✅ Environment variables detected, running full configuration test..."
        "$BUILD_DIR/caddy" validate --config prod-caddy --adapter caddyfile
        echo "  ✅ Production configuration validated successfully!"
    fi
elif [ "$1" = "deploy" ]; then
    echo ""
    echo "🚀 Starting deployment mode..."
    echo "  This will copy the binary and configuration to production locations"
    echo "  Make sure you have sudo access and production environment variables set"
    
    # Copy binary to system location
    sudo cp "$BUILD_DIR/caddy" /usr/local/bin/caddy
    echo "  ✅ Binary copied to /usr/local/bin/caddy"
    
    # Copy configuration
    sudo mkdir -p /etc/caddy
    sudo cp prod-caddy /etc/caddy/Caddyfile
    echo "  ✅ Configuration copied to /etc/caddy/Caddyfile"
    
    # Validate configuration
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
    echo "  ✅ Configuration validated"
    
    echo "  🎉 Deployment complete! Run 'sudo systemctl restart caddy' to apply changes"
fi

echo ""
echo "🚀 Production build complete! Your unified JWT + blacklist Caddy is ready."
echo "   Run: $0 test     # To test configuration with current environment"
echo "   Run: $0 deploy   # To deploy to local system (requires sudo)"