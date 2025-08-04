#!/bin/bash

# Build script for caddy-jwt-blacklist plugin
# This script builds Caddy with the JWT blacklist plugin using xcaddy

set -e

echo "🔑 Building Caddy with JWT Blacklist plugin..."

# Check if xcaddy is installed
if ! command -v xcaddy &> /dev/null; then
    echo "📦 xcaddy not found. Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
fi

# Build Caddy with the JWT blacklist plugin
echo "🔨 Building Caddy with caddy-jwt-blacklist plugin..."
xcaddy build --with github.com/chalabi2/caddy-jwt-blacklist=.

# Make the binary executable
chmod +x caddy

echo "✅ Build complete! Caddy binary with JWT blacklist plugin is ready."
echo ""
echo "📋 Example usage:"
echo "  ./caddy run --config example-configs/Caddyfile"
echo "  ./caddy run --config example-configs/caddy.json"
echo ""
echo "🔧 Required environment variables:"
echo "  REDIS_URL=localhost:6379"
echo "  REDIS_PASSWORD=(optional)"
echo "  JWT_SECRET=your-jwt-secret-key"
echo ""
echo "📊 Admin interface will be available at: http://localhost:2019"
echo "🧪 Test your setup with: curl -H 'Authorization: Bearer <jwt>' localhost:8080/api/test"