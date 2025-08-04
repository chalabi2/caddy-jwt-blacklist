#!/bin/bash

# Test script for JWT blacklist plugin
# This script demonstrates the plugin functionality

set -e

echo "🧪 JWT Blacklist Plugin Test Suite"
echo "=================================="

# Configuration
REDIS_URL=${REDIS_URL:-"localhost:6379"}
JWT_SECRET=${JWT_SECRET:-"test-jwt-secret-for-demo"}
API_KEY_ID="test-api-key-123"
USER_ID="test-user-456"

echo "📋 Configuration:"
echo "  Redis URL: $REDIS_URL"
echo "  JWT Secret: ${JWT_SECRET:0:10}..."
echo "  API Key ID: $API_KEY_ID"
echo "  User ID: $USER_ID"
echo ""

# Check if Redis is available
echo "🔍 Checking Redis connection..."
if ! redis-cli -u redis://$REDIS_URL ping > /dev/null 2>&1; then
    echo "❌ Redis not available at $REDIS_URL"
    echo "   Start Redis: docker run -d -p 6379:6379 redis:alpine"
    exit 1
fi
echo "✅ Redis is available"

# Check if Caddy binary exists
if [ ! -f "./caddy" ]; then
    echo "🔨 Building Caddy with JWT blacklist plugin..."
    make xcaddy-build
fi

# Generate a test JWT token
echo "🔑 Generating test JWT token..."
JWT_TOKEN=$(cat << EOF | node -
const jwt = require('jsonwebtoken');
const token = jwt.sign({
    sub: '$USER_ID',
    jti: '$API_KEY_ID',
    tier: 'BASIC',
    scope: 'api_access',
    exp: Math.floor(Date.now() / 1000) + (15 * 60),
    iat: Math.floor(Date.now() / 1000)
}, '$JWT_SECRET');
console.log(token);
EOF
)

if [ -z "$JWT_TOKEN" ]; then
    echo "❌ Failed to generate JWT token. Install Node.js and jsonwebtoken:"
    echo "   npm install -g jsonwebtoken"
    exit 1
fi

echo "✅ JWT token generated: ${JWT_TOKEN:0:20}..."

# Start Caddy in background
echo "🚀 Starting Caddy server..."
export REDIS_URL JWT_SECRET
./caddy run --config example-configs/Caddyfile --adapter caddyfile > caddy.log 2>&1 &
CADDY_PID=$!

# Wait for Caddy to start
sleep 3

# Function to cleanup
cleanup() {
    echo "🧹 Cleaning up..."
    kill $CADDY_PID 2>/dev/null || true
    redis-cli -u redis://$REDIS_URL del "BLACKLIST:key:$API_KEY_ID" > /dev/null 2>&1 || true
    rm -f caddy.log
}
trap cleanup EXIT

# Test 1: Valid token (not blacklisted)
echo ""
echo "🧪 Test 1: Valid token (not blacklisted)"
echo "----------------------------------------"
RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $JWT_TOKEN" http://localhost:8080/api/test)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Test 1 PASSED: Valid token accepted"
    echo "   Response: $BODY"
else
    echo "❌ Test 1 FAILED: Expected 200, got $HTTP_CODE"
    echo "   Response: $BODY"
fi

# Test 2: Blacklist the API key
echo ""
echo "🧪 Test 2: Blacklist API key and test again"
echo "--------------------------------------------"
redis-cli -u redis://$REDIS_URL setex "BLACKLIST:key:$API_KEY_ID" 3600 "cancelled" > /dev/null

# Wait a moment for Redis to propagate
sleep 1

RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $JWT_TOKEN" http://localhost:8080/api/test)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "401" ]; then
    echo "✅ Test 2 PASSED: Blacklisted token rejected"
    echo "   Response: $BODY"
else
    echo "❌ Test 2 FAILED: Expected 401, got $HTTP_CODE"
    echo "   Response: $BODY"
fi

# Test 3: Test different token sources
echo ""
echo "🧪 Test 3: Test different token sources"
echo "---------------------------------------"

# Remove blacklist for this test
redis-cli -u redis://$REDIS_URL del "BLACKLIST:key:$API_KEY_ID" > /dev/null

# Test X-API-Key header
RESPONSE=$(curl -s -w "\n%{http_code}" -H "X-API-Key: $JWT_TOKEN" http://localhost:8080/api/test)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ X-API-Key header works"
else
    echo "❌ X-API-Key header failed: $HTTP_CODE"
fi

# Test query parameter
RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:8080/api/test?api_key=$JWT_TOKEN")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Query parameter works"
else
    echo "❌ Query parameter failed: $HTTP_CODE"
fi

# Test 4: No token provided
echo ""
echo "🧪 Test 4: No token provided"
echo "----------------------------"
RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:8080/api/test)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "401" ]; then
    echo "✅ Test 4 PASSED: Missing token rejected"
else
    echo "❌ Test 4 FAILED: Expected 401, got $HTTP_CODE"
fi

# Test 5: Public endpoint (no auth required)
echo ""
echo "🧪 Test 5: Public endpoint access"
echo "---------------------------------"
RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:8080/)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Test 5 PASSED: Public endpoint accessible"
else
    echo "❌ Test 5 FAILED: Expected 200, got $HTTP_CODE"
fi

# Test 6: Admin metrics endpoint
echo ""
echo "🧪 Test 6: Admin metrics endpoint"
echo "---------------------------------"
RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:2019/metrics)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Test 6 PASSED: Metrics endpoint accessible"
else
    echo "❌ Test 6 FAILED: Expected 200, got $HTTP_CODE"
fi

echo ""
echo "🎉 Test suite completed!"
echo "📊 Check caddy.log for detailed logs"