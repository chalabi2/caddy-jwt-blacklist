# Multi-stage build for JWT blacklist plugin
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Install xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Copy plugin source
COPY . .

# Build Caddy with the stateful JWT auth plugin
RUN xcaddy build --with github.com/chalabi2/caddy-stateful-jwt-auth=.

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates mailcap

# Create caddy user
RUN addgroup -g 1000 caddy && \
    adduser -u 1000 -G caddy -s /bin/sh -D caddy

# Copy Caddy binary from builder stage
COPY --from=builder /app/caddy /usr/bin/caddy

# Copy example configurations
COPY --from=builder /app/example-configs /etc/caddy/

# Create necessary directories
RUN mkdir -p /var/lib/caddy /var/log/caddy && \
    chown -R caddy:caddy /var/lib/caddy /var/log/caddy

# Switch to caddy user
USER caddy

# Set working directory
WORKDIR /etc/caddy

# Expose ports
EXPOSE 8080 2019

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Default command
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]