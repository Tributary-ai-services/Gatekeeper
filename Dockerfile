# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -o /app/bin/gatekeeper-server \
    ./cmd/contentintel-server

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 gatekeeper && \
    adduser -u 1000 -G gatekeeper -s /bin/sh -D gatekeeper

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/gatekeeper-server /app/gatekeeper-server

# Copy configuration files
COPY configs/ /app/configs/

# Set ownership
RUN chown -R gatekeeper:gatekeeper /app

# Switch to non-root user
USER gatekeeper

# Expose ports
EXPOSE 8087 8088 9087

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8087/health/live || exit 1

# Run the server
ENTRYPOINT ["/app/gatekeeper-server"]
CMD ["--config", "/app/configs/gatekeeper.yaml"]
