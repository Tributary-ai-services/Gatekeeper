# Build stage
FROM golang:1.24-bookworm AS builder

# Install build dependencies.
# libhyperscan-dev + pkg-config are required to compile the Intel Hyperscan
# engine (github.com/flier/gohs), which is the default scan backend (no `nohs`
# build tag). git is used for the version stamp.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates tzdata \
        libhyperscan-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# NOTE: the build context must contain BOTH this repo (as Gatekeeper/) and its
# local replace dependency (as aether-shared/go-events/), because Gatekeeper's
# go.mod has `replace ... => ../aether-shared/go-events` — the sibling module
# lives outside this directory. `make docker-build` assembles a slim context
# with exactly those two paths; build it that way rather than running
# `docker build` against the repo directly.

# Copy the local `replace` dependency first, preserving the relative layout the
# go.mod expects (../aether-shared/go-events from the Gatekeeper module dir).
WORKDIR /src
COPY aether-shared/go-events/ ./aether-shared/go-events/

# Copy module files and download dependencies (cached unless go.mod/go.sum change)
WORKDIR /src/Gatekeeper
COPY Gatekeeper/go.mod Gatekeeper/go.sum ./
RUN go mod download

# Copy the Gatekeeper source code
COPY Gatekeeper/ ./

# Build the binary with Intel Hyperscan enabled.
# CGO must be on for the gohs bindings; Intel Hyperscan is x86_64-only, so the
# target stays linux/amd64. No build tag is passed, so the default Hyperscan
# engine (pkg/scan/engine_hyperscan.go, //go:build !nohs) is compiled in.
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -o /app/bin/gatekeeper-server \
    ./cmd/contentintel-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies.
# The builder statically links Intel Hyperscan (libhs.a) into the binary, so
# libhyperscan5 is not loaded today; it is kept as a safety net in case a future
# gohs/toolchain change switches to dynamic linking against libhs.so.
# wget is used by the container HEALTHCHECK below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tzdata libhyperscan5 wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 gatekeeper && \
    useradd -u 1000 -g gatekeeper -s /bin/sh -M gatekeeper

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/gatekeeper-server /app/gatekeeper-server

# Copy configuration files (context root is the monorepo root)
COPY Gatekeeper/configs/ /app/configs/

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
