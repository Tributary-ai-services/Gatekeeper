# Gatekeeper - TAS Content Intelligence Library
# Makefile for build, test, and development tasks

.PHONY: all build test test-coverage lint security clean help
.PHONY: generate generate-mocks proto docker-build docker-push
.PHONY: dev-services dev-services-down ci pre-commit check-all
.PHONY: build-server run-server benchmark install-tools

# Build variables
BINARY_NAME=contentintel-server
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOLINT=golangci-lint

# Docker parameters
DOCKER_REGISTRY?=registry.tas.scharber.com
DOCKER_IMAGE=$(DOCKER_REGISTRY)/tas-contentintel
DOCKER_TAG?=$(VERSION)

# Directories
CMD_DIR=./cmd/contentintel-server
PKG_DIR=./pkg/...
MIDDLEWARE_DIR=./middleware/...
SERVICE_DIR=./service/...
ALL_PACKAGES=$(PKG_DIR) $(MIDDLEWARE_DIR) $(SERVICE_DIR) $(CMD_DIR)/...

# Default target
all: lint test build

## help: Show this help message
help:
	@echo "TAS Content Intelligence Library"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build          Build the library"
	@echo "  build-server   Build the standalone server binary"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Test targets:"
	@echo "  test           Run unit tests"
	@echo "  test-coverage  Run tests with coverage report"
	@echo "  test-race      Run tests with race detector"
	@echo "  benchmark      Run benchmark tests"
	@echo ""
	@echo "Code quality targets:"
	@echo "  lint           Run linter"
	@echo "  fmt            Format code"
	@echo "  vet            Run go vet"
	@echo "  security       Run security scan (gosec)"
	@echo "  check-all      Run all checks (fmt, vet, lint, security)"
	@echo ""
	@echo "Development targets:"
	@echo "  dev-services      Start development dependencies (Redis, Kafka)"
	@echo "  dev-services-down Stop development dependencies"
	@echo "  run-server        Run the server locally"
	@echo "  install-tools     Install development tools"
	@echo ""
	@echo "CI/CD targets:"
	@echo "  ci             Full CI pipeline (check-all, test-coverage, build)"
	@echo "  pre-commit     Pre-commit checks (fmt-check, lint, test)"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-push    Push Docker image to registry"
	@echo ""
	@echo "Code generation targets:"
	@echo "  generate       Run all code generation"
	@echo "  generate-mocks Generate mock files for testing"
	@echo "  proto          Generate protobuf files"

## build: Build the library (verify it compiles)
build:
	@echo "Building library..."
	$(GOBUILD) $(ALL_PACKAGES)

## build-server: Build the standalone server binary
build-server:
	@echo "Building server binary..."
	$(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME) $(CMD_DIR)

## test: Run unit tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -short $(ALL_PACKAGES)

## test-coverage: Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out -covermode=atomic $(ALL_PACKAGES)
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## test-race: Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	$(GOTEST) -v -race $(ALL_PACKAGES)

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration $(ALL_PACKAGES)

## benchmark: Run benchmark tests
benchmark:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem $(ALL_PACKAGES)

## lint: Run linter
lint:
	@echo "Running linter..."
	$(GOLINT) run ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

## fmt-check: Check code formatting
fmt-check:
	@echo "Checking code formatting..."
	@test -z "$$($(GOFMT) -l .)" || (echo "Code not formatted. Run 'make fmt'" && exit 1)

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOCMD) vet $(ALL_PACKAGES)

## security: Run security scan
security:
	@echo "Running security scan..."
	gosec -quiet ./...

## check-all: Run all checks
check-all: fmt-check vet lint security
	@echo "All checks passed!"

## ci: Full CI pipeline
ci: check-all test-coverage build build-server
	@echo "CI pipeline completed!"

## pre-commit: Pre-commit checks
pre-commit: fmt-check lint test
	@echo "Pre-commit checks passed!"

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -rf dist/

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

## deps-tidy: Tidy dependencies
deps-tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

## deps-verify: Verify dependencies
deps-verify:
	@echo "Verifying dependencies..."
	$(GOMOD) verify

## generate: Run all code generation
generate: generate-mocks
	@echo "Code generation completed!"

## generate-mocks: Generate mock files
generate-mocks:
	@echo "Generating mocks..."
	@if command -v mockgen > /dev/null; then \
		mockgen -source=pkg/scan/scanner.go -destination=internal/testutil/mocks/scanner_mock.go -package=mocks; \
		mockgen -source=pkg/attest/attestor.go -destination=internal/testutil/mocks/attestor_mock.go -package=mocks; \
		mockgen -source=pkg/stream/streamer.go -destination=internal/testutil/mocks/streamer_mock.go -package=mocks; \
	else \
		echo "mockgen not installed. Run 'make install-tools'"; \
	fi

## proto: Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@if [ -d "api/proto" ]; then \
		protoc --go_out=. --go-grpc_out=. api/proto/*.proto; \
	else \
		echo "No proto files found in api/proto/"; \
	fi

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

## docker-push: Push Docker image
docker-push:
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest

## dev-services: Start development dependencies
dev-services:
	@echo "Starting development services..."
	docker-compose -f docker-compose.dev.yml up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Development services started!"
	@echo "  Redis: localhost:6379"
	@echo "  Kafka: localhost:9092"

## dev-services-down: Stop development dependencies
dev-services-down:
	@echo "Stopping development services..."
	docker-compose -f docker-compose.dev.yml down

## run-server: Run the server locally
run-server: build-server
	@echo "Running server..."
	./bin/$(BINARY_NAME)

## install-tools: Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install go.uber.org/mock/mockgen@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Tools installed!"
