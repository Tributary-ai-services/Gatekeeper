// Package main provides the standalone Gatekeeper server binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Version information (set via ldflags)
var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "configs/gatekeeper.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version and exit
	if *showVersion {
		fmt.Printf("Gatekeeper v%s (built %s)\n", Version, BuildTime)
		os.Exit(0)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
		cancel()
	}()

	// TODO: Load configuration from configPath
	_ = configPath

	// TODO: Initialize components:
	// - Scanner (with pattern registry)
	// - Attestor (with signer and cache)
	// - Tokenizer (Databunker client)
	// - Streamer (Kafka producer)
	// - Action Engine
	// - Extractor (optional)
	// - Processor (orchestrates all components)

	// TODO: Start servers:
	// - HTTP server (Gin)
	// - gRPC server
	// - Metrics server (Prometheus)

	fmt.Println("Gatekeeper server starting...")
	fmt.Printf("Version: %s, Build: %s\n", Version, BuildTime)
	fmt.Println("Server not yet implemented - scaffolding only")

	// Wait for shutdown
	<-ctx.Done()
	fmt.Println("Gatekeeper server stopped")
}
