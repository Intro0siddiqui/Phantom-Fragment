package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/you/ai-sandbox/internal/config"
	"github.com/you/ai-sandbox/internal/supervisor"
)

func main() {
	// Initialize configuration
	cfg := &config.Config{}

	// Create supervisor service
	svc, err := supervisor.NewService(cfg)
	if err != nil {
		log.Fatalf("Failed to create supervisor service: %v", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the service
	if err := svc.Start(ctx); err != nil {
		log.Fatalf("Failed to start supervisor service: %v", err)
	}

	log.Println("Supervisor service started successfully")
	log.Println("Endpoints available:")
	log.Println("  - Health: http://localhost:8080/health")
	log.Println("  - Metrics: http://localhost:8080/metrics")
	log.Println("  - API: http://localhost:8080/api/v1")

	// Wait for shutdown signal
	<-sigChan
	log.Println("Received shutdown signal, stopping service...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := svc.Stop(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("Supervisor service stopped")
}