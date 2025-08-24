package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/you/ai-sandbox/internal/config"
	"github.com/you/ai-sandbox/internal/mcp/server"
	"github.com/you/ai-sandbox/internal/security/audit"
	"github.com/you/ai-sandbox/internal/security/seccomp"
	"github.com/you/ai-sandbox/internal/security/secrets"
)

// RateLimiter interface for rate limiting functionality
type RateLimiter interface {
	Allow() bool
}

// SimpleRateLimiter implements basic rate limiting
type SimpleRateLimiter struct {
	mu       sync.Mutex
	requests []time.Time
	limit    int
	window   time.Duration
}

// NewSimpleRateLimiter creates a new rate limiter
func NewSimpleRateLimiter(limit int, window time.Duration) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		requests: make([]time.Time, 0),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request is allowed under the rate limit
func (rl *SimpleRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Remove old requests
	validRequests := rl.requests[:0]
	for _, req := range rl.requests {
		if req.After(cutoff) {
			validRequests = append(validRequests, req)
		}
	}
	rl.requests = validRequests

	// Check limit
	if len(rl.requests) >= rl.limit {
		return false
	}

	// Add current request
	rl.requests = append(rl.requests, now)
	return true
}

// Service represents the supervisor micro-service
type Service struct {
	config     *config.Config
	router     *mux.Router
	httpServer *http.Server
	mu         sync.RWMutex

	// Metrics
	metrics *Metrics

	// Health check
	health *HealthChecker

	// Security components
	mcpServer    *server.Server
	auditLogger  *audit.Logger
	seccompMgr   *seccomp.Manager
	secretsVault *secrets.Vault

	// Security & rate limiting
	apiKey      string
	rateLimiter RateLimiter
	requestLogs map[string][]time.Time
	logsMutex   sync.RWMutex
}

// Metrics holds Prometheus metrics
type Metrics struct {
	requestsTotal      prometheus.Counter
	requestsDuration   prometheus.Histogram
	activeConnections  prometheus.Gauge
	errorCount         prometheus.Counter
	sandboxStarts      prometheus.Counter
	sandboxStops       prometheus.Counter
	sandboxDuration    prometheus.Histogram
	cpuUsage           prometheus.Gauge
	memoryUsage        prometheus.Gauge
	diskUsage          prometheus.Gauge
	authFailures       prometheus.Counter
	rateLimitHits      prometheus.Counter
	securityViolations prometheus.Counter
}

// HealthChecker provides health monitoring
type HealthChecker struct {
	lastCheck time.Time
	status    string
	checks    map[string]HealthCheck
	mu        sync.RWMutex
}

// HealthCheck represents a single health check
type HealthCheck struct {
	Name    string
	Status  string
	Message string
	LastRun time.Time
}

// NewService creates a new supervisor service
func NewService(cfg *config.Config) (*Service, error) {
	// Generate API key for authentication
	apiKey, err := generateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Initialize audit logger
	auditLogger := audit.NewLogger(filepath.Join(cfg.Logging.File, "audit.log"))

	// Initialize security components
	seccompMgr := seccomp.NewManager(cfg)
	secretsVault, err := secrets.NewVault()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secrets vault: %w", err)
	}

	// Initialize MCP server
	mcpServer := server.NewServer()

	svc := &Service{
		config:       cfg,
		router:       mux.NewRouter(),
		metrics:      newMetrics(),
		health:       newHealthChecker(),
		mcpServer:    mcpServer,
		auditLogger:  auditLogger,
		seccompMgr:   seccompMgr,
		secretsVault: secretsVault,
		apiKey:       apiKey,
		rateLimiter:  NewSimpleRateLimiter(100, time.Minute), // 100 req/min
		requestLogs:  make(map[string][]time.Time),
	}

	// Setup routes with security middleware
	svc.setupRoutes()

	// Initialize HTTP server with security headers
	svc.httpServer = &http.Server{
		Addr:         ":8080",
		Handler:      svc.securityMiddleware(svc.router),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return svc, nil
}

// generateAPIKey generates a secure API key
func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

// newMetrics creates Prometheus metrics
func newMetrics() *Metrics {
	return &Metrics{
		requestsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aisbx_requests_total",
				Help: "Total number of requests",
			},
		),
		requestsDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "aisbx_request_duration_seconds",
				Help:    "Request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
		),
		activeConnections: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "aisbx_active_connections",
				Help: "Number of active connections",
			},
		),
		errorCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aisbx_errors_total",
				Help: "Total number of errors",
			},
		),
		sandboxStarts: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aisbx_sandbox_starts_total",
				Help: "Total number of sandbox starts",
			},
		),
		sandboxStops: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aisbx_sandbox_stops_total",
				Help: "Total number of sandbox stops",
			},
		),
		sandboxDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "aisbx_sandbox_duration_seconds",
				Help:    "Sandbox execution duration",
				Buckets: prometheus.DefBuckets,
			},
		),
		cpuUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "aisbx_cpu_usage_percent",
				Help: "CPU usage percentage",
			},
		),
		memoryUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "aisbx_memory_usage_bytes",
				Help: "Memory usage in bytes",
			},
		),
		diskUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "aisbx_disk_usage_bytes",
				Help: "Disk usage in bytes",
			},
		),
		authFailures: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aisbx_auth_failures_total",
				Help: "Total number of authentication failures",
			},
		),
		rateLimitHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aisbx_rate_limit_hits_total",
				Help: "Total number of rate limit hits",
			},
		),
		securityViolations: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "aisbx_security_violations_total",
				Help: "Total number of security violations",
			},
		),
	}
}

// newHealthChecker creates a health checker
func newHealthChecker() *HealthChecker {
	return &HealthChecker{
		status: "starting",
		checks: make(map[string]HealthCheck),
	}
}

// setupRoutes configures HTTP routes with security enhancements
func (s *Service) setupRoutes() {
	// Prometheus metrics
	s.router.Handle("/metrics", promhttp.Handler())

	// Health check
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// API routes with authentication
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Sandbox management with input validation
	api.HandleFunc("/sandbox/start", s.validateInput(s.handleStartSandbox)).Methods("POST")
	api.HandleFunc("/sandbox/stop/{id}", s.validateSandboxID(s.handleStopSandbox)).Methods("POST")
	api.HandleFunc("/sandbox/status/{id}", s.validateSandboxID(s.handleSandboxStatus)).Methods("GET")

	// Configuration with validation
	api.HandleFunc("/config", s.handleGetConfig).Methods("GET")
	api.HandleFunc("/config", s.validateInput(s.handleUpdateConfig)).Methods("PUT")

	// Profiles with validation
	api.HandleFunc("/profiles", s.handleListProfiles).Methods("GET")
	api.HandleFunc("/profiles/{name}", s.validateProfileName(s.handleGetProfile)).Methods("GET")

	// Secrets with enhanced security
	api.HandleFunc("/secrets", s.handleListSecrets).Methods("GET")
	api.HandleFunc("/secrets/{name}", s.validateSecretName(s.handleGetSecret)).Methods("GET")
	api.HandleFunc("/secrets", s.validateInput(s.handleCreateSecret)).Methods("POST")
	api.HandleFunc("/secrets/{name}", s.validateSecretName(s.handleDeleteSecret)).Methods("DELETE")

	// MCP endpoints
	api.HandleFunc("/mcp/tools", s.handleMCPTools).Methods("GET")
	api.HandleFunc("/mcp/execute", s.validateInput(s.handleMCPExecute)).Methods("POST")

	// Security monitoring
	api.HandleFunc("/security/audit", s.handleSecurityAudit).Methods("GET")
	api.HandleFunc("/security/violations", s.handleSecurityViolations).Methods("GET")
}

// securityMiddleware applies security headers and authentication
func (s *Service) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Skip auth for health and metrics endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		// Rate limiting
		if !s.rateLimiter.Allow() {
			s.metrics.rateLimitHits.Inc()
			s.auditLogger.LogSecurityViolation("", "rate_limit", "Rate limit exceeded", map[string]interface{}{
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
			})
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Authentication for API endpoints
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				apiKey = r.URL.Query().Get("api_key")
			}

			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(s.apiKey)) != 1 {
				s.metrics.authFailures.Inc()
				s.auditLogger.LogSecurityViolation("", "auth_failure", "Invalid API key", map[string]interface{}{
					"remote_addr": r.RemoteAddr,
					"user_agent":  r.UserAgent(),
					"path":        r.URL.Path,
				})
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// Log request for monitoring
		s.logRequest(r.RemoteAddr)

		next.ServeHTTP(w, r)
	})
}

// logRequest tracks request frequency for anomaly detection
func (s *Service) logRequest(remoteAddr string) {
	s.logsMutex.Lock()
	defer s.logsMutex.Unlock()

	now := time.Now()
	logs := s.requestLogs[remoteAddr]

	// Remove old entries (older than 1 hour)
	cutoff := now.Add(-time.Hour)
	var filtered []time.Time
	for _, t := range logs {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}

	// Add current request
	filtered = append(filtered, now)
	s.requestLogs[remoteAddr] = filtered

	// Alert if too many requests from same IP
	if len(filtered) > 1000 { // 1000 requests per hour threshold
		s.metrics.securityViolations.Inc()
		s.auditLogger.LogSecurityViolation("", "suspicious_activity", "High request frequency detected", map[string]interface{}{
			"remote_addr":   remoteAddr,
			"request_count": len(filtered),
			"time_window":   "1hour",
		})
	}
}

// Start starts the supervisor service with enhanced security monitoring
func (s *Service) Start(ctx context.Context) error {
	log.Printf("Starting supervisor service on :8080 with API key: %s", s.apiKey[:8]+"...")

	// Initialize security components
	if err := s.initializeSecurity(); err != nil {
		return fmt.Errorf("failed to initialize security: %w", err)
	}

	// Register metrics
	for _, collector := range s.getCollectors() {
		prometheus.MustRegister(collector)
	}

	// Start health monitoring
	go s.startHealthMonitoring(ctx)

	// Start security monitoring
	go s.startSecurityMonitoring(ctx)

	// Start HTTP server
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
			s.auditLogger.LogSecurityViolation("", "server_error", fmt.Sprintf("HTTP server error: %v", err), nil)
		}
	}()

	// Log startup
	s.auditLogger.LogEvent("service_start", "", "Supervisor service started", map[string]interface{}{
		"port":             8080,
		"security_enabled": true,
	})

	return nil
}

// Stop stops the supervisor service
func (s *Service) Stop(ctx context.Context) error {
	log.Printf("Stopping supervisor service")

	// Log shutdown
	s.auditLogger.LogEvent("service_stop", "", "Supervisor service stopping", nil)

	// Shutdown HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown HTTP server: %w", err)
	}

	return nil
}
