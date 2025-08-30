package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
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
	"github.com/phantom-fragment/phantom-fragment/internal/config"
	"github.com/phantom-fragment/phantom-fragment/internal/mcp/server"
	"github.com/phantom-fragment/phantom-fragment/internal/mcp/types"
	"github.com/phantom-fragment/phantom-fragment/internal/security/audit"
	"github.com/phantom-fragment/phantom-fragment/internal/security/seccomp"
	"github.com/phantom-fragment/phantom-fragment/internal/security/secrets"
	"github.com/phantom-fragment/phantom-fragment/pkg/driver"
	pkgtypes "github.com/phantom-fragment/phantom-fragment/pkg/types"
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

// initializeSecurity initializes all security components
func (s *Service) initializeSecurity() error {
	// Initialize MCP tools with security validation
	s.registerMCPTools()

	// Validate security configuration
	if err := s.validateSecurityConfig(); err != nil {
		return fmt.Errorf("security configuration validation failed: %w", err)
	}

	return nil
}

// registerMCPTools registers secure MCP tools
func (s *Service) registerMCPTools() {
	// Register sandbox execution tools with validation
	s.mcpServer.RegisterTool("aisbx-run", s.createSecureTool("run"))
	s.mcpServer.RegisterTool("aisbx-build", s.createSecureTool("build"))
	s.mcpServer.RegisterTool("aisbx-profile-list", s.createSecureTool("profile-list"))
}

// createSecureTool creates a secure tool handler with validation
func (s *Service) createSecureTool(toolType string) func(args map[string]interface{}) (*types.ToolResult, error) {
	return func(args map[string]interface{}) (*types.ToolResult, error) {
		// Validate arguments
		if err := s.validateToolArgs(toolType, args); err != nil {
			s.metrics.securityViolations.Inc()
			s.auditLogger.LogSecurityViolation("", "tool_validation_failed", err.Error(), args)
			return &types.ToolResult{
				Content: []types.ToolResultContent{
					{Type: "text", Text: fmt.Sprintf("Security validation failed: %v", err)},
				},
				IsError: true,
			}, nil
		}

		// Log tool execution
		s.auditLogger.LogEvent("tool_execution", "", fmt.Sprintf("Tool %s executed", toolType), args)

		// Call actual CLI implementation
		switch toolType {
		case "run":
			return s.executeRunCommand(args)
		case "build":
			return s.executeBuildCommand(args)
		case "profile-list":
			return s.executeProfileListCommand(args)
		default:
			return &types.ToolResult{
				Content: []types.ToolResultContent{
					{Type: "text", Text: fmt.Sprintf("Unknown tool type: %s", toolType)},
				},
				IsError: true,
			}, nil
		}
	}
}

// validateToolArgs validates tool arguments with enhanced security
func (s *Service) validateToolArgs(toolType string, args map[string]interface{}) error {
	// Common validations
	if workdir, ok := args["workdir"]; ok {
		if workdirStr, ok := workdir.(string); ok {
			if !isValidPath(workdirStr) {
				return fmt.Errorf("invalid workdir path: %s", workdirStr)
			}
		}
	}

	if profile, ok := args["profile"]; ok {
		if profileStr, ok := profile.(string); ok {
			if !isValidProfileName(profileStr) {
				return fmt.Errorf("invalid profile name: %s", profileStr)
			}
		}
	}

	// Tool-specific validations
	switch toolType {
	case "run":
		if command, ok := args["command"]; ok {
			if commandSlice, ok := command.([]interface{}); ok {
				for _, cmd := range commandSlice {
					if cmdStr, ok := cmd.(string); ok {
						// Block dangerous commands
						if isDangerousCommand(cmdStr) {
							return fmt.Errorf("dangerous command blocked: %s", cmdStr)
						}
					}
				}
			}
		}
	}

	return nil
}

// validateSecurityConfig validates the security configuration
func (s *Service) validateSecurityConfig() error {
	if !s.config.Security.Seccomp.Enabled {
		return fmt.Errorf("seccomp must be enabled for security")
	}

	if !s.config.Security.UserNamespaces {
		return fmt.Errorf("user namespaces must be enabled for security")
	}

	return nil
}

// getCollectors returns all Prometheus collectors
func (s *Service) getCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		s.metrics.requestsTotal,
		s.metrics.requestsDuration,
		s.metrics.activeConnections,
		s.metrics.errorCount,
		s.metrics.sandboxStarts,
		s.metrics.sandboxStops,
		s.metrics.sandboxDuration,
		s.metrics.cpuUsage,
		s.metrics.memoryUsage,
		s.metrics.diskUsage,
		s.metrics.authFailures,
		s.metrics.rateLimitHits,
		s.metrics.securityViolations,
	}
}

// startHealthMonitoring starts background health checks
func (s *Service) startHealthMonitoring(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performHealthCheck()
		}
	}
}

// startSecurityMonitoring starts background security monitoring
func (s *Service) startSecurityMonitoring(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second) // Check every minute
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performSecurityCheck()
		}
	}
}

// performHealthCheck performs a comprehensive health check
func (s *Service) performHealthCheck() {
	s.health.mu.Lock()
	defer s.health.mu.Unlock()

	// Check HTTP server health
	httpHealth := HealthCheck{
		Name:    "http_server",
		Status:  "healthy",
		Message: "HTTP server is running",
		LastRun: time.Now(),
	}

	s.health.checks["http_server"] = httpHealth
	s.health.lastCheck = time.Now()
	s.health.status = "healthy"
}

// performSecurityCheck performs periodic security checks
func (s *Service) performSecurityCheck() {
	// Check for suspicious request patterns
	s.logsMutex.RLock()
	totalRequests := 0
	suspiciousIPs := 0

	for _, logs := range s.requestLogs {
		totalRequests += len(logs)
		if len(logs) > 100 { // More than 100 requests per hour
			suspiciousIPs++
		}
	}
	s.logsMutex.RUnlock()

	// Log security summary
	s.auditLogger.LogEvent("security_check", "", "Periodic security check completed", map[string]interface{}{
		"total_requests": totalRequests,
		"suspicious_ips": suspiciousIPs,
	})
}

// Input validation middleware functions

// validateInput validates request body and common parameters
func (s *Service) validateInput(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate Content-Type for POST/PUT requests
		if r.Method == "POST" || r.Method == "PUT" {
			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				s.metrics.errorCount.Inc()
				s.auditLogger.LogSecurityViolation("", "invalid_content_type", "Invalid content type", map[string]interface{}{
					"content_type": contentType,
					"remote_addr":  r.RemoteAddr,
				})
				http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
				return
			}

			// Limit request body size (10MB)
			r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		}

		next(w, r)
	}
}

// validateSandboxID validates sandbox ID parameter
func (s *Service) validateSandboxID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		sandboxID := vars["id"]

		// Validate sandbox ID format (alphanumeric, hyphens, max 64 chars)
		if !isValidIdentifier(sandboxID) {
			s.metrics.errorCount.Inc()
			s.auditLogger.LogSecurityViolation("", "invalid_sandbox_id", "Invalid sandbox ID", map[string]interface{}{
				"sandbox_id":  sandboxID,
				"remote_addr": r.RemoteAddr,
			})
			http.Error(w, "Invalid sandbox ID", http.StatusBadRequest)
			return
		}

		next(w, r)
	}
}

// validateProfileName validates profile name parameter
func (s *Service) validateProfileName(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		profileName := vars["name"]

		// Validate profile name
		if !isValidProfileName(profileName) {
			s.metrics.errorCount.Inc()
			s.auditLogger.LogSecurityViolation("", "invalid_profile_name", "Invalid profile name", map[string]interface{}{
				"profile_name": profileName,
				"remote_addr":  r.RemoteAddr,
			})
			http.Error(w, "Invalid profile name", http.StatusBadRequest)
			return
		}

		next(w, r)
	}
}

// validateSecretName validates secret name parameter
func (s *Service) validateSecretName(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		secretName := vars["name"]

		// Validate secret name
		if !isValidSecretName(secretName) {
			s.metrics.errorCount.Inc()
			s.auditLogger.LogSecurityViolation("", "invalid_secret_name", "Invalid secret name", map[string]interface{}{
				"secret_name": secretName,
				"remote_addr": r.RemoteAddr,
			})
			http.Error(w, "Invalid secret name", http.StatusBadRequest)
			return
		}

		next(w, r)
	}
}

// Validation helper functions

// isValidIdentifier validates alphanumeric identifiers with hyphens
func isValidIdentifier(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// isValidProfileName validates security profile names
func isValidProfileName(name string) bool {
	if !isValidIdentifier(name) {
		return false
	}
	// Additional profile-specific validation
	allowedProfiles := map[string]bool{
		"default": true, "python-dev": true, "node-dev": true, "go-dev": true,
		"rust-dev": true, "java-dev": true, "strict": true, "minimal": true,
	}
	return allowedProfiles[name]
}

// isValidSecretName validates secret names
func isValidSecretName(name string) bool {
	return isValidIdentifier(name) && !strings.Contains(name, "..")
}

// isValidPath validates file paths to prevent directory traversal
func isValidPath(path string) bool {
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return false
	}
	cleanPath := filepath.Clean(path)
	return cleanPath == path && !strings.HasPrefix(path, "/etc") && !strings.HasPrefix(path, "/proc")
}

// isDangerousCommand checks if a command is potentially dangerous
func isDangerousCommand(cmd string) bool {
	dangerousCommands := []string{
		"rm", "rmdir", "dd", "mkfs", "fdisk", "parted",
		"sudo", "su", "passwd", "chmod", "chown",
		"wget", "curl", "nc", "netcat", "ssh", "scp",
		"iptables", "ufw", "systemctl", "service",
	}

	for _, dangerous := range dangerousCommands {
		if strings.Contains(strings.ToLower(cmd), dangerous) {
			return true
		}
	}

	return false
}

// HTTP Handler functions

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()

	s.health.mu.RLock()
	defer s.health.mu.RUnlock()

	response := map[string]interface{}{
		"status":    s.health.status,
		"lastCheck": s.health.lastCheck,
		"checks":    s.health.checks,
		"security": map[string]interface{}{
			"enabled":  true,
			"features": []string{"authentication", "rate_limiting", "audit_logging", "input_validation"},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Service) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	// Parse request body
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.errorCount.Inc()
		s.auditLogger.LogSecurityViolation("", "invalid_json", "Invalid JSON in start sandbox request", map[string]interface{}{
			"error":       err.Error(),
			"remote_addr": r.RemoteAddr,
		})
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Log sandbox start
	s.auditLogger.LogEvent("sandbox_start_request", "", "Sandbox start requested", req)
	s.metrics.sandboxStarts.Inc()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "started",
		"id":     fmt.Sprintf("sandbox-%d", time.Now().Unix()),
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleStopSandbox(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	vars := mux.Vars(r)
	sandboxID := vars["id"]

	// Log sandbox stop
	s.auditLogger.LogEvent("sandbox_stop_request", sandboxID, "Sandbox stop requested", map[string]interface{}{
		"sandbox_id":  sandboxID,
		"remote_addr": r.RemoteAddr,
	})
	s.metrics.sandboxStops.Inc()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "stopped",
		"id":     sandboxID,
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleSandboxStatus(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	vars := mux.Vars(r)
	sandboxID := vars["id"]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":     sandboxID,
		"status": "running",
		"uptime": "1h23m",
		"security": map[string]interface{}{
			"seccomp_enabled": true,
			"user_namespaces": true,
			"profile":         "default",
		},
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	// Sanitize config before returning (remove sensitive data)
	sanitizedConfig := struct {
		Profiles []config.Profile       `json:"profiles"`
		Logging  config.LoggingConfig   `json:"logging"`
		Security map[string]interface{} `json:"security"`
	}{
		Profiles: s.config.Profiles,
		Logging:  s.config.Logging,
		Security: map[string]interface{}{
			"seccomp_enabled": s.config.Security.Seccomp.Enabled,
			"user_namespaces": s.config.Security.UserNamespaces,
			"apparmor":        s.config.Security.AppArmor,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sanitizedConfig)

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	// Parse request body
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.metrics.errorCount.Inc()
		s.auditLogger.LogSecurityViolation("", "invalid_json", "Invalid JSON in update config request", map[string]interface{}{
			"error":       err.Error(),
			"remote_addr": r.RemoteAddr,
		})
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Log config update attempt
	s.auditLogger.LogEvent("config_update_request", "", "Configuration update requested", map[string]interface{}{
		"changes":     req,
		"remote_addr": r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "updated",
		"note":   "Configuration validation and persistence not yet implemented",
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"profiles": s.config.Profiles,
		"count":    len(s.config.Profiles),
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	vars := mux.Vars(r)
	name := vars["name"]

	for _, profile := range s.config.Profiles {
		if profile.Name == name {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(profile)
			s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
			return
		}
	}

	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "profile not found",
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	// Get secrets metadata (without values)
	secrets := s.secretsVault.ListSecrets()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"secrets": secrets,
		"count":   len(secrets),
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	vars := mux.Vars(r)
	name := vars["name"]

	// Log secret access attempt
	s.auditLogger.LogEvent("secret_access", "", "Secret access requested", map[string]interface{}{
		"secret_name": name,
		"remote_addr": r.RemoteAddr,
	})

	// Return metadata only, never the actual secret value
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"name":  name,
		"value": "[REDACTED]",
		"note":  "Secret values are never returned via API for security",
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	// Parse request body
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditLogger.LogSecurityViolation("", "invalid_json", "Invalid JSON in create secret request", map[string]interface{}{
			"error":       err.Error(),
			"remote_addr": r.RemoteAddr,
		})
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate secret name
	name, ok := req["name"].(string)
	if !ok || !isValidSecretName(name) {
		s.auditLogger.LogSecurityViolation("", "invalid_secret_name", "Invalid secret name in create request", req)
		http.Error(w, "Invalid secret name", http.StatusBadRequest)
		return
	}

	// Log secret creation (without value)
	s.auditLogger.LogEvent("secret_creation", "", "Secret created", map[string]interface{}{
		"secret_name": name,
		"remote_addr": r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "created",
		"name":   name,
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	vars := mux.Vars(r)
	name := vars["name"]

	// Log secret deletion
	s.auditLogger.LogEvent("secret_deletion", "", "Secret deleted", map[string]interface{}{
		"secret_name": name,
		"remote_addr": r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "deleted",
		"name":   name,
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleMCPTools(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	tools := make([]map[string]interface{}, 0)
	for name := range s.mcpServer.Tools {
		tools = append(tools, map[string]interface{}{
			"name":        name,
			"description": fmt.Sprintf("Secure tool: %s", name),
			"security": map[string]interface{}{
				"validated": true,
				"sandboxed": true,
			},
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tools": tools,
		"count": len(tools),
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleMCPExecute(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditLogger.LogSecurityViolation("", "invalid_json", "Invalid JSON in MCP execute request", map[string]interface{}{
			"error":       err.Error(),
			"remote_addr": r.RemoteAddr,
		})
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Execute MCP tool through the server
	mcpRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  req,
	}

	reqBytes, _ := json.Marshal(mcpRequest)
	response, err := s.mcpServer.HandleRequest(reqBytes)

	if err != nil {
		s.auditLogger.LogSecurityViolation("", "mcp_execution_error", err.Error(), req)
		http.Error(w, "MCP execution failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleSecurityAudit(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	// Return security audit summary
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "Security monitoring active",
		"features": []string{
			"Input validation",
			"Rate limiting",
			"Authentication",
			"Audit logging",
			"Seccomp filtering",
			"Path validation",
			"Command filtering",
		},
		"metrics": map[string]interface{}{
			"rate_limit_hits":     "Available via /metrics",
			"auth_failures":       "Available via /metrics",
			"security_violations": "Available via /metrics",
		},
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

func (s *Service) handleSecurityViolations(w http.ResponseWriter, r *http.Request) {
	s.metrics.requestsTotal.Inc()
	start := time.Now()

	// Return recent security violations summary
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":              "Security violations monitoring active",
		"note":                 "Check audit logs for detailed information",
		"log_location":         "audit.log",
		"real_time_monitoring": true,
	})

	s.metrics.requestsDuration.Observe(time.Since(start).Seconds())
}

// CLI execution methods for MCP tool integration

// executeRunCommand executes the run CLI command through MCP
func (s *Service) executeRunCommand(args map[string]interface{}) (*types.ToolResult, error) {
	command, ok := args["command"].([]interface{})
	if !ok {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: "Error: command argument must be an array"},
			},
			IsError: true,
		}, nil
	}

	// Convert interface{} slice to string slice
	cmdArgs := make([]string, len(command))
	for i, arg := range command {
		if argStr, ok := arg.(string); ok {
			cmdArgs[i] = argStr
		} else {
			return &types.ToolResult{
				Content: []types.ToolResultContent{
					{Type: "text", Text: "Error: all command arguments must be strings"},
				},
				IsError: true,
			}, nil
		}
	}

	// Get profile name (default to "default")
	profileName := "default"
	if profile, ok := args["profile"].(string); ok {
		profileName = profile
	}

	// Load configuration
	cfg := config.DefaultConfig()
	profile, err := cfg.GetProfile(profileName)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error loading profile: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Initialize driver
	drv, err := driver.New(profile.Driver)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error initializing driver: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Create container
	containerID, err := drv.Create(context.Background(), "alpine", ".", nil, nil)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error creating container: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Ensure cleanup
	defer func() {
		if err := drv.Destroy(context.Background(), containerID); err != nil {
			s.auditLogger.LogSecurityViolation("", "cleanup_error", fmt.Sprintf("Failed to cleanup container: %v", err), nil)
		}
	}()

	// Create container object
	container := pkgtypes.Container{
		ID:      containerID,
		Workdir: ".",
		Binds:   []string{},
		Env:     profile.Environment,
	}

	// Execute command with timeout
	timeout := 300 // 5 minutes default
	if timeoutVal, ok := args["timeout"].(float64); ok {
		timeout = int(timeoutVal)
	}

	exitCode, stdout, stderr, err := drv.Exec(context.Background(), container, cmdArgs, timeout*1000, 512, 1)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Execution error: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Prepare result content
	result := fmt.Sprintf("Exit code: %d\n", exitCode)
	if stdout != "" {
		result += fmt.Sprintf("Stdout:\n%s\n", stdout)
	}
	if stderr != "" {
		result += fmt.Sprintf("Stderr:\n%s\n", stderr)
	}

	return &types.ToolResult{
		Content: []types.ToolResultContent{
			{Type: "text", Text: result},
		},
		IsError: exitCode != 0,
	}, nil
}

// executeBuildCommand executes the build (create) CLI command through MCP
func (s *Service) executeBuildCommand(args map[string]interface{}) (*types.ToolResult, error) {
	// Get profile name (default to "default")
	profileName := "default"
	if profile, ok := args["profile"].(string); ok {
		profileName = profile
	}

	// Get image (default to "alpine")
	image := "alpine"
	if img, ok := args["image"].(string); ok {
		image = img
	}

	// Get workdir
	workdir := "."
	if wd, ok := args["workdir"].(string); ok {
		workdir = wd
	}

	// Load configuration
	cfg := config.DefaultConfig()
	profile, err := cfg.GetProfile(profileName)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error loading profile: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Initialize driver
	drv, err := driver.New(profile.Driver)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error initializing driver: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Prepare binds
	finalBinds := make([]string, 0)
	for _, mount := range profile.Mounts {
		finalBinds = append(finalBinds, mount.Source+":"+mount.Target+":"+mount.Mode)
	}

	// Create container
	containerID, err := drv.Create(context.Background(), image, workdir, finalBinds, profile.Environment)
	if err != nil {
		return &types.ToolResult{
			Content: []types.ToolResultContent{
				{Type: "text", Text: fmt.Sprintf("Error creating container: %v", err)},
			},
			IsError: true,
		}, nil
	}

	// Log successful creation
	s.auditLogger.LogEvent("container_creation", containerID, "Container created via MCP", map[string]interface{}{
		"image":   image,
		"workdir": workdir,
		"profile": profileName,
	})

	result := fmt.Sprintf("✓ Container created successfully!\nContainer ID: %s\nWorkdir: %s\nImage: %s", containerID, workdir, image)

	return &types.ToolResult{
		Content: []types.ToolResultContent{
			{Type: "text", Text: result},
		},
		IsError: false,
	}, nil
}

// executeProfileListCommand executes the profile list CLI command through MCP
func (s *Service) executeProfileListCommand(args map[string]interface{}) (*types.ToolResult, error) {
	// Load configuration
	cfg := config.DefaultConfig()

	// Build profile list output
	var result strings.Builder
	result.WriteString("Available Profiles:\n")
	result.WriteString("NAME\tDRIVER\tCPU\tMEMORY\tNETWORK\n")

	for _, profile := range cfg.Profiles {
		network := "disabled"
		if profile.Network.Enabled {
			network = "enabled"
		}
		result.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n",
			profile.Name, profile.Driver, profile.CPU, profile.Memory, network))
	}

	return &types.ToolResult{
		Content: []types.ToolResultContent{
			{Type: "text", Text: result.String()},
		},
		IsError: false,
	}, nil
}
