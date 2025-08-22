package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server represents the metrics HTTP server
type Server struct {
	addr   string
	server *http.Server
}

// NewServer creates a new metrics server
func NewServer(addr string) *Server {
	return &Server{
		addr: addr,
	}
}

// Start starts the metrics server
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		fmt.Printf("Metrics server listening on %s\n", s.addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Metrics server error: %v\n", err)
		}
	}()

	return nil
}

// Stop stops the metrics server
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}