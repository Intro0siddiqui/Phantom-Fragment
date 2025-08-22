package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collector holds all the Prometheus metrics for the sandbox
type Collector struct {
	RunDuration       *prometheus.HistogramVec
	OOMs              *prometheus.CounterVec
	DeniedSyscalls    *prometheus.CounterVec
	CacheHitRate      *prometheus.GaugeVec
	NetworkViolations *prometheus.CounterVec
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		RunDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sandbox_run_duration_seconds",
			Help: "Duration of sandbox runs in seconds",
		}, []string{"container_id"}),
		OOMs: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "sandbox_oom_events_total",
			Help: "Total number of out-of-memory events",
		}, []string{"container_id"}),
		DeniedSyscalls: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "sandbox_denied_syscalls_total",
			Help: "Total number of denied system calls",
		}, []string{"container_id", "syscall"}),
		CacheHitRate: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sandbox_cache_hit_rate",
			Help: "Cache hit rate for the sandbox",
		}, []string{"cache_type"}),
		NetworkViolations: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "sandbox_network_violations_total",
			Help: "Total number of network policy violations",
		}, []string{"container_id", "violation_type"}),
	}
}

// RecordRunDuration records the duration of a sandbox run
func (c *Collector) RecordRunDuration(containerID string, durationSeconds float64) {
	c.RunDuration.WithLabelValues(containerID).Observe(durationSeconds)
}

// RecordOOM records an out-of-memory event
func (c *Collector) RecordOOM(containerID string) {
	c.OOMs.WithLabelValues(containerID).Inc()
}

// RecordDeniedSyscall records a denied system call
func (c *Collector) RecordDeniedSyscall(containerID, syscall string) {
	c.DeniedSyscalls.WithLabelValues(containerID, syscall).Inc()
}

// SetCacheHitRate sets the cache hit rate
func (c *Collector) SetCacheHitRate(cacheType string, rate float64) {
	c.CacheHitRate.WithLabelValues(cacheType).Set(rate)
}

// RecordNetworkViolation records a network policy violation
func (c *Collector) RecordNetworkViolation(containerID, violationType string) {
	c.NetworkViolations.WithLabelValues(containerID, violationType).Inc()
}
