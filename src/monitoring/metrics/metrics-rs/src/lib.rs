//! Metrics Collector
//!
//! Collects and exports system metrics (CPU, memory, I/O) in Prometheus format.

use prometheus::{Encoder, Gauge, IntCounter, Registry, TextEncoder};
use std::sync::Arc;
use types_rs::PhantomError;

#[cfg(feature = "server")]
pub mod server;

lazy_static::lazy_static! {
    static ref REGISTRY: Registry = Registry::new();

    static ref CONTAINER_COUNT: Gauge = Gauge::new(
        "phantom_container_count",
        "Number of active containers"
    ).unwrap();

    static ref MEMORY_USAGE: Gauge = Gauge::new(
        "phantom_memory_usage_bytes",
        "Total memory usage in bytes"
    ).unwrap();

    static ref IO_OPS_TOTAL: IntCounter = IntCounter::new(
        "phantom_io_ops_total",
        "Total I/O operations performed"
    ).unwrap();
}

/// Metrics Collector
pub struct MetricsCollector {
    registry: Arc<Registry>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        // Register default metrics
        let registry = &*REGISTRY;
        registry
            .register(Box::new(CONTAINER_COUNT.clone()))
            .unwrap();
        registry.register(Box::new(MEMORY_USAGE.clone())).unwrap();
        registry.register(Box::new(IO_OPS_TOTAL.clone())).unwrap();

        Self {
            registry: Arc::new(registry.clone()),
        }
    }

    /// Update container count
    pub fn set_container_count(&self, count: f64) {
        CONTAINER_COUNT.set(count);
    }

    /// Update memory usage
    pub fn set_memory_usage(&self, bytes: f64) {
        MEMORY_USAGE.set(bytes);
    }

    /// Increment I/O operations
    pub fn inc_io_ops(&self) {
        IO_OPS_TOTAL.inc();
    }

    /// Export metrics in Prometheus text format
    pub fn export(&self) -> Result<String, PhantomError> {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();

        encoder
            .encode(&self.registry.gather(), &mut buffer)
            .map_err(|e| PhantomError::Internal(format!("Failed to encode metrics: {}", e)))?;

        String::from_utf8(buffer)
            .map_err(|e| PhantomError::Internal(format!("Invalid UTF-8 in metrics: {}", e)))
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_export() {
        let collector = MetricsCollector::new();

        collector.set_container_count(5.0);
        collector.set_memory_usage(1024.0);
        collector.inc_io_ops();

        let output = collector.export().unwrap();

        assert!(output.contains("phantom_container_count 5"));
        assert!(output.contains("phantom_memory_usage_bytes 1024"));
        assert!(output.contains("phantom_io_ops_total 1"));
    }
}
