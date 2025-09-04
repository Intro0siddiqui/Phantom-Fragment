# Phantom Utils

A performance-focused system utilities library for container orchestration and resource management.

## 🎯 Purpose

This library provides **on-demand, detachable functions** for system-level performance optimization without the overhead of the full phantom-fragment system.

## 📦 Installation

```bash
go get github.com/phantom-fragment/phantom-utils
```

## 🏗️ Architecture

### Core Modules (Load on Demand)

#### 1. `numa` - NUMA Topology Management
```go
import "github.com/phantom-fragment/phantom-utils/numa"

topology := numa.NewTopology()
cpus := topology.GetCPUsForNode(0)
memory := topology.GetMemoryInfo()
```

#### 2. `memory` - Advanced Memory Management
```go
import "github.com/phantom-fragment/phantom-utils/memory"

pool := memory.NewBufferPool(256 * 1024 * 1024)
buf := pool.Allocate(4096)
```

#### 3. `metrics` - System Monitoring
```go
import "github.com/phantom-fragment/phantom-utils/metrics"

collector := metrics.NewSystemCollector()
psi := collector.GetPSIMetrics()
```

#### 4. `platform` - Cross-Platform Abstractions
```go
import "github.com/phantom-fragment/phantom-utils/platform"

io := platform.NewFastIO()
mem := platform.NewMemoryManager()
```

## 🚀 Usage Patterns

### Minimal Import (Tree-Shaking Friendly)
```go
// Only import what you need
import (
    "github.com/phantom-fragment/phantom-utils/numa"
    "github.com/phantom-fragment/phantom-utils/memory"
)
```

### Zero-Dependency Fallbacks
All functions include graceful fallbacks for unsupported platforms.

### Performance Benchmarks
```bash
go test -bench=. ./...
```

## 🎯 Design Principles

1. **On-Demand Loading**: No global initialization
2. **Zero Overhead**: Only pay for what you use
3. **Cross-Platform**: Windows, Linux, macOS support
4. **Graceful Degradation**: Fallbacks for missing features
5. **Performance First**: Microsecond-level optimizations

## 📊 Performance Targets

| Operation | Target Latency | Platform Coverage |
|-----------|----------------|-------------------|
| NUMA Discovery | <1ms | 95% |
| Buffer Allocation | <5μs | 100% |
| PSI Monitoring | <100μs | 90% |
| I/O Fast Path | <10μs | 85% |

## 🔧 Development

```bash
# Run tests
go test ./...

# Run benchmarks
go test -bench=. ./...

# Generate documentation
godoc -http=:6060
```