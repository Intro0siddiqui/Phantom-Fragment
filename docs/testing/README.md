# Phantom Fragment Testing Documentation

This document provides comprehensive information about the testing infrastructure for the Phantom Fragment system.

## Overview

The Phantom Fragment testing suite consists of multiple layers of testing to ensure system reliability, performance, and security:

- **Unit Tests**: Test individual components and functions
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **Performance Tests**: Validate performance characteristics
- **Security Tests**: Validate security features
- **Validation Tools**: Automated validation and verification

## Test Structure

```
src/tools/integration-tests/
├── src/
│   ├── lib.rs                      # Test helpers
│   ├── execution_integration_tests.rs
│   ├── security_integration_tests.rs
│   ├── storage_integration_tests.rs
│   └── system_tests.rs

src/
├── core/
│   └── */src/lib.rs        # Unit tests in each crate
├── security/
│   └── */src/lib.rs        # Security component tests
└── ...
```

## Running Tests

### Unit Tests

Run all unit tests:
```bash
cargo test
```

Run unit tests for a specific crate:
```bash
cargo test -p execution-rs
```

Run with verbose output:
```bash
cargo test -- --nocapture
```

### Integration Tests

Run integration tests:
```bash
cargo test --release -p integration-tests
```

## Validation Tools

### Using the C Validation Tool

The C validation tool provides automated testing and verification:

```c
#include <stdio.h>
#include <stdlib.h>
#include "validator.h"

// Forward declarations for the functions in the library
ValidationSuite* run_validation_suite(ValidationSuite* suite);
ValidationResult* validate_system_initialization(void* ctx);
ValidationResult* validate_fragment_creation(void* ctx);
ValidationResult* validate_container_spawning(void* ctx);
ValidationResult* validate_pool_warmup(void* ctx);

int main() {
    ValidationTest tests[] = {
        {
            .name = "system-initialization",
            .description = "Test system component initialization",
            .validator = validate_system_initialization,
            .timeout_seconds = 30,
            .required = true,
        },
        // ... more tests
    };

    ValidationSuite suite = {
        .name = "basic-validation-c",
        .description = "Basic functionality validation tests in C",
        .tests = tests,
        .num_tests = sizeof(tests) / sizeof(tests[0]),
    };

    run_validation_suite(&suite);

    // Clean up results
    for (int i = 0; i < suite.num_results; i++) {
        // Free dynamically allocated strings
    }
    free(suite.results);

    return 0;
}
```

### Running Validation Suites

Build and run the C validation tool:
```bash
cd tools/validation-c
cmake .
make
./validation-c
```

The tool runs a basic validation suite and outputs results to stdout.

## Test Examples

### Unit Test Example

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_fragment_creation() -> Result<()> {
        let mut registry = FragmentRegistry::new()?;
        
        let fragment = registry.create("test-fragment", "sandbox")?;
        
        assert!(!fragment.name.is_empty());
        assert_eq!(fragment.profile, "sandbox");
        assert!(matches!(fragment.status, FragmentStatus::Created));
        
        Ok(())
    }
}
```

### Integration Test Example

```rust
#[tokio::test]
async fn test_full_workflow_integration() -> anyhow::Result<()> {
    // Setup components
    let config = Config::default();
    let mut registry = FragmentRegistry::new()?;
    
    // Test complete workflow
    let fragment = registry.create("integration-test", "sandbox")?;
    assert_eq!(fragment.name, "integration-test");
    
    // Simulate container execution
    let result = execute_in_fragment(&fragment, &["echo", "workflow test"]).await?;
    assert!(result.success);
    
    // Cleanup
    registry.destroy("integration-test")?;
    
    Ok(())
}
```

### Performance Test Example

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_spawn_throughput(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("spawn_container", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let request = SpawnRequest {
                    image: "bench-image".to_string(),
                    command: vec!["echo".to_string(), "benchmark".to_string()],
                    ..Default::default()
                };
                black_box(spawn_from_pool("bench-profile", request).await)
            })
        })
    });
}

criterion_group!(benches, benchmark_spawn_throughput);
criterion_main!(benches);
```

### Security Test Example

```rust
#[tokio::test]
async fn test_security_context_isolation() -> anyhow::Result<()> {
    let spawner = create_secure_spawner()?;
    
    // Test that different profiles get isolated security contexts
    let profiles = ["app1", "app2", "app3"];
    
    for profile in profiles {
        let request = SpawnRequest {
            image: "secure-image".to_string(),
            command: vec!["echo".to_string(), "security test".to_string()],
            ..Default::default()
        };
        
        let container = spawner.spawn_from_pool(profile, request).await?;
        assert!(container.is_some());
    }
    
    // Verify security stats
    let stats = spawner.get_optimization_stats();
    assert!(stats.security_reuse_hits + stats.security_reuse_misses > 0);
    
    Ok(())
}
```

## Test Configuration

### Test Environment Setup

Create a test configuration file:

```json
{
  "test_environment": {
    "temp_dir": "/tmp/phantom-tests",
    "test_images": [
      "ubuntu:latest",
      "alpine:latest",
      "nginx:latest"
    ],
    "timeouts": {
      "unit_test": "30s",
      "integration_test": "2m",
      "e2e_test": "5m",
      "performance_test": "10m"
    }
  }
}
```

### Performance Test Configuration

```json
{
  "performance_tests": {
    "spawn_throughput": {
      "target_operations": 1000,
      "min_throughput": 50.0,
      "max_latency_p95": "100ms"
    },
    "memory_efficiency": {
      "max_memory_per_fragment": "1MB",
      "max_memory_per_container": "512KB"
    },
    "concurrent_load": {
      "threads": 50,
      "operations_per_thread": 20,
      "min_efficiency": 0.8
    }
  }
}
```

## Test Data

### Sample Test Data

Test data is located in the `testdata/` directory:

- `testdata/mcp/` - MCP protocol test data
- `testdata/images/` - Test container images
- `testdata/configs/` - Test configuration files

### Generating Test Data

```bash
# Generate test fragments
cargo run -p phantom-cli -- create --name test-fragment-1 --profile sandbox

# Run benchmarks with custom iterations
cargo bench -- --sample-size 100

# Generate performance baseline
cargo run --release -p phantom-cli -- metrics > baseline.json
```

## Continuous Integration

### CI Configuration

Example GitHub Actions configuration:

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Rust
      uses: dtolnay/rust-action@stable
      with:
        toolchain: stable
        components: clippy, rustfmt

    - name: Set up Zig
      uses: goto-bus-stop/setup-zig@v2
      with:
        version: 0.11.0

    - name: Run unit tests
      run: cargo test --workspace

    - name: Run clippy
      run: cargo clippy --workspace -- -D warnings

    - name: Run benchmarks
      run: cargo bench --no-run

    - name: Upload test results
      uses: actions/upload-artifact@v4
      with:
        name: test-results
        path: target/criterion/
```

### Test Reporting

Test results are automatically generated in multiple formats:

- **JUnit XML**: For CI integration (via `cargo2junit`)
- **JSON**: For programmatic processing
- **HTML**: For human-readable reports (Criterion benchmarks)
- **Coverage Reports**: For code coverage analysis (via `cargo-tarpaulin`)

## Best Practices

### Writing Tests

1. **Use descriptive test names** that explain what is being tested
2. **Follow the AAA pattern**: Arrange, Act, Assert
3. **Test one thing per test** function
4. **Use parameterized tests** for multiple scenarios
5. **Mock external dependencies** appropriately
6. **Include performance benchmarks** for critical paths

### Test Organization

1. **Group related tests** in the same module
2. **Use feature flags** to separate different test types
3. **Create helper functions** for common test setup
4. **Document test requirements** and assumptions
5. **Include cleanup** in test teardown (use `Drop` trait)

### Performance Testing

1. **Warm up** the system before measuring
2. **Run tests multiple times** for statistical significance
3. **Monitor system resources** during tests
4. **Set realistic performance targets**
5. **Test under various load conditions**

### Security Testing

1. **Test security boundaries** between components
2. **Validate security context isolation**
3. **Test resource limit enforcement**
4. **Verify attack surface reduction**
5. **Test security feature integration**

## Troubleshooting

### Common Issues

**Tests failing due to timing issues:**
- Increase timeout values
- Add proper synchronization with `tokio::sync`
- Use deterministic test data

**Performance tests showing inconsistent results:**
- Run tests in isolated environment
- Disable background processes
- Use consistent hardware

**Security tests failing:**
- Ensure proper kernel support for LSM features
- Check capability requirements
- Verify namespace support

### Debug Mode

Enable debug logging for tests:

```bash
RUST_LOG=debug cargo test -- --nocapture
```

Run tests with thread sanitizer:

```bash
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test
```

Generate flamegraphs:

```bash
cargo flamegraph --test integration_tests
```

## Contributing

When adding new tests:

1. **Follow existing patterns** in the codebase
2. **Add appropriate documentation**
3. **Include examples** where helpful
4. **Update this README** if needed
5. **Run the full test suite** before submitting

## Related Documentation

- [Architecture Documentation](../architecture/)
- [Security Guide](../security/)
- [CLI Reference](../usage/cli-reference.md)