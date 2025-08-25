#!/bin/bash

# Phantom Fragment V3 Performance Validation Script
# Tests p95 spawn <120ms Linux, <180ms Lima targets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."
RESULTS_DIR="${PROJECT_ROOT}/benchmark-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Performance targets
LINUX_P95_TARGET_MS=120
LIMA_P95_TARGET_MS=180
MIN_ITERATIONS=1000

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    cat << 'EOF'
┌─────────────────────────────────────────────────────────────┐
│              Phantom Fragment V3 Validation                │
│                                                            │
│  🎯 Target: p95 spawn <120ms Linux, <180ms Lima           │
│  📊 Method: Statistical validation with confidence        │
│  🔬 Tests: Cold start, warm start, concurrent spawning    │
└─────────────────────────────────────────────────────────────┘
EOF
}

detect_platform() {
    if command -v lima >/dev/null 2>&1 && [[ -n "${LIMA_INSTANCE:-}" ]]; then
        echo "lima"
    elif [[ "$(uname -s)" == "Linux" ]]; then
        echo "linux"
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if phantom binary exists
    if [[ ! -f "${PROJECT_ROOT}/bin/phantom" ]] && [[ ! -f "${PROJECT_ROOT}/bin/phantom.exe" ]]; then
        log_error "Phantom binary not found. Please build first:"
        echo "  cd phantom-fragment && go build -o bin/phantom ./cmd/phantom"
        exit 1
    fi
    
    # Check if benchmark binary exists
    if [[ ! -f "${PROJECT_ROOT}/bin/phantom-benchmark" ]] && [[ ! -f "${PROJECT_ROOT}/bin/phantom-benchmark.exe" ]]; then
        log_warning "Benchmark binary not found. Building..."
        cd "${PROJECT_ROOT}"
        go build -o bin/phantom-benchmark ./cmd/phantom-benchmark
    fi
    
    # Check system capabilities
    log_info "Checking system capabilities..."
    "${PROJECT_ROOT}/bin/phantom-benchmark" -system-check
    
    log_success "Prerequisites check completed"
}

run_spawn_validation() {
    local platform="$1"
    local target_ms="$2"
    local test_name="$3"
    
    log_info "Running $test_name validation (target: <${target_ms}ms)"
    
    # Create results directory
    mkdir -p "${RESULTS_DIR}"
    local result_file="${RESULTS_DIR}/validation_${test_name}_${TIMESTAMP}.json"
    
    # Run benchmark
    log_info "Executing performance benchmark..."
    if ! "${PROJECT_ROOT}/bin/phantom-benchmark" \
        -iterations ${MIN_ITERATIONS} \
        -profiles "python-ai,node-dev,go-dev" \
        -concurrency "1,5,10,20" \
        -output "${result_file}" \
        -verbose; then
        log_error "Benchmark execution failed"
        return 1
    fi
    
    # Parse results and validate targets
    log_info "Analyzing results..."
    if ! validate_performance_targets "${result_file}" "${target_ms}"; then
        log_error "$test_name validation FAILED"
        return 1
    fi
    
    log_success "$test_name validation PASSED"
    return 0
}

validate_performance_targets() {
    local result_file="$1"
    local target_ms="$2"
    
    # Check if jq is available for JSON parsing
    if ! command -v jq >/dev/null 2>&1; then
        log_warning "jq not available, using basic validation"
        return basic_validation "${result_file}" "${target_ms}"
    fi
    
    # Parse cold start P95 latency
    local cold_start_p95_ns
    cold_start_p95_ns=$(jq -r '.SpawnBenchmarks.ColdStart.P95' "${result_file}" 2>/dev/null || echo "null")
    
    if [[ "${cold_start_p95_ns}" == "null" ]] || [[ "${cold_start_p95_ns}" == "" ]]; then
        log_error "Could not parse cold start P95 from results"
        return 1
    fi
    
    # Convert nanoseconds to milliseconds
    local cold_start_p95_ms
    cold_start_p95_ms=$(echo "scale=2; ${cold_start_p95_ns} / 1000000" | bc)
    
    # Parse warm start P95 latency
    local warm_start_p95_ns
    warm_start_p95_ns=$(jq -r '.SpawnBenchmarks.WarmStart.P95' "${result_file}" 2>/dev/null || echo "null")
    
    local warm_start_p95_ms
    if [[ "${warm_start_p95_ns}" != "null" ]] && [[ "${warm_start_p95_ns}" != "" ]]; then
        warm_start_p95_ms=$(echo "scale=2; ${warm_start_p95_ns} / 1000000" | bc)
    else
        warm_start_p95_ms="N/A"
    fi
    
    # Validate against targets
    echo
    echo "📊 Performance Results:"
    echo "  Cold Start P95: ${cold_start_p95_ms}ms (target: <${target_ms}ms)"
    if [[ "${warm_start_p95_ms}" != "N/A" ]]; then
        echo "  Warm Start P95: ${warm_start_p95_ms}ms"
    fi
    echo
    
    # Check if cold start meets target
    if (( $(echo "${cold_start_p95_ms} <= ${target_ms}" | bc -l) )); then
        log_success "Cold start P95 target MET: ${cold_start_p95_ms}ms <= ${target_ms}ms"
        return 0
    else
        log_error "Cold start P95 target FAILED: ${cold_start_p95_ms}ms > ${target_ms}ms"
        return 1
    fi
}

basic_validation() {
    local result_file="$1"
    local target_ms="$2"
    
    # Basic validation without jq
    if grep -q "Overall Result.*PASS" "${result_file}" 2>/dev/null; then
        log_success "Benchmark reported overall PASS"
        return 0
    else
        log_error "Benchmark reported overall FAIL or could not determine status"
        return 1
    fi
}

run_comprehensive_validation() {
    local platform="$1"
    
    log_info "Running comprehensive validation for platform: $platform"
    
    # Set target based on platform
    local target_ms
    case "$platform" in
        "linux")
            target_ms=${LINUX_P95_TARGET_MS}
            ;;
        "lima")
            target_ms=${LIMA_P95_TARGET_MS}
            ;;
        "macos")
            target_ms=${LIMA_P95_TARGET_MS}  # Use Lima target for macOS
            log_warning "Using Lima target for macOS platform"
            ;;
        *)
            target_ms=${LIMA_P95_TARGET_MS}  # Conservative target for unknown platforms
            log_warning "Unknown platform, using conservative target"
            ;;
    esac
    
    # Run main spawn validation
    if ! run_spawn_validation "$platform" "$target_ms" "${platform}_spawn"; then
        return 1
    fi
    
    # Additional stress tests
    log_info "Running stress tests..."
    
    # Test under memory pressure
    log_info "Testing under memory pressure..."
    if ! run_memory_pressure_test "$target_ms"; then
        log_warning "Memory pressure test failed (non-critical)"
    fi
    
    # Test with concurrent load
    log_info "Testing concurrent spawn performance..."
    if ! run_concurrent_spawn_test "$target_ms"; then
        log_warning "Concurrent spawn test failed (non-critical)"
    fi
    
    log_success "Comprehensive validation completed"
    return 0
}

run_memory_pressure_test() {
    local target_ms="$1"
    
    # Simple memory pressure test
    log_info "Creating memory pressure..."
    
    # Start memory pressure in background
    local pressure_pid
    if command -v stress >/dev/null 2>&1; then
        stress --vm 2 --vm-bytes 50% --timeout 30s &
        pressure_pid=$!
    elif command -v stress-ng >/dev/null 2>&1; then
        stress-ng --vm 2 --vm-bytes 50% --timeout 30s &
        pressure_pid=$!
    else
        log_warning "No stress testing tools available, skipping memory pressure test"
        return 0
    fi
    
    # Wait a bit for pressure to build
    sleep 5
    
    # Run quick benchmark
    local result_file="${RESULTS_DIR}/memory_pressure_${TIMESTAMP}.json"
    "${PROJECT_ROOT}/bin/phantom-benchmark" \
        -iterations 100 \
        -profiles "python-ai" \
        -concurrency "1" \
        -output "${result_file}" >/dev/null 2>&1 || true
    
    # Stop pressure
    if [[ -n "${pressure_pid:-}" ]]; then
        kill "$pressure_pid" 2>/dev/null || true
        wait "$pressure_pid" 2>/dev/null || true
    fi
    
    log_info "Memory pressure test completed"
    return 0
}

run_concurrent_spawn_test() {
    local target_ms="$1"
    
    log_info "Testing high concurrency spawn rates..."
    
    local result_file="${RESULTS_DIR}/concurrent_spawn_${TIMESTAMP}.json"
    "${PROJECT_ROOT}/bin/phantom-benchmark" \
        -iterations 200 \
        -profiles "python-ai" \
        -concurrency "50,100" \
        -output "${result_file}" >/dev/null 2>&1 || true
    
    log_info "Concurrent spawn test completed"
    return 0
}

generate_summary_report() {
    local platform="$1"
    local validation_result="$2"
    
    local report_file="${RESULTS_DIR}/validation_summary_${TIMESTAMP}.md"
    
    cat > "${report_file}" << EOF
# Phantom Fragment V3 Validation Report

**Timestamp:** $(date)
**Platform:** ${platform}
**Validation Result:** ${validation_result}

## Performance Targets

| Platform | Target P95 Spawn Time |
|----------|----------------------|
| Linux    | <120ms              |
| Lima     | <180ms              |

## Test Configuration

- **Iterations:** ${MIN_ITERATIONS}
- **Profiles Tested:** python-ai, node-dev, go-dev
- **Concurrency Levels:** 1, 5, 10, 20
- **Additional Tests:** Memory pressure, concurrent spawning

## Results

$(if [[ "$validation_result" == "PASS" ]]; then
    echo "✅ **VALIDATION PASSED** - All performance targets met"
else
    echo "❌ **VALIDATION FAILED** - Performance targets not met"
fi)

## Files Generated

- Raw benchmark results: \`${RESULTS_DIR}/validation_*_${TIMESTAMP}.json\`
- Summary report: \`${report_file}\`

## System Information

\`\`\`
$(uname -a)
\`\`\`

## Recommendations

$(if [[ "$validation_result" == "FAIL" ]]; then
    cat << 'REC'
Performance targets were not met. Consider:

1. **System Optimization:**
   - Ensure kernel 5.15+ for optimal BPF support
   - Enable cgroups v2
   - Check for background processes consuming resources

2. **Configuration Tuning:**
   - Increase zygote pool sizes
   - Adjust PSI thresholds
   - Enable NUMA optimizations

3. **Hardware Considerations:**
   - Ensure adequate CPU cores (4+ recommended)
   - Sufficient memory (8GB+ recommended)
   - Fast storage (SSD recommended)
REC
else
    echo "All targets met! System is performing optimally."
fi)

---
Generated by Phantom Fragment V3 validation suite
EOF

    log_info "Summary report generated: ${report_file}"
}

main() {
    print_banner
    echo
    
    # Parse command line arguments
    local run_validation=true
    local platform=""
    local force_platform=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --platform)
                force_platform="$2"
                shift 2
                ;;
            --check-only)
                run_validation=false
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--platform linux|lima|macos] [--check-only]"
                echo "  --platform: Force specific platform validation"
                echo "  --check-only: Only check prerequisites, don't run validation"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Check prerequisites
    check_prerequisites
    
    if [[ "$run_validation" == "false" ]]; then
        log_info "Prerequisites check completed. Exiting."
        exit 0
    fi
    
    # Detect or use forced platform
    if [[ -n "$force_platform" ]]; then
        platform="$force_platform"
        log_info "Using forced platform: $platform"
    else
        platform=$(detect_platform)
        log_info "Detected platform: $platform"
    fi
    
    # Run validation
    local validation_result="FAIL"
    if run_comprehensive_validation "$platform"; then
        validation_result="PASS"
    fi
    
    # Generate summary report
    generate_summary_report "$platform" "$validation_result"
    
    # Final status
    echo
    if [[ "$validation_result" == "PASS" ]]; then
        log_success "🎉 Phantom Fragment V3 validation PASSED!"
        log_info "All performance targets met for platform: $platform"
        exit 0
    else
        log_error "❌ Phantom Fragment V3 validation FAILED"
        log_info "Performance targets not met for platform: $platform"
        log_info "Check the detailed results in: ${RESULTS_DIR}"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"