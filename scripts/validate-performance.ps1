# Phantom Fragment V3 Performance Validation Script (Windows PowerShell)
# Tests p95 spawn <120ms Linux, <180ms Lima targets

param(
    [string]$Platform = "",
    [switch]$CheckOnly = $false,
    [switch]$Help = $false
)

# Colors for output
$Global:Red = "Red"
$Global:Green = "Green"
$Global:Yellow = "Yellow"
$Global:Blue = "Blue"

# Performance targets
$Global:LINUX_P95_TARGET_MS = 120
$Global:LIMA_P95_TARGET_MS = 180
$Global:MIN_ITERATIONS = 1000

# Logging functions
function Log-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Global:Blue
}

function Log-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Global:Green
}

function Log-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Global:Yellow
}

function Log-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Global:Red
}

function Print-Banner {
    Write-Host @"
┌─────────────────────────────────────────────────────────────┐
│              Phantom Fragment V3 Validation                │
│                                                            │
│  🎯 Target: p95 spawn <120ms Linux, <180ms Lima           │
│  📊 Method: Statistical validation with confidence        │
│  🔬 Tests: Cold start, warm start, concurrent spawning    │
└─────────────────────────────────────────────────────────────┘
"@
}

function Detect-Platform {
    if (Get-Command lima -ErrorAction SilentlyContinue) {
        if ($env:LIMA_INSTANCE) {
            return "lima"
        }
    }
    
    switch ($PSVersionTable.Platform) {
        "Win32NT" { return "windows" }
        "Unix" {
            if ($IsLinux) { return "linux" }
            if ($IsMacOS) { return "macos" }
            return "unix"
        }
        default { return "windows" }
    }
}

function Check-Prerequisites {
    Log-Info "Checking prerequisites..."
    
    $ProjectRoot = Get-Location
    
    # Check if phantom binary exists
    $PhantomBinary = Join-Path $ProjectRoot "bin\phantom.exe"
    $PhantomBinaryAlt = Join-Path $ProjectRoot "bin\phantom"
    
    if (!(Test-Path $PhantomBinary) -and !(Test-Path $PhantomBinaryAlt)) {
        Log-Error "Phantom binary not found. Please build first:"
        Write-Host "  go build -o bin\phantom.exe .\cmd\phantom"
        exit 1
    }
    
    # Check if benchmark binary exists
    $BenchmarkBinary = Join-Path $ProjectRoot "bin\phantom-benchmark.exe"
    $BenchmarkBinaryAlt = Join-Path $ProjectRoot "bin\phantom-benchmark"
    
    if (!(Test-Path $BenchmarkBinary) -and !(Test-Path $BenchmarkBinaryAlt)) {
        Log-Warning "Benchmark binary not found. Building..."
        try {
            & go build -o "bin\phantom-benchmark.exe" ".\cmd\phantom-benchmark"
            if ($LASTEXITCODE -ne 0) {
                throw "Build failed"
            }
        }
        catch {
            Log-Error "Failed to build benchmark binary: $_"
            exit 1
        }
    }
    
    # Check system capabilities
    Log-Info "Checking system capabilities..."
    $BenchBinary = if (Test-Path $BenchmarkBinary) { $BenchmarkBinary } else { $BenchmarkBinaryAlt }
    & $BenchBinary -system-check
    
    Log-Success "Prerequisites check completed"
}

function Run-SpawnValidation {
    param(
        [string]$Platform,
        [int]$TargetMs,
        [string]$TestName
    )
    
    Log-Info "Running $TestName validation (target: <${TargetMs}ms)"
    
    # Create results directory
    $ResultsDir = "benchmark-results"
    if (!(Test-Path $ResultsDir)) {
        New-Item -ItemType Directory -Path $ResultsDir | Out-Null
    }
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ResultFile = Join-Path $ResultsDir "validation_${TestName}_${Timestamp}.json"
    
    # Run benchmark
    Log-Info "Executing performance benchmark..."
    
    $BenchmarkBinary = if (Test-Path "bin\phantom-benchmark.exe") { "bin\phantom-benchmark.exe" } else { "bin\phantom-benchmark" }
    
    $BenchmarkArgs = @(
        "-iterations", $Global:MIN_ITERATIONS,
        "-profiles", "python-ai,node-dev,go-dev",
        "-concurrency", "1,5,10,20",
        "-output", $ResultFile,
        "-verbose"
    )
    
    try {
        & $BenchmarkBinary @BenchmarkArgs
        if ($LASTEXITCODE -ne 0) {
            Log-Error "Benchmark execution failed"
            return $false
        }
    }
    catch {
        Log-Error "Benchmark execution failed: $_"
        return $false
    }
    
    # Parse results and validate targets
    Log-Info "Analyzing results..."
    if (!(Validate-PerformanceTargets $ResultFile $TargetMs)) {
        Log-Error "$TestName validation FAILED"
        return $false
    }
    
    Log-Success "$TestName validation PASSED"
    return $true
}

function Validate-PerformanceTargets {
    param(
        [string]$ResultFile,
        [int]$TargetMs
    )
    
    if (!(Test-Path $ResultFile)) {
        Log-Error "Result file not found: $ResultFile"
        return $false
    }
    
    try {
        $Results = Get-Content $ResultFile | ConvertFrom-Json
        
        # Extract cold start P95 latency (assuming nanoseconds)
        $ColdStartP95Ns = $Results.SpawnBenchmarks.ColdStart.P95
        
        if ($null -eq $ColdStartP95Ns) {
            Log-Error "Could not parse cold start P95 from results"
            return $false
        }
        
        # Convert nanoseconds to milliseconds
        $ColdStartP95Ms = [math]::Round($ColdStartP95Ns / 1000000, 2)
        
        # Extract warm start P95 latency if available
        $WarmStartP95Ms = "N/A"
        if ($Results.SpawnBenchmarks.WarmStart.P95) {
            $WarmStartP95Ms = [math]::Round($Results.SpawnBenchmarks.WarmStart.P95 / 1000000, 2)
        }
        
        # Display results
        Write-Host ""
        Write-Host "📊 Performance Results:"
        Write-Host "  Cold Start P95: ${ColdStartP95Ms}ms (target: <${TargetMs}ms)"
        if ($WarmStartP95Ms -ne "N/A") {
            Write-Host "  Warm Start P95: ${WarmStartP95Ms}ms"
        }
        Write-Host ""
        
        # Check if cold start meets target
        if ($ColdStartP95Ms -le $TargetMs) {
            Log-Success "Cold start P95 target MET: ${ColdStartP95Ms}ms <= ${TargetMs}ms"
            return $true
        }
        else {
            Log-Error "Cold start P95 target FAILED: ${ColdStartP95Ms}ms > ${TargetMs}ms"
            return $false
        }
    }
    catch {
        Log-Error "Failed to parse results: $_"
        return $false
    }
}

function Run-ComprehensiveValidation {
    param([string]$Platform)
    
    Log-Info "Running comprehensive validation for platform: $Platform"
    
    # Set target based on platform
    $TargetMs = switch ($Platform) {
        "linux" { $Global:LINUX_P95_TARGET_MS }
        "lima" { $Global:LIMA_P95_TARGET_MS }
        "macos" { 
            Log-Warning "Using Lima target for macOS platform"
            $Global:LIMA_P95_TARGET_MS 
        }
        "windows" {
            Log-Warning "Using Lima target for Windows platform" 
            $Global:LIMA_P95_TARGET_MS
        }
        default { 
            Log-Warning "Unknown platform, using conservative target"
            $Global:LIMA_P95_TARGET_MS 
        }
    }
    
    # Run main spawn validation
    if (!(Run-SpawnValidation $Platform $TargetMs "${Platform}_spawn")) {
        return $false
    }
    
    Log-Success "Comprehensive validation completed"
    return $true
}

function Generate-SummaryReport {
    param(
        [string]$Platform,
        [string]$ValidationResult
    )
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportFile = "benchmark-results\validation_summary_${Timestamp}.md"
    
    $ReportContent = @"
# Phantom Fragment V3 Validation Report

**Timestamp:** $(Get-Date)
**Platform:** $Platform
**Validation Result:** $ValidationResult

## Performance Targets

| Platform | Target P95 Spawn Time |
|----------|----------------------|
| Linux    | <120ms              |
| Lima     | <180ms              |

## Test Configuration

- **Iterations:** $($Global:MIN_ITERATIONS)
- **Profiles Tested:** python-ai, node-dev, go-dev
- **Concurrency Levels:** 1, 5, 10, 20

## Results

$(if ($ValidationResult -eq "PASS") {
    "✅ **VALIDATION PASSED** - All performance targets met"
} else {
    "❌ **VALIDATION FAILED** - Performance targets not met"
})

## System Information

```
$($PSVersionTable | Format-Table | Out-String)
```

---
Generated by Phantom Fragment V3 validation suite
"@

    $ReportContent | Out-File -FilePath $ReportFile -Encoding UTF8
    Log-Info "Summary report generated: $ReportFile"
}

# Main execution
function Main {
    if ($Help) {
        Write-Host "Usage: .\validate-performance.ps1 [-Platform linux|lima|macos|windows] [-CheckOnly]"
        Write-Host "  -Platform: Force specific platform validation"
        Write-Host "  -CheckOnly: Only check prerequisites, don't run validation"
        exit 0
    }
    
    Print-Banner
    Write-Host ""
    
    # Check prerequisites
    Check-Prerequisites
    
    if ($CheckOnly) {
        Log-Info "Prerequisites check completed. Exiting."
        exit 0
    }
    
    # Detect or use forced platform
    $DetectedPlatform = if ($Platform) { 
        Log-Info "Using forced platform: $Platform"
        $Platform 
    } else { 
        $DetectedPlatform = Detect-Platform
        Log-Info "Detected platform: $DetectedPlatform"
        $DetectedPlatform
    }
    
    # Run validation
    $ValidationResult = if (Run-ComprehensiveValidation $DetectedPlatform) { "PASS" } else { "FAIL" }
    
    # Generate summary report
    Generate-SummaryReport $DetectedPlatform $ValidationResult
    
    # Final status
    Write-Host ""
    if ($ValidationResult -eq "PASS") {
        Log-Success "🎉 Phantom Fragment V3 validation PASSED!"
        Log-Info "All performance targets met for platform: $DetectedPlatform"
        exit 0
    }
    else {
        Log-Error "❌ Phantom Fragment V3 validation FAILED"
        Log-Info "Performance targets not met for platform: $DetectedPlatform"
        Log-Info "Check the detailed results in: benchmark-results\"
        exit 1
    }
}

# Execute main function
Main