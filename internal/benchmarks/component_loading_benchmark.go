package benchmarks

import (
	"fmt"
	"sync"
	"time"

	"github.com/phantom-fragment/phantom-fragment/pkg/fragments"
)

// ComponentLoadingBenchmark measures component loading performance
type ComponentLoadingBenchmark struct {
	loader   *fragments.ComponentLoader
	library  *fragments.UnifiedOSLibrary
	analyzer *fragments.TaskAnalyzer
	composer *fragments.FragmentComposer
}

// BenchmarkResult represents the result of a benchmark run
type BenchmarkResult struct {
	TestName      string
	Iterations    int
	Duration      time.Duration
	AvgLoadTime   time.Duration
	MinLoadTime   time.Duration
	MaxLoadTime   time.Duration
	TotalMemory   int64
	MemoryPerLoad float64
	SuccessRate   float64
	Throughput    float64 // loads per second
	ErrorCount    int
	Errors        []string
}

// NewComponentLoadingBenchmark creates a new benchmark instance
func NewComponentLoadingBenchmark() *ComponentLoadingBenchmark {
	library := fragments.NewUnifiedOSLibrary()
	loader := fragments.NewComponentLoader(library)
	analyzer := fragments.NewTaskAnalyzer()
	composer := fragments.NewFragmentComposer(library, analyzer)

	return &ComponentLoadingBenchmark{
		loader:   loader,
		library:  library,
		analyzer: analyzer,
		composer: composer,
	}
}

// RunSingleComponentBenchmark runs a benchmark for loading a single component
func (clb *ComponentLoadingBenchmark) RunSingleComponentBenchmark(componentName string, iterations int) *BenchmarkResult {
	result := &BenchmarkResult{
		TestName:   fmt.Sprintf("SingleComponent_%s", componentName),
		Iterations: iterations,
		Errors:     make([]string, 0),
	}

	startTime := time.Now()
	minLoadTime := time.Hour
	maxLoadTime := time.Nanosecond
	var totalLoadTime time.Duration
	successCount := 0

	for i := 0; i < iterations; i++ {
		loadStart := time.Now()
		_, err := clb.loader.LoadComponent(componentName)
		loadDuration := time.Since(loadStart)

		// Update load time statistics
		if loadDuration < minLoadTime {
			minLoadTime = loadDuration
		}
		if loadDuration > maxLoadTime {
			maxLoadTime = loadDuration
		}
		totalLoadTime += loadDuration

		if err != nil {
			result.ErrorCount++
			if len(result.Errors) < 10 { // Limit error logging
				result.Errors = append(result.Errors, err.Error())
			}
		} else {
			successCount++
		}
	}

	result.Duration = time.Since(startTime)
	result.AvgLoadTime = totalLoadTime / time.Duration(iterations)
	result.MinLoadTime = minLoadTime
	result.MaxLoadTime = maxLoadTime
	result.SuccessRate = float64(successCount) / float64(iterations) * 100
	result.Throughput = float64(iterations) / result.Duration.Seconds()

	// Get memory usage
	stats := clb.loader.GetLoadStats()
	if mem, ok := stats["total_memory"].(int64); ok {
		result.TotalMemory = mem
		result.MemoryPerLoad = float64(mem) / float64(iterations)
	}

	return result
}

// RunParallelComponentBenchmark runs a benchmark for loading components in parallel
func (clb *ComponentLoadingBenchmark) RunParallelComponentBenchmark(componentNames []string, concurrency int, iterations int) *BenchmarkResult {
	result := &BenchmarkResult{
		TestName:   fmt.Sprintf("ParallelComponents_Concurrency%d", concurrency),
		Iterations: iterations * len(componentNames),
		Errors:     make([]string, 0),
	}

	startTime := time.Now()
	minLoadTime := time.Hour
	maxLoadTime := time.Nanosecond
	var totalLoadTime time.Duration
	successCount := 0
	errorCount := 0
	var mu sync.Mutex
	var errors []string

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for i := 0; i < iterations; i++ {
		for _, componentName := range componentNames {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore

			go func(name string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore

				loadStart := time.Now()
				_, err := clb.loader.LoadComponent(name)
				loadDuration := time.Since(loadStart)

				mu.Lock()
				defer mu.Unlock()

				// Update load time statistics
				if loadDuration < minLoadTime {
					minLoadTime = loadDuration
				}
				if loadDuration > maxLoadTime {
					maxLoadTime = loadDuration
				}
				totalLoadTime += loadDuration

				if err != nil {
					errorCount++
					if len(errors) < 10 { // Limit error logging
						errors = append(errors, fmt.Sprintf("%s: %v", name, err))
					}
				} else {
					successCount++
				}
			}(componentName)
		}
	}

	wg.Wait()

	result.Duration = time.Since(startTime)
	result.AvgLoadTime = totalLoadTime / time.Duration(result.Iterations)
	result.MinLoadTime = minLoadTime
	result.MaxLoadTime = maxLoadTime
	result.SuccessRate = float64(successCount) / float64(result.Iterations) * 100
	result.Throughput = float64(result.Iterations) / result.Duration.Seconds()
	result.ErrorCount = errorCount
	result.Errors = errors

	// Get memory usage
	stats := clb.loader.GetLoadStats()
	if mem, ok := stats["total_memory"].(int64); ok {
		result.TotalMemory = mem
		result.MemoryPerLoad = float64(mem) / float64(result.Iterations)
	}

	return result
}

// RunFragmentCompositionBenchmark runs a benchmark for fragment composition
func (clb *ComponentLoadingBenchmark) RunFragmentCompositionBenchmark(task *fragments.Task, iterations int) *BenchmarkResult {
	result := &BenchmarkResult{
		TestName:   "FragmentComposition",
		Iterations: iterations,
		Errors:     make([]string, 0),
	}

	startTime := time.Now()
	minComposeTime := time.Hour
	maxComposeTime := time.Nanosecond
	var totalComposeTime time.Duration
	successCount := 0

	for i := 0; i < iterations; i++ {
		composeStart := time.Now()
		_, err := clb.composer.ComposeForTask(task)
		composeDuration := time.Since(composeStart)

		// Update composition time statistics
		if composeDuration < minComposeTime {
			minComposeTime = composeDuration
		}
		if composeDuration > maxComposeTime {
			maxComposeTime = composeDuration
		}
		totalComposeTime += composeDuration

		if err != nil {
			result.ErrorCount++
			if len(result.Errors) < 10 { // Limit error logging
				result.Errors = append(result.Errors, err.Error())
			}
		} else {
			successCount++
		}
	}

	result.Duration = time.Since(startTime)
	result.AvgLoadTime = totalComposeTime / time.Duration(iterations)
	result.MinLoadTime = minComposeTime
	result.MaxLoadTime = maxComposeTime
	result.SuccessRate = float64(successCount) / float64(iterations) * 100
	result.Throughput = float64(iterations) / result.Duration.Seconds()

	return result
}

// RunTaskAnalysisBenchmark runs a benchmark for task analysis
func (clb *ComponentLoadingBenchmark) RunTaskAnalysisBenchmark(task *fragments.Task, iterations int) *BenchmarkResult {
	result := &BenchmarkResult{
		TestName:   "TaskAnalysis",
		Iterations: iterations,
		Errors:     make([]string, 0),
	}

	startTime := time.Now()
	minAnalysisTime := time.Hour
	maxAnalysisTime := time.Nanosecond
	var totalAnalysisTime time.Duration
	successCount := 0

	for i := 0; i < iterations; i++ {
		analysisStart := time.Now()
		capabilities := clb.analyzer.AnalyzeTask(task)
		analysisDuration := time.Since(analysisStart)

		// Update analysis time statistics
		if analysisDuration < minAnalysisTime {
			minAnalysisTime = analysisDuration
		}
		if analysisDuration > maxAnalysisTime {
			maxAnalysisTime = analysisDuration
		}
		totalAnalysisTime += analysisDuration

		if len(capabilities) > 0 {
			successCount++
		}
	}

	result.Duration = time.Since(startTime)
	result.AvgLoadTime = totalAnalysisTime / time.Duration(iterations)
	result.MinLoadTime = minAnalysisTime
	result.MaxLoadTime = maxAnalysisTime
	result.SuccessRate = float64(successCount) / float64(iterations) * 100
	result.Throughput = float64(iterations) / result.Duration.Seconds()

	return result
}

// PrintBenchmarkResult prints a formatted benchmark result
func (clb *ComponentLoadingBenchmark) PrintBenchmarkResult(result *BenchmarkResult) {
	fmt.Printf("\n=== Benchmark Results: %s ===\n", result.TestName)
	fmt.Printf("Iterations: %d\n", result.Iterations)
	fmt.Printf("Duration: %v\n", result.Duration)
	fmt.Printf("Average Load Time: %v\n", result.AvgLoadTime)
	fmt.Printf("Min Load Time: %v\n", result.MinLoadTime)
	fmt.Printf("Max Load Time: %v\n", result.MaxLoadTime)
	fmt.Printf("Success Rate: %.2f%%\n", result.SuccessRate)
	fmt.Printf("Throughput: %.2f loads/sec\n", result.Throughput)

	if result.TotalMemory > 0 {
		fmt.Printf("Total Memory: %d bytes (%.2f MB)\n", result.TotalMemory, float64(result.TotalMemory)/(1024*1024))
		fmt.Printf("Memory per Load: %.2f bytes\n", result.MemoryPerLoad)
	}

	if result.ErrorCount > 0 {
		fmt.Printf("Errors: %d\n", result.ErrorCount)
		if len(result.Errors) > 0 {
			fmt.Printf("Sample Errors:\n")
			for _, err := range result.Errors {
				fmt.Printf("  - %s\n", err)
			}
		}
	}
	fmt.Printf("\n")
}

// RunAllBenchmarks runs all benchmark tests
func (clb *ComponentLoadingBenchmark) RunAllBenchmarks() {
	suite := NewBenchmarkSuite("Component Loading")

	// Single component benchmarks
	suite.Add("SingleComponent_tcp-stack", func() *BenchmarkResult {
		return clb.RunSingleComponentBenchmark("tcp-stack", 100)
	})
	suite.Add("SingleComponent_dns-resolver", func() *BenchmarkResult {
		return clb.RunSingleComponentBenchmark("dns-resolver", 100)
	})
	suite.Add("SingleComponent_socket-api", func() *BenchmarkResult {
		return clb.RunSingleComponentBenchmark("socket-api", 100)
	})

	// Parallel component benchmark
	suite.Add("ParallelComponent_Concurrency5", func() *BenchmarkResult {
		parallelComponents := []string{"tcp-stack", "dns-resolver", "socket-api", "init-system"}
		return clb.RunParallelComponentBenchmark(parallelComponents, 5, 20)
	})

	// Task analysis benchmark
	suite.Add("TaskAnalysis", func() *BenchmarkResult {
		task := fragments.NewTask("curl", "https://example.com")
		return clb.RunTaskAnalysisBenchmark(task, 1000)
	})

	// Fragment composition benchmark
	suite.Add("FragmentComposition", func() *BenchmarkResult {
		task := fragments.NewTask("curl", "https://example.com")
		return clb.RunFragmentCompositionBenchmark(task, 100)
	})

	suite.Run()
	suite.PrintResults()
}
