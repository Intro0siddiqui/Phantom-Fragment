package benchmarks

import (
	"fmt"
	"time"
)

// Benchmark represents a single benchmark test
type Benchmark struct {
	Name   string
	Func   func() *BenchmarkResult
	Result *BenchmarkResult
}

// BenchmarkSuite represents a collection of benchmarks
type BenchmarkSuite struct {
	Name       string
	Benchmarks []*Benchmark
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite(name string) *BenchmarkSuite {
	return &BenchmarkSuite{
		Name:       name,
		Benchmarks: make([]*Benchmark, 0),
	}
}

// Add adds a new benchmark to the suite
func (bs *BenchmarkSuite) Add(name string, f func() *BenchmarkResult) {
	benchmark := &Benchmark{
		Name: name,
		Func: f,
	}
	bs.Benchmarks = append(bs.Benchmarks, benchmark)
}

// Run runs all benchmarks in the suite
func (bs *BenchmarkSuite) Run() {
	fmt.Printf("Running benchmark suite: %s\n", bs.Name)
	for _, benchmark := range bs.Benchmarks {
		fmt.Printf("  Running benchmark: %s...\n", benchmark.Name)
		startTime := time.Now()
		benchmark.Result = benchmark.Func()
		benchmark.Result.Duration = time.Since(startTime)
		fmt.Printf("  ...completed in %v\n", benchmark.Result.Duration)
	}
}

// PrintResults prints the results of all benchmarks in the suite
func (bs *BenchmarkSuite) PrintResults() {
	fmt.Printf("\n--- Benchmark Suite Results: %s ---\n", bs.Name)
	for _, benchmark := range bs.Benchmarks {
		if benchmark.Result != nil {
			clb := &ComponentLoadingBenchmark{}
			clb.PrintBenchmarkResult(benchmark.Result)
		}
	}
}
