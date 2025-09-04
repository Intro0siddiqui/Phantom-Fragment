package memory

import (
	"fmt"
	"testing"
	"time"
	"unsafe"
)

func TestMemoryDisciplineV3_BasicAllocation(t *testing.T) {
	// Create memory discipline with default configuration
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		t.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	// Test basic allocation
	ptr, err := md.Malloc(1024, 0)
	if err != nil {
		t.Fatalf("Malloc failed: %v", err)
	}

	// Verify we got valid memory
	if ptr == nil {
		t.Fatal("Malloc returned nil pointer")
	}

	// Test writing to the memory
	mem := (*[1024]byte)(ptr)
	for i := range mem {
		mem[i] = byte(i % 256)
	}

	// Test reading back
	for i := range mem {
		if mem[i] != byte(i%256) {
			t.Errorf("Memory corruption at index %d", i)
		}
	}

	// Test free
	err = md.Free(ptr)
	if err != nil {
		t.Errorf("Free failed: %v", err)
	}
}

func TestMemoryDisciplineV3_Calloc(t *testing.T) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		t.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	// Test calloc (should zero memory)
	ptr, err := md.Calloc(1, 1024, 0)
	if err != nil {
		t.Fatalf("Calloc failed: %v", err)
	}

	// Verify memory is zeroed
	mem := (*[1024]byte)(ptr)
	for i := range mem {
		if mem[i] != 0 {
			t.Errorf("Calloc did not zero memory at index %d: got %d", i, mem[i])
		}
	}

	// Test free
	err = md.Free(ptr)
	if err != nil {
		t.Errorf("Free failed: %v", err)
	}
}

func TestMemoryDisciplineV3_Realloc(t *testing.T) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		t.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	// Initial allocation
	ptr, err := md.Malloc(512, 0)
	if err != nil {
		t.Fatalf("Malloc failed: %v", err)
	}

	// Write some data
	mem := (*[512]byte)(ptr)
	for i := range mem {
		mem[i] = byte(i % 256)
	}

	// Realloc to larger size
	newPtr, err := md.Realloc(ptr, 1024, 0)
	if err != nil {
		t.Fatalf("Realloc failed: %v", err)
	}

	// Verify data was preserved
	newMem := (*[1024]byte)(newPtr)
	for i := 0; i < 512; i++ {
		if newMem[i] != byte(i%256) {
			t.Errorf("Data not preserved after realloc at index %d", i)
		}
	}

	// Test free
	err = md.Free(newPtr)
	if err != nil {
		t.Errorf("Free failed: %v", err)
	}
}

func TestMemoryDisciplineV3_MultipleAllocations(t *testing.T) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		t.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	// Allocate multiple blocks
	pointers := make([]unsafe.Pointer, 100)
	for i := range pointers {
		ptr, err := md.Malloc(128, 0)
		if err != nil {
			t.Fatalf("Malloc %d failed: %v", i, err)
		}
		pointers[i] = ptr

		// Write unique pattern to each allocation
		mem := (*[128]byte)(ptr)
		for j := range mem {
			mem[j] = byte(i + j)
		}
	}

	// Verify and free all allocations
	for i, ptr := range pointers {
		mem := (*[128]byte)(ptr)
		for j := range mem {
			if mem[j] != byte(i+j) {
				t.Errorf("Memory corruption in allocation %d at index %d", i, j)
			}
		}

		err := md.Free(ptr)
		if err != nil {
			t.Errorf("Free %d failed: %v", i, err)
		}
	}
}

func TestMemoryDisciplineV3_Statistics(t *testing.T) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		t.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	// Get initial stats
	initialStats := md.GetStats()

	// Perform some allocations
	ptr1, err := md.Malloc(1024, 0)
	if err != nil {
		t.Fatalf("Malloc failed: %v", err)
	}

	ptr2, err := md.Malloc(2048, 0)
	if err != nil {
		t.Fatalf("Malloc failed: %v", err)
	}

	// Check stats after allocations
	stats := md.GetStats()
	if stats.TotalAllocations != initialStats.TotalAllocations+2 {
		t.Errorf("Expected %d allocations, got %d", initialStats.TotalAllocations+2, stats.TotalAllocations)
	}

	if stats.AllocatedBytes != initialStats.AllocatedBytes+3072 {
		t.Errorf("Expected %d bytes allocated, got %d", initialStats.AllocatedBytes+3072, stats.AllocatedBytes)
	}

	// Free allocations
	err = md.Free(ptr1)
	if err != nil {
		t.Errorf("Free failed: %v", err)
	}

	err = md.Free(ptr2)
	if err != nil {
		t.Errorf("Free failed: %v", err)
	}

	// Check final stats
	finalStats := md.GetStats()
	if finalStats.TotalDeallocations != initialStats.TotalDeallocations+2 {
		t.Errorf("Expected %d deallocations, got %d", initialStats.TotalDeallocations+2, finalStats.TotalDeallocations)
	}
}

func TestMemoryDisciplineV3_ConcurrentAccess(t *testing.T) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		t.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	// Test concurrent allocations from multiple goroutines
	const numGoroutines = 10
	const allocsPerGoroutine = 100

	errors := make(chan error, numGoroutines*allocsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < allocsPerGoroutine; j++ {
				ptr, err := md.Malloc(64, 0)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d, alloc %d: %v", goroutineID, j, err)
					return
				}

				// Write and verify pattern
				mem := (*[64]byte)(ptr)
				for k := range mem {
					mem[k] = byte(goroutineID + j + k)
				}

				for k := range mem {
					if mem[k] != byte(goroutineID+j+k) {
						errors <- fmt.Errorf("goroutine %d, alloc %d: memory corruption at index %d", goroutineID, j, k)
						return
					}
				}

				err = md.Free(ptr)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d, alloc %d: free failed: %v", goroutineID, j, err)
					return
				}
			}
			errors <- nil
		}(i)
	}

	// Collect errors
	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Error(err)
		}
	}
}

func TestMemoryDisciplineV3_Configuration(t *testing.T) {
	// Test with custom configuration
	config := &DisciplineConfig{
		EnableJemalloc:     true,
		EnableBufferPools:  true,
		EnableKSM:         false, // Disable KSM for this test
		EnableMetrics:     true,
		
		MaxHeapSize:       512 * 1024 * 1024, // 512MB
		MaxBufferPoolSize: 64 * 1024 * 1024,  // 64MB
		
		ArenaCount:        4,
		ThreadCacheEnabled: true,
		
		EnableGuardPages:  true,
		EnableRandomization: true,
	}

	md, err := NewMemoryDisciplineV3(config)
	if err != nil {
		t.Fatalf("Failed to create memory discipline with custom config: %v", err)
	}
	defer md.Shutdown()

	// Verify configuration was applied
	currentConfig := md.GetConfig()
	if currentConfig.MaxHeapSize != config.MaxHeapSize {
		t.Errorf("MaxHeapSize not applied: expected %d, got %d", config.MaxHeapSize, currentConfig.MaxHeapSize)
	}

	if currentConfig.EnableKSM {
		t.Error("KSM should be disabled but is enabled")
	}

	// Test that the system works with custom config
	ptr, err := md.Malloc(4096, 0)
	if err != nil {
		t.Fatalf("Malloc failed with custom config: %v", err)
	}

	err = md.Free(ptr)
	if err != nil {
		t.Errorf("Free failed: %v", err)
	}
}

func TestMemoryDisciplineV3_Shutdown(t *testing.T) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		t.Fatalf("Failed to create memory discipline: %v", err)
	}

	// Allocate some memory before shutdown
	ptr, err := md.Malloc(1024, 0)
	if err != nil {
		t.Fatalf("Malloc failed: %v", err)
	}

	// Shutdown should clean up everything
	err = md.Shutdown()
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Verify system is shutdown
	if md.IsInitialized() {
		t.Error("Memory discipline should not be initialized after shutdown")
	}

	// Note: We can't test freeing after shutdown since the system is designed
	// to handle that gracefully through fallback mechanisms
}

func BenchmarkMemoryDisciplineV3_Allocation(b *testing.B) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		b.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ptr, err := md.Malloc(128, 0)
		if err != nil {
			b.Fatalf("Malloc failed: %v", err)
		}

		err = md.Free(ptr)
		if err != nil {
			b.Fatalf("Free failed: %v", err)
		}
	}
}

func BenchmarkMemoryDisciplineV3_ConcurrentAllocation(b *testing.B) {
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		b.Fatalf("Failed to create memory discipline: %v", err)
	}
	defer md.Shutdown()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ptr, err := md.Malloc(64, 0)
			if err != nil {
				b.Fatalf("Malloc failed: %v", err)
			}

			err = md.Free(ptr)
			if err != nil {
				b.Fatalf("Free failed: %v", err)
			}
		}
	})
}

// Example usage demonstration
func ExampleMemoryDisciplineV3() {
	// Create a memory discipline instance with default configuration
	md, err := NewMemoryDisciplineV3(nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer md.Shutdown()

	// Allocate memory
	ptr, err := md.Malloc(1024, 0)
	if err != nil {
		fmt.Printf("Allocation error: %v\n", err)
		return
	}

	// Use the memory
	memory := (*[1024]byte)(ptr)
	for i := range memory {
		memory[i] = byte(i % 256)
	}

	// Free the memory
	err = md.Free(ptr)
	if err != nil {
		fmt.Printf("Free error: %v\n", err)
	}

	fmt.Println("Memory allocation and free completed successfully")
	// Output: Memory allocation and free completed successfully
}