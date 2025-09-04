package main

import (
	"fmt"
	"log"
	"time"

	"github.com/phantom-fragment/phantom-fragment/pkg/fragments"
)

func main() {
	fmt.Println("🚀 Phantom Fragment - Modular Fragment System Demo")
	fmt.Println("==================================================")
	
	// Create the modular fragment manager
	manager, err := fragments.NewModularFragmentManager()
	if err != nil {
		log.Fatalf("Failed to create fragment manager: %v", err)
	}
	defer manager.Shutdown()
	
	// Display system information
	fmt.Println("\n📊 System Information:")
	fmt.Println("---------------------")
	displaySystemInfo(manager)
	
	// Demo different task types
	fmt.Println("\n🎯 Task Processing Demo:")
	fmt.Println("----------------------")
	
	// Simple task (core fragment only)
	fmt.Println("\n1. Simple Task (Core Fragment Only - 3MB):")
	simpleTask := fragments.NewTask("echo", "Hello, World!")
	processTask(manager, simpleTask, "Simple echo command")
	
	// Network task
	fmt.Println("\n2. Network Task (Core + Network Components - 7MB):")
	networkTask := fragments.NewTask("curl", "-I", "https://example.com")
	processTask(manager, networkTask, "HTTP request with curl")
	
	// DNS task
	fmt.Println("\n3. DNS Task (Core + DNS Component - 4MB):")
	dnsTask := fragments.NewTask("nslookup", "google.com")
	processTask(manager, dnsTask, "DNS lookup")
	
	// System task
	fmt.Println("\n4. System Task (Core + OS Services - 9MB):")
	systemTask := fragments.NewTask("systemctl", "status", "ssh")
	processTask(manager, systemTask, "System service status check")
	
	// Complex task (multiple components)
	fmt.Println("\n5. Complex Task (Core + Multiple Components - 12MB):")
	complexTask := fragments.NewTask("systemctl", "restart", "nginx").
		SetEnvironment(map[string]string{"HTTP_PROXY": "http://proxy:8080"})
	processTask(manager, complexTask, "Service restart with proxy")
	
	// Display component status
	fmt.Println("\n📦 Component Status:")
	fmt.Println("-------------------")
	displayComponentStatus(manager)
	
	// Display performance metrics
	fmt.Println("\n⚡ Performance Metrics:")
	fmt.Println("----------------------")
	displayPerformanceMetrics(manager)
	
	fmt.Println("\n✅ Demo completed successfully!")
}

func displaySystemInfo(manager *fragments.ModularFragmentManager) {
	info := manager.GetSystemInfo()
	
	// Core fragment info
	core := info["core_fragment"].(map[string]interface{})
	fmt.Printf("Core Fragment: %s (%.1f MB)\n", 
		core["id"], core["size_mb"])
	
	// Library info
	library := info["library"].(map[string]interface{})
	fmt.Printf("Available Components: %d\n", library["total_components"])
	
	// Loader stats
	loaderStats := info["loader_stats"].(map[string]interface{})
	fmt.Printf("Loaded Components: %d (%.1f MB)\n", 
		loaderStats["loaded_count"], loaderStats["total_memory_mb"])
	
	// Cache stats
	cacheStats := info["cache_stats"].(map[string]interface{})
	fmt.Printf("Cached Fragments: %d\n", cacheStats["fragment_count"])
}

func processTask(manager *fragments.ModularFragmentManager, task *fragments.Task, description string) {
	fmt.Printf("  Task: %s\n", description)
	fmt.Printf("  Command: %s\n", task.GetFullCommand())
	
	// Analyze task complexity
	complexity := task.GetEstimatedComplexity()
	fmt.Printf("  Complexity: %s\n", complexity.String())
	
	// Process the task
	start := time.Now()
	fragment, err := manager.ProcessTask(task)
	processTime := time.Since(start)
	
	if err != nil {
		fmt.Printf("  ❌ Error: %v\n", err)
		return
	}
	
	// Display fragment information
	fmt.Printf("  ✅ Fragment ID: %s\n", fragment.ID)
	fmt.Printf("  📏 Total Size: %.1f MB\n", float64(fragment.TotalSize)/(1024*1024))
	fmt.Printf("  ⏱️  Load Time: %v\n", fragment.LoadTime)
	fmt.Printf("  🔧 Components: %d\n", len(fragment.Components))
	
	// Display capabilities
	if len(fragment.Capabilities) > 0 {
		fmt.Printf("  🎯 Capabilities: ")
		first := true
		for capability := range fragment.Capabilities {
			if !first {
				fmt.Print(", ")
			}
			fmt.Print(string(capability))
			first = false
		}
		fmt.Println()
	}
	
	fmt.Printf("  ⚡ Process Time: %v\n", processTime)
}

func displayComponentStatus(manager *fragments.ModularFragmentManager) {
	components := manager.ListAvailableComponents()
	
	for name, info := range components {
		componentInfo := info.(map[string]interface{})
		status := "❌ Unloaded"
		if componentInfo["loaded"].(bool) {
			status = "✅ Loaded"
		}
		
		fmt.Printf("%-20s %s (%.1f MB) - %s\n", 
			name, 
			status,
			componentInfo["size_mb"],
			componentInfo["description"])
	}
}

func displayPerformanceMetrics(manager *fragments.ModularFragmentManager) {
	metrics := manager.GetPerformanceMetrics()
	
	fmt.Printf("Tasks Processed: %d\n", metrics["tasks_processed"])
	fmt.Printf("Fragments Created: %d\n", metrics["fragments_created"])
	fmt.Printf("Total Memory Used: %.1f MB\n", metrics["total_memory_mb"])
	fmt.Printf("Average Load Time: %v\n", metrics["average_load_time"])
	fmt.Printf("Loaded Components: %d\n", metrics["loaded_components"])
	fmt.Printf("Cached Fragments: %d\n", metrics["cached_fragments"])
}