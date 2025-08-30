package main

import (
	"fmt"
	"log"
	"time"

	"github.com/phantom-fragment/phantom-fragment/internal/fragments"
)

// This example demonstrates the modular fragment system
func main() {
	fmt.Println("🎯 Phantom Fragment - Modular Fragment System Example")
	fmt.Println("=====================================================")
	
	// Create the modular fragment manager
	manager, err := fragments.NewModularFragmentManager()
	if err != nil {
		log.Fatalf("Failed to create fragment manager: %v", err)
	}
	defer manager.Shutdown()
	
	// Example 1: Simple task (core fragment only)
	fmt.Println("\n📝 Example 1: Simple Task")
	fmt.Println("-------------------------")
	simpleTask := fragments.NewTask("echo", "Hello, Phantom Fragment!").
		SetWorkdir("/tmp").
		SetTimeout(10 * time.Second)
	
	fragment, err := manager.ProcessTask(simpleTask)
	if err != nil {
		log.Printf("Error processing simple task: %v", err)
	} else {
		fmt.Printf("✅ Created fragment: %s (%.1f MB)\n", 
			fragment.ID, float64(fragment.TotalSize)/(1024*1024))
	}
	
	// Example 2: Network task
	fmt.Println("\n🌐 Example 2: Network Task")
	fmt.Println("-------------------------")
	networkTask := fragments.NewTask("curl", "-s", "https://httpbin.org/ip").
		SetEnvironment(map[string]string{
			"HTTP_PROXY": "http://proxy:8080",
			"HTTPS_PROXY": "http://proxy:8080",
		}).
		SetTimeout(30 * time.Second)
	
	fragment, err = manager.ProcessTask(networkTask)
	if err != nil {
		log.Printf("Error processing network task: %v", err)
	} else {
		fmt.Printf("✅ Created fragment: %s (%.1f MB)\n", 
			fragment.ID, float64(fragment.TotalSize)/(1024*1024))
		fmt.Printf("   Components loaded: %d\n", len(fragment.Components))
	}
	
	// Example 3: System administration task
	fmt.Println("\n⚙️  Example 3: System Task")
	fmt.Println("-------------------------")
	systemTask := fragments.NewTask("systemctl", "status", "docker").
		SetPriority(fragments.TaskPriorityHigh).
		SetTimeout(15 * time.Second)
	
	fragment, err = manager.ProcessTask(systemTask)
	if err != nil {
		log.Printf("Error processing system task: %v", err)
	} else {
		fmt.Printf("✅ Created fragment: %s (%.1f MB)\n", 
			fragment.ID, float64(fragment.TotalSize)/(1024*1024))
		fmt.Printf("   Components loaded: %d\n", len(fragment.Components))
	}
	
	// Example 4: Complex task with multiple capabilities
	fmt.Println("\n🔧 Example 4: Complex Task")
	fmt.Println("-------------------------")
	complexTask := fragments.NewTask("docker", "run", "--rm", "nginx:alpine", "nginx", "-v").
		SetEnvironment(map[string]string{
			"DOCKER_HOST": "unix:///var/run/docker.sock",
		}).
		SetPriority(fragments.TaskPriorityCritical).
		SetTimeout(60 * time.Second).
		SetMetadata("container_runtime", "docker").
		SetMetadata("image", "nginx:alpine")
	
	fragment, err = manager.ProcessTask(complexTask)
	if err != nil {
		log.Printf("Error processing complex task: %v", err)
	} else {
		fmt.Printf("✅ Created fragment: %s (%.1f MB)\n", 
			fragment.ID, float64(fragment.TotalSize)/(1024*1024))
		fmt.Printf("   Components loaded: %d\n", len(fragment.Components))
	}
	
	// Display system information
	fmt.Println("\n📊 System Information")
	fmt.Println("--------------------")
	displaySystemInfo(manager)
	
	// Display component status
	fmt.Println("\n📦 Component Status")
	fmt.Println("------------------")
	displayComponentStatus(manager)
	
	// Display performance metrics
	fmt.Println("\n⚡ Performance Metrics")
	fmt.Println("---------------------")
	displayPerformanceMetrics(manager)
	
	fmt.Println("\n🎉 Example completed successfully!")
}

func displaySystemInfo(manager *fragments.ModularFragmentManager) {
	info := manager.GetSystemInfo()
	
	// Core fragment
	core := info["core_fragment"].(map[string]interface{})
	fmt.Printf("Core Fragment: %s (%.1f MB)\n", 
		core["id"], core["size_mb"])
	
	// Library
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

func displayComponentStatus(manager *fragments.ModularFragmentManager) {
	components := manager.ListAvailableComponents()
	
	for name, info := range components {
		componentInfo := info.(map[string]interface{})
		status := "❌"
		if componentInfo["loaded"].(bool) {
			status = "✅"
		}
		
		fmt.Printf("%s %-20s (%.1f MB) - %s\n", 
			status,
			name, 
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

// demonstrateTaskAnalysis shows how to analyze tasks
func demonstrateTaskAnalysis() {
	fmt.Println("\n🔍 Task Analysis Example")
	fmt.Println("------------------------")
	
	analyzer := fragments.NewTaskAnalyzer()
	
	// Create various tasks
	tasks := []struct {
		name string
		task *fragments.Task
	}{
		{"Simple Command", fragments.NewTask("echo", "Hello")},
		{"Network Request", fragments.NewTask("curl", "https://example.com")},
		{"DNS Lookup", fragments.NewTask("nslookup", "google.com")},
		{"System Service", fragments.NewTask("systemctl", "status", "ssh")},
		{"Device Mount", fragments.NewTask("mount", "/dev/sda1", "/mnt")},
		{"Process Management", fragments.NewTask("ps", "aux")},
	}
	
	for _, t := range tasks {
		fmt.Printf("\nTask: %s\n", t.name)
		fmt.Printf("Command: %s\n", t.task.GetFullCommand())
		
		// Analyze capabilities
		capabilities := analyzer.AnalyzeTask(t.task)
		fmt.Printf("Required Capabilities: %d\n", len(capabilities))
		
		if len(capabilities) > 0 {
			fmt.Printf("Capabilities: ")
			first := true
			for capability := range capabilities {
				if !first {
					fmt.Print(", ")
				}
				fmt.Print(string(capability))
				first = false
			}
			fmt.Println()
		}
		
		// Analyze complexity
		complexity := analyzer.AnalyzeTaskComplexity(t.task)
		fmt.Printf("Complexity: %s\n", complexity.String())
	}
}

// demonstrateComponentManagement shows how to manage components
func demonstrateComponentManagement() {
	fmt.Println("\n📦 Component Management Example")
	fmt.Println("-------------------------------")
	
	library := fragments.NewUnifiedOSLibrary()
	loader := fragments.NewComponentLoader(library)
	
	// List available components
	fmt.Println("Available Components:")
	components := library.ListComponents()
	for name, component := range components {
		fmt.Printf("  %s: %.1f MB - %s\n", 
			name, 
			float64(component.Size)/(1024*1024),
			component.Description)
	}
	
	// Load specific components
	fmt.Println("\nLoading network components...")
	networkComponents := []string{"tcp-stack", "dns-resolver", "socket-api"}
	
	loaded, err := loader.LoadComponents(networkComponents)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("Loaded %d components:\n", len(loaded))
	for name, loadedComponent := range loaded {
		fmt.Printf("  %s: Loaded in %v\n", name, loadedComponent.LoadTime)
	}
	
	// Get loader statistics
	stats := loader.GetLoadStats()
	fmt.Printf("\nLoader Statistics:\n")
	fmt.Printf("  Loaded Components: %d\n", stats["loaded_count"])
	fmt.Printf("  Total Memory: %.1f MB\n", stats["total_memory_mb"])
	fmt.Printf("  Average Load Time: %v\n", stats["avg_load_time"])
	
	// Unload a component
	fmt.Println("\nUnloading tcp-stack component...")
	err = loader.UnloadComponent("tcp-stack")
	if err != nil {
		fmt.Printf("Error unloading: %v\n", err)
	} else {
		fmt.Println("✅ Successfully unloaded tcp-stack")
	}
	
	// Final statistics
	stats = loader.GetLoadStats()
	fmt.Printf("\nFinal Statistics:\n")
	fmt.Printf("  Loaded Components: %d\n", stats["loaded_count"])
	fmt.Printf("  Total Memory: %.1f MB\n", stats["total_memory_mb"])
}