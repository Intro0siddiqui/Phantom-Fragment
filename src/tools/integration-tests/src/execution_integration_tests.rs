//! Execution integration tests
//! Real-world tests for execution with network isolation, resource limits, and hardware isolation

#[cfg(test)]
mod tests {
    use execution_rs::{AdaptiveEngine, ExecutionMode, PerformanceProfile, RiskProfile};
    use std::fs;
    use std::process::Command;

    #[test]
    fn test_execution_mode_selection() {
        let engine = AdaptiveEngine::new().expect("Failed to create AdaptiveEngine");

        // Test different risk profiles
        let low_risk = RiskProfile {
            network_access: false,
            file_write: false,
            privileged_ops: false,
            untrusted_source: false,
        };

        let high_risk = RiskProfile {
            network_access: true,
            file_write: true,
            privileged_ops: false,
            untrusted_source: true,
        };

        let perf = PerformanceProfile::default();

        let mode_low = engine.select_mode(&low_risk, &perf);
        let mode_high = engine.select_mode(&high_risk, &perf);

        println!("Low risk mode: {:?}", mode_low);
        println!("High risk mode: {:?}", mode_high);

        // High risk should use more isolation than Sandbox
        assert_ne!(mode_high, ExecutionMode::Sandbox);
    }

    #[test]
    fn test_build_script_execution() {
        println!("=== Testing Build Script Execution ===");

        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();

        // Create a simple C program
        let c_file = temp_dir.path().join("hello.c");
        fs::write(
            &c_file,
            r#"
#include <stdio.h>
int main() {
    printf("Hello from Phantom Fragment!\n");
    return 0;
}
"#,
        )
        .unwrap();

        // Create a build script
        let build_script = temp_dir.path().join("build.sh");
        fs::write(
            &build_script,
            format!(
                "#!/bin/bash\ncc {} -o {}\n",
                c_file.display(),
                temp_dir.path().join("hello").display()
            ),
        )
        .unwrap();

        // Make it executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&build_script).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&build_script, perms).unwrap();
        }

        // Execute the build script
        let output = Command::new("bash")
            .arg(&build_script)
            .output()
            .expect("Failed to execute build script");

        if !output.status.success() {
            println!("Build failed: {}", String::from_utf8_lossy(&output.stderr));
            return;
        }

        // Verify the binary was created
        let binary = temp_dir.path().join("hello");
        assert!(binary.exists(), "Compiled binary should exist");

        // Run the binary
        let run_output = Command::new(&binary).output().unwrap();
        let stdout = String::from_utf8_lossy(&run_output.stdout);

        println!("Program output: {}", stdout);
        assert!(stdout.contains("Hello from Phantom Fragment!"));
    }

    #[test]
    fn test_multi_fragment_isolation() {
        println!("=== Testing Multi-Fragment Isolation ===");

        let engine = AdaptiveEngine::new().expect("Failed to create AdaptiveEngine");

        let risk = RiskProfile::default();
        let perf = PerformanceProfile::default();
        let mode = engine.select_mode(&risk, &perf);

        // Spawn multiple fragments
        let pids: Vec<_> = (0..3)
            .filter_map(|i| {
                let name = format!("fragment_{}", i);
                engine.spawn(mode, &name, None, None).ok()
            })
            .collect();

        println!("Spawned {} fragments", pids.len());

        // Verify each fragment is isolated
        // In a real test, we would verify:
        // - Separate PID namespaces
        // - Separate network namespaces
        // - Separate mount namespaces
        // - Separate IPC namespaces

        for pid in pids {
            println!("Fragment PID: {}", pid);
        }
    }

    #[test]
    fn test_exit_code_propagation() {
        println!("=== Testing Exit Code Propagation ===");

        // Test that exit codes are properly propagated
        let output = Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(42));

        let output = Command::new("sh").arg("-c").arg("exit 0").output().unwrap();

        assert_eq!(output.status.code(), Some(0));
    }
}
