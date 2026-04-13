#[cfg(test)]
mod system_tests;

#[cfg(test)]
mod test_helpers;

#[cfg(test)]
mod security_integration_tests;

#[cfg(test)]
mod storage_integration_tests;

#[cfg(test)]
mod execution_integration_tests;

#[cfg(test)]
mod tests {
    use execution_rs::{AdaptiveEngine, ExecutionMode, PerformanceProfile, RiskProfile};
    use health_rs::{HealthMonitor, HealthStatus};
    use metrics_rs::MetricsCollector;
    use policy_dsl_rs::PolicyCompiler;
    use task_analyzer_rs::{Command, Component, TaskAnalyzer};

    #[test]
    fn test_end_to_end_flow() {
        // 1. Analyze Task
        let analyzer = TaskAnalyzer::new();
        let cmd = Command {
            executable: "/usr/bin/curl".to_string(),
            args: vec!["https://example.com".to_string()],
            env: vec![],
            working_dir: None,
        };

        let required = analyzer.analyze(&cmd);
        assert!(required.components.contains(&Component::TcpStack));

        // 2. Determine Execution Mode
        let engine = AdaptiveEngine::new().expect("Failed to create AdaptiveEngine");
        let risk = RiskProfile {
            network_access: true,
            ..Default::default()
        };
        let perf = PerformanceProfile::default();

        let mode = engine.select_mode(&risk, &perf);
        assert_eq!(mode, ExecutionMode::Sandbox); // Network implies sandbox

        // 3. Compile Policy
        let policy_yaml = r#"
name: curl-policy
version: "1.0"
seccomp:
  default_action: kill
  rules:
    - syscall: socket
      action: allow
    - syscall: connect
      action: allow
"#;
        let mut compiler = PolicyCompiler::new();
        compiler.load_yaml(policy_yaml).unwrap();
        let compiled = compiler.compile("curl-policy").unwrap();
        assert!(compiled.seccomp_filter.is_some());

        // 4. Check Health & Metrics
        let health = HealthMonitor::new();
        health.update("execution-engine", HealthStatus::Healthy, "Ready");
        assert_eq!(health.check_system(), HealthStatus::Healthy);

        let metrics = MetricsCollector::new();
        metrics.inc_io_ops();
        let report = metrics.export().unwrap();
        assert!(report.contains("phantom_io_ops_total 1"));
    }
}
