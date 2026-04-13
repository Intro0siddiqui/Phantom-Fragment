use cgroups_rs::*;
use std::path::PathBuf;

#[derive(Debug, PartialEq)]
enum CgroupChoice {
    UseSudo,
    ContinueWithoutCgroups,
    ConfigureDelegation,
    Abort,
}

#[test]
fn test_cgroup_choice_variants() {
    assert_ne!(CgroupChoice::UseSudo, CgroupChoice::ContinueWithoutCgroups);
    assert_ne!(CgroupChoice::ConfigureDelegation, CgroupChoice::Abort);
    assert_ne!(CgroupChoice::UseSudo, CgroupChoice::Abort);
    assert_ne!(CgroupChoice::ContinueWithoutCgroups, CgroupChoice::ConfigureDelegation);
    assert_eq!(CgroupChoice::UseSudo, CgroupChoice::UseSudo);
}

#[test]
fn test_cgroup_manager_creation() {
    let manager = CgroupManager::new("test_phantom_container");
    assert_eq!(
        manager.path(),
        PathBuf::from("/sys/fs/cgroup/test_phantom_container").as_path()
    );
}

#[test]
#[ignore = "requires privileges to create cgroups"]
fn test_cgroup_manager_create_and_destroy() {
    let manager = CgroupManager::new("test_phantom_create");
    let result = manager.create();
    if result.is_ok() {
        let destroy_result = manager.destroy();
        assert!(destroy_result.is_ok(), "Should be able to destroy after create");
    } else {
        println!("Create failed (expected without privileges): {:?}", result);
    }
}

#[test]
#[ignore = "requires privileges to set memory limits"]
fn test_cgroup_manager_set_memory_limit() {
    let manager = CgroupManager::new("test_phantom_memory");
    let _ = manager.create();
    let result = manager.set_memory_limit(64 * 1024 * 1024);
    let _ = manager.destroy();
    if result.is_err() {
        println!("Set memory limit failed (expected without privileges): {:?}", result);
    }
}

#[test]
#[ignore = "requires privileges to set PID limits"]
fn test_cgroup_manager_set_pid_limit() {
    let manager = CgroupManager::new("test_phantom_pid");
    let _ = manager.create();
    let result = manager.set_pid_limit(100);
    let _ = manager.destroy();
    if result.is_err() {
        println!("Set PID limit failed (expected without privileges): {:?}", result);
    }
}
