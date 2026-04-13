use cgroups_rs::*;
use std::path::PathBuf;

#[test]
fn test_cgroup_manager_paths() {
    let manager = CgroupManager::new("test_container");
    assert_eq!(
        manager.path(),
        PathBuf::from("/sys/fs/cgroup/test_container").as_path()
    );

    let manager_abs = CgroupManager::new("/tmp/cgroup/test");
    assert_eq!(
        manager_abs.path(),
        PathBuf::from("/tmp/cgroup/test").as_path()
    );
}

#[test]
fn test_user_slice_status_enum() {
    assert_ne!(UserSliceStatus::Available, UserSliceStatus::Unavailable);
    assert_ne!(UserSliceStatus::CanCreate, UserSliceStatus::NotWritable);
}

#[test]
fn test_get_user_slice_path() {
    let path = get_user_slice_path();
    let uid = unsafe { libc::getuid() };
    let expected = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    assert_eq!(path, expected);
}

#[test]
fn test_detect_cgroup_version() {
    let version = detect_cgroup_version();
    assert!(version <= 2);
}
