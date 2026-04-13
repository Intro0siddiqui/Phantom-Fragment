use crate::permission_prompt::*;
use security_rs::{PrivilegeChoice, PrivilegeRequirements, SecurityFeature};

#[test]
fn test_privilege_choice_variants() {
    // Test that all variants exist and are distinct
    assert_ne!(PrivilegeChoice::UseSudo, PrivilegeChoice::ContinueWithout);
    assert_ne!(PrivilegeChoice::ContinueWithout, PrivilegeChoice::Abort);
    assert_ne!(PrivilegeChoice::UseSudo, PrivilegeChoice::Abort);
}

#[test]
fn test_privilege_requirements() {
    let req = PrivilegeRequirements {
        required: vec![SecurityFeature::BpfLsm],
        available: vec![SecurityFeature::Cgroups],
    };
    assert!(req.needs_elevation());

    let req_empty = PrivilegeRequirements {
        required: vec![],
        available: vec![SecurityFeature::Cgroups, SecurityFeature::BpfLsm],
    };
    assert!(!req_empty.needs_elevation());
}
