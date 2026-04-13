use oci_registry_rs::*;

#[test]
fn test_basic_auth_header() {
    let auth = AuthConfig::from_credentials("user".to_string(), "pass".to_string());
    let header = auth
        .basic_auth_header()
        .expect("basic_auth_header should return Some for valid credentials");
    assert!(header.starts_with("Basic "));
}

#[test]
fn test_bearer_token_header() {
    let auth = AuthConfig::from_token("mytoken123".to_string());
    let header = auth
        .bearer_token_header()
        .expect("bearer_token_header should return Some for valid token");
    assert_eq!(header, "Bearer mytoken123");
}
