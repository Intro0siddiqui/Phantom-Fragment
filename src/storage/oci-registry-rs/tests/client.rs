use oci_registry_rs::*;

#[test]
fn test_parse_docker_hub() {
    let ref_ = ImageReference::parse("ubuntu:22.04").unwrap();
    assert_eq!(ref_.registry, "docker.io");
    assert_eq!(ref_.registry_url(), "https://registry-1.docker.io");
}

#[test]
fn test_parse_ghcr() {
    let ref_ = ImageReference::parse("ghcr.io/user/app:latest").unwrap();
    assert_eq!(ref_.registry, "ghcr.io");
    assert_eq!(ref_.registry_url(), "https://ghcr.io");
}

#[test]
fn test_parse_quay() {
    let ref_ = ImageReference::parse("quay.io/org/image:v1").unwrap();
    assert_eq!(ref_.registry, "quay.io");
    assert_eq!(ref_.registry_url(), "https://quay.io");
}

#[test]
fn test_parse_custom_registry() {
    let ref_ = ImageReference::parse("myregistry.com:5000/app:latest").unwrap();
    assert_eq!(ref_.registry, "myregistry.com:5000");
    assert_eq!(ref_.registry_url(), "https://myregistry.com:5000");
}
