use oci_registry_rs::*;

#[test]
fn test_parse_simple() {
    let ref_ = ImageReference::parse("ubuntu:22.04").unwrap();
    assert_eq!(ref_.registry, "docker.io");
    assert_eq!(ref_.repository, "library/ubuntu");
    assert_eq!(ref_.tag, "22.04");
}

#[test]
fn test_parse_ghcr() {
    let ref_ = ImageReference::parse("ghcr.io/user/app:latest").unwrap();
    assert_eq!(ref_.registry, "ghcr.io");
    assert_eq!(ref_.repository, "user/app");
    assert_eq!(ref_.tag, "latest");
}

#[test]
fn test_parse_default_tag() {
    let ref_ = ImageReference::parse("nginx").unwrap();
    assert_eq!(ref_.registry, "docker.io");
    assert_eq!(ref_.repository, "library/nginx");
    assert_eq!(ref_.tag, "latest");
}
