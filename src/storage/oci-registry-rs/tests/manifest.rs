use oci_registry_rs::*;

#[test]
fn test_parse_oci_manifest() {
    let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 1234,
                "digest": "sha256:abcd"
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": 5678,
                    "digest": "sha256:efgh"
                }
            ]
        }"#;

    let manifest = ImageManifest::from_bytes(json.as_bytes()).unwrap();
    assert_eq!(manifest.schema_version, 2);
    assert_eq!(manifest.layers.len(), 1);
    assert_eq!(manifest.total_size(), 1234 + 5678);
}
