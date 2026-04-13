use phantom_build::*;
use phantom_build::executor::BuildContext;
use phantom_build::parser::{Fragmentfile, Instruction};
use std::path::PathBuf;

#[test]
fn test_build_context_add_secret() {
    let args = Args {
        context: PathBuf::from("."),
        tag: None,
        file: "Fragmentfile".to_string(),
        no_cache: false,
        target: None,
        verbose: false,
        secret: vec!["mysecret=/path/to/secret".to_string()],
        build_arg: vec![],
    };

    let mut context = BuildContext::new(&args.context);
    for secret_arg in &args.secret {
        if let Some((id, path)) = secret_arg.split_once('=') {
            context.secrets.insert(id.to_string(), PathBuf::from(path));
        }
    }

    assert!(context.secrets.contains_key("mysecret"));
    assert_eq!(context.secrets["mysecret"], PathBuf::from("/path/to/secret"));
}

#[test]
fn test_build_context_add_build_arg() {
    let args = Args {
        context: PathBuf::from("."),
        tag: None,
        file: "Fragmentfile".to_string(),
        no_cache: false,
        target: None,
        verbose: false,
        secret: vec![],
        build_arg: vec![
            "VERSION=1.0.0".to_string(),
            "APP_NAME=myapp".to_string(),
        ],
    };

    let mut context = BuildContext::new(&args.context);
    for build_arg in &args.build_arg {
        if let Some((name, value)) = build_arg.split_once('=') {
            context
                .build_args
                .insert(name.to_string(), value.to_string());
        }
    }

    assert_eq!(context.build_args.get("VERSION"), Some(&"1.0.0".to_string()));
    assert_eq!(context.build_args.get("APP_NAME"), Some(&"myapp".to_string()));
    assert_eq!(context.build_args.len(), 2);
}

#[test]
fn test_parse_and_execute_minimal() {
    // Test parsing a minimal Fragmentfile and verifying stage extraction
    let content = r#"FROM alpine:3.18
WORKDIR /app
ENV MY_VAR="test"
EXPOSE 8080
"#;

    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    let stages = fragmentfile.stages();

    assert_eq!(stages.len(), 1);
    assert_eq!(stages[0].base_image, "alpine:3.18");
    assert_eq!(stages[0].instructions.len(), 3);

    // Verify instruction types
    assert!(matches!(stages[0].instructions[0], Instruction::Workdir { .. }));
    assert!(matches!(stages[0].instructions[1], Instruction::Env { .. }));
    assert!(matches!(stages[0].instructions[2], Instruction::Expose { .. }));
}
