use phantom_build::parser::*;

#[test]
fn test_parse_simple_fragmentfile() {
    let content = r#"
FROM rust:1.75-alpine
WORKDIR /app
COPY . .
RUN cargo build --release
CMD ["./target/release/app"]
"#;

    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 5);
}

#[test]
fn test_parse_multistage() {
    let content = r#"
FROM rust:1.75 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM alpine:3.18
COPY --from=builder /build/target/release/app /usr/local/bin/
CMD ["app"]
"#;

    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    let stages = fragmentfile.stages();
    assert_eq!(stages.len(), 2);
    assert_eq!(stages[0].name, Some("builder".to_string()));
}

#[test]
fn test_parse_empty_input() {
    let content = "";
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 0);
}

#[test]
fn test_parse_comments() {
    let content = r#"
# This is a comment
FROM alpine:3.18
# Another comment
RUN echo hello
"#;
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 2);
    assert!(matches!(fragmentfile.instructions[0], Instruction::From { .. }));
    assert!(matches!(fragmentfile.instructions[1], Instruction::Run { .. }));
}

#[test]
fn test_parse_whitespace_only() {
    let content = "   \n\n  \t  \n";
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 0);
}

#[test]
fn test_parse_from_instruction() {
    let content = "FROM ubuntu:22.04 AS myapp";
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 1);
    match &fragmentfile.instructions[0] {
        Instruction::From { image, stage_name } => {
            assert_eq!(image, "ubuntu:22.04");
            assert_eq!(stage_name, &Some("myapp".to_string()));
        }
        _ => panic!("Expected From instruction"),
    }
}

#[test]
fn test_parse_run_instruction() {
    let content = r#"RUN cargo build --release"#;
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 1);
    match &fragmentfile.instructions[0] {
        Instruction::Run { command, mounts } => {
            assert!(command.iter().any(|c| c.contains("cargo")));
            assert!(mounts.is_empty());
        }
        _ => panic!("Expected Run instruction"),
    }
}

#[test]
fn test_parse_copy_instruction() {
    let content = "COPY --from=builder /app/bin /usr/local/bin/app";
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 1);
    match &fragmentfile.instructions[0] {
        Instruction::Copy {
            from_stage,
            sources,
            destination,
        } => {
            assert_eq!(from_stage, &Some("builder".to_string()));
            assert_eq!(sources, &vec!["/app/bin".to_string()]);
            assert_eq!(destination, "/usr/local/bin/app");
        }
        _ => panic!("Expected Copy instruction"),
    }
}

#[test]
fn test_parse_env_instruction() {
    let content = r#"ENV MY_VAR="hello_world""#;
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 1);
    match &fragmentfile.instructions[0] {
        Instruction::Env { key, value } => {
            assert_eq!(key, "MY_VAR");
            assert_eq!(value, "hello_world");
        }
        _ => panic!("Expected Env instruction"),
    }
}

#[test]
fn test_parse_expose_instruction() {
    let content = "EXPOSE 8080";
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    assert_eq!(fragmentfile.instructions.len(), 1);
    match &fragmentfile.instructions[0] {
        Instruction::Expose { port } => {
            assert_eq!(*port, 8080);
        }
        _ => panic!("Expected Expose instruction"),
    }
}

#[test]
fn test_parse_error_invalid_syntax() {
    let content = "INVALID_KEYWORD something";
    let result = Fragmentfile::from_string(content);
    assert!(result.is_err());
}

#[test]
fn test_parse_multistage_with_names() {
    let content = r#"
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
RUN go build -o /app

FROM alpine:3.18 AS runtime
COPY --from=builder /app /usr/local/bin/
CMD ["/usr/local/bin/app"]
"#;
    let fragmentfile = Fragmentfile::from_string(content).unwrap();
    let stages = fragmentfile.stages();
    assert_eq!(stages.len(), 2);
    assert_eq!(stages[0].name, Some("builder".to_string()));
    assert_eq!(stages[0].base_image, "golang:1.21");
    assert_eq!(stages[1].name, Some("runtime".to_string()));
    assert_eq!(stages[1].base_image, "alpine:3.18");
    assert_eq!(stages[0].instructions.len(), 3);
    assert_eq!(stages[1].instructions.len(), 2);
}
