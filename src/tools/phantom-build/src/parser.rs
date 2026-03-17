//! Fragmentfile parser
//!
//! Parses Dockerfile-compatible Fragmentfiles with extensions

use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::path::Path;

#[derive(Parser)]
#[grammar = "fragmentfile.pest"]
pub struct FragmentfileParser;

/// Parsed Fragmentfile instruction
#[derive(Debug, Clone)]
pub enum Instruction {
    From {
        image: String,
        stage_name: Option<String>,
    },
    Run {
        command: Vec<String>,
        mounts: Vec<String>,
    },
    Copy {
        from_stage: Option<String>,
        sources: Vec<String>,
        destination: String,
    },
    Add {
        source: String,
        destination: String,
        checksum: Option<String>,
    },
    Workdir {
        path: String,
    },
    Env {
        key: String,
        value: String,
    },
    Expose {
        port: u16,
    },
    Cmd {
        args: Vec<String>,
    },
    Entrypoint {
        args: Vec<String>,
    },
    User {
        user: String,
    },
    Label {
        key: String,
        value: String,
    },
    Arg {
        name: String,
        default: Option<String>,
    },
    Volume {
        paths: Vec<String>,
    },
}

/// Parsed Fragmentfile
#[derive(Debug, Clone)]
pub struct Fragmentfile {
    pub instructions: Vec<Instruction>,
}

impl Fragmentfile {
    /// Parse from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_string(&content)
    }

    /// Parse from string
    pub fn from_string(content: &str) -> anyhow::Result<Self> {
        // use pest::iterators::Pair; // Removed unused import

        let pairs = FragmentfileParser::parse(Rule::fragmentfile, content)
            .map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;

        let mut instructions = Vec::new();

        for pair in pairs {
            for inner in pair.into_inner() {
                if let Some(instruction) = Self::parse_instruction(inner)? {
                    instructions.push(instruction);
                }
            }
        }

        Ok(Fragmentfile { instructions })
    }

    fn parse_instruction(pair: Pair<Rule>) -> anyhow::Result<Option<Instruction>> {
        match pair.as_rule() {
            Rule::instruction => {
                let inner = pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Expected instruction content"))?;
                Self::parse_instruction(inner)
            }
            Rule::from_instruction => {
                let mut inner = pair.into_inner();
                let image = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("FROM instruction requires an image name"))?
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                let stage_name = inner.next().map(|p| p.as_str().to_string());
                Ok(Some(Instruction::From { image, stage_name }))
            }

            Rule::run_instruction => {
                let mut mounts = Vec::new();
                let mut command = Vec::new();

                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::run_mount => {
                            let mount_str = inner_pair.as_str();
                            mounts.push(mount_str.to_string());
                        }
                        _ => {
                            // Assume it's a value (command part)
                            command.push(inner_pair.as_str().to_string());
                        }
                    }
                }
                Ok(Some(Instruction::Run { command, mounts }))
            }

            Rule::copy_instruction => {
                let mut from_stage: Option<String> = None;
                let mut paths: Vec<String> = Vec::new();

                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::copy_from => {
                            // Extract identifier from copy_from
                            if let Some(id) = inner_pair.into_inner().next() {
                                from_stage = Some(id.as_str().to_string());
                            }
                        }
                        Rule::path => {
                            paths.push(inner_pair.as_str().to_string());
                        }
                        _ => {}
                    }
                }

                if paths.len() < 2 {
                    return Err(anyhow::anyhow!(
                        "COPY requires at least two arguments (source and destination)"
                    ));
                }

                let destination = paths
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("COPY instruction requires a destination"))?;
                let sources = paths;

                Ok(Some(Instruction::Copy {
                    from_stage,
                    sources,
                    destination,
                }))
            }

            Rule::add_instruction => {
                let mut inner = pair.into_inner();
                let source = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("ADD instruction requires a source"))?
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                let destination = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("ADD instruction requires a destination"))?
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                // Note: checksum parsing would require additional grammar rules
                // For now, checksum can be specified via comment or future enhancement
                Ok(Some(Instruction::Add {
                    source,
                    destination,
                    checksum: None,
                }))
            }

            Rule::workdir_instruction => {
                let path = pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("WORKDIR instruction requires a path"))?
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                Ok(Some(Instruction::Workdir { path }))
            }

            Rule::env_instruction => {
                let mut inner = pair.into_inner();
                let key = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("ENV instruction requires a key"))?
                    .as_str()
                    .to_string();
                let value = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("ENV instruction requires a value"))?
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                Ok(Some(Instruction::Env { key, value }))
            }

            Rule::cmd_instruction => {
                let args: Vec<String> = pair
                    .into_inner()
                    .map(|p| p.as_str().trim_matches('"').to_string())
                    .collect();
                Ok(Some(Instruction::Cmd { args }))
            }

            Rule::entrypoint_instruction => {
                let args: Vec<String> = pair
                    .into_inner()
                    .map(|p| p.as_str().trim_matches('"').to_string())
                    .collect();
                Ok(Some(Instruction::Entrypoint { args }))
            }

            Rule::user_instruction => {
                let user = pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("USER instruction requires a user name"))?
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                Ok(Some(Instruction::User { user }))
            }

            Rule::arg_instruction => {
                let mut inner = pair.into_inner();
                let name = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("ARG instruction requires a name"))?
                    .as_str()
                    .to_string();
                let default = inner
                    .next()
                    .map(|p| p.as_str().trim_matches('"').to_string());
                Ok(Some(Instruction::Arg { name, default }))
            }

            Rule::label_instruction => {
                let mut inner = pair.into_inner();
                let key = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("LABEL instruction requires a key"))?
                    .as_str()
                    .to_string();
                let value = inner
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("LABEL instruction requires a value"))?
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                Ok(Some(Instruction::Label { key, value }))
            }

            Rule::expose_instruction => {
                let port_str = pair
                    .into_inner()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("EXPOSE instruction requires a port number"))?
                    .as_str();
                let port = port_str
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid port number '{}': {}", port_str, e))?;
                Ok(Some(Instruction::Expose { port }))
            }

            Rule::volume_instruction => {
                let paths: Vec<String> = pair
                    .into_inner()
                    .map(|p| p.as_str().trim_matches('"').to_string())
                    .collect();
                Ok(Some(Instruction::Volume { paths }))
            }

            _ => Ok(None),
        }
    }

    /// Get all build stages (for multi-stage builds)
    pub fn stages(&self) -> Vec<BuildStage> {
        let mut stages = Vec::new();
        let mut current_stage = BuildStage {
            name: None,
            base_image: String::new(),
            instructions: Vec::new(),
        };

        for instruction in &self.instructions {
            match instruction {
                Instruction::From { image, stage_name } => {
                    if !current_stage.base_image.is_empty() {
                        stages.push(current_stage.clone());
                    }
                    current_stage = BuildStage {
                        name: stage_name.clone(),
                        base_image: image.clone(),
                        instructions: Vec::new(),
                    };
                }
                _ => {
                    current_stage.instructions.push(instruction.clone());
                }
            }
        }

        if !current_stage.base_image.is_empty() {
            stages.push(current_stage);
        }

        stages
    }
}

/// A build stage (for multi-stage builds)
#[derive(Debug, Clone)]
pub struct BuildStage {
    pub name: Option<String>,
    pub base_image: String,
    pub instructions: Vec<Instruction>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
