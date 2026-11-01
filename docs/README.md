# Phantom Fragment Documentation

Status: index. Last verified against `8b51686`, version 3.1.0.

Start with the [main README](../README.md) if you have not built the project yet.

## Using it

| Document | Description |
|---|---|
| [CLI Reference](usage/cli-reference.md) | Every subcommand and flag |
| [Configuration](CONFIGURATION_GUIDE.md) | `phantom.toml`, profiles, resource settings |
| [Migration from Docker](migration/from-docker.md) | Moving workloads over |

## Understanding it

| Document | Description |
|---|---|
| [Technical overview](architecture/overview.md) | One-page map: what it is, measured numbers, how a run is dispatched, what is missing |
| [Native executor](architecture/components/native-executor.md) | The default cold engine: process layout, mounts, Landlock scope, verified behaviour, gaps |
| [Warm execution](architecture/components/warm-exec-v2.md) | What warm is, the three methods (mother fragment, zygote pool, artifact cache), status of each |
| [Adaptive execution](architecture/components/adaptive-execution.md) | `execution-rs`: mode selection and the host fork-exec path |
| [Memory discipline](architecture/components/memory-discipline.md) | The Zig buffer pool, KSM and NUMA |
| [Policy DSL](architecture/components/policy-dsl.md) | YAML policy compiled to seccomp and Landlock rules |

## Working on it

| Document | Description |
|---|---|
| [Testing](testing/README.md) | Test layout and how to run the suites |
| [Changelog](CHANGELOG.md) | Version history |
| [AGENTS.md](../AGENTS.md) | Build commands, conventions, workspace layout |
