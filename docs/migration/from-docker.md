# Migrating from Docker

Status: current. Last verified against `8b51686`.

This guide covers what actually transfers. Several Docker features have **no equivalent
yet** — they are listed explicitly at the end rather than papered over with a flag that
does not exist.

## What transfers

| Docker | Phantom Fragment | Notes |
|---|---|---|
| Dockerfile | Fragmentfile | the parser accepts a Dockerfile subset, see below |
| `docker build -t x .` | `phantom build -t x .` | multi-stage builds work |
| `docker run image cmd` | `phantom run image cmd` | rootless, no daemon |
| `docker run --rm` | `phantom run` | cold runs are already ephemeral |
| `docker run -e K=V` | `phantom run` with the variable in the environment | no `-e` flag yet |
| `docker run --network host` | `phantom run -n` | `-n` keeps the host network namespace |
| `docker run --network none` | `phantom run` (default) | network namespace with no route |
| `docker run --read-only` | `phantom run -p hardened` | read-only rootfs |
| `docker ps` | `phantom list` | registry-backed, not a live process list |
| `docker rm` | `phantom destroy` | |
| `docker logs` | `phantom logs` | reads `~/.phantom/logs/<name>.log` |

## What does not transfer

| Docker | Status here |
|---|---|
| `docker pull` | no `pull` subcommand; `phantom run` pulls on demand (`--no-pull` to disable) |
| `-p` / `--expose` | no port publishing |
| `-v` / `--mount` | no user volumes; `phantom volume` manages internal storage only |
| `docker exec` | no exec into a running fragment |
| `docker run -d` | no detached mode |
| `docker attach` | no attach; warm runs stream to the caller's stdio but cannot be attached later |
| `docker compose` | no Compose parser, no `up`/`down` |
| `--restart` | no restart policy |
| `docker commit` | no commit |
| `docker save` / `load` | no image export/import |
| `--privileged`, `--cap-add` | no capability *addition*; the runtime only drops |
| healthchecks in the image | not read |

## Dockerfile → Fragmentfile

The migrate tool converts and can rewrite layers:

```bash
phantom migrate analyze Dockerfile
phantom migrate docker Dockerfile --output Fragmentfile --optimize
phantom migrate docker Dockerfile --compat
```

`--optimize` merges adjacent `RUN` lines and appends cache cleanup. `--compat` keeps the
file byte-identical in behaviour to the Docker original.

The parser is a subset. Supported instructions: `FROM`, `RUN`, `COPY`, `ADD`, `WORKDIR`,
`ENV`, `ARG`, `CMD`, `ENTRYPOINT`, `EXPOSE` (parsed and recorded, not published), `USER`,
`LABEL`, `VOLUME` (recorded, not mounted). Multi-stage `COPY --from=` works.

If the parser rejects an instruction it fails the build rather than skipping it.

## Building

```bash
phantom build -t myapp:latest .
```

`phantom build` is the only path that records `ENTRYPOINT`/`CMD`/`USER` for later runs
(in `phantom-config.json` inside the rootfs). Images pulled from a registry do not carry
that metadata yet, so `phantom run <pulled-image>` requires an explicit command.

## From a running container

```bash
docker export my-container > container.tar
mkdir rootfs && tar -xf container.tar -C rootfs
```

There is no `--rootfs` flag. To run that tree you currently have to register it as an
image, which is not implemented either. Exporting a running container is therefore a dead
end today; rebuild from the Dockerfile instead.

## Compose

No equivalent. A Compose file has to be translated by hand into separate `phantom run`
invocations plus profile definitions in `phantom.toml`.

## Benchmarks

Measure it yourself:

```bash
time docker run --rm alpine true
time phantom run alpine true
```

On the development machine: `phantom run alpine true` ≈ 14 ms, of which ~7 ms is CLI
startup. Rootless podman is ~342 ms with a cached image, and much faster when its own
cache is warm.
Any "N× faster" figure depends on that cache state; the previously quoted "8–10× faster,
39× lighter, 640× smaller" was never measured and has been removed.
