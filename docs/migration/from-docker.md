# Migrating from Docker to Phantom Fragment

This guide shows you how to migrate your Docker setup to Phantom Fragment.

## Why Migrate?

**Performance Benefits:**
- **8-10× faster** startup times
- **39× lighter** memory footprint  
- **2.6-3.7× faster** I/O throughput
- **640× smaller** tooling (3.6MB vs 2.3GB)

## Migration Tools

Phantom Fragment provides integrated migration subcommands:

```bash
# Analyze your Dockerfile
phantom migrate analyze Dockerfile

# Convert Dockerfile to Fragmentfile (with optimizations)
phantom migrate docker Dockerfile --output Fragmentfile --optimize

# Maintain strict Docker compatibility
phantom migrate docker Dockerfile --compat
```

## Dockerfile → Fragmentfile Migration

**Good news:** Fragmentfiles ARE Dockerfiles! The syntax is 100% compatible.

### Simple Migration

Most Dockerfiles work as-is:

```bash
# Just rename it!
cp Dockerfile Fragmentfile

# Or use migrate tool
phantom migrate docker Dockerfile
```

### With Optimization

The migrate tool can optimize your Dockerfiles:

```bash
phantom migrate docker Dockerfile --optimize
```

**Before (Docker):**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y wget
COPY app.py /app/
CMD ["python3", "/app/app.py"]
```

**After (Optimized Fragmentfile):**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y curl wget && \
    rm -rf /var/lib/apt/lists/*
COPY app.py /app/
CMD ["python3", "/app/app.py"]
```

**Benefits:**
- Fewer layers = smaller image
- Better caching
- Cleanup included

## Multi-Stage Build Migration

Docker multi-stage builds work identically:

```dockerfile
# Build stage
FROM rust:1.75-alpine AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:3.18
COPY --from=builder /build/target/release/app /usr/local/bin/
CMD ["app"]
```

**No changes needed!** Use with Phantom Fragment:

```bash
phantom build -t myapp:latest .
```

## Migrating Running Containers

### Export from Docker

```bash
# Export Docker container filesystem
docker export my-container > container.tar

# Import to Phantom Fragment
mkdir rootfs
tar -xf container.tar -C rootfs
phantom run --rootfs ./rootfs -- /bin/bash
```

### Docker Compose Migration

Docker Compose files need conversion to Phantom Fragment profiles.

**Docker Compose:**
```yaml
services:
  web:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/data
```

**Phantom Fragment Equivalent:**
```bash
# Build image
phantom build -t web:latest .

# Run with options
phantom run web:latest \
  --network enabled \
  --expose 8000 \
  --mount ./data:/data:rw \
  -- python app.py
```

## Registry Migration

Pull images from Docker Hub:

```bash
# Phantom Fragment can pull directly
phantom pull ubuntu:22.04
phantom pull python:3.11-slim
phantom pull node:18-alpine
```

## Common Migration Patterns

### Pattern 1: Web Application

**Docker:**
```bash
docker build -t myapp .
docker run -p 8000:8000 myapp
```

**Phantom Fragment:**
```bash
phantom build -t myapp .
phantom run myapp --network enabled --expose 8000
```

### Pattern 2: Development Environment

**Docker:**
```bash
docker run -it --rm -v $(pwd):/workspace ubuntu:22.04 bash
```

**Phantom Fragment:**
```bash
phantom run ubuntu:22.04 \
  --mount $(pwd):/workspace:rw \
  -- /bin/bash
```

### Pattern 3: CI/CD Pipeline

**Docker:**
```bash
docker build -t test .
docker run --rm test npm test
```

**Phantom Fragment:**
```bash
phantom build -t test .
phantom run test -- npm test
```

## Migration Checklist

- [ ] Analyze current Dockerfiles with `phantom-migrate analyze`
- [ ] Convert Dockerfiles to Fragmentfiles
- [ ] Test builds with `phantom build`
- [ ] Verify runtime behavior with `phantom run`
- [ ] Update CI/CD pipelines
- [ ] Migrate docker-compose to Phantom profiles
- [ ] Update team documentation

## Troubleshooting

### Issue: "Image not found"

Make sure to pull or build the image first:
```bash
phantom pull ubuntu:22.04
# OR
phantom build -t myapp .
```

### Issue: "Permission denied"

Enable user namespaces:
```bash
echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone
```

### Issue: "Network not working"

Use network-enabled profile:
```bash
phantom run --network enabled myimage
```

## Performance Comparison

Run your own benchmark:

```bash
# Compare Docker vs Phantom Fragment
time docker run --rm ubuntu:22.04 echo "Hello"
time phantom run ubuntu:22.04 -- echo "Hello"
```

**Typical results:**
- Docker: ~1.2 seconds
- Phantom Fragment: ~0.15 seconds ⚡

## Next Steps

- Read the [Architecture Overview](../architecture/overview.md)
- Check the [Implementation Guide](../IMPLEMENTATION_GUIDE.md)
