# AI Sandbox — Deep-Dive Analysis (LLM-first, human-friendly)

## 🚩 **PROJECT STATUS & VISION** 

**Current State: Foundation Complete** • **Next Vision: LLM-Native Runtime** • **Last Updated: Aug 2024**

### **Achievements Unlocked 🏆**
- **Phase 1: CLI Foundation** - Complete Cobra-based interface with configuration management
- **Phase 2: Security Infrastructure** - Comprehensive sandboxing framework with monitoring
- **Current Architecture**: Production-ready CLI tool with extensible plugin architecture

### **Strategic Vision: Phase 3 🔮**
Evolution toward **LLM-native development environment**:
- Seamless AI agent integration through industry standards
- Optional enhancement layer preserving core CLI simplicity
- Bridge between human developers and AI-assisted workflows
- Modular architecture enabling selective feature adoption

---

## Executive Summary

You built a **contextual runtime** for code execution that’s **LLM-native** and **lighter than Docker**. It mixes **bubblewrap**, **chroot**, and **Lima** under a **Go** control plane, wrapped by a **Model Context Protocol (MCP)**. Net effect: an **agent dojo**—LLMs can generate, run, and iterate code safely without polluting your real **maktab \[workspace]**. Humans piggyback with the same smooth UX.

**Positioning:** Not a Docker competitor; a **specialized, AI-first sandbox** optimized for **sar’a \[speed]**, **amn \[security]**, and **low wazn \[overhead]**.

---

## Design Goals (What it optimizes)

* **LLM agency at runtime:** Give models **total access** to compile/run/test within tight **hudud \[boundaries]**.
* **Zero-daemon footprint:** Spawn-on-demand, pay-for-use model.
* **Cross-platform portability:** Native on Linux; **Lima** shims macOS/Windows with minimal ceremony.
* **Predictable isolation:** Stronger defaults than ad-hoc scripts; easier than full containers.
* **Reproducible experiments:** Ephemeral, versionable **rootfs** seeds; deterministic run scaffolds.

---

## Architecture Overview 🏧 **Current Implementation Status**

**Control plane (Go): ✅ IMPLEMENTED**

* Cobra-based CLI orchestrates sandbox lifecycle, profile management, and driver selection.
* Complete configuration system with YAML profiles and structured logging.
* Production-ready static binary delivery = low **wazn \[overhead]** and simple rollout.

**Isolation backends (drivers):**

* **bubblewrap (bwrap):** user namespaces, mount namespace, **seccomp**, capabilities drop; selective bind mounts; minimal **nizam \[system]** exposure.
* **chroot:** fast, primitive FS jail; used where bwrap isn’t available or as last-mile step inside bwrap.
* **Lima:** micro-VM bridge for non-Linux hosts to present a Linux-like substrate.

**Filesystem strategy:**

* Base: `alpine-minirootfs.tar.gz` (or similar).
* Ephemeral writable **overlayfs** (or tmpfs) per run; promote-on-success optional.
* **Qayd \[metadata]** manifests (JSON/YAML) to describe mounts, env, entrypoint.

**MCP (Model Context Protocol) layer:**

* Declares **hudud \[limits]**: CPU/RAM caps, FS scope, network policy, lifetime, tool access.
* Exposes **intents**: `run`, `test`, `build`, `format`, `lint`, `bench`.
* Streams logs/artifacts back to the calling agent with trace IDs.

**I/O & Telemetry:**

* Structured logs (JSON), **stdout/stderr** capture, exit codes.
* Optional event bus hooks for observability (OpenTelemetry).

---

## Security Model (Why it can outperform Docker defaults)

**Threat model:** Untrusted code from an LLM running on your box. Goals: contain file access, kill network unless allowed, limit resource abuse, prevent escape.

**Controls:**

* **User namespaces:** unprivileged root inside; non-root outside.
* **Seccomp:** syscall allowlist; deny risky syscalls by default.
* **Capabilities:** start from none; add only what’s strictly needed.
* **Read-only rootfs:** bind-ro everything except ephemeral work dirs.
* **Network policy:** default **la shabaka \[no network]**, opt-in per run (loopback only, or egress-restricted).
* **cgroups v2:** hard caps on CPU, memory, pids; OOM-kill friendly.
* **No long-lived daemon:** fewer attack surfaces than `dockerd`.
* **Minimal device exposure:** controlled `/dev` nodes only, no raw disk.
* **Mount filters:** disallow proc/sys sensitive paths unless read-only and sanitized (`/proc` subset, masked `/sys`).

**Where Docker still wins:**

* Mature enterprise hardening profiles, SELinux/AppArmor presets, broad ecosystem scanners (Trivy, etc.).
* Complex multi-container network topologies and secrets distribution.

---

## Performance & Footprint

**Startup latency:** Milliseconds to a few hundred ms (no daemon, minimal setup).
**Memory overhead:** Only the target process + small runtime scaffolding.
**Disk:** Rootfs tarballs are small; overlayfs layers are ephemeral.
**Throughput:** Ideal for many short-lived runs (LLM iteration loops).

**Suggested benchmark protocol (copy-paste playbook):**

1. **Cold start:** time to `bash -lc "echo ok"` inside sandbox (10x runs; p50/p95).
2. **Compile micro-target:** `go build`, `python -m py_compile`, `npm ci && npm test` (synthetic).
3. **Resource caps:** verify CPU throttling and OOM behavior with stress tests.
4. **Network policy:** attempt outbound calls under default deny; confirm block.
5. **File containment:** attempt path traversal and special file access; confirm deny.

---

## Developer Experience (DX)

**CLI sketch:**

```bash
aisbx init --rootfs alpine-3.20.tar.gz
aisbx run --driver bwrap --cpu 1 --mem 256m --no-net -- /usr/bin/python main.py
aisbx mount --ro ./dataset:/mnt/ds
aisbx allow net:egress:github.com:443
aisbx logs --follow <run-id>
aisbx promote --artifact build/mybin --to ../repo/bin/
```

**Agent flow (MCP Tools):**

1. `tools/list` → discover available tools (run, test, build, etc.).
2. `tools/call` → execute tool with parameters; capture structured results.
3. `resources/read` → access contextual data (files, logs, artifacts).
4. `prompts/get` → retrieve workflow templates for common tasks.
5. **Human-in-the-loop** → user approves sensitive operations.

**Human UX:** Same commands, just fewer flags thanks to sane defaults.

---

## Interop & Packaging

* **Direct rootfs + wrapper** = simplest, fastest for your niche.
* Optional **pseudo-image** spec (lightweight):

  * `image.yaml` (name, version, base), `layers/` (rsync/tar diffs), `policy.json` (caps, seccomp, net).
  * Distribution via simple HTTP/OCI-artifact store later if needed.
* **OCI compatibility (optional):** Convert OCI image → rootfs tarball for reuse, skipping the Docker daemon entirely.

---

## Core Use Cases (Where it crushes)

1. **Agentic coding loops:** rapid generate-run-fix cycles with strong guardrails.
2. **Security research & untrusted snippets:** default-deny network, tight seccomp.
3. **Education/labs:** disposable environments without Docker Desktop overhead.
4. **CI sidecars for unit tests:** spawn thousands of short runs cheaply.
5. **Data prep & tooling trials:** mount datasets read-only; zero host pollution.

---

## Limitations (Be honest, stay strong)

* **Complex networking:** multi-service topologies are DIY (you can add a tiny CNI later).
* **Ecosystem gravity:** no registry/network effects like Docker Hub—by design.
* **Observability at scale:** you’ll add exporters if you ever run farms of sandboxes.
* **Windows native syscall parity:** relies on Lima; that’s fine, but it’s a shim.

---

## Roadmap (Zero fluff, high ROI)

**Security hardening:**

* Prebuilt **seccomp** profiles per language/toolchain.
* **AppArmor/SELinux** policy templates on Linux.
* **Secrets API:** tmpfs injection, auto-scrub from logs.

**DX & control:**

* **Profiles** (`profiles/dev.yaml`, `profiles/strict.yaml`) for one-flag runs.
* **Snapshot/restore:** `aisbx snap` to checkpoint working states.
* **Policy-as-code:** Rego (OPA) or cue for guardrails.

**Scale & ops:**

* **Supervisor micro-service** to queue/rate-limit runs across a node.
* **Prom metrics:** run duration, OOMs, denied syscalls, cache hit rate.

**Interop (optional):**

* **OCI → rootfs** converter; **rootfs → pseudo-image** packer.

---

## Minimal Config Examples

**Sandbox profile (YAML):**

```yaml
name: py-dev-strict
driver: bwrap
cpu: "1"
mem: "256m"
net: "none"
mounts:
  - host: ./src
    guest: /workspace/src
    mode: ro
  - host: ./tmp
    guest: /workspace/tmp
    mode: rw
seccomp: profiles/python-min.json
caps: []
lifetime: "300s"
env:
  - PYTHONUNBUFFERED=1
entrypoint: ["/usr/bin/python3", "/workspace/src/main.py"]
```

**MCP tool call (JSON-RPC 2.0):**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "run",
    "arguments": {
      "profile": "python-dev",
      "command": ["python", "test.py"],
      "workdir": "/workspace"
    }
  }
}
```

---

## 🎯 Strategic Roadmap: LLM-Native Evolution

**Vision**: Transform AI Sandbox into the standard runtime for LLM-assisted development while preserving its core simplicity and security.

### **Architectural Philosophy**
- **Modular Enhancement**: Core CLI remains unchanged, AI features as optional layer
- **Industry Standards**: Leverage established protocols for maximum compatibility  
- **User Choice**: Developers choose their level of AI integration
- **Security First**: All enhancements maintain existing security guarantees

### **Integration Approach**
- Separate enhancement binary for AI functionality
- Standard protocol compliance for broad ecosystem support
- Seamless bridge between CLI and AI agent workflows
- Preservation of performance characteristics for direct usage

---

## Testing Matrix (Don't ship vibes, ship evidence)

* **Langs:** Python, Node, Go, Rust, Java (minimal JRE), C/C++.
* **Ops:** CPU/mem caps; disk quotas; PID limits; fork bombs blocked.
* **Security:** path traversal, device access, ptrace attempts, `/proc` probing, `clone3` regimes.
* **Network:** default-deny; selective allow; DNS leaks; proxy abuse.
* **Portability:** Linux (bare), macOS (Lima), Windows (Lima) parity checks.

---

## KPIs to Track (Business brain on)

* **p50/p95** sandbox start time.
* **Sandbox per hour** throughput on a standard dev laptop.
* **OOM/kill rate** and mean fix time for agents.
* **Network policy violations** per 1k runs (should trend to zero).
* **Artifact promotion accuracy** (no dirty host writes).
* **Agent success rate** per N steps (measures your MCP + sandbox synergy).

---

## Naming (optional, brand-fit)

You want it **serious, fast, and AI-aware**:

* **ForgeBox**, **PulseCore**, **SpectreLab**, **Slipstream**, **Draftium**.
  Pick one that matches your **ru’ya \[vision]**—or let Reddit fight it out. 😉

---

## Bottom Line

You’ve created a **lean, secure, cross-platform** **nizam \[system]** that maximizes **LLM agency** with minimal **wazn \[overhead]**. It’s **lighter than Docker**, safer by default for untrusted snippets, and purpose-built for **agentic coding loops**. Keep it focused. If you ever pivot to a public ecosystem, bolt on a **pseudo-image** and a thin registry—**ba’dayn \[later]**, not now.

If you want, I can compress this into a **README skeleton** next, optimized for developer eyeballs and Reddit clout.
