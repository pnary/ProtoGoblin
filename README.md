# ProtoGoblin

**Cross-Platform Game Compatibility, Profiling, and Optimization Runtime**

> [!WARNING]
> **Project Status: Early Architecture & Planning Phase**
> 
> **Nothing works yet.** ProtoGoblin is currently under active initial development (Phase 0). Features, wrappers, and telemetry hooks are in design/prototyping and are not yet functional for general gameplay.

ProtoGoblin is an open-source, locally controlled compatibility and runtime optimization framework for running Windows games on Linux through a custom Steam Proton compatibility tool (with a standalone Windows launcher planned for future phases).

Unlike traditional external profilers or opaque compatibility wrappers, ProtoGoblin's distinguishing feature is **introspective telemetry**: because it sits directly in the application's execution path as the compatibility and API translation layer (Wine, DXVK, vkd3d-proton), it monitors its own internal utilization alongside platform counters in user space—without requiring game source code, binary modification, or elevated kernel privileges.

---

## Key Features

* **Introspective Self-Monitoring:**
  * **Tier 1 (Always-On Footprint):** Ultra-low-overhead (<0.1%) runtime counters tracking loaded Win32/graphics subsystems, active translation backends, and synchronization paths (`ntsync`, `fsync`, or `wineserver` RPC fallbacks). Emits a structured `utilization.json` manifest upon exit.
  * **Tier 2 (ROI-Gated Latency Histograms):** Activated during targeted gameplay capture windows (via in-game hotkey `Alt+F11` or warmup timers). Accurately distinguishes **Game Execution Time** from **Compatibility Layer Overhead**.
* **Dual Operating Modes:**
  * **Play Mode:** Minimal-overhead execution applying only validated, user-approved optimizations while pruning unused interceptors identified by Tier-1 telemetry.
  * **Profile Mode:** Comprehensive diagnostic data gathering, frame-time pacing, and translation-layer boundary profiling within controlled Regions of Interest (ROI).
* **Process-Tree & Launcher Tracking:**
  * Transparently monitors intermediate game launchers and bootstrappers, ensuring telemetry and hooks bind to the actual target game binary and cleanly finalize sessions upon exit.
* **Safe, Reversible Optimization Lifecycle:**
  * Strict policy-driven workflow: `observed → proposed → tested → validated/rejected → approved for play`.
  * Game binaries remain completely untouched. All optimizations fail closed and can be rolled back instantly.

---

## Project Scope & Current Focus

* **Platform Focus:** **Linux Steam Compatibility Tool** (Proof of Concept). Native Windows launcher support is deferred until the Linux PoC is established.
* **Architecture:** Strictly **x86 variants (x86_64 and 32-bit x86)**. Non-x86 architectures (ARM64, FEX-Emu emulation, ARM64EC) are explicitly out of scope.
* **Upstream Foundation:** Built on top of Valve Proton and GE-Proton patch stacks.

---

## Roadmap

* **Phase 0 — Linux PoC & Tier-1 Manifest (Current):**
  * Custom Steam compatibility tool registration (`ProtoGoblin-0.02`).
  * Process-tree tracking through game launchers.
  * Tier-1 always-on subsystem tracking and `utilization.json` generation.
* **Phase 1 — Profiling MVP & Tier-2 Boundary Histograms:**
  * Region-of-Interest (ROI) controller (timers & hotkey toggles).
  * Lock-free TLS latency histograms measuring compatibility-layer vs. game execution time.
  * Frame timing and offline analytical summaries.
* **Phase 2 — Experiments & Subsystem Pruning:**
  * Per-game TOML profile manager.
  * Play-mode pruning of unused subsystem hooks.
  * Reproducible A/B experiment evaluation and rollback.
* **Phase 3+ — Custom Compatibility Fast-Paths & Ecosystem:**
  * State caching and fast-path overrides for identified translation bottlenecks.
  * Windows wrapper implementation once Linux PoC is complete.

---

## Building and Installation

### Requirements
* Linux host with Docker or Podman
* Steam Runtime SDK container

### Development Commands
```bash
# Populate dependencies
git submodule update --init --recursive

# Apply patch set from root
./patches/protonprep-valve-staging.sh &> patchlog.txt

# Create build directory
mkdir -p build && cd build

# Configure build
../configure.sh --build-name=ProtoGoblin-local --container-engine=docker

# Build distributable package
make -j$(nproc) redist

# Install locally to Steam (~/.steam/root/compatibilitytools.d/)
make install
```

---

## License & Attribution

ProtoGoblin incorporates and builds upon components from Valve Proton, GE-Proton, Wine, DXVK, and vkd3d-proton. Individual components are licensed under their respective licenses (GPL, LGPL, zlib, MIT). See [dist.LICENSE](dist.LICENSE) and [LICENSE.proton](LICENSE.proton) for details.
