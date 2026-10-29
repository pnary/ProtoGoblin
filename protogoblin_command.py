#!/usr/bin/env python3
"""
ProtoGoblin Command - Graphical Optimization & Diagnostic Dashboard
"""

import glob
import json
import os
import platform
import shutil
import subprocess
import re
import sys
import tkinter as tk
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, simpledialog, ttk

# Ensure local modules can be loaded
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import protogoblin
from protogoblin import (
    compute_session_diff,
    format_diff_report,
    ExperimentStatus,
    ExperimentVerdict,
    ExperimentalValidationEngine,
    SystemProbe,
)


class DiagnosticAdvisor:
    """Evaluates session manifests and generates actionable recommendations and fixes."""

    @staticmethod
    def analyze(manifest):
        if not manifest:
            return []

        suggestions = []
        sync = manifest.get("synchronization") or {}
        gfx = manifest.get("graphics") or {}
        roi = manifest.get("roi_telemetry")
        ac = manifest.get("anti_cheat") or {}
        env = manifest.get("environment") or {}
        sub = manifest.get("subsystems") or {}
        tgt = manifest.get("target") or {}

        # 1. Anti-Cheat Passthrough & Profiling Suppression
        if ac.get("detected"):
            provider = ac.get("provider", "Anti-Cheat")
            suggestions.append(
                {
                    "level": "warning",
                    "title": f"🛡️ Anti-Cheat Active ({provider}) — Profiling Suppressed",
                    "description": (
                        f"Game is protected by {provider}. ProtoGoblin automatically suppressed Profile Mode and HUD/overlay "
                        f"hooks to enforce strict Zero-Injection Passthrough (Play Mode). This minimizes client disconnects "
                        f"and ban risk by strictly avoiding in-process hooks and overlay injection."
                    ),
                    "action": "Game runs in clean Play Mode. In-process shims and profiling hooks are intentionally disabled.",
                }
            )

        # 2. Synchronization Backend
        sync_backend = sync.get("sync_backend", "")
        if sync_backend == "wineserver_rpc":
            suggestions.append(
                {
                    "level": "error",
                    "title": "Slow Wineserver RPC Synchronization Fallback",
                    "description": "Kernel fast-path synchronization (ntsync/fsync) is disabled, causing synchronization primitives to fall back to slow wineserver socket IPC round-trips. This often induces heavy frame stutter in multithreaded engines.",
                    "action": "Verify Linux kernel ntsync module (/dev/ntsync) or launch with WINEFSYNC=1 in Steam Launch Options.",
                }
            )
        elif sync_backend in ["ntsync", "fsync"]:
            suggestions.append(
                {
                    "level": "success",
                    "title": f"Optimal Fast-Path Sync Active ({sync_backend.upper()})",
                    "description": f"Synchronization primitives are executing directly via Linux kernel fast-path ({sync_backend}), bypassing wineserver IPC bottlenecks.",
                    "action": "No synchronization action needed.",
                }
            )

        # 3. Shader Compilation Stalls
        sh = gfx.get("shader_compiles") or {}
        count = sh.get("count", 0)
        time_ms = sh.get("total_time_ms", 0.0)
        hit_rate = sh.get("pipeline_cache_hit_rate", 1.0)
        if count > 50 and time_ms > 200:
            dxvk_info = gfx.get("dxvk") or {}
            async_supported = bool(dxvk_info.get("async_supported", False))
            if async_supported:
                desc = (
                    f"{count} pipelines compiled during session taking {time_ms:.1f}ms total (cache hit rate: {hit_rate:.1%}). "
                    "DXVK build supports asynchronous pipeline compilation."
                )
                action = "Enable local shader caching (PROTON_LOCAL_SHADER_CACHE=1) or asynchronous compilation (dxvk.enableAsync = true)."
                fix_id = "async_shader_compile"
                btn_text = "⚡ Enable Async Shader Compilation"
            else:
                desc = (
                    f"{count} pipelines compiled during session taking {time_ms:.1f}ms total (cache hit rate: {hit_rate:.1%}). "
                    "Standard forward path is Vulkan Graphics Pipeline Libraries (GPL) driver pre-compilation."
                )
                action = "Enable local shader caching (PROTON_LOCAL_SHADER_CACHE=1) and ensure Vulkan GPL is active."
                fix_id = "local_shader_cache"
                btn_text = "⚡ Enable Local Shader Cache (GPL)"

            suggestions.append(
                {
                    "level": "warning",
                    "title": "Shader Compilation Stuttering Observed",
                    "description": desc,
                    "action": action,
                    "fix_id": fix_id,
                    "fix_button_text": btn_text,
                }
            )

        # 4. Bottleneck & CPU Core Pinning
        if roi and roi.get("roi_enabled"):
            b_class = roi.get("bottleneck_classification")
            fm = roi.get("frame_metrics") or {}
            pacing = roi.get("pacing") or {}
            cpu_info = (env.get("cpu") if isinstance(env.get("cpu"), dict) else None) or SystemProbe.get_cpu_info()
            cores = cpu_info.get("logical_cores") or 1
            is_vcache = cpu_info.get("is_vcache") or False

            if b_class == "cpu_bound":
                if cores >= 12 or is_vcache:
                    suggestions.append(
                        {
                            "level": "warning",
                            "title": "CPU-Bound Workload on Multi-Core / Multi-CCD CPU",
                            "description": f"Session CPU load reached {pacing.get('cpu_busy_pct', 0)}% while GPU was underutilized ({pacing.get('gpu_busy_pct', 0)}%). On multi-CCD processors (e.g. AMD Ryzen 9 / X3D) and hybrid CPUs, thread migration across dies induces cache thrashing and inter-core latency penalty.",
                            "action": "Pin game threads to high-performance/V-Cache cores in profile.toml [cpu.pin_performance_cores].",
                            "fix_id": "pin_performance_cores",
                            "fix_button_text": "⚡ Pin Threads to Performance/V-Cache Cores",
                        }
                    )
                else:
                    suggestions.append(
                        {
                            "level": "info",
                            "title": "CPU-Bound Game Execution",
                            "description": "Game is CPU execution limited. Check thread count and CPU governor frequency scaling.",
                            "action": "Ensure Linux CPU governor is set to 'performance'.",
                        }
                    )
                suggestions.append(
                    {
                        "level": "info",
                        "title": "High-Concurrency Heap Allocator (mimalloc)",
                        "description": (
                            "Entity simulation and pathfinding loops generate heavy small-object heap allocation churn. "
                            "Preloading Microsoft mimalloc replaces glibc/Wine heap locking with lock-free page allocators."
                        ),
                        "action": "Enable mimalloc heap allocator in profile.toml [memory.allocator].",
                        "fix_id": "enable_mimalloc",
                        "fix_button_text": "⚡ Preload mimalloc Allocator",
                    }
                )
                suggestions.append(
                    {
                        "level": "info",
                        "title": "CPU Draw Call Overhead (Vulkan Descriptor Buffers)",
                        "description": "DXVK 2.7+ Vulkan descriptor buffers bypass driver descriptor pool allocation overhead, cutting CPU draw call submission latency.",
                        "action": "Enable dxvk.enableDescriptorBuffer = true in profile.toml.",
                        "fix_id": "enable_descriptor_buffer",
                        "fix_button_text": "⚡ Enable Vulkan Descriptor Buffers (DXVK 2.7)",
                    }
                )
            elif b_class == "gpu_bound":
                suggestions.append(
                    {
                        "level": "info",
                        "title": "GPU Bound (Full Graphics Utilization)",
                        "description": f"GPU load was {pacing.get('gpu_busy_pct', 0)}%. Compatibility translation layer is keeping the GPU fully fed.",
                        "action": "If higher framerates are desired, consider FSR upscaling (WINE_FULLSCREEN_FSR=1) or reducing in-game render resolution.",
                    }
                )
            elif b_class == "sync_bound":
                gpu_load = pacing.get("gpu_busy_pct", 0)
                cpu_load = pacing.get("cpu_busy_pct", 0)
                if gpu_load < 50 and cpu_load < 55:
                    suggestions.append(
                        {
                            "level": "error",
                            "title": "Intra-Frame CPU-GPU Staging Synchronization Stall",
                            "description": f"Severe GPU under-utilization ({gpu_load}%) and low CPU utilization ({cpu_load}%) observed during active rendering. This signature indicates recurring intra-frame staging buffer readbacks (Map/CopyResource cycles) where the render thread repeatedly flushes and stalls on GPU fences multiple times per frame. (Common engine flaw in Gust/Koei Tecmo titles and naive D3D9->D3D11 ports).",
                            "action": "Deploy shadow staging buffer wrapper (Atelier Sync Fix) and force dxgi.syncInterval = 0 in profile.toml.",
                            "fix_id": "atelier_sync_fix",
                            "fix_button_text": "⚡ Apply Staging Buffer Sync Fix & VSync Off",
                        }
                    )
                else:
                    suggestions.append(
                        {
                            "level": "warning",
                            "title": "Thread Starvation / Synchronization Waits",
                            "description": "Both CPU and GPU reported low utilization despite active gameplay. Threads are likely blocked on internal locks or waiting on timer intervals.",
                            "action": "Test adaptive wait policies or check if frame rate limiter is set below monitor refresh rate.",
                        }
                    )

                if sync_backend != "ntsync" and not os.path.exists("/dev/ntsync"):
                    suggestions.append(
                        {
                            "level": "info",
                            "title": "Kernel NT Synchronization (ntsync) Driver Inactive",
                            "description": "Session relied on slower wineserver RPC/eventfd waits. Upgrading to a kernel with the /dev/ntsync driver (Linux 6.13+) provides native Windows NT synchronization primitives to eliminate thread wait overhead.",
                            "action": "Ensure ntsync kernel module is active or upgrade to Linux 6.13+.",
                        }
                    )

            # Frame Pacing & 1% Lows
            fps_avg = fm.get("fps_avg", 0)
            fps_1 = fm.get("fps_1_pct_low", 0)
            jitter = fm.get("frametime_jitter_ms", 0)
            if fps_avg > 0 and fps_1 > 0 and (fps_1 / fps_avg) < 0.65:
                cap_target = max(30, int(fps_avg))
                suggestions.append(
                    {
                        "level": "warning",
                        "title": "Significant Frame Pacing Volatility",
                        "description": f"1% Low FPS ({fps_1:.1f}) dropped to {fps_1/fps_avg:.0%} of average FPS ({fps_avg:.1f}). Frametime jitter was {jitter:.1f}ms.",
                        "action": f"Set a clean frame rate cap via DXVK_FRAME_RATE={cap_target} to stabilize frame presentation intervals.",
                        "fix_id": "cap_framerate",
                        "fix_button_text": f"⚡ Cap Frame Rate to {cap_target} FPS",
                        "cap_target": cap_target,
                    }
                )

            if jitter >= 8.0:
                # Tightened diagnostic rule: Jitter alone does NOT establish constant buffer spam
                # or swapchain resize storms. Only recommend wrapper debouncing when wrapper telemetry confirms it.
                w_stats_check = gfx.get("d3d11_wrapper_stats")
                if not w_stats_check:
                    suggestions.append(
                        {
                            "level": "warning",
                            "title": "Elevated Presentation Frametime Jitter",
                            "description": (
                                f"Frametime jitter is elevated ({jitter:.1f}ms). Presentation pacing varies across frames."
                            ),
                            "action": "Set a presentation frame rate limiter (DXVK_FRAME_RATE) to stabilize frame pacing, or run in Profile Mode to capture D3D11 wrapper telemetry.",
                            "fix_id": "cap_framerate",
                            "fix_button_text": f"⚡ Cap Frame Rate ({max(30, int(fps_avg or 60))} FPS)",
                            "cap_target": max(30, int(fps_avg or 60)),
                        }
                    )

        # 4b. D3D11 / DXGI Wrapper Introspective Live Telemetry
        w_stats = gfx.get("d3d11_wrapper_stats")
        if w_stats:
            cb = w_stats.get("constant_buffers") or {}
            cb_total = cb.get("updates_total", 0)
            cb_redundant = cb.get("updates_redundant", 0)
            cb_rate = cb.get("redundancy_rate_pct", 0.0)
            state_active = w_stats.get("state_dedup_active", False)

            if cb_total >= 500 and cb_rate >= 35.0:
                if not state_active:
                    suggestions.append(
                        {
                            "level": "warning",
                            "title": f"Constant Buffer State Spam Detected ({cb_rate:.1f}% Redundant)",
                            "description": (
                                f"Game issued {cb_total:,} constant buffer updates, but {cb_redundant:,} ({cb_rate:.1f}%) "
                                "were identical to prior payloads. This causes redundant Vulkan descriptor set thrashing."
                            ),
                            "action": "Enable D3D11 Constant Buffer Deduplication in profile.toml [synchronization.state_dedup].",
                            "fix_id": "state_dedup_and_debounce",
                            "fix_button_text": "⚡ Enable State Dedup & Debounce",
                        }
                    )
                else:
                    suggestions.append(
                        {
                            "level": "success",
                            "title": f"Constant Buffer Deduplication Active ({cb_redundant:,} calls pruned)",
                            "description": (
                                f"ProtoGoblin D3D11 wrapper dropped {cb_redundant:,} of {cb_total:,} constant buffer updates "
                                f"({cb_rate:.1f}% bandwidth reduction), eliminating driver descriptor updates."
                            ),
                            "action": "Optimal constant buffer state caching is active.",
                        }
                    )

            sc = w_stats.get("swapchain") or {}
            sc_total = sc.get("resizes_total", 0)
            sc_identical = sc.get("resizes_identical", 0)
            sc_rapid = sc.get("resizes_rapid", 0)
            sc_active = w_stats.get("swapchain_debounce_active", False)

            if (sc_identical + sc_rapid) >= 3:
                if not sc_active:
                    suggestions.append(
                        {
                            "level": "warning",
                            "title": f"SwapChain Resize Choke Detected ({sc_identical + sc_rapid} redundant resizes)",
                            "description": (
                                f"Observed {sc_total} swapchain resize requests ({sc_identical} identical dimensions, "
                                f"{sc_rapid} rapid bursts <50ms). Each unmitigated resize causes vkDeviceWaitIdle micro-stutters."
                            ),
                            "action": "Enable DXGI SwapChain Resize Debouncing in profile.toml [synchronization.swapchain_debounce].",
                            "fix_id": "state_dedup_and_debounce",
                            "fix_button_text": "⚡ Enable State Dedup & Debounce",
                        }
                    )
                else:
                    suggestions.append(
                        {
                            "level": "success",
                            "title": f"SwapChain Debounce Active ({sc_identical + sc_rapid} stalls prevented)",
                            "description": (
                                f"Filtered {sc_identical} identical-dimension resizes and {sc_rapid} rapid-burst spikes, "
                                "preserving smooth presentation without swapchain recreation stalls."
                            ),
                            "action": "Optimal swapchain presentation pacing is active.",
                        }
                    )

            timing = w_stats.get("timing") or {}
            sleep_total = timing.get("sleep_calls_total", 0)
            overshoot_calls = timing.get("overshoot_prevented_calls", 0)
            overshoot_ms = timing.get("overshoot_avoided_ms", 0.0)
            timers_active = timing.get("high_precision_timers_active", False)

            if sleep_total >= 500:
                if not timers_active:
                    suggestions.append(
                        {
                            "level": "warning",
                            "title": f"High Game-Loop Sleep Timer Activity ({sleep_total:,} Calls)",
                            "description": (
                                f"Game issued {sleep_total:,} Win32 Sleep calls to pace its frame or physics ticks. "
                                "Without precision timer overrides, standard Wine timer coarse scheduling (1-4ms overshoot) "
                                "induces micro-stutter and frame-pacing drift."
                            ),
                            "action": "Enable High-Precision Sleep & Pacing Timers in profile.toml [timing.precision_timers].",
                            "fix_id": "enable_precision_timers",
                            "fix_button_text": "⚡ Enable High-Precision Sleep Timers",
                        }
                    )
                else:
                    suggestions.append(
                        {
                            "level": "success",
                            "title": f"High-Precision Sleep Timers Active ({overshoot_calls:,} overshoots prevented)",
                            "description": (
                                f"Sub-millisecond QPC hybrid sleep-spin pacing eliminated timer wake latency drift "
                                f"(~{overshoot_ms:.1f}ms overshoot avoided across {sleep_total:,} sleep requests)."
                            ),
                            "action": "Optimal high-precision sleep and frame pacing cadence is active.",
                        }
                    )

        # 4c. Filesystem & Asset Streaming Traversal I/O Telemetry
        fs = manifest.get("filesystem") or {}
        io_stats = fs.get("io_cache_stats")
        if io_stats:
            reads_total = io_stats.get("reads_total", 0)
            hits = io_stats.get("reads_cached_hits", 0)
            hit_rate = io_stats.get("hit_rate_pct", 0.0)
            saved_mb = io_stats.get("bytes_cached_saved", 0) / (1024 * 1024)
            saved_ms = io_stats.get("estimated_latency_saved_ms", 0.0)
            io_active = io_stats.get("io_cache_active", False)

            if reads_total >= 1000:
                if not io_active:
                    suggestions.append(
                        {
                            "level": "warning",
                            "title": f"Synchronous Traversal File I/O Overhead ({reads_total:,} Reads)",
                            "description": (
                                f"The game issued {reads_total:,} synchronous asset streaming reads ({io_stats.get('bytes_read_total', 0) / (1024*1024):.1f} MB), "
                                "triggering repeated Wine/kernel boundary crossings during traversal. This is a primary driver of zone traversal micro-stutter."
                            ),
                            "action": "Enable Adaptive Traversal File I/O Cache in profile.toml [filesystem.io_cache].",
                            "fix_id": "enable_io_cache",
                            "fix_button_text": "⚡ Enable Traversal File I/O Cache",
                        }
                    )
                else:
                    suggestions.append(
                        {
                            "level": "success",
                            "title": f"Traversal File I/O Cache Active ({hit_rate:.1f}% Hit Rate)",
                            "description": (
                                f"Satisfied {hits:,} of {reads_total:,} asset reads directly from RAM cache ({saved_mb:.1f} MB saved), "
                                f"preventing ~{saved_ms:.1f}ms of synchronous disk/kernel traversal stalls."
                            ),
                            "action": "Optimal asset streaming read-ahead caching is active.",
                        }
                    )

        # 5. Subsystem Pruning
        unutilized = sub.get("unutilized", [])
        if unutilized:
            suggestions.append(
                {
                    "level": "info",
                    "title": f"Subsystem Pruning Available ({len(unutilized)} unused)",
                    "description": f"The target binary never loaded the following subsystems: {', '.join(unutilized[:5])}.",
                    "action": "In Play mode, ProtoGoblin can skip initializing these shims to reduce startup latency and prefix memory footprint.",
                }
            )

        # 6. Intermediate Launcher Detected
        if tgt.get("launcher_executable"):
            l_name = os.path.basename(tgt["launcher_executable"].get("path", "Launcher"))
            t_name = os.path.basename(tgt["target_executable"].get("path", "Game"))
            suggestions.append(
                {
                    "level": "info",
                    "title": f"Multi-Stage Launcher Managed ({l_name} -> {t_name})",
                    "description": f"ProtoGoblin successfully tracked through intermediate bootstrapper {l_name} and bound instrumentation to true target binary {t_name}.",
                    "action": "No action needed. Session tracking cleanly waited for the true game payload to exit.",
                }
            )

        # 7. Engine-Specific Optimization Profiles
        engine = tgt.get("engine") or {}
        eng_name = engine.get("engine", "")
        if eng_name == "unreal_5":
            roi_fm = (roi.get("frame_metrics") or {}) if isinstance(roi, dict) else {}
            roi_bot = roi.get("bottleneck_classification", "") if isinstance(roi, dict) else ""
            is_heavy = roi_bot in ["gpu_bound", "sync_bound"] or (bool(roi) and roi_fm.get("fps_1_pct_low", 0) < 45)
            suggestions.append(
                {
                    "level": "warning" if is_heavy else "info",
                    "title": "⚡ Optimize UE5 Lumen & Virtual Shadow Maps" if is_heavy else "Unreal Engine 5 Optimization Profile (Lumen & VSM Available)",
                    "description": (
                        "Game runs on Unreal Engine 5 with heavy compute passes (Virtual Shadow Maps and Lumen screen probe gather). "
                        "Throttling shadow ray sampling and downsampling screen probes provides a ~25% frametime speedup under VKD3D."
                    ),
                    "action": "Enable Lumen screen-probe downsampling and Virtual Shadow Map optimization in profile.toml.",
                    "fix_id": "optimize_ue5_lumen_vsm",
                    "fix_button_text": "⚡ Optimize UE5 Lumen & Virtual Shadow Maps",
                }
            )
        elif eng_name == "unreal_4":
            suggestions.append(
                {
                    "level": "info",
                    "title": "Unreal Engine 4 Optimization Profile Available",
                    "description": "Game runs on Unreal Engine 4. ProtoGoblin can tune internal Scalability/Engine.ini variables (e.g. motion blur, depth of field, bloom) and apply DXVK asynchronous pipeline compilation.",
                    "action": "Use profile.toml [engine.unreal] section to adjust engine-specific Cvars.",
                }
            )
        elif eng_name == "unity":
            details = engine.get("details", {})
            backend = details.get("backend", "runtime")
            suggestions.append(
                {
                    "level": "info",
                    "title": f"Unity Engine Detected ({backend})",
                    "description": f"Game runs on Unity ({backend}). Prefix boot.config can be tuned to enable native graphics jobs and bypass unused runtime debugger checks.",
                    "action": "Ensure gfx-enable-native-gfx-jobs=1 is configured in prefix boot.config.",
                }
            )
            suggestions.append(
                {
                    "level": "warning" if (isinstance(roi, dict) and roi.get("bottleneck_classification") == "cpu_bound") else "info",
                    "title": "⚡ Optimize Unity Mono GC Nursery Sizing",
                    "description": (
                        "Unity Mono runtime defaults to a small 4MB generational nursery, inducing recurring "
                        "stop-the-world GC pauses during entity simulation cycles. Expanding nursery sizing to 64MB "
                        "reduces GC collection frequency by up to 75%."
                    ),
                    "action": "Configure MONO_GC_PARAMS=nursery-size=64m in profile.toml [engine.unity.mono_gc_tuning].",
                    "fix_id": "unity_mono_gc_tuning",
                    "fix_button_text": "⚡ Enable 64MB Unity GC Nursery",
                }
            )
        elif eng_name == "godot":
            suggestions.append(
                {
                    "level": "info",
                    "title": "Godot Engine Detected",
                    "description": "Game runs on Godot Engine. Custom override.cfg or CLI launch arguments can directly enforce Vulkan renderers or fixed physics framerates.",
                    "action": "Apply Godot-specific launch options in profile.toml.",
                }
            )

        # 8. ProtonDB Preset Community Recommendations & Known Flaws
        app_id = tgt.get("steam_appid")
        preset = protogoblin.PresetDatabase.get_preset(app_id) if app_id else None
        if preset:
            known_issues = preset.get("known_issues", [])
            tier = preset.get("tier", "unknown")
            recs = preset.get("recommended_tweaks", {})
            if "gust_d3d11_staging_sync_stall" in known_issues:
                suggestions.append(
                    {
                        "level": "error",
                        "title": "Documented Gust Engine D3D11 Sync Stall (ProtonDB)",
                        "description": "ProtonDB reports confirm this title has the severe Gust D3D11 staging buffer sync defect. Without a shadow staging wrapper, the GPU sits mostly idle and FPS drops heavily.",
                        "action": "Apply Atelier Sync Fix (doitsujin/TellowKrinkle) and set dxgi.syncInterval = 0 in profile.toml.",
                        "fix_id": "atelier_sync_fix",
                        "fix_button_text": "⚡ Apply Staging Buffer Sync Fix & VSync Off",
                    }
                )
            if "ue5_fsr_frame_gen_crash" in known_issues:
                suggestions.append(
                    {
                        "level": "warning",
                        "title": "FSR3 Frame Generation Crash Trap (UE5 / Proton)",
                        "description": "ProtonDB reports alert that toggling in-game FSR3 Frame Generation causes immediate freezes and persistent startup crash-loops via VKD3D-Proton swapchains. Standard FSR upscaling without frame gen works fine.",
                        "action": "Disable Frame Generation in GameUserSettings.ini or keep standard FSR upscaling active without frame gen.",
                    }
                )
            if "ue5_nanite_lumen_heavy_load" in known_issues:
                suggestions.append(
                    {
                        "level": "info",
                        "title": "Heavy UE5 Nanite & Lumen Translation Overhead",
                        "description": "Virtualized Nanite geometry and Lumen software/hardware raytracing place intense demand on VKD3D-Proton and VRAM. Without pacing limits, 1% low FPS dips dramatically.",
                        "action": "Cap frame rate to 60 FPS (VKD3D_FRAME_RATE=60) and disable Motion Blur/Depth of Field via -ExecCmds in profile.toml.",
                        "fix_id": "cap_framerate",
                        "fix_button_text": "⚡ Apply 60 FPS Cap & UE5 Cleanups",
                        "cap_target": 60,
                    }
                )
            if recs.get("env") or recs.get("args"):
                opts_summary = []
                for k, v in recs.get("env", {}).items():
                    opts_summary.append(f"{k}={v}")
                opts_summary.extend(recs.get("args", []))
                suggestions.append(
                    {
                        "level": "info",
                        "title": f"ProtonDB Community Profile Available (Rating: {tier.upper()})",
                        "description": f"Mined from {preset.get('reports', 1)} community reports. Recommended parameters: {' '.join(opts_summary)}.",
                        "action": "Click 'Generate Profile TOML' to automatically merge community launch options into game config.",
                    }
                )

        # 9. Compatibility & Native Microsoft DLL Diagnostics
        compat = manifest.get("compatibility") or {}
        remedies = compat.get("remedies", [])
        is_clean = (manifest.get("session") or {}).get("clean_shutdown", True)
        for remedy in remedies:
            verb = remedy.get("verb", "unknown")
            dll = remedy.get("dll", "native.dll")
            pkg = remedy.get("package", "Microsoft Component")
            err = remedy.get("log_error", "")
            suggestions.append(
                {
                    "level": "warning" if is_clean else "error",
                    "title": f"📦 Missing Microsoft Native DLL: {dll} ({verb})",
                    "description": (
                        f"Session log analysis identified an unresolved DLL import failure or unimplemented stub: '{err}'. "
                        f"This issue is routinely resolved by deploying the official Microsoft {pkg} ({dll})."
                    ),
                    "action": f"Snag and deploy official Microsoft {dll} into prefix and configure native DLL override ({verb}=n,b).",
                    "fix_id": f"snag_dll_{verb}",
                    "fix_button_text": f"⚡ Snag & Deploy Microsoft {dll}",
                    "remedy": remedy,
                }
            )

        # 10. Steam Deck Hardware & Optimization Elevation
        deck = manifest.get("steam_deck") or (manifest.get("environment") or {}).get("steam_deck") or {}
        if deck.get("is_deck"):
            model = deck.get("model") or "Steam Deck"
            suggestions.append(
                {
                    "level": "info",
                    "title": f"🎮 Steam Deck Environment Active ({model})",
                    "description": (
                        f"ProtoGoblin elevated Steam Deck-specific optimizations for {model} "
                        f"(native 1280x800 presentation, SteamDeck=1 environment flag, and elevated APU power pacing)."
                    ),
                    "action": "Steam Deck presets and controller glyph overrides automatically elevated.",
                }
            )

        return suggestions


def generate_debug_dump(manifest=None, base_dir=None):
    """Generates a comprehensive diagnostic dictionary for developer debugging."""
    if not base_dir:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    # Host info
    host_info = {
        "python_version": sys.version.replace("\n", " "),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "host_os": protogoblin.SystemProbe.get_host_os(),
        "cpu": protogoblin.SystemProbe.get_cpu_info(),
        "ram_total_mb": protogoblin.SystemProbe.get_ram_total_mb(),
        "container_runtime": protogoblin.SystemProbe.get_container_runtime(),
    }

    # Tool installation info
    tool_files = {
        "base_dir": base_dir,
        "proton": os.path.isfile(os.path.join(base_dir, "proton")),
        "protogoblin.py": os.path.isfile(os.path.join(base_dir, "protogoblin.py")),
        "protogoblin_command.py": os.path.isfile(os.path.join(base_dir, "protogoblin_command.py")),
        "presets_json": os.path.isfile(os.path.join(base_dir, "share", "protogoblin", "protogoblin_presets.json")),
        "staging_sync_fix_dll_64": os.path.isfile(os.path.join(base_dir, "share", "protogoblin", "lib64", "d3d11.dll")),
        "staging_sync_fix_source": os.path.isdir(os.path.join(base_dir, "vklayers", "staging-sync-fix")),
    }

    compat_paths = [
        os.path.expanduser("~/.local/share/Steam/compatibilitytools.d"),
        os.path.expanduser("~/.steam/root/compatibilitytools.d"),
    ]
    existing_compat = [p for p in compat_paths if os.path.isdir(p)]

    interesting_prefixes = (
        "PROTOGOBLIN", "STEAM", "Steam", "PROTON", "WINE", "DXVK", "VKD3D", "MANGOHUD", "PRESSURE_VESSEL"
    )
    env_dump = {
        k: v for k, v in sorted(os.environ.items()) if any(k.startswith(pfx) for pfx in interesting_prefixes)
    }

    session_summary = None
    if manifest:
        sess = manifest.get("session") or {}
        tgt = manifest.get("target") or {}
        sub = manifest.get("subsystems") or {}
        gfx = manifest.get("graphics") or {}
        sync = manifest.get("synchronization") or {}
        roi = manifest.get("roi_telemetry") or manifest.get("roi") or {}

        session_summary = {
            "session_id": sess.get("id"),
            "mode": sess.get("mode"),
            "dev_mode": sess.get("dev_mode", False),
            "steam_appid": tgt.get("steam_appid"),
            "target_executable": tgt.get("target_executable"),
            "engine": tgt.get("engine"),
            "subsystems_loaded": sub.get("loaded", []),
            "subsystems_unutilized": sub.get("unutilized", []),
            "subsystems_pruned": sub.get("pruned", []),
            "active_backend": gfx.get("active_backend"),
            "sync_backend": sync.get("sync_backend"),
            "bottleneck": roi.get("bottleneck_classification"),
            "frame_metrics": roi.get("frame_metrics"),
        }

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host_info,
        "tool_files": tool_files,
        "steam_compatibility_dirs": existing_compat,
        "environment": env_dump,
        "active_session": session_summary,
    }


def format_debug_dump(dump):
    """Formats diagnostic dump dictionary into a human-readable ASCII report."""
    h = dump["host"]
    t = dump["tool_files"]
    lines = [
        "=" * 82,
        " PROTOGOBLIN DEVELOPER DIAGNOSTIC DUMP",
        "=" * 82,
        f" Timestamp:           {dump['timestamp']}",
        "",
        " HOST ENVIRONMENT",
        "-" * 82,
        f" Host OS:             {h['host_os']}",
        f" Python:              {h['python_version'][:60]}",
        f" Python Binary:       {h['python_executable']}",
        f" Architecture:        {h['platform']} ({h['machine']})",
        f" CPU Info:            {h['cpu'].get('model')} ({h['cpu'].get('logical_cores')} logical cores)",
        f" RAM Total:           {h['ram_total_mb']} MB",
        f" Container Runtime:   {h['container_runtime'] or 'None (Native Host)'}",
        "",
        " PROTOGOBLIN INSTALLATION & ASSETS",
        "-" * 82,
        f" Repository Root:     {t['base_dir']}",
        f" Proton Launcher:     {'FOUND' if t['proton'] else 'NOT FOUND'}",
        f" protogoblin.py:      {'FOUND' if t['protogoblin.py'] else 'NOT FOUND'}",
        f" Goblin Commander:    {'FOUND' if t['protogoblin_command.py'] else 'NOT FOUND'}",
        f" Presets Database:    {'FOUND' if t['presets_json'] else 'NOT FOUND'}",
        f" Staging Sync Wrapper:{'BUILT DLL FOUND' if t['staging_sync_fix_dll_64'] else ('SOURCE FOUND' if t['staging_sync_fix_source'] else 'NOT FOUND')}",
        f" Steam Compat Dirs:   {', '.join(dump['steam_compatibility_dirs']) or 'None'}",
        "",
    ]

    s = dump.get("active_session")
    if s:
        lines.extend([
            " ACTIVE SELECTED SESSION INTERNALS",
            "-" * 82,
            f" Session ID:          {s['session_id']} [Dev Mode: {'ON' if s.get('dev_mode') else 'OFF'}]",
            f" Runtime Mode:        {s['mode']}",
            f" Steam AppID:         {s['steam_appid']}",
            f" Target Executable:   {(s.get('target_executable') or {}).get('path', 'Unknown')}",
            f" Detected Engine:     {s.get('engine', {}).get('engine', 'Unknown')} (confidence: {s.get('engine', {}).get('confidence', 0.0)})",
            f" Graphics Backend:    {s.get('active_backend', 'Unknown')}",
            f" Sync Backend:        {s.get('sync_backend', 'Unknown')}",
            f" Subsystems Loaded:   {', '.join(s.get('subsystems_loaded', []))}",
            f" Subsystems Pruned:   {', '.join(s.get('subsystems_pruned', [])) or 'None'}",
            f" Subsystems Unused:   {', '.join(s.get('subsystems_unutilized', []))}",
            f" Bottleneck:          {s.get('bottleneck') or 'None'}",
            "",
        ])
    else:
        lines.extend([
            " ACTIVE SELECTED SESSION INTERNALS",
            "-" * 82,
            " No game session currently selected in Goblin Commander.",
            "",
        ])

    lines.extend([
        " ACTIVE ENVIRONMENT VARIABLES",
        "-" * 82,
    ])
    if dump.get("environment"):
        for k in sorted(dump["environment"].keys()):
            lines.append(f" {k:<25} = {dump['environment'][k]}")
    else:
        lines.append(" No relevant ProtoGoblin / Wine / Proton environment flags set.")

    lines.extend(["=" * 82, ""])
    return "\n".join(lines)


class ProtoGoblinCommandApp:
    """Main Application Window for ProtoGoblin Command GUI."""

    compute_session_diff = staticmethod(compute_session_diff)
    format_diff_report = staticmethod(format_diff_report)
    generate_debug_dump = staticmethod(generate_debug_dump)
    format_debug_dump = staticmethod(format_debug_dump)

    def __init__(self, root, initial_session_id=None, auto_refresh=True):
        self.root = root
        self.root.title("ProtoGoblin Command - Optimization & Diagnostics")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        # Configure style
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.style.configure(
            "Treeview",
            background="#161b22",
            foreground="#c9d1d9",
            fieldbackground="#161b22",
            borderwidth=0,
            font=("Segoe UI", 9),
            rowheight=22,
        )
        self.style.map(
            "Treeview",
            background=[("selected", "#1f6feb")],
            foreground=[("selected", "#ffffff")],
        )

        # Color palette
        self.bg_color = "#1e1e24"
        self.fg_color = "#f0f0f5"
        self.card_bg = "#282832"
        self.accent_color = "#4a90e2"
        self.success_color = "#2ecc71"
        self.warning_color = "#f39c12"
        self.error_color = "#e74c3c"

        self.root.configure(bg=self.bg_color)

        self.manifest_paths = []
        self.current_manifest = None
        self.current_manifest_path = None
        self.custom_suggestion_states = {}
        self.initial_session_id = initial_session_id
        self._game_name_cache = {}
        self._steam_libs_cache = None
        self.tree_item_to_path = {}
        self._last_known_manifest_mtimes = {}
        self._last_manifest_count = 0
        self._poll_interval_ms = 2000
        self._poll_timer_id = None
        self._last_launched_app_id = None

        self._build_ui()
        if self.initial_session_id:
            self.search_var.set(self.initial_session_id)
        self.refresh_sessions()

        if auto_refresh:
            self._start_auto_refresh()

        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        except Exception:
            pass

    def _build_ui(self):
        # Top Header Bar
        header = tk.Frame(self.root, bg="#18181e", height=50)
        header.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(
            header,
            text="ProtoGoblin Command",
            font=("Segoe UI", 14, "bold"),
            bg="#18181e",
            fg="#58a6ff",
        )
        title_lbl.pack(side=tk.LEFT, padx=15, pady=10)

        subtitle_lbl = tk.Label(
            header,
            text="Game Profiling, Diagnostics & Optimization",
            font=("Segoe UI", 9),
            bg="#18181e",
            fg="#8b949e",
        )
        subtitle_lbl.pack(side=tk.LEFT, padx=5, pady=12)

        # Header Action Buttons
        btn_refresh = tk.Button(
            header,
            text="🔄 Refresh",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.refresh_sessions,
        )
        btn_refresh.pack(side=tk.RIGHT, padx=10, pady=10)

        self.btn_toggle_mode = tk.Button(
            header,
            text="🎯 Profiling: OFF",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            command=self.toggle_selected_game_mode,
        )
        self.btn_toggle_mode.pack(side=tk.RIGHT, padx=5, pady=10)

        self.btn_launch_game = tk.Button(
            header,
            text="🚀 Launch Game",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            command=self.launch_selected_game,
        )
        self.btn_launch_game.pack(side=tk.RIGHT, padx=5, pady=10)

        self.btn_game_library = tk.Button(
            header,
            text="🎮 Library...",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.open_game_launcher_dialog,
        )
        self.btn_game_library.pack(side=tk.RIGHT, padx=5, pady=10)

        self.dev_mode = False
        self.btn_dev_mode = tk.Button(
            header,
            text="🛠️ Dev Mode: OFF",
            bg="#21262d",
            fg="#8b949e",
            activebackground="#30363d",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            command=self.toggle_dev_mode,
        )
        self.btn_dev_mode.pack(side=tk.RIGHT, padx=5, pady=10)

        btn_add_game = tk.Button(
            header,
            text="➕ Configure Game...",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.add_game_dialog,
        )
        btn_add_game.pack(side=tk.RIGHT, padx=5, pady=10)

        btn_inspect = tk.Button(
            header,
            text="🔍 Inspect .EXE...",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.inspect_file_dialog,
        )
        btn_inspect.pack(side=tk.RIGHT, padx=5, pady=10)

        btn_gen_profile = tk.Button(
            header,
            text="⚙️ Generate Profile TOML",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.generate_profile_toml,
        )
        btn_gen_profile.pack(side=tk.RIGHT, padx=5, pady=10)

        btn_drop_profile = tk.Button(
            header,
            text="🗑️ Drop Profile",
            bg="#21262d",
            fg="#f85149",
            activebackground="#b62324",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.drop_current_profile,
        )
        btn_drop_profile.pack(side=tk.RIGHT, padx=5, pady=10)

        # Status Bar at bottom
        status_bar = tk.Frame(self.root, bg="#161b22", height=24)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_bar_lbl = tk.Label(
            status_bar,
            text="Ready",
            font=("Segoe UI", 9),
            bg="#161b22",
            fg="#8b949e",
            anchor=tk.W,
            padx=10,
            pady=3,
        )
        self.status_bar_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Main Content Panes
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.bg_color, sashrelief=tk.FLAT)
        paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(10, 5))

        # Left Pane: Session / Game List
        left_frame = tk.Frame(paned, bg=self.card_bg, width=320)
        paned.add(left_frame, minsize=260)

        lbl_list = tk.Label(
            left_frame,
            text="Recorded Game Sessions",
            font=("Segoe UI", 10, "bold"),
            bg=self.card_bg,
            fg="#c9d1d9",
        )
        lbl_list.pack(anchor=tk.W, padx=10, pady=(10, 5))

        # Search Bar
        search_frame = tk.Frame(left_frame, bg=self.card_bg)
        search_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._filter_session_list())
        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            bg="#161b22",
            fg="#c9d1d9",
            insertbackground="#ffffff",
            relief=tk.FLAT,
        )
        search_entry.pack(fill=tk.X, ipady=3)

        # Sessions Treeview with scrollbar (grouped by Steam ID)
        list_container = tk.Frame(left_frame, bg=self.card_bg)
        list_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        scrollbar = tk.Scrollbar(list_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.sessions_tree = ttk.Treeview(
            list_container,
            show="tree",
            selectmode="browse",
            yscrollcommand=scrollbar.set,
        )
        self.sessions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.sessions_tree.yview)

        self.sessions_tree.tag_configure("group_header", font=("Segoe UI", 9, "bold"), foreground="#58a6ff")
        self.sessions_tree.tag_configure("exe_item", font=("Segoe UI", 9), foreground="#c9d1d9")

        self.sessions_tree.bind("<<TreeviewSelect>>", self.on_session_selected)
        self.sessions_listbox = self.sessions_tree

        self.tree_context_menu = tk.Menu(self.root, tearoff=0, bg="#161b22", fg="#c9d1d9", activebackground="#1f6feb", activeforeground="#ffffff")
        self.tree_context_menu.add_command(label="🚀 Launch Game (with ProtoGoblin)", command=self.launch_selected_game)
        self.tree_context_menu.add_command(label="🎯 Toggle Profiling Mode", command=self.toggle_selected_game_mode)
        self.tree_context_menu.add_separator()
        self.tree_context_menu.add_command(label="🗑️ Drop Profile (Reset for Re-Profiling)", command=self.drop_current_profile)
        self.tree_context_menu.add_command(label="⚙️ Reset Tweaks to Stock", command=self.reset_tweaks_to_stock)
        self.tree_context_menu.add_separator()
        self.tree_context_menu.add_command(label="🔄 Refresh Sessions", command=self.refresh_sessions)

        def on_tree_right_click(event):
            item = self.sessions_tree.identify_row(event.y)
            if item:
                self.sessions_tree.selection_set(item)
                self.on_session_selected(None)
                self.tree_context_menu.post(event.x_root, event.y_root)

        self.sessions_tree.bind("<Button-3>", on_tree_right_click)

        # Right Pane: Notebook Dashboard
        right_frame = tk.Frame(paned, bg=self.bg_color)
        paned.add(right_frame, minsize=500)

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Diagnostics & Suggestions
        self.tab_diag = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_diag, text="  🩺 Diagnostics & Suggested Fixes  ")

        # Tab 2: Engine & Graphics Tweaks
        self.tab_tweaks = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_tweaks, text="  ⚡ Engine & Graphics Tweaks  ")

        # Tab 3: Performance & Frame Metrics
        self.tab_perf = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_perf, text="  📊 Performance & Pacing  ")

        # Tab 4: Session Comparison (A/B Diff)
        self.tab_diff = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_diff, text="  ⚖️ Session Comparison (A/B Diff)  ")

        # Tab 5: System & Translation Details
        self.tab_sys = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_sys, text="  ⚙️ Graphics & Subsystems  ")

        # Tab 6: Raw JSON Manifest
        self.tab_json = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_json, text="  📄 Raw Manifest (JSON)  ")

        # Tab 7: Developer Debug & Internals (hidden until Dev Mode is enabled)
        self.tab_dev = tk.Frame(self.notebook, bg=self.card_bg)

        # Build individual tab views
        self._build_diag_tab()
        self._build_tweaks_tab()
        self._build_perf_tab()
        self._build_diff_tab()
        self._build_sys_tab()
        self._build_json_tab()
        self._build_dev_tab()

    def _build_diag_tab(self):
        # Summary Header
        self.diag_header_lbl = tk.Label(
            self.tab_diag,
            text="Select a game session to view analysis.",
            font=("Segoe UI", 11, "bold"),
            bg=self.card_bg,
            fg="#58a6ff",
            anchor=tk.W,
        )
        self.diag_header_lbl.pack(fill=tk.X, padx=15, pady=(15, 5))

        # Canvas & scrollable container for suggestions
        canvas_frame = tk.Frame(self.tab_diag, bg=self.card_bg)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.diag_canvas = tk.Canvas(canvas_frame, bg=self.card_bg, highlightthickness=0)
        diag_scrollbar = tk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.diag_canvas.yview)
        self.diag_cards_container = tk.Frame(self.diag_canvas, bg=self.card_bg)

        self.diag_cards_container.bind(
            "<Configure>",
            lambda e: self.diag_canvas.configure(scrollregion=self.diag_canvas.bbox("all")),
        )
        self.diag_canvas.create_window((0, 0), window=self.diag_cards_container, anchor="nw", width=620)
        self.diag_canvas.configure(yscrollcommand=diag_scrollbar.set)

        self.diag_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        diag_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_tweaks_tab(self):
        # Header in Tweaks tab
        banner_frame = tk.Frame(self.tab_tweaks, bg=self.card_bg)
        banner_frame.pack(fill=tk.X, padx=15, pady=(15, 10))

        lbl = tk.Label(
            banner_frame,
            text="Engine Command Intercepts & Graphics Tweaks",
            font=("Segoe UI", 12, "bold"),
            bg=self.card_bg,
            fg="#58a6ff",
        )
        lbl.pack(anchor=tk.W)

        self.tweaks_game_lbl = tk.Label(
            banner_frame,
            text="Toggle common performance drains to inject via launch commands, DXVK, or prefix overrides.",
            font=("Segoe UI", 9),
            bg=self.card_bg,
            fg="#8b949e",
        )
        self.tweaks_game_lbl.pack(anchor=tk.W, pady=(2, 0))

        # Scrollable container for tweak categories
        container = tk.Frame(self.tab_tweaks, bg=self.card_bg)
        container.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        # 0. Execution & Telemetry Mode Card
        self.mode_frame = tk.LabelFrame(
            container,
            text=" 🎯 Execution & Telemetry Mode (Applies Automatically from Steam) ",
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=10,
        )
        self.mode_frame.pack(fill=tk.X, pady=6)

        self.var_profile_mode = tk.StringVar(value="play")
        rb_play = tk.Radiobutton(
            self.mode_frame,
            text="Play Mode - Clean, silent execution. Optimizations and tweaks apply without HUD or background disk logging.",
            variable=self.var_profile_mode,
            value="play",
            bg="#161b22",
            fg="#c9d1d9",
            selectcolor="#0d1117",
            activebackground="#161b22",
            activeforeground="#58a6ff",
            font=("Segoe UI", 9),
            command=self._on_mode_radio_changed,
        )
        rb_play.pack(anchor=tk.W, pady=2)

        rb_profile = tk.Radiobutton(
            self.mode_frame,
            text="Profile Mode - Active 'ProtoGoblin' HUD overlay, frametime variance, 1% lows, and hardware load telemetry recorded.",
            variable=self.var_profile_mode,
            value="profile",
            bg="#161b22",
            fg="#39FF14",
            selectcolor="#0d1117",
            activebackground="#161b22",
            activeforeground="#39FF14",
            font=("Segoe UI", 9, "bold"),
            command=self._on_mode_radio_changed,
        )
        rb_profile.pack(anchor=tk.W, pady=2)

        # 1. Unreal Engine Tweaks Card
        self.ue_frame = tk.LabelFrame(
            container,
            text=" Unreal Engine (UE4 / UE5) - Injected via -ExecCmds & Engine.ini ",
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=10,
        )
        self.ue_frame.pack(fill=tk.X, pady=6)

        self.var_ue_motion_blur = tk.BooleanVar(value=True)
        self.var_ue_depth_of_field = tk.BooleanVar(value=True)
        self.var_ue_chromatic_aberration = tk.BooleanVar(value=True)
        self.var_ue_film_grain = tk.BooleanVar(value=True)
        self.var_ue_lens_flare = tk.BooleanVar(value=False)
        self.var_ue_volumetric_fog = tk.BooleanVar(value=False)
        self.var_ue_lumen = tk.BooleanVar(value=False)
        self.var_ue_optimize_lumen = tk.BooleanVar(value=True)
        self.var_ue_optimize_vsm = tk.BooleanVar(value=True)
        self.var_ue_optimize_nanite = tk.BooleanVar(value=False)
        self.var_ue_disable_vsm = tk.BooleanVar(value=False)

        ue_checks = [
            ("Disable Motion Blur (r.MotionBlurQuality 0, r.MotionBlur.Max 0)", self.var_ue_motion_blur),
            ("Disable Depth of Field (r.DepthOfFieldQuality 0)", self.var_ue_depth_of_field),
            ("Disable Chromatic Aberration (r.SceneColorFringeQuality 0)", self.var_ue_chromatic_aberration),
            ("Disable Film Grain (r.FilmGrain 0)", self.var_ue_film_grain),
            ("Disable Lens Flare (r.LensFlareQuality 0)", self.var_ue_lens_flare),
            ("Disable Volumetric Fog (r.VolumetricFog 0)", self.var_ue_volumetric_fog),
            ("Disable Lumen Reflections (r.Lumen.Reflections.Allow 0)", self.var_ue_lumen),
            ("Optimize Lumen GI & Reflections (Screen probe downsampling & translucency cap)", self.var_ue_optimize_lumen),
            ("Optimize Virtual Shadow Maps (Throttle SMRT ray counts & clipmap page thrashing)", self.var_ue_optimize_vsm),
            ("Optimize Nanite Streaming (Cap compute cluster nodes per frame to prevent VRAM bubbles)", self.var_ue_optimize_nanite),
            ("Disable Virtual Shadow Maps entirely (Fallback to traditional shadow maps)", self.var_ue_disable_vsm),
        ]
        for text, var in ue_checks:
            cb = tk.Checkbutton(
                self.ue_frame,
                text=text,
                variable=var,
                bg="#161b22",
                fg="#c9d1d9",
                selectcolor="#0d1117",
                activebackground="#161b22",
                activeforeground="#58a6ff",
            )
            cb.pack(anchor=tk.W, pady=2)

        # 2. Unity & Godot Engine Tweaks Card
        self.engine_other_frame = tk.LabelFrame(
            container,
            text=" Unity & Godot Engine Runtime Overrides ",
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=10,
        )
        self.engine_other_frame.pack(fill=tk.X, pady=6)

        self.var_unity_native_jobs = tk.BooleanVar(value=True)
        self.var_unity_disable_vr = tk.BooleanVar(value=True)
        self.var_unity_vulkan = tk.BooleanVar(value=False)
        self.var_unity_mono_gc = tk.BooleanVar(value=False)
        self.var_godot_vsync = tk.BooleanVar(value=True)
        self.var_godot_vulkan = tk.BooleanVar(value=True)

        other_checks = [
            ("Unity: Force Native Gfx Jobs (gfx-enable-native-gfx-jobs=1 in boot.config)", self.var_unity_native_jobs),
            ("Unity: Disable Unused VR Subsystem (vr-enabled=0 in boot.config)", self.var_unity_disable_vr),
            ("Unity: Force Vulkan Backend (-force-vulkan)", self.var_unity_vulkan),
            ("Unity: Mono 64MB Generational GC Nursery (MONO_GC_PARAMS=nursery-size=64m)", self.var_unity_mono_gc),
            ("Godot: Disable VSync (window/vsync/vsync_mode=0 in override.cfg)", self.var_godot_vsync),
            ("Godot: Force Vulkan Forward+ Renderer (--rendering-driver vulkan)", self.var_godot_vulkan),
        ]
        for text, var in other_checks:
            cb = tk.Checkbutton(
                self.engine_other_frame,
                text=text,
                variable=var,
                bg="#161b22",
                fg="#c9d1d9",
                selectcolor="#0d1117",
                activebackground="#161b22",
                activeforeground="#58a6ff",
            )
            cb.pack(anchor=tk.W, pady=2)

        # 3. Translation Layer (DXVK / VKD3D-Proton) Card
        self.dxvk_frame = tk.LabelFrame(
            container,
            text=" Vulkan Translation Layer (DXVK / VKD3D) Overrides ",
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=10,
        )
        self.dxvk_frame.pack(fill=tk.X, pady=6)

        self.var_gfx_vsync_off = tk.BooleanVar(value=True)
        self.var_gfx_async_shader = tk.BooleanVar(value=True)
        self.var_gfx_aniso16 = tk.BooleanVar(value=True)
        self.var_gfx_low_latency = tk.BooleanVar(value=True)
        self.var_gfx_descriptor_buffer = tk.BooleanVar(value=True)
        self.var_gfx_reflex = tk.BooleanVar(value=True)
        self.var_sync_ntsync = tk.BooleanVar(value=True)
        self.var_atelier_sync_fix = tk.BooleanVar(value=False)
        self.var_sync_state_dedup = tk.BooleanVar(value=True)
        self.var_sync_swapchain_debounce = tk.BooleanVar(value=True)
        self.var_sync_precision_timers = tk.BooleanVar(value=True)
        self.var_vkd3d_static_cbv = tk.BooleanVar(value=True)
        self.var_vkd3d_single_queue = tk.BooleanVar(value=False)
        self.var_gfx_max_fps = tk.StringVar(value="0")

        dxvk_checks = [
            ("Force VSync Off (dxgi.syncInterval = 0 for minimum presentation latency)", self.var_gfx_vsync_off),
            ("Asynchronous Shader Compilation (DXVK_ASYNC=1 to prevent stutter)", self.var_gfx_async_shader),
            ("Force 16x Anisotropic Filtering (d3d11.samplerAnisotropy = 16)", self.var_gfx_aniso16),
            ("Vulkan Descriptor Buffers (dxvk.enableDescriptorBuffer = true for DXVK 2.7+)", self.var_gfx_descriptor_buffer),
            ("Nvidia Reflex Low-Latency Queueing (dxvk.nvLowLatency2 = true)", self.var_gfx_reflex),
            ("Kernel Fast-Path NT Synchronization (ntsync)", self.var_sync_ntsync),
            ("Gust / Atelier D3D11 Staging Buffer Sync Fix (Shadow staging wrapper override)", self.var_atelier_sync_fix),
            ("Constant Buffer & State Rebind Deduplication (D3D11 wrapper state filter)", self.var_sync_state_dedup),
            ("Debounce Rapid SwapChain Resize Choke (DXGI/D3D11 scale-factor filter)", self.var_sync_swapchain_debounce),
            ("High-Precision Sleep & Frame Pacing Timers (QPC hybrid spin-sleep pacing)", self.var_sync_precision_timers),
            ("VKD3D: Force Static Constant Buffer Views (VKD3D_CONFIG=force_static_cbv)", self.var_vkd3d_static_cbv),
            ("VKD3D: Enforce Single Submission Queue (Stabilize async compute queue desyncs)", self.var_vkd3d_single_queue),
        ]
        for text, var in dxvk_checks:
            cb = tk.Checkbutton(
                self.dxvk_frame,
                text=text,
                variable=var,
                bg="#161b22",
                fg="#c9d1d9",
                selectcolor="#0d1117",
                activebackground="#161b22",
                activeforeground="#58a6ff",
            )
            cb.pack(anchor=tk.W, pady=2)

        fps_row = tk.Frame(self.dxvk_frame, bg="#161b22")
        fps_row.pack(fill=tk.X, pady=(4, 0))
        lbl_fps = tk.Label(fps_row, text="Target Frame Rate Cap (0 = uncapped):", bg="#161b22", fg="#c9d1d9")
        lbl_fps.pack(side=tk.LEFT)
        entry_fps = tk.Entry(
            fps_row,
            textvariable=self.var_gfx_max_fps,
            width=8,
            bg="#0d1117",
            fg="#c9d1d9",
            insertbackground="#fff",
            relief=tk.FLAT,
        )
        entry_fps.pack(side=tk.LEFT, padx=10)

        # 4. Filesystem & Asset Streaming Card
        self.fs_frame = tk.LabelFrame(
            container,
            text=" Filesystem & Asset Streaming Overrides ",
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=10,
        )
        self.fs_frame.pack(fill=tk.X, pady=6)

        self.var_fs_io_cache = tk.BooleanVar(value=True)
        cb_fs = tk.Checkbutton(
            self.fs_frame,
            text="Adaptive Asset Streaming Read-Ahead Cache (Eliminates traversal stutter in open-world titles)",
            variable=self.var_fs_io_cache,
            bg="#161b22",
            fg="#c9d1d9",
            selectcolor="#0d1117",
            activebackground="#161b22",
            activeforeground="#58a6ff",
        )
        cb_fs.pack(anchor=tk.W, pady=2)

        # 5. CPU Topology & High-Concurrency Memory Card
        self.cpu_mem_frame = tk.LabelFrame(
            container,
            text=" CPU Core Affinity & High-Concurrency Memory Subsystem ",
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=10,
        )
        self.cpu_mem_frame.pack(fill=tk.X, pady=6)

        self.var_cpu_pin_cores = tk.BooleanVar(value=False)
        self.var_mem_mimalloc = tk.BooleanVar(value=False)

        cpu_mem_checks = [
            ("Pin Threads to Primary Performance / 3D V-Cache Cores (taskset / WINE_CPU_TOPOLOGY)", self.var_cpu_pin_cores),
            ("Preload High-Concurrency mimalloc Allocator (Eliminates heap lock contention)", self.var_mem_mimalloc),
        ]
        for text, var in cpu_mem_checks:
            cb = tk.Checkbutton(
                self.cpu_mem_frame,
                text=text,
                variable=var,
                bg="#161b22",
                fg="#c9d1d9",
                selectcolor="#0d1117",
                activebackground="#161b22",
                activeforeground="#58a6ff",
            )
            cb.pack(anchor=tk.W, pady=2)

        # 6. Compatibility & Native Microsoft DLL Overrides Card
        self.compat_frame = tk.LabelFrame(
            container,
            text=" Compatibility & Native Microsoft DLL Overrides (Winetricks-style) ",
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 10, "bold"),
            padx=12,
            pady=10,
        )
        self.compat_frame.pack(fill=tk.X, pady=6)

        self.var_compat_d3dcompiler_47 = tk.BooleanVar(value=False)
        self.var_compat_d3dcompiler_43 = tk.BooleanVar(value=False)
        self.var_compat_vcrun2022 = tk.BooleanVar(value=False)
        self.var_compat_xaudio27 = tk.BooleanVar(value=False)
        self.var_compat_d3dx9 = tk.BooleanVar(value=False)

        compat_checks = [
            ("Microsoft D3DCompiler 47 (d3dcompiler_47=n,b for HLSL dynamic shaders)", self.var_compat_d3dcompiler_47),
            ("Microsoft D3DCompiler 43 (d3dcompiler_43=n,b for legacy D3D11 shaders)", self.var_compat_d3dcompiler_43),
            ("Microsoft Visual C++ 2015-2022 Runtimes (vcruntime140=n,b, msvcp140=n,b)", self.var_compat_vcrun2022),
            ("Microsoft DirectX XAudio 2.7 (xaudio2_7=n,b for audio engine stubs)", self.var_compat_xaudio27),
            ("Microsoft Direct3D 9 Extensions (d3dx9_43=n,b utility library)", self.var_compat_d3dx9),
        ]
        for text, var in compat_checks:
            cb = tk.Checkbutton(
                self.compat_frame,
                text=text,
                variable=var,
                bg="#161b22",
                fg="#c9d1d9",
                selectcolor="#0d1117",
                activebackground="#161b22",
                activeforeground="#58a6ff",
            )
            cb.pack(anchor=tk.W, pady=2)

        compat_btn_row = tk.Frame(self.compat_frame, bg="#161b22")
        compat_btn_row.pack(fill=tk.X, pady=(6, 2))
        btn_snag = tk.Button(
            compat_btn_row,
            text="🔍 Scan Logs & Auto-Snag Missing DLLs",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            command=self.scan_and_snag_dialog,
        )
        btn_snag.pack(side=tk.LEFT, padx=4)

        # Button row in tweaks tab
        btn_row = tk.Frame(self.tab_tweaks, bg=self.card_bg)
        btn_row.pack(pady=12)

        btn_stock = tk.Button(
            btn_row,
            text="🧹 Reset All to Clean Stock (Disable Tweaks)",
            bg="#30363d",
            fg="#c9d1d9",
            activebackground="#21262d",
            activeforeground="#ffffff",
            font=("Segoe UI", 9),
            relief=tk.FLAT,
            padx=12,
            pady=8,
            command=self.reset_tweaks_to_stock,
        )
        btn_stock.pack(side=tk.LEFT, padx=6)

        btn_apply = tk.Button(
            btn_row,
            text="💾 Save & Apply Profile TOML for Selected Game",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=15,
            pady=8,
            command=self.generate_profile_toml,
        )
        btn_apply.pack(side=tk.LEFT, padx=6)

        btn_drop = tk.Button(
            btn_row,
            text="🗑️ Drop Profile",
            bg="#21262d",
            fg="#f85149",
            activebackground="#b62324",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=8,
            command=self.drop_current_profile,
        )
        btn_drop.pack(side=tk.LEFT, padx=6)

    def _build_perf_tab(self):
        self.perf_text = tk.Text(
            self.tab_perf,
            bg="#161b22",
            fg="#c9d1d9",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
        )
        self.perf_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_diff_tab(self):
        ctrl_bar = tk.Frame(self.tab_diff, bg="#161b22", padx=15, pady=12)
        ctrl_bar.pack(fill=tk.X)

        lbl_title = tk.Label(
            ctrl_bar,
            text="A/B Session Comparison & Regression Analysis",
            font=("Segoe UI", 11, "bold"),
            bg="#161b22",
            fg="#58a6ff",
        )
        lbl_title.pack(anchor=tk.W, pady=(0, 8))

        row = tk.Frame(ctrl_bar, bg="#161b22")
        row.pack(fill=tk.X)

        tk.Label(row, text="Baseline (A - Before):", font=("Segoe UI", 9), bg="#161b22", fg="#c9d1d9").pack(side=tk.LEFT, padx=(0, 5))
        self.combo_session_a = ttk.Combobox(row, width=34, state="readonly")
        self.combo_session_a.pack(side=tk.LEFT, padx=(0, 10))
        self.combo_session_a.bind("<<ComboboxSelected>>", lambda e: self.run_session_diff())

        btn_swap = tk.Button(
            row,
            text="⇄ Swap",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=8,
            pady=2,
            font=("Segoe UI", 8, "bold"),
            command=self.swap_diff_sessions,
        )
        btn_swap.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(row, text="Target (B - After):", font=("Segoe UI", 9), bg="#161b22", fg="#c9d1d9").pack(side=tk.LEFT, padx=(0, 5))
        self.combo_session_b = ttk.Combobox(row, width=34, state="readonly")
        self.combo_session_b.pack(side=tk.LEFT, padx=(0, 10))
        self.combo_session_b.bind("<<ComboboxSelected>>", lambda e: self.run_session_diff())

        btn_diff = tk.Button(
            row,
            text="⚡ Compare",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=12,
            pady=2,
            font=("Segoe UI", 9, "bold"),
            command=self.run_session_diff,
        )
        btn_diff.pack(side=tk.LEFT, padx=(5, 0))

        self.diff_text = tk.Text(
            self.tab_diff,
            bg="#0d1117",
            fg="#c9d1d9",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
        )
        self.diff_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def swap_diff_sessions(self):
        if not hasattr(self, "combo_session_a") or not hasattr(self, "combo_session_b"):
            return
        cur_a = self.combo_session_a.current()
        cur_b = self.combo_session_b.current()
        if cur_a >= 0 and cur_b >= 0:
            self.combo_session_a.current(cur_b)
            self.combo_session_b.current(cur_a)
            self.run_session_diff()

        if getattr(self, "dev_mode", False):
            self.refresh_dev_tab()

    def _load_manifest_by_index(self, idx):
        paths = getattr(self, "filtered_manifest_paths", self.manifest_paths)
        if 0 <= idx < len(paths):
            p = paths[idx]
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def run_session_diff(self):
        if not hasattr(self, "diff_text") or not hasattr(self, "combo_session_a") or not hasattr(self, "combo_session_b"):
            return
        idx_a = self.combo_session_a.current()
        idx_b = self.combo_session_b.current()

        if idx_a < 0 or idx_b < 0:
            self.diff_text.delete("1.0", tk.END)
            self.diff_text.insert(tk.END, "Please select both Baseline (Session A) and Target (Session B) to compare.\n")
            return

        manifest_a = self._load_manifest_by_index(idx_a)
        manifest_b = self._load_manifest_by_index(idx_b)

        if not manifest_a or not manifest_b:
            self.diff_text.delete("1.0", tk.END)
            self.diff_text.insert(tk.END, "Failed to load one or both session manifests.\n")
            return

        diff_data = compute_session_diff(manifest_a, manifest_b)
        report = format_diff_report(diff_data)
        self.diff_text.delete("1.0", tk.END)
        self.diff_text.insert(tk.END, report)

    def _build_sys_tab(self):
        self.sys_text = tk.Text(
            self.tab_sys,
            bg="#161b22",
            fg="#c9d1d9",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
        )
        self.sys_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_json_tab(self):
        self.json_text = tk.Text(
            self.tab_json,
            bg="#0d1117",
            fg="#c9d1d9",
            font=("Consolas", 9),
            relief=tk.FLAT,
            padx=15,
            pady=15,
        )
        self.json_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_dev_tab(self):
        ctrl_bar = tk.Frame(self.tab_dev, bg="#161b22", padx=15, pady=10)
        ctrl_bar.pack(fill=tk.X)

        lbl = tk.Label(
            ctrl_bar,
            text="Developer Diagnostic Information & Runtime Internals",
            font=("Segoe UI", 11, "bold"),
            bg="#161b22",
            fg="#a371f7",
        )
        lbl.pack(side=tk.LEFT)

        btn_refresh = tk.Button(
            ctrl_bar,
            text="🔄 Refresh",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            command=self.refresh_dev_tab,
        )
        btn_refresh.pack(side=tk.RIGHT, padx=4)

        btn_copy = tk.Button(
            ctrl_bar,
            text="📋 Copy to Clipboard",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            command=self.copy_dev_dump_to_clipboard,
        )
        btn_copy.pack(side=tk.RIGHT, padx=4)

        btn_export = tk.Button(
            ctrl_bar,
            text="💾 Save Dump...",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            command=self.export_debug_dump,
        )
        btn_export.pack(side=tk.RIGHT, padx=4)

        btn_toggle_game_dev = tk.Button(
            ctrl_bar,
            text="⚡ Toggle Profile Dev Logging",
            bg="#6e40c9",
            fg="#ffffff",
            activebackground="#8957e5",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=3,
            command=self.toggle_game_profile_dev_mode,
        )
        btn_toggle_game_dev.pack(side=tk.RIGHT, padx=4)

        text_container = tk.Frame(self.tab_dev, bg="#0d1117")
        text_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(text_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.dev_text = tk.Text(
            text_container,
            bg="#0d1117",
            fg="#c9d1d9",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
            yscrollcommand=scrollbar.set,
        )
        self.dev_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.dev_text.yview)

    def toggle_dev_mode(self):
        self.dev_mode = not self.dev_mode
        if self.dev_mode:
            self.btn_dev_mode.config(text="🛠️ Dev Mode: ON", bg="#6e40c9", fg="#ffffff")
            tab_ids = [str(t) for t in self.notebook.tabs()]
            if str(self.tab_dev) not in tab_ids:
                self.notebook.add(self.tab_dev, text="  🛠️ Dev Debug & Internals  ")
            self.notebook.select(self.tab_dev)
            self.refresh_dev_tab()
        else:
            self.btn_dev_mode.config(text="🛠️ Dev Mode: OFF", bg="#21262d", fg="#8b949e")
            try:
                self.notebook.forget(self.tab_dev)
            except Exception:
                pass

    def refresh_dev_tab(self):
        if not hasattr(self, "dev_text"):
            return
        dump = generate_debug_dump(manifest=self.current_manifest)
        formatted = format_debug_dump(dump)
        self.dev_text.delete("1.0", tk.END)
        self.dev_text.insert(tk.END, formatted)

    def copy_dev_dump_to_clipboard(self):
        if not hasattr(self, "dev_text"):
            return
        dump_text = self.dev_text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(dump_text)
        messagebox.showinfo("Clipboard", "Developer diagnostic dump copied to clipboard!")

    def export_debug_dump(self):
        dump = generate_debug_dump(manifest=self.current_manifest)
        fpath = filedialog.asksaveasfilename(
            title="Save Developer Diagnostic Dump",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=f"protogoblin_debug_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json",
        )
        if not fpath:
            return
        try:
            if fpath.endswith(".txt"):
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(format_debug_dump(dump))
            else:
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(dump, f, indent=2)
            messagebox.showinfo("Export Successful", f"Saved debug dump to:\n{fpath}")
        except OSError as e:
            messagebox.showerror("Export Failed", f"Failed to save debug dump: {e}")

    def toggle_game_profile_dev_mode(self):
        if not self.current_manifest:
            messagebox.showwarning("Warning", "Select a session first to configure its profile dev mode.")
            return

        tgt = self.current_manifest.get("target") or {}
        app_id = tgt.get("steam_appid")
        t_exe = os.path.basename((tgt.get("target_executable") or {}).get("path", "unknown.exe"))

        if not app_id:
            messagebox.showwarning("Warning", "Selected session does not have a valid AppID.")
            return

        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        p_file = os.path.join(xdg_config, "protogoblin", "games", f"{app_id}.toml")

        current_dev = False
        if os.path.isfile(p_file):
            prof = protogoblin.EngineTweakManager.load_profile(p_file)
            current_dev = bool((prof or {}).get("runtime", {}).get("dev_mode", False))

        new_dev = not current_dev
        toml_content = protogoblin.EngineTweakManager.generate_profile_toml(
            game_id=str(app_id),
            app_id=app_id,
            target_exe=t_exe,
            user_tweaks={"dev_mode": new_dev},
        )
        os.makedirs(os.path.dirname(p_file), exist_ok=True)
        with open(p_file, "w", encoding="utf-8") as f:
            f.write(toml_content)

        state_str = "ENABLED (verbose logs will be written to session directory)" if new_dev else "DISABLED"
        messagebox.showinfo("Profile Dev Mode", f"Dev mode logging for {t_exe} ({app_id}) is now {state_str}.\nProfile saved to: {p_file}")
        self.refresh_dev_tab()

    def _get_steam_libraries(self):
        if self._steam_libs_cache is not None:
            return self._steam_libs_cache
        libs = set()
        roots = [
            os.path.expanduser("~/.local/share/Steam"),
            os.path.expanduser("~/.steam/steam"),
            os.path.expanduser("~/.steam/root"),
            os.path.expanduser("~/.var/app/com.valvesoftware.Steam/.local/share/Steam"),
            os.path.expanduser("~/.var/app/com.valvesoftware.Steam/.steam/steam"),
        ]
        if os.environ.get("STEAM_DIR"):
            roots.append(os.environ["STEAM_DIR"])
        if os.environ.get("STEAM_LIBRARY"):
            libs.add(os.environ["STEAM_LIBRARY"])
        if sys.platform == "win32":
            for win_root in [
                os.path.expandvars("%ProgramFiles(x86)%\\Steam"),
                os.path.expandvars("%ProgramFiles%\\Steam"),
                "C:\\Program Files (x86)\\Steam",
                "C:\\Steam",
                "D:\\Steam",
            ]:
                if os.path.isdir(win_root):
                    roots.append(win_root)
        for root in roots:
            if os.path.isdir(root):
                sapps = os.path.join(root, "steamapps")
                if os.path.isdir(sapps):
                    libs.add(sapps)
                vdf = os.path.join(root, "steamapps", "libraryfolders.vdf")
                if os.path.isfile(vdf):
                    try:
                        with open(vdf, "r", encoding="utf-8") as f:
                            for line in f:
                                m = re.search(r'\"path\"\s+\"([^\"]+)\"', line)
                                if m:
                                    cand = os.path.join(m.group(1), "steamapps")
                                    if os.path.isdir(cand):
                                        libs.add(cand)
                    except Exception:
                        pass
        self._steam_libs_cache = list(libs)
        return self._steam_libs_cache

    def get_installed_steam_games(self):
        """Scans Steam library folders for all installed games via appmanifest_*.acf."""
        games = []
        seen = set()
        for lib in self._get_steam_libraries():
            pattern = os.path.join(lib, "appmanifest_*.acf")
            for acf in glob.glob(pattern):
                try:
                    app_id = None
                    name = None
                    install_dir = None
                    with open(acf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            m_id = re.search(r'\"appid\"\s+\"(\d+)\"', line)
                            if m_id:
                                app_id = m_id.group(1).strip()
                            m_name = re.search(r'\"name\"\s+\"([^\"]+)\"', line)
                            if m_name:
                                name = m_name.group(1).strip()
                            m_dir = re.search(r'\"installdir\"\s+\"([^\"]+)\"', line)
                            if m_dir:
                                install_dir = m_dir.group(1).strip()

                    if app_id and app_id not in seen:
                        if app_id in ("228980",):
                            continue
                        seen.add(app_id)
                        title = name or self.resolve_game_name(app_id)
                        games.append({
                            "app_id": app_id,
                            "name": title,
                            "install_dir": install_dir or "",
                            "library_path": lib,
                            "is_steam": True,
                        })
                except Exception:
                    continue
        games.sort(key=lambda g: g["name"].lower())
        return games

    def get_profiled_non_steam_games(self):
        """Discovers profiled non-Steam games from session manifests and profile configs."""
        non_steam = []
        seen = set()

        # 1. From recorded session manifests
        for path in getattr(self, "manifest_paths", []):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                tgt = data.get("target") or {}
                sess = data.get("session") or {}
                app_id = str(tgt.get("steam_appid") or "")
                t_exe = (tgt.get("target_executable") or {}).get("path")
                if not t_exe:
                    continue
                if not app_id.isdigit() or app_id in ("-", "unknown", "unknown_game", "custom-game"):
                    key = t_exe
                    if key in seen:
                        continue
                    seen.add(key)
                    name = os.path.splitext(os.path.basename(t_exe))[0]
                    non_steam.append({
                        "app_id": app_id or "non_steam",
                        "name": name,
                        "target_exe": t_exe,
                        "prefix_dir": sess.get("prefix_dir"),
                        "working_dir": tgt.get("working_directory"),
                        "argv": sess.get("argv", []),
                        "is_steam": False,
                    })
            except Exception:
                continue

        # 2. From ~/.config/protogoblin/games/*.toml
        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        games_dir = os.path.join(xdg_config, "protogoblin", "games")
        if os.path.isdir(games_dir):
            for toml_path in glob.glob(os.path.join(games_dir, "*.toml")):
                try:
                    prof = protogoblin.EngineTweakManager.load_profile(toml_path)
                    g_sec = (prof or {}).get("game") or {}
                    t_exe = g_sec.get("target_exe")
                    app_id = str(g_sec.get("app_id") or os.path.splitext(os.path.basename(toml_path))[0])
                    if t_exe and t_exe not in seen and not app_id.isdigit():
                        seen.add(t_exe)
                        name = os.path.splitext(os.path.basename(t_exe))[0]
                        non_steam.append({
                            "app_id": app_id,
                            "name": name,
                            "target_exe": t_exe,
                            "prefix_dir": g_sec.get("prefix_dir"),
                            "working_dir": os.path.dirname(t_exe) if os.path.isfile(t_exe) else None,
                            "argv": [t_exe],
                            "is_steam": False,
                        })
                except Exception:
                    continue

        non_steam.sort(key=lambda g: g["name"].lower())
        return non_steam

    def resolve_game_name(self, app_id):
        """Resolves human-readable game title from PresetDatabase or Steam appmanifest."""
        if not app_id or str(app_id) in ("-", "unknown", "unknown_game", "custom-game"):
            return "Custom / Non-Steam Game"
        app_id_str = str(app_id).strip()
        if app_id_str in self._game_name_cache:
            return self._game_name_cache[app_id_str]

        # 1. Preset Database lookup
        preset = protogoblin.PresetDatabase.get_preset(app_id_str)
        if preset and preset.get("title"):
            self._game_name_cache[app_id_str] = preset["title"]
            return preset["title"]

        # 2. Local Steam appmanifest lookup
        for lib in self._get_steam_libraries():
            acf = os.path.join(lib, f"appmanifest_{app_id_str}.acf")
            if os.path.isfile(acf):
                try:
                    with open(acf, "r", encoding="utf-8") as f:
                        for line in f:
                            m = re.search(r'\"name\"\s+\"([^\"]+)\"', line)
                            if m:
                                name = m.group(1).strip()
                                self._game_name_cache[app_id_str] = name
                                return name
                except Exception:
                    pass

        # 3. Fallback
        fallback = f"Steam App {app_id_str}" if app_id_str.isdigit() else f"Game {app_id_str}"
        self._game_name_cache[app_id_str] = fallback
        return fallback

    def refresh_sessions(self, preserve_selection=True):
        """Scans for all utilization.json files across ProtoGoblin sessions."""
        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        base = os.path.join(xdg_data, "protogoblin", "sessions")

        pattern = os.path.join(base, "*", "*", "utilization.json")
        self.manifest_paths = glob.glob(pattern)
        self.manifest_paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)

        self._filter_session_list(preserve_selection=preserve_selection)

    def _filter_session_list(self, preserve_selection=True):
        for item in self.sessions_tree.get_children():
            self.sessions_tree.delete(item)

        query = self.search_var.get().lower().strip()
        self.filtered_manifest_paths = []
        self.diff_session_labels = []
        self.tree_item_to_path = {}

        # Group executables and sessions by steam_appid
        grouped = {}

        for idx, path in enumerate(self.manifest_paths):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sess = data.get("session", {})
                tgt = data.get("target", {})
                t_exe = os.path.basename(tgt.get("target_executable", {}).get("path", "Unknown"))
                app_id = str(tgt.get("steam_appid") or "unknown_game")
                mode = sess.get("mode", "play").upper()
                sess_id = sess.get("id", f"sess_{idx}")
                start_time = sess.get("start_time", sess_id)
                time_str = start_time[:19].replace("T", " ") if "T" in str(start_time) else str(sess_id[:16])
                mtime = os.path.getmtime(path)

                if app_id not in grouped:
                    game_name = self.resolve_game_name(app_id)
                    grouped[app_id] = {
                        "app_id": app_id,
                        "game_name": game_name,
                        "latest_mtime": mtime,
                        "sessions": [],
                    }
                else:
                    if mtime > grouped[app_id]["latest_mtime"]:
                        grouped[app_id]["latest_mtime"] = mtime

                grouped[app_id]["sessions"].append({
                    "path": path,
                    "t_exe": t_exe,
                    "mode": mode,
                    "sess_id": sess_id,
                    "time_str": time_str,
                    "mtime": mtime,
                })
            except Exception:
                continue

        # Sort groups by most recent activity
        sorted_groups = sorted(grouped.values(), key=lambda g: g["latest_mtime"], reverse=True)

        for group in sorted_groups:
            app_id = group["app_id"]
            game_name = group["game_name"]
            group_label = f"{game_name} ({app_id})"

            # Sort sessions within the group by mtime descending
            group["sessions"].sort(key=lambda s: s["mtime"], reverse=True)

            # Filter sessions based on search query
            matching_sessions = []
            group_matches_query = (not query) or (query in group_label.lower()) or (query in app_id.lower())

            for s in group["sessions"]:
                display_exe = f"[{s['mode']}] {s['t_exe']} ({s['time_str']})"
                if group_matches_query or (query in s["t_exe"].lower()) or (query in s["mode"].lower()) or (query in s["sess_id"].lower()):
                    matching_sessions.append((s, display_exe))

            if not matching_sessions:
                continue

            # Insert parent group node in Treeview (expanded by default)
            parent_id = self.sessions_tree.insert(
                "",
                "end",
                text=group_label,
                open=True,
                tags=("group_header",),
            )

            for s, display_exe in matching_sessions:
                item_id = self.sessions_tree.insert(
                    parent_id,
                    "end",
                    text=display_exe,
                    tags=("exe_item",),
                )
                self.tree_item_to_path[item_id] = s["path"]
                self.filtered_manifest_paths.append(s["path"])
                self.diff_session_labels.append(f"[{s['mode']}] {game_name} ({app_id}) - {s['t_exe']} ({s['sess_id'][:16]})")

        if hasattr(self, "combo_session_a") and hasattr(self, "combo_session_b"):
            self.combo_session_a["values"] = self.diff_session_labels
            self.combo_session_b["values"] = self.diff_session_labels
            if len(self.diff_session_labels) >= 2:
                self.combo_session_a.current(1)
                self.combo_session_b.current(0)
            elif len(self.diff_session_labels) == 1:
                self.combo_session_a.current(0)
                self.combo_session_b.current(0)
            self.run_session_diff()

        if getattr(self, "dev_mode", False):
            self.refresh_dev_tab()

        # Select first available executable session, or restore existing selection
        selected = False
        if preserve_selection and getattr(self, "current_manifest_path", None):
            for item_id, path in self.tree_item_to_path.items():
                if path == self.current_manifest_path:
                    self.sessions_tree.selection_set(item_id)
                    self.sessions_tree.focus(item_id)
                    selected = True
                    break

        if not selected:
            root_children = self.sessions_tree.get_children()
            if root_children:
                first_group = root_children[0]
                group_children = self.sessions_tree.get_children(first_group)
                target = group_children[0] if group_children else first_group
                self.sessions_tree.selection_set(target)
                self.sessions_tree.focus(target)
                self.on_session_selected(None)

    def on_session_selected(self, event=None):
        sel = self.sessions_tree.selection()
        if not sel:
            return

        item_id = sel[0]
        path = self.tree_item_to_path.get(item_id)
        if not path:
            # User clicked the group header node! Select first child executable
            children = self.sessions_tree.get_children(item_id)
            if children:
                first_child = children[0]
                self.sessions_tree.selection_set(first_child)
                self.sessions_tree.focus(first_child)
                path = self.tree_item_to_path.get(first_child)
            if not path:
                return

        paths = getattr(self, "filtered_manifest_paths", self.manifest_paths)
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.current_manifest = json.load(f)
            self.current_manifest_path = path
            self._render_manifest_data(self.current_manifest, path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load manifest: {e}")

        if hasattr(self, "combo_session_b") and path in paths:
            idx = paths.index(path)
            self.combo_session_b.current(idx)
            if idx + 1 < len(paths):
                self.combo_session_a.current(idx + 1)
            elif len(paths) > 1 and idx > 0:
                self.combo_session_a.current(idx - 1)
            else:
                self.combo_session_a.current(idx)
            self.run_session_diff()

        if getattr(self, "dev_mode", False):
            self.refresh_dev_tab()

    def _render_manifest_data(self, data, path=""):
        if path:
            self.current_manifest_path = path
        sess = data.get("session", {})
        tgt = data.get("target", {})
        t_exe = tgt.get("target_executable", {}) or {}
        l_exe = tgt.get("launcher_executable")
        env = data.get("environment", {})
        gfx = data.get("graphics", {})
        sync = data.get("synchronization", {})
        roi = data.get("roi_telemetry")
        sub = data.get("subsystems", {})

        # Tab 1: Diagnostics & Suggestions
        t_name = os.path.basename(t_exe.get("path", "Target"))
        eng_info = tgt.get("engine") or {}
        eng_name = eng_info.get("engine", "generic").upper()
        eng_tag = f" | Engine: {eng_name}" if eng_info.get("detected") else ""
        ac = data.get("anti_cheat", {})
        ac_tag = f" | 🛡️ {ac.get('provider')} (PASSTHROUGH)" if ac.get("detected") else ""
        app_id = tgt.get("steam_appid") or "-"
        game_name = self.resolve_game_name(app_id)
        game_display = f"{game_name} ({app_id})" if app_id != "-" else game_name
        self.diag_header_lbl.config(
            text=f"Game: {game_display} | Target: {t_name}{eng_tag}{ac_tag} | Mode: {sess.get('mode', 'play').upper()} | Session: {sess.get('id')}"
        )
        if hasattr(self, "tweaks_game_lbl"):
            self.tweaks_game_lbl.config(
                text=f"Active Game: {game_display} | Executable: {t_name} (Engine: {eng_name})"
            )
        if hasattr(self, "btn_launch_game"):
            short_name = t_name if len(t_name) <= 15 else t_name[:12] + "..."
            self.btn_launch_game.config(text=f"🚀 Launch {short_name}")

        app_id = tgt.get("steam_appid")
        preset = protogoblin.PresetDatabase.get_preset(app_id) if app_id else None
        if preset and "gust_d3d11_staging_sync_stall" in preset.get("known_issues", []):
            self.var_atelier_sync_fix.set(True)
        else:
            self.var_atelier_sync_fix.set(False)

        # Sync profile mode from existing .toml profile if present
        prof_mode = None
        if app_id:
            xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
            p_file = os.path.join(xdg_config, "protogoblin", "games", f"{app_id}.toml")
            if os.path.isfile(p_file):
                prof_data = protogoblin.EngineTweakManager.load_profile(p_file)
                if prof_data:
                    self._sync_profile_data_to_variables(prof_data)
                    prof_mode = (
                        prof_data.get("runtime", {}).get("mode")
                        or prof_data.get("protogoblin", {}).get("mode")
                    )
        if not prof_mode:
            prof_mode = sess.get("mode", "play")

        self.var_profile_mode.set(prof_mode)
        self._update_header_mode_button(prof_mode)

        for widget in self.diag_cards_container.winfo_children():
            widget.destroy()

        suggestions = DiagnosticAdvisor.analyze(data)

        if not suggestions:
            card = tk.Label(
                self.diag_cards_container,
                text="No optimization interventions required. Runtime health is clean.",
                bg="#161b22",
                fg="#2ecc71",
                font=("Segoe UI", 10),
                padx=15,
                pady=15,
            )
            card.pack(fill=tk.X, pady=5)
        else:
            for s in suggestions:
                lvl = s["level"]
                border_color = (
                    self.error_color
                    if lvl == "error"
                    else self.warning_color
                    if lvl == "warning"
                    else self.success_color
                    if lvl == "success"
                    else "#58a6ff"
                )

                card_frame = tk.Frame(
                    self.diag_cards_container,
                    bg="#161b22",
                    highlightbackground=border_color,
                    highlightthickness=1,
                    padx=12,
                    pady=10,
                    cursor="hand2",
                )
                card_frame.pack(fill=tk.X, pady=6)

                header_frame = tk.Frame(card_frame, bg="#161b22")
                header_frame.pack(fill=tk.X)

                lbl_t = tk.Label(
                    header_frame,
                    text=s["title"],
                    font=("Segoe UI", 10, "bold"),
                    bg="#161b22",
                    fg=border_color,
                    anchor=tk.W,
                    cursor="hand2",
                )
                lbl_t.pack(side=tk.LEFT, fill=tk.X, expand=True)

                is_active = self.is_suggestion_enabled(s)
                cb_var = tk.BooleanVar(value=is_active)

                # Experiment lifecycle status
                fix_id = s.get("fix_id")
                tgt_appid = (data.get("target") or {}).get("steam_appid")
                p_file_curr = self.find_game_profile_path(tgt_appid)
                exp_st = protogoblin.ExperimentalValidationEngine.get_experiment_status(p_file_curr, fix_id) if fix_id else None

                if exp_st == protogoblin.ExperimentStatus.VALIDATED:
                    st_badge = "✅ VALIDATED (Play Default)"
                    badge_fg = "#2ecc71"
                elif exp_st == protogoblin.ExperimentStatus.APPLIED:
                    st_badge = "🧪 EXPERIMENT (In Test)"
                    badge_fg = "#f39c12"
                elif exp_st == protogoblin.ExperimentStatus.BENCHMARKED:
                    st_badge = "📊 BENCHMARKED"
                    badge_fg = "#58a6ff"
                elif exp_st == protogoblin.ExperimentStatus.REJECTED:
                    st_badge = "❌ REGRESSED (Rolled Back)"
                    badge_fg = "#e74c3c"
                elif fix_id:
                    st_badge = "💡 CANDIDATE (Ready to Test)"
                    badge_fg = "#8b949e"
                else:
                    st_badge = None

                if st_badge:
                    lbl_badge = tk.Label(
                        header_frame,
                        text=st_badge,
                        font=("Segoe UI", 8, "bold"),
                        bg="#161b22",
                        fg=badge_fg,
                    )
                    lbl_badge.pack(side=tk.RIGHT, padx=6)

                chk = tk.Checkbutton(
                    header_frame,
                    text="Applied" if is_active else "Enable",
                    variable=cb_var,
                    bg="#161b22",
                    fg="#39FF14" if is_active else "#8b949e",
                    activebackground="#161b22",
                    activeforeground="#39FF14",
                    selectcolor="#0d1117",
                    font=("Segoe UI", 9, "bold"),
                    cursor="hand2",
                    command=lambda sug=s, v=cb_var: self._on_suggestion_checkbox_toggled(sug, v),
                )
                chk.pack(side=tk.RIGHT, padx=5)

                lbl_d = tk.Label(
                    card_frame,
                    text=s["description"],
                    font=("Segoe UI", 9),
                    bg="#161b22",
                    fg="#c9d1d9",
                    wraplength=580,
                    justify=tk.LEFT,
                    anchor=tk.W,
                    cursor="hand2",
                )
                lbl_d.pack(fill=tk.X, pady=(4, 6))

                lbl_a = tk.Label(
                    card_frame,
                    text="👉 Recommendation: " + s["action"],
                    font=("Segoe UI", 9, "bold"),
                    bg="#161b22",
                    fg="#f0f6fc",
                    wraplength=580,
                    justify=tk.LEFT,
                    anchor=tk.W,
                    cursor="hand2",
                )
                lbl_a.pack(fill=tk.X)

                action_frame = tk.Frame(card_frame, bg="#161b22")
                action_frame.pack(fill=tk.X, pady=(8, 2))

                btn_view = tk.Button(
                    action_frame,
                    text="🔍 Configure / Details",
                    bg="#21262d",
                    fg="#58a6ff",
                    activebackground="#30363d",
                    activeforeground="#ffffff",
                    font=("Segoe UI", 8, "bold"),
                    relief=tk.FLAT,
                    padx=8,
                    pady=3,
                    cursor="hand2",
                    command=lambda sug=s, v=cb_var: self.open_suggestion_detail_window(sug, v),
                )
                btn_view.pack(side=tk.LEFT, padx=(0, 8))

                if s.get("fix_id") and not is_active:
                    fix_id = s["fix_id"]
                    extra = s.get("cap_target")
                    btn_fix = tk.Button(
                        action_frame,
                        text=s.get("fix_button_text", "⚡ Apply Suggested Fix"),
                        bg="#238636",
                        fg="#ffffff",
                        activebackground="#2ea043",
                        activeforeground="#ffffff",
                        font=("Segoe UI", 8, "bold"),
                        relief=tk.FLAT,
                        padx=8,
                        pady=3,
                        cursor="hand2",
                        command=lambda fid=fix_id, ext=extra, v=cb_var, sug=s: self._apply_and_sync_fix(fid, ext, v, sug),
                    )
                    btn_fix.pack(side=tk.LEFT)

                for w in (card_frame, lbl_t, lbl_d, lbl_a):
                    w.bind("<Button-1>", lambda e, sug=s, v=cb_var: self.open_suggestion_detail_window(sug, v))

        # Tab 2: Performance
        self.perf_text.delete("1.0", tk.END)
        p_lines = [
            "=" * 60,
            f" PERFORMANCE REPORT: {sess.get('id')}",
            "=" * 60,
            f"Execution Duration:   {sess.get('duration_seconds', 0):.2f} seconds",
            f"Process Exit Status:  {'Clean (0)' if sess.get('clean_shutdown') else f'Error ({tgt.get('exit_code')})'}",
            f"Process Tree Size:    {tgt.get('process_tree_count', 1)} processes spawned",
            f"Peak Thread Count:    {tgt.get('peak_thread_count', 1)} threads",
            "",
        ]

        if roi and roi.get("roi_enabled"):
            fm = roi.get("frame_metrics") or {}
            pacing = roi.get("pacing") or {}
            p_lines.extend(
                [
                    "REGION-OF-INTEREST (ROI) FRAMETIME TELEMETRY",
                    "-" * 60,
                    f"Bottleneck Status:    {(roi.get('bottleneck_classification') or 'balanced').upper()}",
                    f"Average Framerate:    {(fm.get('fps_avg') or 0):.1f} FPS",
                    f"1% Low Framerate:     {(fm.get('fps_1_pct_low') or 0):.1f} FPS",
                    f"0.1% Low Framerate:   {(fm.get('fps_0_1_pct_low') or 0):.1f} FPS",
                    f"Average Frametime:    {(fm.get('frametime_avg_ms') or 0):.2f} ms",
                    f"Frametime Percentiles:p95 = {fm.get('frametime_p95_ms') or 0} ms | p99 = {fm.get('frametime_p99_ms') or 0} ms",
                    f"Frametime Jitter:     {(fm.get('frametime_jitter_ms') or 0):.2f} ms (StdDev)",
                    f"Total Frames Scanned: {(fm.get('total_frames') or 0):,}",
                    "",
                    "HARDWARE RESOURCE ALLOCATION",
                    "-" * 60,
                    f"CPU Busy Utilization: {pacing.get('cpu_busy_pct') or 0}%",
                    f"CPU Wait/Blocked:     {pacing.get('cpu_wait_pct') or 0}%",
                    f"GPU Busy Utilization: {pacing.get('gpu_busy_pct') or 0}%",
                ]
            )
        else:
            ac = data.get("anti_cheat", {})
            if ac.get("detected"):
                provider = ac.get("provider", "Anti-Cheat")
                p_lines.extend(
                    [
                        f"ROI Telemetry: NOT RECORDED (🛡️ Anti-Cheat Active: {provider})",
                        "-" * 60,
                        f"NOTICE: Active anti-cheat ({provider}) was detected in the game payload.",
                        "ProtoGoblin automatically suppressed Profile Mode and HUD/overlay hooks to enforce",
                        "strict Zero-Injection Passthrough. In-process telemetry and frametime instrumentation",
                        "were intentionally disabled to prevent client bans or multiplayer disconnections.",
                    ]
                )
            else:
                p_lines.extend(
                    [
                        "ROI Telemetry: Not recorded (Session was launched in PLAY mode).",
                        "To collect frame percentiles and latency breakdown, launch with:",
                        "  PROTOGOBLIN_MODE=profile %command%",
                    ]
                )

        d3d11_stats = sess.get("graphics", {}).get("d3d11_wrapper_stats")
        if d3d11_stats:
            cb = d3d11_stats.get("constant_buffers", {})
            st = d3d11_stats.get("pipeline_states", {})
            sc = d3d11_stats.get("swapchain", {})
            p_lines.extend(
                [
                    "",
                    "D3D11 / DXGI WRAPPER INTROSPECTION METRICS",
                    "-" * 60,
                    f"Constant Buffer Updates: {(cb.get('updates_total') or 0):,} total | {(cb.get('updates_redundant') or 0):,} redundant ({(cb.get('redundancy_rate_pct') or 0.0):.1f}% spam)",
                    f"Pipeline State Binds:   {(st.get('binds_total') or 0):,} total | {(st.get('binds_redundant') or 0):,} redundant ({(st.get('redundancy_rate_pct') or 0.0):.1f}% rebinds)",
                    f"SwapChain Resizes:       {sc.get('resizes_total') or 0} total | {sc.get('resizes_identical') or 0} identical drops | {sc.get('resizes_rapid') or 0} rapid bursts",
                    f"Deduplication Active:   State Dedup: {'YES' if d3d11_stats.get('state_dedup_active') else 'NO'} | Debounce: {'YES' if d3d11_stats.get('swapchain_debounce_active') else 'NO'}",
                ]
            )

        io_stats = sess.get("filesystem", {}).get("io_cache_stats")
        if io_stats:
            p_lines.extend(
                [
                    "",
                    "FILESYSTEM & ASSET STREAMING TELEMETRY",
                    "-" * 60,
                    f"Cache Active:           {'YES' if io_stats.get('io_cache_active') else 'NO'}",
                    f"Tracked Game Archives:  {io_stats.get('tracked_archives_count') or 0} containers",
                    f"Synchronous Reads:      {(io_stats.get('reads_total') or 0):,} total | {(io_stats.get('reads_cached_hits') or 0):,} cache hits ({(io_stats.get('hit_rate_pct') or 0.0):.1f}%)",
                    f"Data Streamed / Saved:  {(io_stats.get('bytes_read_total') or 0) / (1024*1024):.1f} MB read | {(io_stats.get('bytes_cached_saved') or 0) / (1024*1024):.1f} MB served from RAM",
                    f"Est. Latency Avoided:   {(io_stats.get('estimated_latency_saved_ms') or 0.0):.1f} ms",
                ]
            )

        timing_stats = sess.get("graphics", {}).get("d3d11_wrapper_stats", {}).get("timing")
        if timing_stats:
            p_lines.extend(
                [
                    "",
                    "TIMING & FRAME-PACING CADENCE TELEMETRY",
                    "-" * 60,
                    f"Precision Timers Active:{'YES' if timing_stats.get('high_precision_timers_active') else 'NO'}",
                    f"Win32 Sleep Calls:      {(timing_stats.get('sleep_calls_total') or 0):,} total | {(timing_stats.get('sleep_spin_hybrid_calls') or 0):,} QPC spin-paced",
                    f"Overshoots Prevented:   {(timing_stats.get('overshoot_prevented_calls') or 0):,} calls (~{(timing_stats.get('overshoot_avoided_ms') or 0.0):.1f} ms drift avoided)",
                ]
            )

        self.perf_text.insert(tk.END, "\n".join(p_lines))

        # Tab 3: System & Translation
        self.sys_text.delete("1.0", tk.END)
        s_lines = [
            "=" * 60,
            " COMPATIBILITY & TRANSLATION TELEMETRY",
            "=" * 60,
            f"Target Binary:        {t_exe.get('path', 'unknown')}",
            f"Architecture:         {t_exe.get('arch', 'unknown').upper()}",
            f"Target SHA256:        {t_exe.get('sha256', 'unknown')}",
            f"PE Timestamp:         {t_exe.get('pe_timestamp') or 'None'}",
            f"PE Size of Image:     {(t_exe.get('pe_size_of_image') or 0):,} bytes",
            "",
            "INTERMEDIATE LAUNCHER",
            "-" * 60,
            f"Launcher Present:     {'Yes' if l_exe else 'No (Direct Execution)'}",
        ]
        if l_exe:
            s_lines.extend(
                [
                    f"Launcher Path:        {l_exe.get('path')}",
                    f"Launcher Arch:        {l_exe.get('arch')}",
                ]
            )

        s_lines.extend(
            [
                "",
                "GRAPHICS TRANSLATION (DXVK / VKD3D)",
                "-" * 60,
                f"Active Backend:       {gfx.get('active_backend', 'unknown').upper()}",
                f"D3D APIs Detected:    {', '.join(gfx.get('d3d_api_versions', []))}",
                f"Swapchain Mode:       {gfx.get('presentation_model', 'unknown')} ({gfx.get('present_mode', 'unknown')})",
                f"Resolution:           {gfx.get('resolution', 'unknown')}",
                f"Shader Pipelines:     {(gfx.get('shader_compiles') or {}).get('count') or 0} compiled ({((gfx.get('shader_compiles') or {}).get('total_time_ms') or 0):.1f} ms)",
                f"VRAM Allocated:       {gfx.get('memory', {}).get('vram_used_mb') or 'N/A'} MB",
                "",
                "SYNCHRONIZATION & SUBSYSTEMS",
                "-" * 60,
                f"Sync Backend:         {sync.get('sync_backend', 'unknown').upper()}",
                f"Kernel Fast Path:     {'Enabled' if sync.get('fast_path_enabled') else 'Disabled'}",
                f"Subsystems Loaded:    {', '.join(sub.get('loaded', []))}",
                f"Subsystems Unutilized:{', '.join(sub.get('unutilized', []))}",
                f"Subsystems Pruned:    {', '.join(sub.get('pruned', [])) or 'None'}",
            ]
        )
        self.sys_text.insert(tk.END, "\n".join(s_lines))

        # Tab 4: Raw JSON
        self.json_text.delete("1.0", tk.END)
        self.json_text.insert(tk.END, json.dumps(data, indent=2))

    def inspect_file_dialog(self):
        f = filedialog.askopenfilename(
            title="Inspect Windows Executable",
            filetypes=[("Executable Files", "*.exe *.dll"), ("All Files", "*.*")],
        )
        if not f:
            return

        pe = protogoblin.PEInfo.inspect(f)
        ac = protogoblin.AntiCheatDetector.scan(f)
        engine = protogoblin.EngineDetector.detect(f)

        eng_str = engine.get("engine", "Unknown").upper() if engine.get("detected") else "Custom / In-house"
        if engine.get("version"):
            eng_str += f" ({engine['version']})"

        msg = (
            f"File: {f}\n\n"
            f"Game Engine: {eng_str}\n"
            f"Architecture: {pe.get('arch', 'unknown')}\n"
            f"SHA256: {pe.get('sha256', 'unknown')}\n"
            f"PE Timestamp: {pe.get('pe_timestamp') or 'None'}\n"
            f"PE Size of Image: {(pe.get('pe_size_of_image') or 0):,} bytes\n\n"
            f"Anti-Cheat Detected: {'YES (' + ac.get('provider') + ')' if ac.get('detected') else 'Clean (None)'}"
        )
        messagebox.showinfo("PE Binary Inspection", msg)

    def _update_header_mode_button(self, mode):
        if mode == "profile":
            self.btn_toggle_mode.config(
                text="🎯 Profiling: ON (ProtoGoblin)",
                bg="#238636",
                fg="#ffffff",
                activebackground="#2ea043",
                activeforeground="#ffffff",
            )
        else:
            self.btn_toggle_mode.config(
                text="⚪ Profiling: OFF (Play Mode)",
                bg="#21262d",
                fg="#c9d1d9",
                activebackground="#30363d",
                activeforeground="#ffffff",
            )

    def _on_mode_radio_changed(self):
        m = self.var_profile_mode.get()
        self._update_header_mode_button(m)

    def set_status(self, text, fg="#c9d1d9"):
        """Updates the bottom status bar message."""
        if hasattr(self, "status_bar_lbl"):
            try:
                self.status_bar_lbl.config(text=text, fg=fg)
            except Exception:
                pass

    def get_game_profile_mode(self, app_id):
        """Reads current mode ('profile' or 'play') for an AppID/game from its profile TOML."""
        if not app_id:
            return "play"
        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        p_file = os.path.join(xdg_config, "protogoblin", "games", f"{app_id}.toml")
        if os.path.isfile(p_file):
            try:
                prof = protogoblin.EngineTweakManager.load_profile(p_file)
                mode = (
                    (prof or {}).get("runtime", {}).get("mode")
                    or (prof or {}).get("protogoblin", {}).get("mode")
                )
                if mode in ("profile", "play"):
                    return mode
            except Exception:
                pass
        return "play"

    def set_game_profile_mode(self, app_id, mode, target_exe=None):
        """Sets the mode ('profile' or 'play') in the game's profile TOML."""
        if not app_id:
            return None
        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        profile_dir = os.path.join(xdg_config, "protogoblin", "games")
        os.makedirs(profile_dir, exist_ok=True)
        p_file = os.path.join(profile_dir, f"{app_id}.toml")

        existing_tweaks = {"mode": mode}
        exe = target_exe or f"game_{app_id}.exe"
        if os.path.isfile(p_file):
            try:
                prof = protogoblin.EngineTweakManager.load_profile(p_file)
                if (prof or {}).get("game", {}).get("target_exe"):
                    exe = prof["game"]["target_exe"]
            except Exception:
                pass

        toml_content = protogoblin.EngineTweakManager.generate_profile_toml(
            game_id=str(app_id),
            app_id=str(app_id),
            target_exe=exe,
            user_tweaks=existing_tweaks,
        )
        with open(p_file, "w", encoding="utf-8") as f:
            f.write(toml_content)
        return p_file

    def launch_game(self, app_id, target_exe=None, prefix_dir=None, argv=None, game_name=None):
        """Launches an installed Steam game or profiled non-Steam game with ProtoGoblin."""
        app_id_str = str(app_id).strip() if app_id else ""
        is_steam = app_id_str.isdigit()
        title = game_name or self.resolve_game_name(app_id_str)
        curr_mode = self.get_game_profile_mode(app_id_str)

        log_fn = getattr(protogoblin, "log", print)
        log_fn(f"ProtoGoblin Command launching {title} (AppID: {app_id_str}, Mode: {curr_mode.upper()})")

        launcher = getattr(self, "process_launcher", subprocess.Popen)
        launched_proc = None
        cmd = []

        try:
            if is_steam:
                steam_url = f"steam://rungameid/{app_id_str}"
                if sys.platform == "win32":
                    cmd = ["cmd", "/c", "start", steam_url]
                    launched_proc = launcher(cmd, shell=True)
                else:
                    if shutil.which("steam"):
                        cmd = ["steam", steam_url]
                    elif shutil.which("xdg-open"):
                        cmd = ["xdg-open", steam_url]
                    elif shutil.which("flatpak"):
                        cmd = ["flatpak", "run", "com.valvesoftware.Steam", steam_url]
                    else:
                        cmd = ["steam", steam_url]
                    launched_proc = launcher(cmd)
            else:
                if not target_exe:
                    raise ValueError(f"No executable path specified for non-Steam game {title}")

                proton_path = os.path.join(SCRIPT_DIR, "proton")
                env = os.environ.copy()
                if prefix_dir:
                    env["STEAM_COMPAT_DATA_PATH"] = prefix_dir
                env["SteamAppId"] = app_id_str or "non_steam"
                env["PROTOGOBLIN_MODE"] = curr_mode

                working_dir = os.path.dirname(target_exe) if (target_exe and os.path.isfile(target_exe)) else None

                if os.path.isfile(proton_path) and sys.platform != "win32":
                    extra_args = argv[1:] if (argv and len(argv) > 1) else []
                    cmd = [sys.executable, proton_path, "run", target_exe] + extra_args
                    launched_proc = launcher(cmd, env=env, cwd=working_dir)
                else:
                    extra_args = argv[1:] if (argv and len(argv) > 1) else []
                    cmd = [target_exe] + extra_args
                    launched_proc = launcher(cmd, env=env, cwd=working_dir)

            mode_badge = "🎯 PROFILE MODE" if curr_mode == "profile" else "⚪ PLAY MODE"
            msg = f"🚀 Launched {title} in {mode_badge}. Waiting for session results..."
            self.set_status(msg, fg="#39FF14" if curr_mode == "profile" else "#58a6ff")

            self._last_launched_app_id = app_id_str

            return {
                "success": True,
                "process": launched_proc,
                "cmd": cmd,
                "app_id": app_id_str,
                "mode": curr_mode,
            }
        except Exception as e:
            err_msg = f"Failed to launch {title}: {e}"
            log_fn(err_msg)
            self.set_status(f"⚠️ {err_msg}", fg="#e74c3c")
            try:
                messagebox.showerror("Launch Error", err_msg)
            except Exception:
                pass
            return {
                "success": False,
                "error": str(e),
                "cmd": cmd,
                "app_id": app_id_str,
            }

    def find_game_profile_path(self, app_id):
        """Resolves the profile path for a given AppID."""
        if not app_id:
            return None
        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        p_file = os.path.join(xdg_config, "protogoblin", "games", f"{app_id}.toml")
        return p_file

    def start_validation_experiment(self, suggestion):
        """Starts an isolated A/B validation experiment for a suggested fix."""
        fix_id = suggestion.get("fix_id")
        if not fix_id or not self.current_manifest:
            return

        tgt = self.current_manifest.get("target") or {}
        app_id = tgt.get("steam_appid")
        sess_id = (self.current_manifest.get("session") or {}).get("id")
        t_exe = os.path.basename((tgt.get("target_executable") or {}).get("path", f"game_{app_id}.exe"))
        p_file = self.find_game_profile_path(app_id)

        try:
            confirm = messagebox.askyesno(
                "Start Validation Experiment",
                f"Start isolated A/B validation experiment for:\n\n"
                f"• Optimization: {suggestion['title']}\n"
                f"• Baseline Session: {sess_id}\n"
                f"• Target Game: {t_exe} ({app_id})\n\n"
                f"Validation Engine Workflow:\n"
                f"1. Applies this fix in isolated Profile Mode\n"
                f"2. Measures subsequent benchmark session against baseline\n"
                f"3. Automatically promotes to permanent Play Mode default IF performance improves\n"
                f"4. Automatically rolls back to stock IF performance regresses\n\n"
                f"Start experiment now?",
            )
        except Exception:
            confirm = True

        if not confirm:
            return

        kwargs = {}
        if fix_id == "cap_framerate" and suggestion.get("cap_target"):
            kwargs["cap_target"] = suggestion["cap_target"]

        try:
            protogoblin.ExperimentalValidationEngine.start_experiment(
                profile_path=p_file,
                fix_id=fix_id,
                baseline_session_id=sess_id,
                baseline_metrics=(self.current_manifest.get("roi_telemetry") or {}).get("frame_metrics"),
                **kwargs,
            )
        except ValueError as e:
            try:
                messagebox.showerror("Unsupported Experiment", str(e))
            except Exception:
                pass
            return
        self.var_profile_mode.set("profile")
        self._update_header_mode_button("profile")
        self.set_status(f"🧪 Experiment started for {fix_id}! Launch game to benchmark.", fg="#f39c12")
        self.refresh_sessions(preserve_selection=True)

        try:
            messagebox.showinfo(
                "Experiment Active",
                f"Experiment for '{fix_id}' is now APPLIED and active in Profile Mode.\n\n"
                f"Click '🚀 Launch Game' to run the benchmark session. The results will automatically be evaluated and displayed here upon session completion!",
            )
        except Exception:
            pass

    def launch_selected_game(self):
        """Launches the currently selected game from the dashboard, or opens the library dialog."""
        if not self.current_manifest:
            self.open_game_launcher_dialog()
            return

        tgt = self.current_manifest.get("target") or {}
        sess = self.current_manifest.get("session") or {}
        app_id = tgt.get("steam_appid")
        t_exe = (tgt.get("target_executable") or {}).get("path")
        prefix_dir = sess.get("prefix_dir")
        argv = sess.get("argv", [])
        game_name = self.resolve_game_name(app_id)

        self.launch_game(
            app_id=app_id,
            target_exe=t_exe,
            prefix_dir=prefix_dir,
            argv=argv,
            game_name=game_name,
        )

    def open_game_launcher_dialog(self):
        """Opens the Game Library launcher dialog."""
        return GameLauncherDialog(self)

    def _start_auto_refresh(self):
        """Starts background periodic polling for newly recorded or updated session manifests."""
        self._auto_refresh_check()

    def _auto_refresh_check(self):
        try:
            if not getattr(self, "root", None) or not self.root.winfo_exists():
                return

            xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
            base = os.path.join(xdg_data, "protogoblin", "sessions")
            pattern = os.path.join(base, "*", "*", "utilization.json")
            current_manifests = glob.glob(pattern)

            updated = False
            if len(current_manifests) != getattr(self, "_last_manifest_count", -1):
                updated = True
            else:
                for p in current_manifests:
                    try:
                        mtime = os.path.getmtime(p)
                        if p not in self._last_known_manifest_mtimes or mtime > self._last_known_manifest_mtimes[p]:
                            updated = True
                            break
                    except OSError:
                        pass

            if updated:
                for p in current_manifests:
                    try:
                        self._last_known_manifest_mtimes[p] = os.path.getmtime(p)
                    except OSError:
                        pass
                self._last_manifest_count = len(current_manifests)

                self.refresh_sessions(preserve_selection=False)

                if current_manifests:
                    latest = max(current_manifests, key=lambda p: os.path.getmtime(p))
                    try:
                        with open(latest, "r", encoding="utf-8") as f:
                            m_data = json.load(f)
                        app_id = (m_data.get("target") or {}).get("steam_appid")
                        m_mode = (m_data.get("session") or {}).get("mode", "play").upper()
                        g_title = self.resolve_game_name(app_id)
                        exp_eval = m_data.get("experiment_evaluation")
                        if exp_eval:
                            v = exp_eval.get("verdict", "")
                            f_id = exp_eval.get("fix_id", "")
                            st = exp_eval.get("status", "")
                            summary = exp_eval.get("comparison_summary", "")
                            if st == protogoblin.ExperimentStatus.VALIDATED:
                                self.set_status(
                                    f"🎉 Experiment VALIDATED for {f_id}: {summary}! Graduated to Play Mode default.",
                                    fg="#39FF14",
                                )
                            elif st == protogoblin.ExperimentStatus.REJECTED:
                                self.set_status(
                                    f"⚠️ Experiment REGRESSED for {f_id}: {summary}. Automatically rolled back to stock!",
                                    fg="#e74c3c",
                                )
                            else:
                                self.set_status(
                                    f"📊 Experiment Benchmarked for {f_id}: {summary}",
                                    fg="#58a6ff",
                                )
                        else:
                            self.set_status(
                                f"✨ New session [{m_mode}] detected for {g_title}! Dashboard auto-updated.",
                                fg="#39FF14",
                            )
                    except Exception:
                        self.set_status("✨ New session detected! Dashboard auto-updated.", fg="#39FF14")
        except Exception:
            pass
        finally:
            try:
                if getattr(self, "root", None) and self.root.winfo_exists():
                    self._poll_timer_id = self.root.after(self._poll_interval_ms, self._auto_refresh_check)
            except Exception:
                pass

    def stop_auto_refresh(self):
        """Cancels background polling."""
        if getattr(self, "_poll_timer_id", None) and getattr(self, "root", None):
            try:
                self.root.after_cancel(self._poll_timer_id)
            except Exception:
                pass
            self._poll_timer_id = None

    def on_close(self):
        """Handles clean application exit."""
        self.stop_auto_refresh()
        try:
            self.root.destroy()
        except Exception:
            pass

    def toggle_selected_game_mode(self):
        if not self.current_manifest:
            messagebox.showwarning("Notice", "Select a game session first to toggle its profiling mode.")
            return

        curr = self.var_profile_mode.get()
        new_mode = "play" if curr == "profile" else "profile"
        self.var_profile_mode.set(new_mode)
        self._update_header_mode_button(new_mode)
        path = self.generate_profile_toml(silent=True)

        mode_desc = (
            "Profile Mode (Active 'ProtoGoblin' HUD overlay and telemetry recording)"
            if new_mode == "profile"
            else "Play Mode (Silent execution, optimizations active, telemetry off)"
        )
        messagebox.showinfo(
            "Game Mode Updated",
            f"Mode updated to: {mode_desc}\n\n"
            f"Saved to profile:\n{path}\n\n"
            "This title will now launch in this mode automatically from Steam without needing launch arguments!",
        )

    def add_game_dialog(self):
        app_id = simpledialog.askstring(
            "Configure Game by AppID",
            "Enter Steam AppID to configure profiling and optimizations\n(e.g. 2555360 for Immortals of Aveum Demo):",
            parent=self.root,
        )
        if not app_id:
            return

        app_id = app_id.strip()
        preset = protogoblin.PresetDatabase.get_preset(app_id)
        title = preset.get("title") if preset else f"Steam App {app_id}"

        enable_prof = messagebox.askyesno(
            "Enable Profiling?",
            f"Game: {title} (AppID {app_id})\n\n"
            "Would you like to ENABLE Profiling Mode ('ProtoGoblin' HUD + Telemetry) for this game?\n\n"
            "• Click Yes for Profile Mode\n• Click No for Play Mode (Optimizations only)",
        )

        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        profile_dir = os.path.join(xdg_config, "protogoblin", "games")
        os.makedirs(profile_dir, exist_ok=True)
        profile_file = os.path.join(profile_dir, f"{app_id}.toml")

        mode = "profile" if enable_prof else "play"
        user_tweaks = {"mode": mode}
        if preset and "gust_d3d11_staging_sync_stall" in preset.get("known_issues", []):
            user_tweaks["atelier_sync_fix"] = True

        toml_content = protogoblin.EngineTweakManager.generate_profile_toml(
            game_id=app_id,
            app_id=app_id,
            target_exe=f"{title.replace(' ', '_')}.exe",
            sync_backend="ntsync",
            user_tweaks=user_tweaks,
        )
        with open(profile_file, "w", encoding="utf-8") as f:
            f.write(toml_content)

        messagebox.showinfo(
            "Profile Created",
            f"Successfully configured {title} (AppID: {app_id})!\n\n"
            f"Mode: {'PROFILE MODE (Telemetry & HUD)' if enable_prof else 'PLAY MODE'}\n"
            f"Profile path:\n{profile_file}\n\n"
            "ProtoGoblin will automatically apply this mode whenever the game is launched via Steam.",
        )

    def reset_tweaks_to_stock(self, silent=False, write_profile=True):
        """Disables all engine tweaks, overrides, and limiters to establish a raw baseline."""
        self.var_ue_motion_blur.set(False)
        self.var_ue_depth_of_field.set(False)
        self.var_ue_chromatic_aberration.set(False)
        self.var_ue_film_grain.set(False)
        self.var_ue_lens_flare.set(False)
        self.var_ue_volumetric_fog.set(False)
        self.var_ue_lumen.set(False)
        self.var_ue_optimize_lumen.set(False)
        self.var_ue_optimize_vsm.set(False)
        self.var_ue_optimize_nanite.set(False)
        self.var_ue_disable_vsm.set(False)

        self.var_unity_native_jobs.set(False)
        self.var_unity_disable_vr.set(False)
        self.var_unity_vulkan.set(False)
        self.var_unity_mono_gc.set(False)

        self.var_godot_vsync.set(False)
        self.var_godot_vulkan.set(False)

        self.var_cpu_pin_cores.set(False)
        self.var_mem_mimalloc.set(False)

        self.var_gfx_vsync_off.set(False)
        self.var_gfx_async_shader.set(False)
        self.var_gfx_aniso16.set(False)
        self.var_gfx_low_latency.set(False)
        self.var_gfx_descriptor_buffer.set(False)
        self.var_gfx_reflex.set(False)
        self.var_sync_ntsync.set(False)
        self.var_atelier_sync_fix.set(False)
        self.var_sync_state_dedup.set(False)
        self.var_sync_swapchain_debounce.set(False)
        self.var_sync_precision_timers.set(False)
        self.var_vkd3d_static_cbv.set(False)
        self.var_vkd3d_single_queue.set(False)
        self.var_fs_io_cache.set(False)
        self.var_compat_d3dcompiler_47.set(False)
        self.var_compat_d3dcompiler_43.set(False)
        self.var_compat_vcrun2022.set(False)
        self.var_compat_xaudio27.set(False)
        self.var_compat_d3dx9.set(False)
        self.var_gfx_max_fps.set("0")

        if write_profile:
            if self.current_manifest:
                path = self.generate_profile_toml(silent=True)
                if not silent:
                    messagebox.showinfo(
                        "Stock Baseline Set",
                        f"All overrides disabled in profile TOML:\n{path}\n\n"
                        "The game will execute in raw/unmodified stock mode for clean baseline profiling.",
                    )
            elif not silent:
                messagebox.showinfo("Reset Complete", "All tweak toggles have been reset to stock / disabled.")

    def drop_current_profile(self, prompt=True):
        """Drops the selected game's profile TOML to permit clean re-profiling after game updates."""
        if not self.current_manifest:
            if prompt:
                messagebox.showwarning("Notice", "Select a game session first to drop its profile.")
            return False

        tgt = self.current_manifest.get("target", {})
        app_id = str(tgt.get("steam_appid") or "")
        t_exe = os.path.basename((tgt.get("target_executable") or {}).get("path", "Game.exe"))
        stem = os.path.splitext(t_exe)[0]
        game_id = app_id if app_id and app_id != "unknown_game" else stem
        game_name = self.resolve_game_name(game_id)
        game_display = f"{game_name} ({game_id})"

        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        profile_file = os.path.join(xdg_config, "protogoblin", "games", f"{game_id}.toml")
        profile_exists = os.path.isfile(profile_file)

        clear_sessions = False
        if prompt:
            msg = (
                f"Drop profile for:\n\n"
                f"  {game_display}\n\n"
                f"Profile file:\n  {profile_file if profile_exists else '(Not yet written to disk)'}\n\n"
                f"This deletes the custom profile and resets all active optimization overrides.\n"
                f"ProtoGoblin will treat this title as newly installed on its next launch, "
                f"enabling clean profiling and fresh diagnostic analysis (ideal after game updates).\n\n"
                f"Do you want to proceed?"
            )
            confirm = messagebox.askyesno(
                "Drop Game Profile",
                msg,
                icon="warning",
                default="no",
            )
            if not confirm:
                return False

            clear_sessions = messagebox.askyesno(
                "Clear Historical Sessions?",
                f"Would you also like to clear historical session logs for {game_display}?\n\n"
                f"• YES: Deletes previous utilization manifests so the explorer starts completely fresh.\n"
                f"• NO: Keeps previous session logs in history for A/B comparison against the new post-update run.",
                default="no",
            )

        res = protogoblin.EngineTweakManager.drop_profile(
            game_id,
            clear_sessions=clear_sessions,
        )

        # Reset in-memory tweak UI variables without writing a new profile
        self.reset_tweaks_to_stock(silent=True, write_profile=False)

        # Refresh sessions explorer
        self.refresh_sessions()

        if prompt:
            status_msg = f"Profile successfully dropped for {game_display}!\n\n"
            if res.get("profile_deleted"):
                status_msg += f"• Deleted profile TOML:\n  {profile_file}\n"
            else:
                status_msg += "• No disk profile was present; all active tweaks have been reset to stock.\n"

            if res.get("sessions_cleared"):
                status_msg += "• Historical session manifests cleared from disk.\n"

            status_msg += "\nNext step:\nLaunch the game in Steam to establish a fresh post-update profile."
            messagebox.showinfo("Profile Dropped", status_msg)

        return True

    def _sync_profile_data_to_variables(self, prof_data):
        if not prof_data or not isinstance(prof_data, dict):
            return
        gfx = prof_data.get("graphics", {})
        sync = prof_data.get("synchronization", {})
        fs = prof_data.get("filesystem", {})
        timing = prof_data.get("timing", {})
        ue = prof_data.get("engine", {}).get("unreal", {})
        vkd3d = gfx.get("vkd3d", {})
        compat = prof_data.get("compatibility", {})
        dlls = compat.get("dll_overrides", {})
        cpu = prof_data.get("cpu", {})
        mem = prof_data.get("memory", {})
        unity = prof_data.get("engine", {}).get("unity", {})

        if "pin_performance_cores" in cpu:
            self.var_cpu_pin_cores.set(bool(cpu["pin_performance_cores"]))
        if "allocator" in mem:
            self.var_mem_mimalloc.set(str(mem["allocator"]).lower() == "mimalloc")
        elif "mimalloc" in mem:
            self.var_mem_mimalloc.set(bool(mem["mimalloc"]))
        if "mono_gc_tuning" in unity:
            self.var_unity_mono_gc.set(bool(unity["mono_gc_tuning"]))

        if "descriptor_buffer" in gfx:
            self.var_gfx_descriptor_buffer.set(bool(gfx["descriptor_buffer"]))
        if "async_shader_compile" in gfx:
            self.var_gfx_async_shader.set(bool(gfx["async_shader_compile"]))
        if "max_fps" in gfx:
            self.var_gfx_max_fps.set(str(gfx["max_fps"]))
        if "atelier_sync_fix" in sync:
            v = sync["atelier_sync_fix"]
            self.var_atelier_sync_fix.set(bool(v.get("enabled") if isinstance(v, dict) else v))
        if "state_dedup" in sync:
            v = sync["state_dedup"]
            self.var_sync_state_dedup.set(bool(v.get("enabled") if isinstance(v, dict) else v))
        if "swapchain_debounce" in sync:
            v = sync["swapchain_debounce"]
            self.var_sync_swapchain_debounce.set(bool(v.get("enabled") if isinstance(v, dict) else v))
        if "precision_timers" in timing:
            v = timing["precision_timers"]
            self.var_sync_precision_timers.set(bool(v.get("enabled") if isinstance(v, dict) else v))
        if "io_cache" in fs:
            v = fs["io_cache"]
            self.var_fs_io_cache.set(bool(v.get("enabled") if isinstance(v, dict) else v))
        if "optimize_lumen" in ue:
            self.var_ue_optimize_lumen.set(bool(ue["optimize_lumen"]))
        if "optimize_vsm" in ue:
            self.var_ue_optimize_vsm.set(bool(ue["optimize_vsm"]))
        if "single_queue" in vkd3d:
            self.var_vkd3d_single_queue.set(bool(vkd3d["single_queue"]))

        if "d3dcompiler_47" in dlls:
            self.var_compat_d3dcompiler_47.set(True)
        if "d3dcompiler_43" in dlls:
            self.var_compat_d3dcompiler_43.set(True)
        if any(k in dlls for k in ["vcrun2022", "vcruntime140", "msvcp140"]):
            self.var_compat_vcrun2022.set(True)
        if "xaudio2_7" in dlls or "xaudio27" in dlls:
            self.var_compat_xaudio27.set(True)
        if "d3dx9" in dlls or "d3dx9_43" in dlls:
            self.var_compat_d3dx9.set(True)

    def is_suggestion_enabled(self, s):
        """Checks if a recommendation is currently enabled in UI/profile variables."""
        fid = s.get("fix_id")
        if not fid:
            return self.custom_suggestion_states.get(s.get("title", ""), False)

        if fid == "enable_descriptor_buffer":
            return bool(self.var_gfx_descriptor_buffer.get())
        elif fid == "atelier_sync_fix":
            return bool(self.var_atelier_sync_fix.get())
        elif fid == "async_shader_compile":
            return bool(self.var_gfx_async_shader.get())
        elif fid == "cap_framerate":
            target = str(s.get("cap_target") or 60)
            return self.var_gfx_max_fps.get() == target
        elif fid == "state_dedup_and_debounce":
            return bool(self.var_sync_state_dedup.get() and self.var_sync_swapchain_debounce.get())
        elif fid == "enable_io_cache":
            return bool(self.var_fs_io_cache.get())
        elif fid == "enable_precision_timers":
            return bool(self.var_sync_precision_timers.get())
        elif fid == "optimize_ue5_lumen_vsm":
            return bool(self.var_ue_optimize_lumen.get() and self.var_ue_optimize_vsm.get())
        elif fid == "vkd3d_single_queue":
            return bool(self.var_vkd3d_single_queue.get())
        elif fid == "pin_performance_cores":
            return bool(self.var_cpu_pin_cores.get())
        elif fid == "unity_mono_gc_tuning":
            return bool(self.var_unity_mono_gc.get())
        elif fid == "enable_mimalloc":
            return bool(self.var_mem_mimalloc.get())
        elif fid.startswith("snag_dll_"):
            remedy = s.get("remedy") or {}
            verb = remedy.get("verb", fid.replace("snag_dll_", ""))
            var_map = {
                "d3dcompiler_47": self.var_compat_d3dcompiler_47,
                "d3dcompiler_43": self.var_compat_d3dcompiler_43,
                "vcrun2022": self.var_compat_vcrun2022,
                "xaudio27": self.var_compat_xaudio27,
                "d3dx9": self.var_compat_d3dx9,
            }
            if verb in var_map:
                return bool(var_map[verb].get())
            return False

        return self.custom_suggestion_states.get(s.get("title", ""), False)

    def set_suggestion_enabled(self, s, enabled: bool):
        """Enables or disables an optimization recommendation and syncs profile.toml."""
        fid = s.get("fix_id")
        if not fid:
            self.custom_suggestion_states[s.get("title", "")] = enabled
            self.generate_profile_toml(silent=True)
            return

        if fid == "enable_descriptor_buffer":
            self.var_gfx_descriptor_buffer.set(enabled)
        elif fid == "atelier_sync_fix":
            self.var_atelier_sync_fix.set(enabled)
            if enabled:
                self.var_gfx_vsync_off.set(True)
        elif fid == "async_shader_compile":
            self.var_gfx_async_shader.set(enabled)
        elif fid == "cap_framerate":
            target = str(s.get("cap_target") or 60)
            self.var_gfx_max_fps.set(target if enabled else "0")
        elif fid == "state_dedup_and_debounce":
            self.var_sync_state_dedup.set(enabled)
            self.var_sync_swapchain_debounce.set(enabled)
        elif fid == "enable_io_cache":
            self.var_fs_io_cache.set(enabled)
        elif fid == "enable_precision_timers":
            self.var_sync_precision_timers.set(enabled)
        elif fid == "optimize_ue5_lumen_vsm":
            self.var_ue_optimize_lumen.set(enabled)
            self.var_ue_optimize_vsm.set(enabled)
            if enabled:
                self.var_vkd3d_static_cbv.set(True)
                self.var_gfx_descriptor_buffer.set(True)
        elif fid == "vkd3d_single_queue":
            self.var_vkd3d_single_queue.set(enabled)
        elif fid == "pin_performance_cores":
            self.var_cpu_pin_cores.set(enabled)
        elif fid == "unity_mono_gc_tuning":
            self.var_unity_mono_gc.set(enabled)
        elif fid == "enable_mimalloc":
            self.var_mem_mimalloc.set(enabled)
        elif fid.startswith("snag_dll_"):
            remedy = s.get("remedy") or {}
            verb = remedy.get("verb", fid.replace("snag_dll_", ""))
            var_map = {
                "d3dcompiler_47": self.var_compat_d3dcompiler_47,
                "d3dcompiler_43": self.var_compat_d3dcompiler_43,
                "vcrun2022": self.var_compat_vcrun2022,
                "xaudio27": self.var_compat_xaudio27,
                "d3dx9": self.var_compat_d3dx9,
            }
            if verb in var_map:
                var_map[verb].set(enabled)
            if enabled:
                self.apply_suggested_fix(fid)

        self.generate_profile_toml(silent=True)

    def _on_suggestion_checkbox_toggled(self, s, cb_var):
        new_val = cb_var.get()
        self.set_suggestion_enabled(s, new_val)
        if self.current_manifest:
            self._render_manifest_data(self.current_manifest)

    def _apply_and_sync_fix(self, fix_id, extra, cb_var, s):
        self.apply_suggested_fix(fix_id, extra)
        if cb_var is not None:
            cb_var.set(True)
        if self.current_manifest:
            self._render_manifest_data(self.current_manifest)

    def open_suggestion_detail_window(self, s, cb_var=None):
        """Opens a dedicated screen to inspect and toggle an optimization recommendation."""
        win = tk.Toplevel(self.root)
        win.title(f"Recommendation: {s.get('title', 'Details')}")
        win.geometry("640x500")
        win.minsize(560, 420)
        win.configure(bg="#0d1117")
        win.transient(self.root)

        lvl = s.get("level", "info")
        border_color = (
            self.error_color
            if lvl == "error"
            else self.warning_color
            if lvl == "warning"
            else self.success_color
            if lvl == "success"
            else "#58a6ff"
        )

        header_frame = tk.Frame(win, bg="#161b22", padx=16, pady=12)
        header_frame.pack(fill=tk.X)

        lvl_badge = tk.Label(
            header_frame,
            text=f"[{lvl.upper()}] RECOMMENDATION",
            font=("Segoe UI", 9, "bold"),
            bg="#161b22",
            fg=border_color,
        )
        lvl_badge.pack(anchor=tk.W)

        title_lbl = tk.Label(
            header_frame,
            text=s.get("title", ""),
            font=("Segoe UI", 12, "bold"),
            bg="#161b22",
            fg="#f0f6fc",
            wraplength=600,
            justify=tk.LEFT,
        )
        title_lbl.pack(anchor=tk.W, pady=(4, 0))

        content_frame = tk.Frame(win, bg="#0d1117", padx=16, pady=14)
        content_frame.pack(fill=tk.BOTH, expand=True)

        desc_lbl_header = tk.Label(
            content_frame,
            text="DIAGNOSTIC ANALYSIS & ROOT CAUSE",
            font=("Segoe UI", 9, "bold"),
            bg="#0d1117",
            fg="#8b949e",
        )
        desc_lbl_header.pack(anchor=tk.W)

        desc_box = tk.Text(
            content_frame,
            height=4,
            bg="#161b22",
            fg="#c9d1d9",
            font=("Segoe UI", 9),
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=10,
            pady=8,
            highlightbackground="#30363d",
            highlightthickness=1,
        )
        desc_box.insert(tk.END, s.get("description", ""))
        desc_box.config(state=tk.DISABLED)
        desc_box.pack(fill=tk.X, pady=(4, 12))

        act_lbl_header = tk.Label(
            content_frame,
            text="RECOMMENDED ACTION",
            font=("Segoe UI", 9, "bold"),
            bg="#0d1117",
            fg="#8b949e",
        )
        act_lbl_header.pack(anchor=tk.W)

        act_box = tk.Text(
            content_frame,
            height=3,
            bg="#161b22",
            fg="#58a6ff",
            font=("Segoe UI", 9, "bold"),
            wrap=tk.WORD,
            relief=tk.FLAT,
            padx=10,
            pady=8,
            highlightbackground="#30363d",
            highlightthickness=1,
        )
        act_box.insert(tk.END, s.get("action", ""))
        act_box.config(state=tk.DISABLED)
        act_box.pack(fill=tk.X, pady=(4, 14))

        # Checkbox toggle frame
        toggle_frame = tk.Frame(
            content_frame,
            bg="#161b22",
            padx=14,
            pady=12,
            highlightbackground=border_color,
            highlightthickness=1,
        )
        toggle_frame.pack(fill=tk.X, pady=(0, 14))

        curr_state = self.is_suggestion_enabled(s)
        modal_var = tk.BooleanVar(value=curr_state)

        def on_modal_toggle():
            new_val = modal_var.get()
            self.set_suggestion_enabled(s, new_val)
            if cb_var is not None:
                cb_var.set(new_val)
            chk_modal.config(
                text="Recommendation is Active and Injected in Game Profile"
                if new_val
                else "Recommendation is Disabled (Stock Runtime)",
                fg="#39FF14" if new_val else "#8b949e",
            )
            if self.current_manifest:
                self._render_manifest_data(self.current_manifest)

        chk_modal = tk.Checkbutton(
            toggle_frame,
            text="Recommendation is Active and Injected in Game Profile"
            if curr_state
            else "Recommendation is Disabled (Stock Runtime)",
            variable=modal_var,
            command=on_modal_toggle,
            bg="#161b22",
            fg="#39FF14" if curr_state else "#8b949e",
            activebackground="#161b22",
            activeforeground="#39FF14",
            selectcolor="#0d1117",
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )
        chk_modal.pack(anchor=tk.W)

        sub_msg = tk.Label(
            toggle_frame,
            text="Checking this box writes the optimization into the per-game profile.toml, automatically active on Steam launches.",
            font=("Segoe UI", 8),
            bg="#161b22",
            fg="#8b949e",
            wraplength=560,
            justify=tk.LEFT,
        )
        sub_msg.pack(anchor=tk.W, pady=(4, 0))

        btn_row = tk.Frame(win, bg="#0d1117", padx=16, pady=10)
        btn_row.pack(fill=tk.X, side=tk.BOTTOM)

        btn_close = tk.Button(
            btn_row,
            text="Close & Save",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
            command=win.destroy,
        )
        btn_close.pack(side=tk.RIGHT)

    def apply_suggested_fix(self, fix_id, extra=None):
        if not self.current_manifest:
            messagebox.showwarning("Notice", "Select a session first to apply suggested fix.")
            return

        if fix_id == "enable_descriptor_buffer":
            self.var_gfx_descriptor_buffer.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "Vulkan Descriptor Buffers enabled (dxvk.enableDescriptorBuffer = true)!\n\n"
                "• Cuts driver descriptor allocation overhead in CPU-bound draw-call heavy workloads.\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "atelier_sync_fix":
            self.var_atelier_sync_fix.set(True)
            self.var_gfx_vsync_off.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "Gust / Atelier D3D11 Staging Buffer Sync Fix applied!\n\n"
                "• Shadow staging buffer wrapper override enabled ([synchronization.atelier_sync_fix])\n"
                "• Presentation sync forced off (dxgi.syncInterval = 0)\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "async_shader_compile":
            self.var_gfx_async_shader.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "Asynchronous Shader Compilation enabled!\n\n"
                "• DXVK_ASYNC = 1 enforced in game profile to eliminate pipeline compile stalls.\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "cap_framerate":
            cap = str(extra if extra is not None else 60)
            self.var_gfx_max_fps.set(cap)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                f"Frame Rate Cap Applied ({cap} FPS)!\n\n"
                f"• Target frame rate limiter set to {cap} FPS to eliminate frametime jitter.\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "state_dedup_and_debounce":
            self.var_sync_state_dedup.set(True)
            self.var_sync_swapchain_debounce.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "State Deduplication & SwapChain Resize Debouncing enabled!\n\n"
                "• D3D11 Constant Buffer deduplication enabled to prevent Vulkan descriptor thrashing.\n"
                "• DXGI SwapChain rapid resize debouncing enabled to eliminate UI/render-target presentation stalls.\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "enable_io_cache":
            self.var_fs_io_cache.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "Adaptive Traversal File I/O Cache enabled ([filesystem.io_cache])!\n\n"
                "• Intercepts synchronous reads on streaming archive containers (.pak, .bundle, etc.)\n"
                "• Read-ahead LRU ring buffer satisfies asset reads directly from RAM to eliminate traversal hitching.\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "enable_precision_timers":
            self.var_sync_precision_timers.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "High-Precision Sleep & Pacing Timers enabled ([timing.precision_timers])!\n\n"
                "• Intercepts Win32 Sleep/SleepEx game loop timers.\n"
                "• Enforces sub-millisecond QPC hybrid spin-sleep pacing to eliminate scheduling overshoot.\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "optimize_ue5_lumen_vsm":
            self.var_ue_optimize_lumen.set(True)
            self.var_ue_optimize_vsm.set(True)
            self.var_vkd3d_static_cbv.set(True)
            self.var_gfx_descriptor_buffer.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "Unreal Engine 5 Lumen & VSM Optimizations Applied!\n\n"
                "• Lumen Screen Probe Gather downsampled (r.Lumen.ScreenProbeGather.DownsampleByTwo 1)\n"
                "• Front-layer translucent ray reflections disabled (r.Lumen.TranslucencyReflections.FrontLayer.Allow 0)\n"
                "• Virtual Shadow Maps SMRT rays capped (r.Shadow.Virtual.SMRT.RayCountDirectional 4)\n"
                "• VKD3D descriptor buffers and static CBVs enforced\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id == "vkd3d_single_queue":
            self.var_vkd3d_single_queue.set(True)
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Fix Applied",
                "VKD3D Single Submission Queue Enabled!\n\n"
                "• Forces single submission queue (VKD3D_CONFIG=single_queue)\n"
                "• Eliminates async compute queue synchronization micro-stutter\n\n"
                f"Saved to profile:\n{path}",
            )
        elif fix_id.startswith("snag_dll_"):
            verb = fix_id.replace("snag_dll_", "")
            prefix_dir = (
                (self.current_manifest.get("environment") or {}).get("wine_prefix")
                or os.environ.get("WINEPREFIX")
                or os.environ.get("STEAM_COMPAT_DATA_PATH")
            )
            tgt = self.current_manifest.get("target", {})
            steam_id = str(tgt.get("steam_appid") or "custom-game")
            xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
            profile_file = os.path.join(xdg_config, "protogoblin", "games", f"{steam_id}.toml")

            res = protogoblin.CompatibilityFixer.snag_and_apply(
                verb=verb,
                prefix_dir=prefix_dir,
                profile_path=profile_file if os.path.isfile(profile_file) else None,
            )

            if verb == "d3dcompiler_47":
                self.var_compat_d3dcompiler_47.set(True)
            elif verb == "d3dcompiler_43":
                self.var_compat_d3dcompiler_43.set(True)
            elif verb in ["vcrun2022", "vcruntime140", "msvcp140"]:
                self.var_compat_vcrun2022.set(True)
            elif verb == "xaudio27":
                self.var_compat_xaudio27.set(True)
            elif verb == "d3dx9":
                self.var_compat_d3dx9.set(True)

            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Native DLL Deployed",
                f"Official Microsoft Native Component ({verb}) Snagged & Deployed!\n\n"
                f"• Target Component: {res.get('package', verb)}\n"
                f"• Deployed Files: {', '.join(res.get('deployed_files', [])) or 'Configured'}\n"
                f"• Overrides Configured: {res.get('overrides_added', {})}\n\n"
                f"Saved to profile:\n{path}",
            )

    def generate_profile_toml(self, silent=False):
        if not self.current_manifest:
            if not silent:
                messagebox.showwarning("Notice", "Select a session first to generate a profile.")
            return None

        tgt = self.current_manifest.get("target", {})
        t_exe = tgt.get("target_executable", {}) or {}
        steam_id = str(tgt.get("steam_appid") or "custom-game")
        t_path = os.path.basename(t_exe.get("path", "Game.exe"))

        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        profile_dir = os.path.join(xdg_config, "protogoblin", "games")
        os.makedirs(profile_dir, exist_ok=True)
        profile_file = os.path.join(profile_dir, f"{steam_id}.toml")

        eng_info = tgt.get("engine") or {}
        eng_name = eng_info.get("engine", "")

        user_tweaks = {
            "mode": self.var_profile_mode.get(),
            "atelier_sync_fix": self.var_atelier_sync_fix.get(),
            "graphics": {
                "backend": self.current_manifest.get("graphics", {}).get("active_backend", "dxvk"),
                "force_vsync": "off" if self.var_gfx_vsync_off.get() else "auto",
                "max_fps": int(self.var_gfx_max_fps.get()) if self.var_gfx_max_fps.get().isdigit() else 0,
                "anisotropic_filtering": 16 if self.var_gfx_aniso16.get() else 0,
                "async_shader_compile": self.var_gfx_async_shader.get(),
                "low_latency": self.var_gfx_low_latency.get(),
                "descriptor_buffer": self.var_gfx_descriptor_buffer.get(),
                "nv_reflex": self.var_gfx_reflex.get(),
                "vkd3d": {
                    "descriptor_buffer": self.var_gfx_descriptor_buffer.get(),
                    "force_static_cbv": self.var_vkd3d_static_cbv.get(),
                    "single_queue": self.var_vkd3d_single_queue.get(),
                },
            },
            "synchronization": {
                "ntsync": self.var_sync_ntsync.get(),
                "state_dedup": self.var_sync_state_dedup.get(),
                "swapchain_debounce": self.var_sync_swapchain_debounce.get(),
            },
            "filesystem": {
                "io_cache": self.var_fs_io_cache.get(),
            },
            "timing": {
                "precision_timers": self.var_sync_precision_timers.get(),
            },
            "compatibility": {
                "dll_overrides": {
                    **({"d3dcompiler_47": "n,b"} if getattr(self, "var_compat_d3dcompiler_47", tk.BooleanVar(value=False)).get() else {}),
                    **({"d3dcompiler_43": "n,b"} if getattr(self, "var_compat_d3dcompiler_43", tk.BooleanVar(value=False)).get() else {}),
                    **({"vcruntime140": "n,b", "msvcp140": "n,b"} if getattr(self, "var_compat_vcrun2022", tk.BooleanVar(value=False)).get() else {}),
                    **({"xaudio2_7": "n,b"} if getattr(self, "var_compat_xaudio27", tk.BooleanVar(value=False)).get() else {}),
                    **({"d3dx9_43": "n,b"} if getattr(self, "var_compat_d3dx9", tk.BooleanVar(value=False)).get() else {}),
                }
            },
            "cpu": {
                "pin_performance_cores": self.var_cpu_pin_cores.get(),
            },
            "memory": {
                "allocator": "mimalloc" if self.var_mem_mimalloc.get() else "default",
            },
        }

        if eng_name in ["unreal_4", "unreal_5", "unreal"]:
            user_tweaks["unreal"] = {
                "disable_motion_blur": self.var_ue_motion_blur.get(),
                "disable_depth_of_field": self.var_ue_depth_of_field.get(),
                "disable_chromatic_aberration": self.var_ue_chromatic_aberration.get(),
                "disable_film_grain": self.var_ue_film_grain.get(),
                "disable_lens_flare": self.var_ue_lens_flare.get(),
                "disable_bloom": self.var_ue_bloom.get() if hasattr(self, "var_ue_bloom") else False,
                "disable_volumetric_fog": self.var_ue_volumetric_fog.get(),
                "disable_lumen_reflections": self.var_ue_lumen.get(),
                "optimize_lumen": self.var_ue_optimize_lumen.get(),
                "optimize_vsm": self.var_ue_optimize_vsm.get(),
                "optimize_nanite": self.var_ue_optimize_nanite.get(),
                "disable_virtual_shadows": self.var_ue_disable_vsm.get(),
            }
        elif eng_name == "unity":
            user_tweaks["unity"] = {
                "native_gfx_jobs": self.var_unity_native_jobs.get(),
                "disable_vr": self.var_unity_disable_vr.get(),
                "force_vulkan": self.var_unity_vulkan.get(),
                "mono_gc_tuning": self.var_unity_mono_gc.get(),
            }
        elif eng_name in ["godot", "godot_3", "godot_4"]:
            user_tweaks["godot"] = {
                "rendering_driver": "vulkan" if self.var_godot_vulkan.get() else "opengl3",
                "disable_vsync": self.var_godot_vsync.get(),
                "max_fps": 0,
            }

        sync_backend = self.current_manifest.get("synchronization", {}).get("sync_backend", "ntsync")

        toml_content = protogoblin.EngineTweakManager.generate_profile_toml(
            game_id=steam_id,
            app_id=steam_id,
            target_exe=t_path,
            engine_info=eng_info,
            sync_backend=sync_backend,
            user_tweaks=user_tweaks,
        )

        try:
            with open(profile_file, "w", encoding="utf-8") as pf:
                pf.write(toml_content)
            if not silent:
                messagebox.showinfo(
                    "Profile Created",
                    f"Generated optimization profile with active engine tweaks at:\n{profile_file}",
                )
            return profile_file
        except OSError as e:
            if not silent:
                messagebox.showerror("Error", f"Failed to save profile: {e}")
            return None

    def scan_and_snag_dialog(self):
        if not self.current_manifest:
            messagebox.showwarning("Notice", "Select a session first to scan compatibility logs.")
            return

        compat = self.current_manifest.get("compatibility") or {}
        remedies = compat.get("remedies", [])
        if not remedies:
            messagebox.showinfo("Log Scan Clean", "No missing native DLL imports or stub failures detected in session logs.")
            return

        remedy_names = [f"• {r.get('dll')} ({r.get('package')})" for r in remedies]
        confirm = messagebox.askyesno(
            "Auto-Snag Missing Native DLLs",
            f"Detected {len(remedies)} missing Microsoft native component(s) in session logs:\n\n"
            + "\n".join(remedy_names)
            + "\n\nDo you want ProtoGoblin to automatically snag and deploy these official DLLs to the prefix?",
        )
        if confirm:
            prefix_dir = (
                (self.current_manifest.get("environment") or {}).get("wine_prefix")
                or os.environ.get("WINEPREFIX")
                or os.environ.get("STEAM_COMPAT_DATA_PATH")
            )
            tgt = self.current_manifest.get("target", {})
            steam_id = str(tgt.get("steam_appid") or "custom-game")
            xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
            profile_file = os.path.join(xdg_config, "protogoblin", "games", f"{steam_id}.toml")

            applied = []
            for r in remedies:
                verb = r.get("verb")
                res = protogoblin.CompatibilityFixer.snag_and_apply(
                    verb=verb,
                    prefix_dir=prefix_dir,
                    profile_path=profile_file if os.path.isfile(profile_file) else None,
                )
                applied.append(f"{r.get('dll')} ({res.get('source', 'deployed')})")
                if verb == "d3dcompiler_47":
                    self.var_compat_d3dcompiler_47.set(True)
                elif verb == "d3dcompiler_43":
                    self.var_compat_d3dcompiler_43.set(True)
                elif verb in ["vcrun2022", "vcruntime140", "msvcp140"]:
                    self.var_compat_vcrun2022.set(True)
                elif verb == "xaudio27":
                    self.var_compat_xaudio27.set(True)
                elif verb == "d3dx9":
                    self.var_compat_d3dx9.set(True)

            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "DLLs Snagged",
                f"Successfully snagged and deployed:\n\n"
                + "\n".join([f"• {a}" for a in applied])
                + f"\n\nSaved to profile:\n{path}",
            )




class GameLauncherDialog(tk.Toplevel):
    """Dialog to browse installed Steam games and profiled non-Steam games, toggle profiling, and launch."""

    def __init__(self, parent_app):
        super().__init__(parent_app.root)
        self.app = parent_app
        self.title("ProtoGoblin Game Launcher & Profiler")
        self.geometry("780x520")
        self.minsize(620, 400)
        self.configure(bg="#1e1e24")
        self.transient(parent_app.root)

        self.visible_games = []
        self._build_ui()
        self.populate_games()

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg="#18181e", height=50)
        hdr.pack(fill=tk.X, side=tk.TOP)
        lbl_title = tk.Label(
            hdr,
            text="🎮 Game Library & Launchpad",
            font=("Segoe UI", 12, "bold"),
            bg="#18181e",
            fg="#58a6ff",
        )
        lbl_title.pack(side=tk.LEFT, padx=15, pady=10)

        lbl_desc = tk.Label(
            hdr,
            text="Launch installed Steam games or profiled non-Steam games with ProtoGoblin",
            font=("Segoe UI", 9),
            bg="#18181e",
            fg="#8b949e",
        )
        lbl_desc.pack(side=tk.LEFT, padx=5, pady=12)

        # Search filter
        search_bar = tk.Frame(self, bg="#1e1e24")
        search_bar.pack(fill=tk.X, padx=15, pady=(10, 5))
        lbl_search = tk.Label(search_bar, text="🔍 Search:", bg="#1e1e24", fg="#c9d1d9", font=("Segoe UI", 9))
        lbl_search.pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.filter_games())
        entry = tk.Entry(search_bar, textvariable=self.search_var, bg="#161b22", fg="#ffffff", insertbackground="#ffffff", relief=tk.FLAT)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)

        # Games Treeview
        tree_container = tk.Frame(self, bg="#1e1e24")
        tree_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        sb = tk.Scrollbar(tree_container)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            tree_container,
            columns=("type", "title", "id_exe", "mode"),
            show="headings",
            selectmode="browse",
            yscrollcommand=sb.set,
        )
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.config(command=self.tree.yview)

        self.tree.heading("type", text="Type", anchor=tk.W)
        self.tree.heading("title", text="Game Title", anchor=tk.W)
        self.tree.heading("id_exe", text="AppID / Target Binary", anchor=tk.W)
        self.tree.heading("mode", text="Profiling Mode", anchor=tk.W)

        self.tree.column("type", width=100, minwidth=80)
        self.tree.column("title", width=280, minwidth=180)
        self.tree.column("id_exe", width=200, minwidth=140)
        self.tree.column("mode", width=140, minwidth=110)

        self.tree.bind("<Double-1>", lambda e: self.on_launch_clicked())
        self.tree.bind("<<TreeviewSelect>>", self.on_select_changed)

        # Action Buttons footer
        btn_bar = tk.Frame(self, bg="#18181e", height=50)
        btn_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.btn_toggle_dialog_mode = tk.Button(
            btn_bar,
            text="🎯 Toggle Profiling Mode",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.on_toggle_mode_clicked,
        )
        self.btn_toggle_dialog_mode.pack(side=tk.LEFT, padx=15, pady=10)

        btn_cancel = tk.Button(
            btn_bar,
            text="Close",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.destroy,
        )
        btn_cancel.pack(side=tk.RIGHT, padx=15, pady=10)

        self.btn_dialog_launch = tk.Button(
            btn_bar,
            text="🚀 Launch Game",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            command=self.on_launch_clicked,
        )
        self.btn_dialog_launch.pack(side=tk.RIGHT, padx=5, pady=10)

    def populate_games(self):
        self.all_games = []
        steam_games = self.app.get_installed_steam_games()
        for g in steam_games:
            app_id = g["app_id"]
            curr_mode = self.app.get_game_profile_mode(app_id)
            self.all_games.append({
                "type": "🎮 Steam",
                "title": g["name"],
                "id_exe": f"AppID {app_id}",
                "app_id": app_id,
                "target_exe": None,
                "prefix_dir": None,
                "argv": [],
                "mode": curr_mode,
                "is_steam": True,
            })

        non_steam = self.app.get_profiled_non_steam_games()
        for g in non_steam:
            app_id = g["app_id"]
            curr_mode = self.app.get_game_profile_mode(app_id)
            t_name = os.path.basename(g["target_exe"]) if g.get("target_exe") else app_id
            self.all_games.append({
                "type": "📦 Non-Steam",
                "title": g["name"],
                "id_exe": t_name,
                "app_id": app_id,
                "target_exe": g.get("target_exe"),
                "prefix_dir": g.get("prefix_dir"),
                "argv": g.get("argv", []),
                "mode": curr_mode,
                "is_steam": False,
            })

        self.filter_games()

    def filter_games(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        q = self.search_var.get().lower().strip()
        self.visible_games = []

        for idx, g in enumerate(self.all_games):
            if q:
                if q not in g["title"].lower() and q not in str(g["app_id"]).lower() and q not in g["id_exe"].lower():
                    continue
            self.visible_games.append(g)
            v_idx = len(self.visible_games) - 1
            mode_badge = "🎯 PROFILE" if g["mode"] == "profile" else "⚪ PLAY"
            self.tree.insert(
                "",
                "end",
                iid=str(v_idx),
                values=(g["type"], g["title"], g["id_exe"], mode_badge),
            )

        if self.visible_games:
            self.tree.selection_set("0")
            self.tree.focus("0")
            self.on_select_changed()

    def on_select_changed(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        game = self.visible_games[idx]
        mode_text = "Switch to PLAY (Optimizations Only)" if game["mode"] == "profile" else "Switch to PROFILE (Telemetry & HUD)"
        self.btn_toggle_dialog_mode.config(text=f"🎯 {mode_text}")
        self.btn_dialog_launch.config(text=f"🚀 Launch {game['title'][:18]}")

    def on_toggle_mode_clicked(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        game = self.visible_games[idx]
        new_mode = "play" if game["mode"] == "profile" else "profile"
        self.app.set_game_profile_mode(game["app_id"], new_mode, target_exe=game.get("target_exe"))
        game["mode"] = new_mode

        mode_badge = "🎯 PROFILE" if new_mode == "profile" else "⚪ PLAY"
        self.tree.item(str(idx), values=(game["type"], game["title"], game["id_exe"], mode_badge))
        self.on_select_changed()
        self.app.set_status(f"Updated {game['title']} profiling mode to: {mode_badge}", fg="#39FF14" if new_mode == "profile" else "#58a6ff")

        if self.app.current_manifest:
            curr_app_id = str((self.app.current_manifest.get("target") or {}).get("steam_appid") or "")
            if curr_app_id == str(game["app_id"]):
                self.app.var_profile_mode.set(new_mode)
                self.app._update_header_mode_button(new_mode)

    def on_launch_clicked(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        game = self.visible_games[idx]
        self.destroy()
        self.app.launch_game(
            app_id=game["app_id"],
            target_exe=game.get("target_exe"),
            prefix_dir=game.get("prefix_dir"),
            argv=game.get("argv"),
            game_name=game["title"],
        )


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ProtoGoblin Command - Graphical Optimization & Diagnostic Dashboard"
    )
    parser.add_argument("--session", dest="session_id", default=None, help="Initial session ID or AppID to select")
    parser.add_argument("--drop-profile", dest="drop_appid", default=None, help="Drop/delete the profile for the given AppID so the game can be re-profiled")
    parser.add_argument("--clear-sessions", dest="clear_sessions", action="store_true", help="When dropping profile, also clear historical session manifests")
    args, _ = parser.parse_known_args()

    if args.drop_appid:
        res = protogoblin.EngineTweakManager.drop_profile(args.drop_appid, clear_sessions=args.clear_sessions)
        if res.get("profile_deleted"):
            print(f"[ProtoGoblin] Successfully dropped profile for {args.drop_appid}: {res.get('profile_path')}")
        else:
            print(f"[ProtoGoblin] No profile file existed on disk for {args.drop_appid} ({res.get('profile_path')}).")
        if res.get("sessions_cleared"):
            print(f"[ProtoGoblin] Cleared historical sessions: {res.get('sessions_dir')}")
        print(f"[ProtoGoblin] Game {args.drop_appid} is ready for clean re-profiling on next launch.")
        return

    root = tk.Tk()
    app = ProtoGoblinCommandApp(root, initial_session_id=args.session_id)
    root.mainloop()


if __name__ == "__main__":
    main()
