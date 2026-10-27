#!/usr/bin/env python3
"""
ProtoGoblin Command - Graphical Optimization & Diagnostic Dashboard
"""

import glob
import json
import os
import platform
import sys
import tkinter as tk
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, simpledialog, ttk

# Ensure local modules can be loaded
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import protogoblin


class DiagnosticAdvisor:
    """Evaluates session manifests and generates actionable recommendations and fixes."""

    @staticmethod
    def analyze(manifest):
        if not manifest:
            return []

        suggestions = []
        sync = manifest.get("synchronization", {})
        gfx = manifest.get("graphics", {})
        roi = manifest.get("roi_telemetry")
        ac = manifest.get("anti_cheat", {})
        env = manifest.get("environment", {})
        sub = manifest.get("subsystems", {})
        tgt = manifest.get("target", {})

        # 1. Anti-Cheat Passthrough
        if ac.get("detected"):
            provider = ac.get("provider", "Anti-Cheat")
            suggestions.append(
                {
                    "level": "warning",
                    "title": f"Anti-Cheat Active ({provider})",
                    "description": f"Game is protected by {provider}. Zero-injection passthrough mode is enforced. Do not apply in-process Detours/shims or invasive binary patches to prevent disconnection or bans.",
                    "action": "Ensure anticheat_policy = 'passthrough' in game profile.",
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
        sh = gfx.get("shader_compiles", {})
        count = sh.get("count", 0)
        time_ms = sh.get("total_time_ms", 0.0)
        hit_rate = sh.get("pipeline_cache_hit_rate", 1.0)
        if count > 50 and time_ms > 200:
            suggestions.append(
                {
                    "level": "warning",
                    "title": "Shader Compilation Stuttering Observed",
                    "description": f"{count} pipelines compiled during session taking {time_ms:.1f}ms total. Pipeline cache hit rate was {hit_rate:.1%}.",
                    "action": "Enable local shader caching (PROTON_LOCAL_SHADER_CACHE=1) or asynchronous compilation (DXVK_ASYNC=1) to prevent gameplay hitching.",
                    "fix_id": "async_shader_compile",
                    "fix_button_text": "⚡ Enable Async Shader Compilation",
                }
            )

        # 4. Bottleneck & CPU Core Pinning
        if roi and roi.get("roi_enabled"):
            b_class = roi.get("bottleneck_classification")
            fm = roi.get("frame_metrics") or {}
            pacing = roi.get("pacing") or {}
            cores = env.get("cpu", {}).get("logical_cores", 1)

            if b_class == "cpu_bound":
                if cores >= 12:
                    suggestions.append(
                        {
                            "level": "info",
                            "title": "CPU-Bound Workload on High-Core CPU",
                            "description": f"Session CPU load reached {pacing.get('cpu_busy_pct', 0)}% while GPU was underutilized. On multi-CCD processors (e.g. AMD Ryzen 9 / X3D), cross-CCD cache latency degrades performance.",
                            "action": "Pin game threads to the high-cache CCD using PROTON_CPU_TOPOLOGY or taskset in your game profile.",
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
        if eng_name in ["unreal_4", "unreal_5"]:
            ver_label = "Unreal Engine 5" if eng_name == "unreal_5" else "Unreal Engine 4"
            suggestions.append(
                {
                    "level": "info",
                    "title": f"{ver_label} Optimization Profile Available",
                    "description": f"Game runs on {ver_label}. ProtoGoblin can tune internal Scalability/Engine.ini variables (e.g. r.Nanite, r.Lumen, r.ScreenPercentage) and apply DXVK asynchronous pipeline compilation.",
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

        return suggestions


def compute_session_diff(manifest_a, manifest_b):
    """Computes an A/B delta comparison between two ProtoGoblin session manifests.

    manifest_a: Baseline session (e.g. before / raw / unoptimized)
    manifest_b: Target session (e.g. after / tweaked / optimized)
    """
    sess_a = manifest_a.get("session") or {}
    sess_b = manifest_b.get("session") or {}
    tgt_a = manifest_a.get("target") or {}
    tgt_b = manifest_b.get("target") or {}
    t_exe_a = os.path.basename((tgt_a.get("target_executable") or {}).get("path", "Unknown"))
    t_exe_b = os.path.basename((tgt_b.get("target_executable") or {}).get("path", "Unknown"))
    app_id_a = tgt_a.get("steam_appid") or "-"
    app_id_b = tgt_b.get("steam_appid") or "-"

    roi_a = manifest_a.get("roi_telemetry") or manifest_a.get("roi") or {}
    roi_b = manifest_b.get("roi_telemetry") or manifest_b.get("roi") or {}

    has_roi_a = bool(roi_a.get("roi_enabled") and roi_a.get("frame_metrics"))
    has_roi_b = bool(roi_b.get("roi_enabled") and roi_b.get("frame_metrics"))

    fm_a = roi_a.get("frame_metrics") or {}
    fm_b = roi_b.get("frame_metrics") or {}
    pacing_a = roi_a.get("pacing") or {}
    pacing_b = roi_b.get("pacing") or {}

    def _delta(a_val, b_val):
        a_f = float(a_val or 0.0)
        b_f = float(b_val or 0.0)
        diff = b_f - a_f
        pct = (diff / a_f * 100.0) if a_f > 0 else 0.0
        return round(diff, 2), round(pct, 1)

    diff_fps_avg, pct_fps_avg = _delta(fm_a.get("fps_avg"), fm_b.get("fps_avg"))
    diff_fps_1p, pct_fps_1p = _delta(fm_a.get("fps_1_pct_low"), fm_b.get("fps_1_pct_low"))
    diff_fps_01p, pct_fps_01p = _delta(fm_a.get("fps_0_1_pct_low"), fm_b.get("fps_0_1_pct_low"))
    diff_ft_avg, pct_ft_avg = _delta(fm_a.get("frametime_avg_ms"), fm_b.get("frametime_avg_ms"))
    diff_jitter, pct_jitter = _delta(fm_a.get("frametime_jitter_ms"), fm_b.get("frametime_jitter_ms"))

    bot_a = roi_a.get("bottleneck_classification", "unknown")
    bot_b = roi_b.get("bottleneck_classification", "unknown")

    cpu_busy_a = float(pacing_a.get("cpu_busy_pct", 0.0))
    cpu_busy_b = float(pacing_b.get("cpu_busy_pct", 0.0))
    cpu_wait_a = float(pacing_a.get("cpu_wait_pct", 0.0))
    cpu_wait_b = float(pacing_b.get("cpu_wait_pct", 0.0))
    gpu_busy_a = float(pacing_a.get("gpu_busy_pct", 0.0))
    gpu_busy_b = float(pacing_b.get("gpu_busy_pct", 0.0))

    # Determine verdict and qualitative notes
    verdict = "NEUTRAL"
    notes = []
    if pct_fps_avg >= 5.0 or pct_fps_1p >= 10.0 or (float(fm_a.get("frametime_jitter_ms", 0)) > 5.0 and pct_jitter <= -20.0):
        verdict = "IMPROVED"
        if pct_fps_avg >= 5.0:
            notes.append(f"Average FPS +{pct_fps_avg:.1f}% ({fm_a.get('fps_avg', 0):.1f} -> {fm_b.get('fps_avg', 0):.1f})")
        if pct_fps_1p >= 10.0:
            notes.append(f"1% lows +{pct_fps_1p:.1f}% ({fm_a.get('fps_1_pct_low', 0):.1f} -> {fm_b.get('fps_1_pct_low', 0):.1f})")
        if pct_jitter <= -20.0:
            notes.append(f"Frametime jitter {pct_jitter:.1f}% ({fm_a.get('frametime_jitter_ms', 0):.2f}ms -> {fm_b.get('frametime_jitter_ms', 0):.2f}ms)")
    elif pct_fps_avg <= -5.0 or pct_fps_1p <= -10.0:
        verdict = "REGRESSED"
        if pct_fps_avg <= -5.0:
            notes.append(f"Average FPS {pct_fps_avg:.1f}% ({fm_a.get('fps_avg', 0):.1f} -> {fm_b.get('fps_avg', 0):.1f})")
        if pct_fps_1p <= -10.0:
            notes.append(f"1% lows {pct_fps_1p:.1f}% ({fm_a.get('fps_1_pct_low', 0):.1f} -> {fm_b.get('fps_1_pct_low', 0):.1f})")

    if bot_a == "sync_bound" and bot_b in ["gpu_bound", "balanced"]:
        notes.append(f"Sync lockstep stall resolved ({bot_a} -> {bot_b})")

    diff_result = {
        "session_a": {
            "id": sess_a.get("id", "Session A"),
            "target_exe": t_exe_a,
            "steam_appid": app_id_a,
            "mode": sess_a.get("mode", "play"),
            "has_roi": has_roi_a,
            "bottleneck": bot_a,
        },
        "session_b": {
            "id": sess_b.get("id", "Session B"),
            "target_exe": t_exe_b,
            "steam_appid": app_id_b,
            "mode": sess_b.get("mode", "play"),
            "has_roi": has_roi_b,
            "bottleneck": bot_b,
        },
        "metrics": {
            "fps_avg": {"a": fm_a.get("fps_avg", 0.0), "b": fm_b.get("fps_avg", 0.0), "delta": diff_fps_avg, "pct": pct_fps_avg},
            "fps_1_pct_low": {"a": fm_a.get("fps_1_pct_low", 0.0), "b": fm_b.get("fps_1_pct_low", 0.0), "delta": diff_fps_1p, "pct": pct_fps_1p},
            "fps_0_1_pct_low": {"a": fm_a.get("fps_0_1_pct_low", 0.0), "b": fm_b.get("fps_0_1_pct_low", 0.0), "delta": diff_fps_01p, "pct": pct_fps_01p},
            "frametime_avg_ms": {"a": fm_a.get("frametime_avg_ms", 0.0), "b": fm_b.get("frametime_avg_ms", 0.0), "delta": diff_ft_avg, "pct": pct_ft_avg},
            "frametime_jitter_ms": {"a": fm_a.get("frametime_jitter_ms", 0.0), "b": fm_b.get("frametime_jitter_ms", 0.0), "delta": diff_jitter, "pct": pct_jitter},
        },
        "bottleneck": {
            "a": bot_a,
            "b": bot_b,
            "transition": f"{bot_a} -> {bot_b}",
            "resolved": (bot_a == "sync_bound" and bot_b in ["gpu_bound", "balanced"]),
        },
        "hardware": {
            "cpu_busy_pct": {"a": cpu_busy_a, "b": cpu_busy_b, "delta": round(cpu_busy_b - cpu_busy_a, 1)},
            "cpu_wait_pct": {"a": cpu_wait_a, "b": cpu_wait_b, "delta": round(cpu_wait_b - cpu_wait_a, 1)},
            "gpu_busy_pct": {"a": gpu_busy_a, "b": gpu_busy_b, "delta": round(gpu_busy_b - gpu_busy_a, 1)},
        },
        "verdict": verdict,
        "notes": notes,
        "summary": "; ".join(notes) if notes else "Performance metrics comparable.",
    }
    return diff_result


def format_diff_report(diff):
    """Formats an A/B session comparison dict into a clean human-readable ASCII report."""
    s_a = diff["session_a"]
    s_b = diff["session_b"]
    m = diff["metrics"]
    bot = diff["bottleneck"]
    hw = diff["hardware"]

    v_icon = "🚀 " if diff["verdict"] == "IMPROVED" else ("⚠️ " if diff["verdict"] == "REGRESSED" else "⚖️ ")
    verdict_str = f"{v_icon}{diff['verdict']}: {diff['summary']}"

    lines = [
        "=" * 82,
        " PROTOGOBLIN A/B SESSION COMPARISON & REGRESSION DIFF",
        "=" * 82,
        f" Baseline Session (A - Before):  {s_a['id']} [{s_a['mode'].upper()}] - {s_a['target_exe']} ({s_a['steam_appid']})",
        f" Target   Session (B - After):   {s_b['id']} [{s_b['mode'].upper()}] - {s_b['target_exe']} ({s_b['steam_appid']})",
        f" Comparison Verdict:            {verdict_str}",
        "=" * 82,
        "",
    ]

    if not s_a.get("has_roi") or not s_b.get("has_roi"):
        lines.extend([
            " [!] NOTICE: One or both sessions were executed in PLAY mode without ROI telemetry.",
            "     Detailed frame percentiles and jitter require sessions launched with:",
            "       PROTOGOBLIN_MODE=profile %command%",
            "",
        ])

    lines.extend([
        " FRAMETIME & PACING BENCHMARK",
        "-" * 82,
        f" {'Metric':<28} {'Session A (Before)':<20} {'Session B (After)':<20} {'Delta':<14}",
        "-" * 82,
    ])

    def _fmt_row(title, metric_dict, unit, higher_is_better=True):
        a_val = float(metric_dict.get("a") or 0.0)
        b_val = float(metric_dict.get("b") or 0.0)
        delta = float(metric_dict.get("delta") or 0.0)
        pct = float(metric_dict.get("pct") or 0.0)
        sign = "+" if delta > 0 else ""
        arrow = "▲" if ((delta > 0 and higher_is_better) or (delta < 0 and not higher_is_better)) else ("▼" if delta != 0 else "=")
        a_str = f"{a_val:.1f} {unit}"
        b_str = f"{b_val:.1f} {unit}"
        d_str = f"{sign}{delta:.1f} {unit} ({sign}{pct:.1f}%) {arrow}"
        return f" {title:<28} {a_str:<20} {b_str:<20} {d_str:<14}"

    lines.append(_fmt_row("Average Framerate:", m["fps_avg"], "FPS", higher_is_better=True))
    lines.append(_fmt_row("1% Low Framerate:", m["fps_1_pct_low"], "FPS", higher_is_better=True))
    lines.append(_fmt_row("0.1% Low Framerate:", m["fps_0_1_pct_low"], "FPS", higher_is_better=True))
    lines.append(_fmt_row("Average Frametime:", m["frametime_avg_ms"], "ms", higher_is_better=False))
    lines.append(_fmt_row("Frametime Jitter (StdDev):", m["frametime_jitter_ms"], "ms", higher_is_better=False))

    bot_res_str = " (Stall Resolved!)" if bot["resolved"] else ""
    lines.extend([
        f" {'Bottleneck Classification:':<28} {s_a['bottleneck'].upper():<20} {s_b['bottleneck'].upper():<20} {bot['transition']}{bot_res_str}",
        "",
        " HARDWARE RESOURCE ALLOCATION",
        "-" * 82,
        f" {'Component':<28} {'Session A (Before)':<20} {'Session B (After)':<20} {'Shift':<14}",
        "-" * 82,
    ])

    for comp_name, key in [("CPU Busy Utilization:", "cpu_busy_pct"), ("CPU Wait / Blocked:", "cpu_wait_pct"), ("GPU Busy Utilization:", "gpu_busy_pct")]:
        h_data = hw[key]
        a_str = f"{h_data['a']:.1f}%"
        b_str = f"{h_data['b']:.1f}%"
        s = "+" if h_data['delta'] > 0 else ""
        d_str = f"{s}{h_data['delta']:.1f}%"
        lines.append(f" {comp_name:<28} {a_str:<20} {b_str:<20} {d_str:<14}")

    lines.extend(["=" * 82, ""])
    return "\n".join(lines)


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

    def __init__(self, root, initial_session_id=None):
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
        self.initial_session_id = initial_session_id

        self._build_ui()
        if self.initial_session_id:
            self.search_var.set(self.initial_session_id)
        self.refresh_sessions()

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

        # Main Content Panes
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.bg_color, sashrelief=tk.FLAT)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

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

        # Sessions Listbox with scrollbar
        list_container = tk.Frame(left_frame, bg=self.card_bg)
        list_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        scrollbar = tk.Scrollbar(list_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.sessions_listbox = tk.Listbox(
            list_container,
            bg="#161b22",
            fg="#c9d1d9",
            selectbackground="#1f6feb",
            selectforeground="#ffffff",
            relief=tk.FLAT,
            font=("Consolas", 9),
            yscrollcommand=scrollbar.set,
        )
        self.sessions_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.sessions_listbox.yview)

        self.sessions_listbox.bind("<<ListboxSelect>>", self.on_session_selected)

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
            text="Profile Mode - Active 'Goblin-ing' HUD overlay, frametime variance, 1% lows, and hardware load telemetry recorded.",
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

        ue_checks = [
            ("Disable Motion Blur (r.MotionBlurQuality 0, r.MotionBlur.Max 0)", self.var_ue_motion_blur),
            ("Disable Depth of Field (r.DepthOfFieldQuality 0)", self.var_ue_depth_of_field),
            ("Disable Chromatic Aberration (r.SceneColorFringeQuality 0)", self.var_ue_chromatic_aberration),
            ("Disable Film Grain (r.FilmGrain 0)", self.var_ue_film_grain),
            ("Disable Lens Flare (r.LensFlareQuality 0)", self.var_ue_lens_flare),
            ("Disable Volumetric Fog (r.VolumetricFog 0)", self.var_ue_volumetric_fog),
            ("Disable Lumen Reflections (r.Lumen.Reflections.Allow 0)", self.var_ue_lumen),
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
        self.var_godot_vsync = tk.BooleanVar(value=True)
        self.var_godot_vulkan = tk.BooleanVar(value=True)

        other_checks = [
            ("Unity: Force Native Gfx Jobs (gfx-enable-native-gfx-jobs=1 in boot.config)", self.var_unity_native_jobs),
            ("Unity: Disable Unused VR Subsystem (vr-enabled=0 in boot.config)", self.var_unity_disable_vr),
            ("Unity: Force Vulkan Backend (-force-vulkan)", self.var_unity_vulkan),
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
        self.var_gfx_max_fps = tk.StringVar(value="0")

        dxvk_checks = [
            ("Force VSync Off (dxgi.syncInterval = 0 for minimum presentation latency)", self.var_gfx_vsync_off),
            ("Asynchronous Shader Compilation (DXVK_ASYNC=1 to prevent stutter)", self.var_gfx_async_shader),
            ("Force 16x Anisotropic Filtering (d3d11.samplerAnisotropy = 16)", self.var_gfx_aniso16),
            ("Vulkan Descriptor Buffers (dxvk.enableDescriptorBuffer = true for DXVK 2.7+)", self.var_gfx_descriptor_buffer),
            ("Nvidia Reflex Low-Latency Queueing (dxvk.nvLowLatency2 = true)", self.var_gfx_reflex),
            ("Kernel Fast-Path NT Synchronization (ntsync)", self.var_sync_ntsync),
            ("Gust / Atelier D3D11 Staging Buffer Sync Fix (Shadow staging wrapper override)", self.var_atelier_sync_fix),
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

    def refresh_sessions(self):
        """Scans for all utilization.json files across ProtoGoblin sessions."""
        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        base = os.path.join(xdg_data, "protogoblin", "sessions")

        pattern = os.path.join(base, "*", "*", "utilization.json")
        self.manifest_paths = glob.glob(pattern)
        self.manifest_paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)

        self._filter_session_list()

    def _filter_session_list(self):
        self.sessions_listbox.delete(0, tk.END)
        query = self.search_var.get().lower().strip()
        self.filtered_manifest_paths = []
        self.diff_session_labels = []

        for idx, path in enumerate(self.manifest_paths):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sess = data.get("session", {})
                tgt = data.get("target", {})
                t_exe = os.path.basename(tgt.get("target_executable", {}).get("path", "Unknown"))
                app_id = tgt.get("steam_appid") or "-"
                mode = sess.get("mode", "play").upper()
                sess_id = sess.get("id", f"sess_{idx}")

                display = f"[{mode:<7}] {t_exe:<18} ({app_id})"
                if not query or query in display.lower() or query in path.lower():
                    self.sessions_listbox.insert(tk.END, display)
                    self.filtered_manifest_paths.append(path)
                    self.diff_session_labels.append(f"[{mode}] {t_exe} ({sess_id[:16]})")
            except Exception:
                continue

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

        if self.sessions_listbox.size() > 0:
            self.sessions_listbox.select_set(0)
            self.on_session_selected(None)

    def on_session_selected(self, event):
        sel = self.sessions_listbox.curselection()
        if not sel:
            return

        idx = sel[0]
        paths = getattr(self, "filtered_manifest_paths", self.manifest_paths)
        if idx < len(paths):
            path = paths[idx]
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.current_manifest = json.load(f)
                self._render_manifest_data(self.current_manifest, path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load manifest: {e}")

        if hasattr(self, "combo_session_b") and idx < len(paths):
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

    def _render_manifest_data(self, data, path):
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
        self.diag_header_lbl.config(
            text=f"Target: {t_name}{eng_tag} | Mode: {sess.get('mode', 'play').upper()} | Session: {sess.get('id')}"
        )
        if hasattr(self, "tweaks_game_lbl"):
            self.tweaks_game_lbl.config(
                text=f"Active Game: {t_name} (AppID: {tgt.get('steam_appid') or '-'}, Engine: {eng_name})"
            )

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
                )
                card_frame.pack(fill=tk.X, pady=6)

                lbl_t = tk.Label(
                    card_frame,
                    text=s["title"],
                    font=("Segoe UI", 10, "bold"),
                    bg="#161b22",
                    fg=border_color,
                    anchor=tk.W,
                )
                lbl_t.pack(fill=tk.X)

                lbl_d = tk.Label(
                    card_frame,
                    text=s["description"],
                    font=("Segoe UI", 9),
                    bg="#161b22",
                    fg="#c9d1d9",
                    wraplength=580,
                    justify=tk.LEFT,
                    anchor=tk.W,
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
                )
                lbl_a.pack(fill=tk.X)

                if s.get("fix_id"):
                    fix_id = s["fix_id"]
                    extra = s.get("cap_target")
                    btn_fix = tk.Button(
                        card_frame,
                        text=s.get("fix_button_text", "⚡ Apply Suggested Fix"),
                        bg="#238636",
                        fg="#ffffff",
                        activebackground="#2ea043",
                        activeforeground="#ffffff",
                        font=("Segoe UI", 9, "bold"),
                        relief=tk.FLAT,
                        padx=10,
                        pady=4,
                        command=lambda fid=fix_id, ext=extra: self.apply_suggested_fix(fid, ext),
                    )
                    btn_fix.pack(anchor=tk.W, pady=(8, 2))

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
                    f"Bottleneck Status:    {roi.get('bottleneck_classification', 'balanced').upper()}",
                    f"Average Framerate:    {fm.get('fps_avg', 0):.1f} FPS",
                    f"1% Low Framerate:     {fm.get('fps_1_pct_low', 0):.1f} FPS",
                    f"0.1% Low Framerate:   {fm.get('fps_0_1_pct_low', 0):.1f} FPS",
                    f"Average Frametime:    {fm.get('frametime_avg_ms', 0):.2f} ms",
                    f"Frametime Percentiles:p95 = {fm.get('frametime_p95_ms', 0)} ms | p99 = {fm.get('frametime_p99_ms', 0)} ms",
                    f"Frametime Jitter:     {fm.get('frametime_jitter_ms', 0):.2f} ms (StdDev)",
                    f"Total Frames Scanned: {fm.get('total_frames', 0):,}",
                    "",
                    "HARDWARE RESOURCE ALLOCATION",
                    "-" * 60,
                    f"CPU Busy Utilization: {pacing.get('cpu_busy_pct', 0)}%",
                    f"CPU Wait/Blocked:     {pacing.get('cpu_wait_pct', 0)}%",
                    f"GPU Busy Utilization: {pacing.get('gpu_busy_pct', 0)}%",
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
            f"PE Timestamp:         {t_exe.get('pe_timestamp', 'None')}",
            f"PE Size of Image:     {t_exe.get('pe_size_of_image', 0):,} bytes",
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
                f"Shader Pipelines:     {gfx.get('shader_compiles', {}).get('count', 0)} compiled ({gfx.get('shader_compiles', {}).get('total_time_ms', 0):.1f} ms)",
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
            f"PE Size of Image: {pe.get('pe_size_of_image', 0):,} bytes\n\n"
            f"Anti-Cheat Detected: {'YES (' + ac.get('provider') + ')' if ac.get('detected') else 'Clean (None)'}"
        )
        messagebox.showinfo("PE Binary Inspection", msg)

    def _update_header_mode_button(self, mode):
        if mode == "profile":
            self.btn_toggle_mode.config(
                text="🎯 Profiling: ON (Goblin-ing)",
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
            "Profile Mode (Active 'Goblin-ing' HUD overlay and telemetry recording)"
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
            "Would you like to ENABLE Profiling Mode ('Goblin-ing' HUD + Telemetry) for this game?\n\n"
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

    def reset_tweaks_to_stock(self):
        """Disables all engine tweaks, overrides, and limiters to establish a raw baseline."""
        self.var_ue_motion_blur.set(False)
        self.var_ue_depth_of_field.set(False)
        self.var_ue_chromatic_aberration.set(False)
        self.var_ue_film_grain.set(False)
        self.var_ue_lens_flare.set(False)
        self.var_ue_volumetric_fog.set(False)
        self.var_ue_lumen.set(False)

        self.var_unity_native_jobs.set(False)
        self.var_unity_disable_vr.set(False)
        self.var_unity_vulkan.set(False)

        self.var_godot_vsync.set(False)
        self.var_godot_vulkan.set(False)

        self.var_gfx_vsync_off.set(False)
        self.var_gfx_async_shader.set(False)
        self.var_gfx_aniso16.set(False)
        self.var_gfx_low_latency.set(False)
        self.var_gfx_descriptor_buffer.set(False)
        self.var_gfx_reflex.set(False)
        self.var_sync_ntsync.set(False)
        self.var_atelier_sync_fix.set(False)
        self.var_gfx_max_fps.set("0")

        if self.current_manifest:
            path = self.generate_profile_toml(silent=True)
            messagebox.showinfo(
                "Stock Baseline Set",
                f"All overrides disabled in profile TOML:\n{path}\n\n"
                "The game will execute in raw/unmodified stock mode for clean baseline profiling.",
            )
        else:
            messagebox.showinfo("Reset Complete", "All tweak toggles have been reset to stock / disabled.")

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

        user_tweaks = {
            "mode": self.var_profile_mode.get(),
            "atelier_sync_fix": self.var_atelier_sync_fix.get(),
            "unreal": {
                "disable_motion_blur": self.var_ue_motion_blur.get(),
                "disable_depth_of_field": self.var_ue_depth_of_field.get(),
                "disable_chromatic_aberration": self.var_ue_chromatic_aberration.get(),
                "disable_film_grain": self.var_ue_film_grain.get(),
                "disable_lens_flare": self.var_ue_lens_flare.get(),
                "disable_bloom": self.var_ue_bloom.get() if hasattr(self, "var_ue_bloom") else False,
                "disable_volumetric_fog": self.var_ue_volumetric_fog.get(),
                "disable_lumen_reflections": self.var_ue_lumen.get(),
            },
            "unity": {
                "native_gfx_jobs": self.var_unity_native_jobs.get(),
                "disable_vr": self.var_unity_disable_vr.get(),
                "force_vulkan": self.var_unity_vulkan.get(),
            },
            "godot": {
                "rendering_driver": "vulkan" if self.var_godot_vulkan.get() else "opengl3",
                "disable_vsync": self.var_godot_vsync.get(),
                "max_fps": 0,
            },
            "graphics": {
                "backend": self.current_manifest.get("graphics", {}).get("active_backend", "dxvk"),
                "force_vsync": "off" if self.var_gfx_vsync_off.get() else "auto",
                "max_fps": int(self.var_gfx_max_fps.get()) if self.var_gfx_max_fps.get().isdigit() else 0,
                "anisotropic_filtering": 16 if self.var_gfx_aniso16.get() else 0,
                "async_shader_compile": self.var_gfx_async_shader.get(),
                "low_latency": self.var_gfx_low_latency.get(),
                "descriptor_buffer": self.var_gfx_descriptor_buffer.get(),
                "nv_reflex": self.var_gfx_reflex.get(),
            },
            "synchronization": {
                "ntsync": self.var_sync_ntsync.get(),
            },
        }

        eng_info = tgt.get("engine") or {}
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


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ProtoGoblin Command - Graphical Optimization & Diagnostic Dashboard"
    )
    parser.add_argument("--session", dest="session_id", default=None, help="Initial session ID or AppID to select")
    args, _ = parser.parse_known_args()

    root = tk.Tk()
    app = ProtoGoblinCommandApp(root, initial_session_id=args.session_id)
    root.mainloop()


if __name__ == "__main__":
    main()
