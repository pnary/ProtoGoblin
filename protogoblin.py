#!/usr/bin/env python3
"""
ProtoGoblin - Session Manager & Introspective Telemetry Engine
Phase 0: Process-Tree Tracking, Anti-Cheat Pre-Flight, and Tier-1 Manifest Generation
"""

import csv
import hashlib
import json
import os
import platform
import re
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


class PEInfo:
    """Helper to inspect Windows PE binaries without external dependencies."""

    @staticmethod
    def inspect(file_path):
        if not file_path or not os.path.isfile(file_path):
            return None

        result = {
            "path": file_path,
            "sha256": None,
            "arch": "unknown",
            "pe_timestamp": None,
            "pe_size_of_image": None,
        }

        # Compute SHA-256
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            result["sha256"] = h.hexdigest()
        except OSError:
            return None

        # Inspect PE Header
        try:
            with open(file_path, "rb") as f:
                # DOS Header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[0:2] != b"MZ":
                    return result  # Not a PE binary (could be shell script/ELF)

                e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]
                f.seek(e_lfanew)

                # PE Signature
                pe_sig = f.read(4)
                if pe_sig != b"PE\0\0":
                    return result

                # COFF File Header (20 bytes)
                coff_header = f.read(20)
                if len(coff_header) < 20:
                    return result

                machine, num_sections, timestamp, _, _, opt_hdr_size, characteristics = struct.unpack(
                    "<HHIIIHH", coff_header
                )

                result["pe_timestamp"] = f"0x{timestamp:08X}"

                # Machine types
                if machine == 0x8664:
                    result["arch"] = "x86_64"
                elif machine == 0x014C:
                    result["arch"] = "x86_32"
                elif machine == 0xAA64:
                    result["arch"] = "arm64"
                else:
                    result["arch"] = f"unknown (0x{machine:04X})"

                # Optional Header
                if opt_hdr_size > 0:
                    opt_header = f.read(opt_hdr_size)
                    if len(opt_header) >= 2:
                        # SizeOfImage is at offset 0x38 in both PE32 and PE32+
                        if len(opt_header) >= 0x3C:
                            size_of_image = struct.unpack_from("<I", opt_header, 0x38)[0]
                            result["pe_size_of_image"] = size_of_image
        except Exception:
            pass

        return result


class AntiCheatDetector:
    """Pre-flight anti-cheat scanner."""

    KNOWN_PATTERNS = {
        "EasyAntiCheat": [
            r"easyanticheat",
            r"eac_server\.so",
            r"easyanticheat_x64\.so",
            r"easyanticheat_x86\.so",
            r"easyanticheat_eos\.sys",
            r"easyanticheat_setup\.exe",
        ],
        "BattlEye": [
            r"beservice.*\.exe",
            r"beclient.*\.dll",
            r"beclient.*\.so",
            r"battleye",
        ],
        "Vanguard": [
            r"vgk\.sys",
            r"vgc\.exe",
        ],
        "Ricochet": [
            r"randgrid\.sys",
        ],
        "Denuvo Anti-Cheat": [
            r"dbk64\.sys",
            r"denuvo.*anti.*cheat",
        ],
        "PunkBuster": [
            r"pbsvc\.exe",
            r"pbcl\.dll",
        ],
    }

    @classmethod
    def scan(cls, target_path, search_dirs=None):
        """Scans the target path and surrounding directories for anti-cheat signatures."""
        targets = []
        if target_path:
            targets.append(str(target_path))

        check_dirs = []
        if search_dirs:
            check_dirs.extend(search_dirs)

        if target_path and os.path.exists(target_path):
            parent = os.path.dirname(os.path.abspath(target_path))
            check_dirs.append(parent)
            check_dirs.append(os.path.dirname(parent))

        for d in set(check_dirs):
            if os.path.isdir(d):
                try:
                    for root, dirs, files in os.walk(d):
                        rel = os.path.relpath(root, d)
                        if rel.count(os.sep) >= 2:
                            continue
                        for f in files:
                            targets.append(os.path.join(root, f))
                except OSError:
                    pass

        for provider, patterns in cls.KNOWN_PATTERNS.items():
            compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
            for target in targets:
                base_name = os.path.basename(target)
                if any(c.search(base_name) or c.search(target) for c in compiled):
                    return {
                        "detected": True,
                        "provider": provider,
                        "passthrough_enforced": True,
                    }

        return {
            "detected": False,
            "provider": None,
            "passthrough_enforced": False,
        }


class ProcessTreeTracker:
    """Monitors the active process tree under Linux /proc to identify intermediate launchers and child game binaries."""

    SYSTEM_HELPER_EXES = {
        "steam.exe",
        "steamservice.exe",
        "steamwebhelper.exe",
        "winedevice.exe",
        "winedbg.exe",
        "services.exe",
        "explorer.exe",
        "plugplay.exe",
        "conhost.exe",
        "rpcss.exe",
        "rundll32.exe",
        "start.exe",
        "cmd.exe",
        "umu.exe",
        "wineboot.exe",
    }

    LAUNCHER_PATTERNS = [
        r"launcher",
        r"bootstrapper",
        r"splash",
        r"autorun",
        r"setup",
        r"updater",
        r"crashpad",
        r"crashreport",
    ]

    def __init__(self, root_pid, prefix_dir=None):
        self.root_pid = root_pid
        self.prefix_dir = prefix_dir
        self.stop_event = threading.Event()
        self.thread = None
        self.lock = threading.Lock()

        # Metrics collected during monitoring
        self.peak_thread_count = 1
        self.peak_process_count = 1
        self.all_seen_pids = set([root_pid]) if root_pid else set()
        # map: resolved_path -> {'peak_threads': int, 'first_seen': float, 'last_seen': float}
        self.discovered_executables = {}

    def start(self):
        if not self.root_pid:
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        if self.thread and self.thread.is_alive():
            self.stop_event.set()
            self.thread.join(timeout=1.0)

    @staticmethod
    def resolve_wine_path(win_path, prefix_dir=None):
        if not win_path:
            return None
        clean = win_path.strip('"\'')
        if os.path.isfile(clean):
            return os.path.abspath(clean)

        norm = clean.replace("\\", "/")
        if len(norm) >= 2 and norm[1] == ":":
            drive = norm[0].lower()
            subpath = norm[2:].lstrip("/")
            if drive == "c" and prefix_dir:
                candidate = os.path.join(prefix_dir, "drive_c", subpath)
                if os.path.isfile(candidate):
                    return os.path.abspath(candidate)
            elif drive == "z":
                candidate = "/" + subpath
                if os.path.isfile(candidate):
                    return os.path.abspath(candidate)
        return clean

    def _monitor_loop(self):
        while not self.stop_event.is_set():
            try:
                self._poll()
            except Exception:
                pass
            time.sleep(0.3)

    def _poll(self):
        if not os.path.isdir("/proc"):
            return

        try:
            pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return

        parent_map = {}
        for pid in pids:
            try:
                with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    idx = content.rfind(")")
                    if idx != -1:
                        rest = content[idx + 2:].split()
                        ppid = int(rest[1])
                        parent_map.setdefault(ppid, []).append(pid)
            except (OSError, IndexError, ValueError):
                continue

        tree_pids = set()
        queue = [self.root_pid]
        while queue:
            curr = queue.pop(0)
            tree_pids.add(curr)
            for child in parent_map.get(curr, []):
                if child not in tree_pids:
                    queue.append(child)

        with self.lock:
            self.all_seen_pids.update(tree_pids)
            if len(tree_pids) > self.peak_process_count:
                self.peak_process_count = len(tree_pids)

            total_threads = 0
            now = time.monotonic()

            for pid in tree_pids:
                try:
                    with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("Threads:"):
                                total_threads += int(line.split()[1])
                                break
                except (OSError, IndexError, ValueError):
                    pass

                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        raw = f.read()
                    parts = raw.split(b"\0")
                    for part in parts:
                        try:
                            token = part.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            continue
                        if token.lower().endswith(".exe"):
                            base = os.path.basename(token).lower()
                            if base not in self.SYSTEM_HELPER_EXES:
                                resolved = self.resolve_wine_path(token, self.prefix_dir)
                                if resolved not in self.discovered_executables:
                                    self.discovered_executables[resolved] = {
                                        "first_seen": now,
                                        "last_seen": now,
                                        "peak_threads": 1,
                                    }
                                else:
                                    entry = self.discovered_executables[resolved]
                                    entry["last_seen"] = now
                                    if total_threads > entry["peak_threads"]:
                                        entry["peak_threads"] = total_threads
                except OSError:
                    continue

            if total_threads > self.peak_thread_count:
                self.peak_thread_count = total_threads

    def evaluate_executables(self, initial_exe_path):
        """Analyzes all discovered executables and classifies (launcher_path, target_path)."""
        with self.lock:
            disc = dict(self.discovered_executables)

        resolved_initial = self.resolve_wine_path(initial_exe_path, self.prefix_dir) if initial_exe_path else None
        if resolved_initial and resolved_initial not in disc:
            disc[resolved_initial] = {"peak_threads": 1, "first_seen": 0, "last_seen": 0}

        candidates = [
            p for p in disc
            if os.path.basename(p).lower() not in self.SYSTEM_HELPER_EXES
        ]

        if not candidates:
            return None, resolved_initial

        if len(candidates) == 1:
            return None, candidates[0]

        launchers = [
            p for p in candidates
            if any(re.search(pat, os.path.basename(p), re.IGNORECASE) for pat in self.LAUNCHER_PATTERNS)
        ]
        non_launchers = [p for p in candidates if p not in launchers]

        if non_launchers:
            non_launchers.sort(
                key=lambda p: (
                    disc[p].get("peak_threads", 0),
                    disc[p].get("last_seen", 0) - disc[p].get("first_seen", 0)
                ),
                reverse=True
            )
            target = non_launchers[0]
            launcher = resolved_initial if resolved_initial != target else (launchers[0] if launchers else None)
            return launcher, target

        candidates.sort(
            key=lambda p: (
                disc[p].get("peak_threads", 0),
                disc[p].get("last_seen", 0) - disc[p].get("first_seen", 0)
            ),
            reverse=True
        )
        return (resolved_initial if resolved_initial != candidates[0] else None), candidates[0]


class GraphicsLogParser:
    """Parses DXVK and VKD3D-Proton runtime logs to extract live graphics telemetry."""

    @classmethod
    def scan_and_parse(cls, target_path=None, launcher_path=None, prefix_dir=None, env=None):
        search_dirs = []
        if env and env.get("DXVK_LOG_PATH"):
            search_dirs.append(env["DXVK_LOG_PATH"])

        if target_path and os.path.exists(target_path):
            search_dirs.append(os.path.dirname(os.path.abspath(target_path)))

        if launcher_path and os.path.exists(launcher_path):
            search_dirs.append(os.path.dirname(os.path.abspath(launcher_path)))

        if env and env.get("STEAM_COMPAT_INSTALL_PATH"):
            search_dirs.append(env["STEAM_COMPAT_INSTALL_PATH"])

        search_dirs.append(os.getcwd())

        if prefix_dir and os.path.isdir(prefix_dir):
            search_dirs.append(prefix_dir)
            drive_c = os.path.join(prefix_dir, "drive_c")
            if os.path.isdir(drive_c):
                search_dirs.append(drive_c)

        log_files = []
        checked = set()
        for d in search_dirs:
            if d and os.path.isdir(d):
                norm_d = os.path.abspath(d)
                if norm_d in checked:
                    continue
                checked.add(norm_d)
                try:
                    for f in os.listdir(norm_d):
                        if f.lower().endswith(("_dxgi.log", "_d3d11.log", "_d3d12.log", "_d3d9.log", "_d3d10core.log")):
                            log_files.append(os.path.join(norm_d, f))
                except OSError:
                    continue

        if not log_files:
            return None

        result = {
            "active_backend": None,
            "d3d_api_versions": set(),
            "device_name": None,
            "driver_version": None,
            "vulkan_version": None,
            "present_mode": None,
            "resolution": None,
            "presentation_model": "flip",
            "shader_compiles": {
                "count": 0,
                "total_time_ms": 0.0,
                "pipeline_cache_hit_rate": 1.0,
            },
            "vram_used_mb": None,
        }

        total_pipelines = 0
        total_time_ms = 0.0
        hit_rates = []

        for log_path in log_files:
            fname = os.path.basename(log_path).lower()
            if "_d3d12" in fname:
                result["d3d_api_versions"].add("d3d12")
                result["active_backend"] = "vkd3d-proton"
            if "_d3d11" in fname:
                result["d3d_api_versions"].add("d3d11")
                if not result["active_backend"]:
                    result["active_backend"] = "dxvk"
            if "_dxgi" in fname:
                result["d3d_api_versions"].add("dxgi")
                if not result["active_backend"]:
                    result["active_backend"] = "dxvk"
            if "_d3d9" in fname:
                result["d3d_api_versions"].add("d3d9")
                if not result["active_backend"]:
                    result["active_backend"] = "dxvk"
            if "_d3d10" in fname:
                result["d3d_api_versions"].add("d3d10")
                if not result["active_backend"]:
                    result["active_backend"] = "dxvk"

            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                dev = re.search(r"(?:Vulkan device|Device):\s+(.+)", content)
                if dev and not result["device_name"]:
                    result["device_name"] = dev.group(1).strip()

                drv = re.search(r"(?:Driver version|Driver):\s+(.+)", content)
                if drv and not result["driver_version"]:
                    result["driver_version"] = drv.group(1).strip()

                vk = re.search(r"Vulkan(?:\s+API\s+version)?:\s+([\d\.]+)", content)
                if vk and not result["vulkan_version"]:
                    result["vulkan_version"] = vk.group(1).strip()

                pm = re.search(r"Present mode:\s+(VK_PRESENT_MODE_\w+)", content)
                if pm:
                    result["present_mode"] = pm.group(1).strip()

                res = re.search(r"(?:Buffer|Swapchain)\s+size:\s+(\d+x\d+)", content)
                if res and not result["resolution"]:
                    result["resolution"] = res.group(1).strip()

                compiles = re.findall(r"Compiled\s+(\d+)\s+pipelines\s+in\s+([\d\.]+)\s*ms", content)
                for count_str, time_str in compiles:
                    total_pipelines += int(count_str)
                    total_time_ms += float(time_str)

                vkd3d_pipes = re.findall(r"Created\s+(\d+)\s+pipelines", content)
                for c in vkd3d_pipes:
                    total_pipelines += int(c)

                hr = re.search(r"cache hit rate:\s+([\d\.]+)%", content)
                if hr:
                    hit_rates.append(float(hr.group(1)) / 100.0)

                vram_matches = re.findall(r"Allocating\s+(\d+)\s+MB\s+of\s+memory", content)
                if vram_matches:
                    vram_mb = sum(int(m) for m in vram_matches)
                    if not result["vram_used_mb"] or vram_mb > result["vram_used_mb"]:
                        result["vram_used_mb"] = vram_mb

            except OSError:
                continue

        result["d3d_api_versions"] = sorted(list(result["d3d_api_versions"]))
        result["shader_compiles"]["count"] = total_pipelines
        result["shader_compiles"]["total_time_ms"] = round(total_time_ms, 2)
        if hit_rates:
            result["shader_compiles"]["pipeline_cache_hit_rate"] = round(sum(hit_rates) / len(hit_rates), 3)

        return result


class MangoHudLogParser:
    """Parses MangoHud summary and frametime CSV logs into standardized ProtoGoblin ROI metrics."""

    @classmethod
    def parse_session(cls, session_dir, duration_sec=0.0):
        if not session_dir or not os.path.isdir(session_dir):
            return None

        summary_files = [
            os.path.join(session_dir, f)
            for f in os.listdir(session_dir)
            if f.endswith("_summary.csv")
        ]

        detail_files = [
            os.path.join(session_dir, f)
            for f in os.listdir(session_dir)
            if f.endswith(".csv") and not f.endswith("_summary.csv")
        ]

        if not summary_files and not detail_files:
            return None

        fps_avg = 0.0
        fps_1 = 0.0
        fps_0_1 = 0.0
        frametime_avg = 0.0
        cpu_busy = 0.0
        gpu_busy = 0.0
        total_frames = 0
        ft_p95 = 0.0
        ft_p99 = 0.0
        jitter = 0.0

        if summary_files:
            try:
                with open(summary_files[0], "r", encoding="utf-8", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    row = next(reader)
                    fps_0_1 = float(row.get("0.1% Min FPS", 0))
                    fps_1 = float(row.get("1% Min FPS", 0))
                    fps_avg = float(row.get("Average FPS", 0))
                    frametime_avg = float(row.get("Average Frame Time", 0))
                    cpu_busy = float(row.get("CPU Load", 0))
                    gpu_busy = float(row.get("GPU Load", 0))
            except Exception:
                pass

        if detail_files:
            try:
                frametimes = []
                with open(detail_files[0], "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    header_idx = -1
                    for idx, line in enumerate(lines):
                        if "frametime" in line and "fps" in line:
                            header_idx = idx
                            break
                    if header_idx != -1:
                        reader = csv.DictReader(lines[header_idx:])
                        for r in reader:
                            val = r.get("frametime")
                            if val:
                                try:
                                    frametimes.append(float(val))
                                except ValueError:
                                    pass

                if frametimes:
                    total_frames = len(frametimes)
                    frametimes.sort()
                    p95_idx = int(0.95 * len(frametimes))
                    p99_idx = int(0.99 * len(frametimes))
                    ft_p95 = round(frametimes[p95_idx], 2)
                    ft_p99 = round(frametimes[p99_idx], 2)
                    if not frametime_avg:
                        frametime_avg = round(sum(frametimes) / len(frametimes), 2)
                    if not fps_avg and frametime_avg > 0:
                        fps_avg = round(1000.0 / frametime_avg, 1)

                    variance = sum((x - frametime_avg) ** 2 for x in frametimes) / len(frametimes)
                    jitter = round(variance**0.5, 2)
            except Exception:
                pass

        if not total_frames and fps_avg > 0 and duration_sec > 0:
            total_frames = int(fps_avg * duration_sec)

        if cpu_busy >= 80 and gpu_busy < 75:
            classification = "cpu_bound"
        elif gpu_busy >= 85:
            classification = "gpu_bound"
        elif cpu_busy < 50 and gpu_busy < 50:
            classification = "sync_bound"
        else:
            classification = "balanced"

        return {
            "roi_enabled": True,
            "roi_capture_duration_sec": round(duration_sec, 2),
            "bottleneck_classification": classification,
            "compatibility_layer_overhead_ratio": None,
            "frame_metrics": {
                "total_frames": total_frames,
                "fps_avg": round(fps_avg, 1),
                "fps_p50": round(fps_avg, 1),
                "fps_1_pct_low": round(fps_1, 1),
                "fps_0_1_pct_low": round(fps_0_1, 1),
                "frametime_avg_ms": round(frametime_avg, 2),
                "frametime_p95_ms": ft_p95 or round(frametime_avg * 1.15, 2),
                "frametime_p99_ms": ft_p99 or round(frametime_avg * 1.35, 2),
                "frametime_jitter_ms": jitter or 0.5,
            },
            "pacing": {
                "cpu_busy_pct": round(cpu_busy, 1),
                "cpu_wait_pct": round(max(0.0, 100.0 - cpu_busy), 1),
                "gpu_busy_pct": round(gpu_busy, 1),
                "in_present_api_pct": None,
            },
        }


class SystemProbe:
    """Probes host and container environment information."""

    @staticmethod
    def get_host_os():
        for path in ["/run/host/os-release", "/etc/os-release"]:
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.startswith("PRETTY_NAME="):
                                return line.split("=", 1)[1].strip().strip('"')
                except OSError:
                    pass
        return platform.platform()

    @staticmethod
    def get_container_runtime():
        if os.environ.get("PRESSURE_VESSEL_VERSION"):
            return f"pressure-vessel-{os.environ['PRESSURE_VESSEL_VERSION']}"
        if os.environ.get("STEAM_RUNTIME_CONTAINER_VERSION"):
            return f"steam-runtime-{os.environ['STEAM_RUNTIME_CONTAINER_VERSION']}"
        if os.path.exists("/steamrt"):
            return "steam-runtime-container"
        return None

    @staticmethod
    def get_cpu_info():
        model = "Unknown CPU"
        logical_cores = os.cpu_count() or 1
        if os.path.isfile("/proc/cpuinfo"):
            try:
                with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
                    for line in f:
                        if "model name" in line:
                            model = line.split(":", 1)[1].strip()
                            break
            except OSError:
                pass
        return {"model": model, "logical_cores": logical_cores}

    @staticmethod
    def get_gpu_info():
        device_name = "Vulkan Compatible GPU"
        driver_version = "Unknown"
        vulkan_version = "1.3"

        if os.environ.get("MESA_LOADER_DRIVER_OVERRIDE"):
            driver_version = f"Mesa ({os.environ['MESA_LOADER_DRIVER_OVERRIDE']})"

        return {
            "device_name": device_name,
            "driver_version": driver_version,
            "vulkan_version": vulkan_version,
        }

    @staticmethod
    def get_ram_total_mb():
        if os.path.isfile("/proc/meminfo"):
            try:
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            kb = int(line.split()[1])
                            return kb // 1024
            except (OSError, ValueError, IndexError):
                pass
        return 16384


class ProtoGoblinSession:
    """Manages the lifecycle of a ProtoGoblin game execution session."""

    def __init__(self, proton_dir=None):
        self.proton_dir = proton_dir or os.path.dirname(os.path.abspath(__file__))
        self.schema_version = "1.0.0"
        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid():04x}"
        self.start_iso = datetime.now(timezone.utc).isoformat()
        self.start_monotonic = time.monotonic()

        self.mode = os.environ.get("PROTOGOBLIN_MODE", "play").lower().strip()
        if self.mode not in ["play", "profile"]:
            self.mode = "play"

        self.steam_appid = os.environ.get("SteamGameId") or os.environ.get("SteamAppId")

        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        game_slug = self.steam_appid or "unknown_game"
        self.session_dir = os.path.join(xdg_data, "protogoblin", "sessions", game_slug, self.session_id)
        self.manifest_path = os.path.join(self.session_dir, "utilization.json")

        self.anti_cheat = {"detected": False, "provider": None, "passthrough_enforced": False}
        self.initial_exe = None
        self.launcher_exe = None
        self.target_exe = None
        self.exit_code = 0
        self.process_tree_count = 1
        self.peak_thread_count = 1
        self.tracker = None

    def _resolve_version(self):
        v_file = os.path.join(self.proton_dir, "VERSION")
        if os.path.isfile(v_file):
            try:
                with open(v_file, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except OSError:
                pass
        return "ProtoGoblin-0.01"

    def pre_flight(self, argv, env):
        """Initializes the session directory, probes environment, and runs anti-cheat scan."""
        try:
            os.makedirs(self.session_dir, exist_ok=True)
        except OSError:
            pass

        target_path = None
        for arg in argv:
            if arg.lower().endswith(".exe"):
                target_path = arg
                break

        self.initial_exe = target_path

        # Anti-cheat scan
        self.anti_cheat = AntiCheatDetector.scan(target_path)
        if self.anti_cheat["detected"]:
            self.mode = "play"

        # In profile mode, configure bundled MangoHud for automatic ROI telemetry capture
        if self.mode == "profile":
            env["MANGOHUD"] = "1"
            config_parts = [
                f"output_folder={self.session_dir}",
                "log_interval=100",
                "benchmark_percentiles=0.001;0.01;0.97;0.99",
            ]
            if os.environ.get("PROTOGOBLIN_OVERLAY") != "1":
                config_parts.append("no_display=1")
            env["MANGOHUD_CONFIG"] = ",".join(config_parts)

        # Initial target info
        if target_path:
            pe_data = PEInfo.inspect(target_path)
            self.target_exe = pe_data or {
                "path": target_path,
                "sha256": "unknown",
                "arch": "x86_64",
                "pe_timestamp": None,
                "pe_size_of_image": None,
            }
        else:
            self.target_exe = {
                "path": "unknown",
                "sha256": "unknown",
                "arch": "x86_64",
                "pe_timestamp": None,
                "pe_size_of_image": None,
            }

    def start_process_tree_monitor(self, root_pid, prefix_dir=None):
        """Starts monitoring child processes spawned by root_pid."""
        self.tracker = ProcessTreeTracker(root_pid, prefix_dir)
        self.tracker.start()

    def stop_process_tree_monitor(self):
        """Stops process monitoring and retrieves intermediate launcher / target classification."""
        if self.tracker:
            self.tracker.stop()
            launcher_path, target_path = self.tracker.evaluate_executables(self.initial_exe)

            if launcher_path:
                self.launcher_exe = PEInfo.inspect(launcher_path) or {
                    "path": launcher_path,
                    "sha256": "unknown",
                    "arch": "x86_64",
                }

            if target_path:
                pe_info = PEInfo.inspect(target_path)
                if pe_info:
                    self.target_exe = pe_info

            disc_peak = max(
                (v.get("peak_threads", 1) for v in self.tracker.discovered_executables.values()),
                default=1,
            )
            self.peak_thread_count = max(self.peak_thread_count, self.tracker.peak_thread_count, disc_peak)
            self.process_tree_count = max(self.process_tree_count, self.tracker.peak_process_count, len(self.tracker.all_seen_pids))

    def post_flight(self, exit_code, env):
        """Finalizes session metadata and generates utilization.json."""
        self.exit_code = exit_code
        end_iso = datetime.now(timezone.utc).isoformat()
        duration_seconds = round(time.monotonic() - self.start_monotonic, 3)

        sync_backend = "wineserver_rpc"
        fast_path = False
        if os.path.exists("/dev/ntsync") or env.get("WINE_USE_NTSYNC") == "1" or env.get("PROTON_USE_NTSYNC") == "1":
            sync_backend = "ntsync"
            fast_path = True
        elif env.get("WINEFSYNC") == "1":
            sync_backend = "fsync"
            fast_path = True
        elif env.get("WINEESYNC") == "1":
            sync_backend = "esync"
            fast_path = True

        if env.get("PROTON_USE_WINED3D") == "1":
            active_backend = "wined3d"
        elif env.get("PROTON_USE_D7VK") == "1":
            active_backend = "d7vk"
        else:
            active_backend = "dxvk"

        d3d_api_versions = ["d3d11", "dxgi"]
        present_mode = "VK_PRESENT_MODE_FIFO_KHR"
        resolution = "unknown"
        shader_compiles = {
            "count": 0,
            "total_time_ms": 0.0,
            "pipeline_cache_hit_rate": 1.0,
        }
        vram_used_mb = None
        gpu_info = SystemProbe.get_gpu_info()

        # Parse live graphics logs from DXVK / VKD3D
        target_path = self.target_exe.get("path") if self.target_exe else None
        launcher_path = self.launcher_exe.get("path") if self.launcher_exe else None
        prefix_dir = getattr(self.tracker, "prefix_dir", None) if self.tracker else None

        parsed_gfx = GraphicsLogParser.scan_and_parse(
            target_path=target_path,
            launcher_path=launcher_path,
            prefix_dir=prefix_dir,
            env=env,
        )

        if parsed_gfx:
            if parsed_gfx["active_backend"]:
                active_backend = parsed_gfx["active_backend"]
            if parsed_gfx["d3d_api_versions"]:
                d3d_api_versions = parsed_gfx["d3d_api_versions"]
            if parsed_gfx["present_mode"]:
                present_mode = parsed_gfx["present_mode"]
            if parsed_gfx["resolution"]:
                resolution = parsed_gfx["resolution"]
            if parsed_gfx["device_name"]:
                gpu_info["device_name"] = parsed_gfx["device_name"]
            if parsed_gfx["driver_version"]:
                gpu_info["driver_version"] = parsed_gfx["driver_version"]
            if parsed_gfx["vulkan_version"]:
                gpu_info["vulkan_version"] = parsed_gfx["vulkan_version"]
            shader_compiles = parsed_gfx["shader_compiles"]
            vram_used_mb = parsed_gfx["vram_used_mb"]

        loaded_subsystems = ["kernel32", "ntdll", "user32", "gdi32", "ws2_32"]
        unutilized_subsystems = ["dinput8", "openvr", "wineopenxr", "mfplat"]

        for api in d3d_api_versions:
            if api not in loaded_subsystems:
                loaded_subsystems.append(api)

        for candidate in ["d3d12", "d3d9"]:
            if candidate not in d3d_api_versions and candidate not in unutilized_subsystems:
                unutilized_subsystems.append(candidate)

        dll_overrides_raw = env.get("WINEDLLOVERRIDES", "")
        active_overrides = {}
        for entry in dll_overrides_raw.split(";"):
            if "=" in entry:
                dlls, mode = entry.split("=", 1)
                for dll in dlls.split(","):
                    dll_clean = dll.strip()
                    if dll_clean:
                        active_overrides[dll_clean] = mode.strip()

        roi_telemetry = None
        if self.mode == "profile":
            roi_telemetry = MangoHudLogParser.parse_session(self.session_dir, duration_seconds)
            if not roi_telemetry:
                roi_telemetry = {
                    "roi_enabled": True,
                    "roi_capture_duration_sec": duration_seconds,
                    "bottleneck_classification": "balanced",
                    "compatibility_layer_overhead_ratio": None,
                    "frame_metrics": None,
                    "pacing": None,
                }

        manifest = {
            "schema_version": self.schema_version,
            "session": {
                "id": self.session_id,
                "mode": self.mode,
                "start_time": self.start_iso,
                "end_time": end_iso,
                "duration_seconds": duration_seconds,
                "clean_shutdown": (exit_code == 0),
            },
            "target": {
                "steam_appid": self.steam_appid,
                "launcher_executable": self.launcher_exe,
                "target_executable": self.target_exe,
                "exit_code": exit_code,
                "process_tree_count": self.process_tree_count,
                "peak_thread_count": self.peak_thread_count,
            },
            "environment": {
                "host_os": SystemProbe.get_host_os(),
                "kernel": platform.release(),
                "container_runtime": SystemProbe.get_container_runtime(),
                "protogoblin_version": self._resolve_version(),
                "cpu": SystemProbe.get_cpu_info(),
                "gpu": gpu_info,
                "ram_total_mb": SystemProbe.get_ram_total_mb(),
            },
            "anti_cheat": self.anti_cheat,
            "subsystems": {
                "loaded": loaded_subsystems,
                "unutilized": unutilized_subsystems,
                "active_dll_overrides": active_overrides,
            },
            "graphics": {
                "active_backend": active_backend,
                "d3d_api_versions": d3d_api_versions,
                "presentation_model": "flip",
                "present_mode": present_mode,
                "resolution": resolution,
                "shader_compiles": shader_compiles,
                "memory": {
                    "vram_used_mb": vram_used_mb,
                    "vram_budget_mb": None,
                    "process_rss_mb": None,
                },
            },
            "synchronization": {
                "sync_backend": sync_backend,
                "fast_path_enabled": fast_path,
                "wineserver_rpc_fallbacks": 0,
            },
            "media_and_audio": {
                "audio_backend": "pipewire" if os.environ.get("PIPEWIRE_REMOTE") else "pulse",
                "media_foundation_active": False,
            },
            "roi_telemetry": roi_telemetry,
        }

        try:
            os.makedirs(self.session_dir, exist_ok=True)
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            sys.stderr.write(f"[ProtoGoblin] Emitted Tier-1 manifest: {self.manifest_path}\n")
        except OSError as e:
            sys.stderr.write(f"[ProtoGoblin] Failed to write manifest: {e}\n")

        return manifest


g_protogoblin = ProtoGoblinSession()
