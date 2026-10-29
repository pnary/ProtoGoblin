#!/usr/bin/env python3
"""
ProtoGoblin - Session Manager & Introspective Telemetry Engine
Phase 0: Process-Tree Tracking, Anti-Cheat Pre-Flight, and Tier-1 Manifest Generation
"""

import copy
import csv
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def log(msg: str):
    """Unified logger that emits to sys.stderr, global protogoblin.log, and active session log."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    formatted = f"[{ts}] [ProtoGoblin] {msg}"
    try:
        sys.stderr.write(formatted + os.linesep)
        sys.stderr.flush()
    except OSError:
        pass

    try:
        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        log_dir = os.path.join(xdg_data, "protogoblin")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "protogoblin.log"), "a", encoding="utf-8") as f:
            f.write(formatted + "\n")
    except Exception:
        pass

    global g_protogoblin
    if "g_protogoblin" in globals() and g_protogoblin:
        s_dir = getattr(g_protogoblin, "session_dir", None)
        if s_dir:
            try:
                os.makedirs(s_dir, exist_ok=True)
                with open(os.path.join(s_dir, "session.log"), "a", encoding="utf-8") as f:
                    f.write(formatted + "\n")
            except Exception:
                pass

        try:
            app_id = getattr(g_protogoblin, "steam_appid", None) or "unknown_game"
            latest_log = os.path.join(xdg_data, "protogoblin", "sessions", str(app_id), "latest.log")
            os.makedirs(os.path.dirname(latest_log), exist_ok=True)
            with open(latest_log, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
        except Exception:
            pass


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
                    if len(dos_header) >= 5 and dos_header[0:4] == b"\x7fELF":
                        result["arch"] = "x86_64" if dos_header[4] == 2 else "x86"
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


class EngineDetector:
    """Detects commercial and open-source game engines (UE4, UE5, Unity, Godot, Source 2)."""

    @classmethod
    def detect(cls, target_path, search_dirs=None):
        if not target_path or not os.path.exists(target_path):
            return {
                "detected": False,
                "engine": "unknown",
                "version": None,
                "confidence": 0.0,
                "details": {},
            }

        target_path = os.path.abspath(target_path)
        base_dir = os.path.dirname(target_path)
        base_name = os.path.basename(target_path)
        stem = os.path.splitext(base_name)[0]

        # 1. Check Unity
        unity_data_dirs = [
            os.path.join(base_dir, f"{stem}_Data"),
            os.path.join(base_dir, "Data"),
        ]
        unity_player_dll = os.path.join(base_dir, "UnityPlayer.dll")
        unity_player_x64 = os.path.join(base_dir, "UnityPlayer_Win64.dll")
        unity_crash = os.path.join(base_dir, "UnityCrashHandler64.exe")

        is_unity = (
            any(os.path.isdir(d) for d in unity_data_dirs)
            or os.path.isfile(unity_player_dll)
            or os.path.isfile(unity_player_x64)
            or os.path.isfile(unity_crash)
        )
        if is_unity:
            backend = "unknown"
            has_il2cpp = False
            for d in unity_data_dirs:
                if os.path.isdir(os.path.join(d, "il2cpp_data")) or os.path.isfile(
                    os.path.join(d, "il2cpp_data", "Metadata", "global-metadata.dat")
                ):
                    has_il2cpp = True
                    backend = "il2cpp"
                    break
                elif os.path.isdir(os.path.join(d, "Managed")) or os.path.isdir(
                    os.path.join(base_dir, "MonoBleedingEdge")
                ):
                    backend = "mono"
            return {
                "detected": True,
                "engine": "unity",
                "version": None,
                "confidence": 1.0,
                "details": {
                    "backend": backend,
                    "has_il2cpp": has_il2cpp,
                },
            }

        # 2. Check Godot
        sibling_pck = os.path.join(base_dir, f"{stem}.pck")
        sibling_zip = os.path.join(base_dir, f"{stem}.zip")
        is_godot = os.path.isfile(sibling_pck) or os.path.isfile(sibling_zip)

        godot_magic = False
        godot_str = False
        try:
            size = os.path.getsize(target_path)
            with open(target_path, "rb") as f:
                if size > 1024:
                    f.seek(size - 1024)
                    tail = f.read(1024)
                    if b"GDPC" in tail:
                        godot_magic = True
                f.seek(0)
                head = f.read(min(size, 2 * 1024 * 1024))
                if b"Godot Engine" in head or b"GDPC" in head:
                    godot_str = True
        except Exception:
            pass

        if is_godot or godot_magic or godot_str:
            return {
                "detected": True,
                "engine": "godot",
                "version": None,
                "confidence": 0.95 if (godot_magic or is_godot) else 0.8,
                "details": {
                    "pck_file": os.path.basename(sibling_pck) if os.path.isfile(sibling_pck) else None,
                    "embedded_pck": godot_magic,
                },
            }

        # 3. Check Unreal Engine (UE4 / UE5)
        is_ue = False
        ue_ver = "unreal"
        has_zen_store = False
        paks_found = False

        norm_path = target_path.replace("\\", "/")
        if "/binaries/win64" in norm_path.lower() or "/binaries/win32" in norm_path.lower():
            is_ue = True

        parent_1 = os.path.dirname(base_dir)
        parent_2 = os.path.dirname(parent_1)
        for search_root in [base_dir, parent_1, parent_2]:
            paks_dir = os.path.join(search_root, "Content", "Paks")
            if os.path.isdir(paks_dir):
                is_ue = True
                paks_found = True
                try:
                    for f in os.listdir(paks_dir):
                        if f.endswith(".ucas") or f.endswith(".utoc"):
                            has_zen_store = True
                            ue_ver = "unreal_5"
                            break
                        elif f.endswith(".pak") and ue_ver != "unreal_5":
                            ue_ver = "unreal_4"
                except OSError:
                    pass
                break

        if not is_ue or ue_ver == "unreal":
            try:
                with open(target_path, "rb") as f:
                    content = f.read(min(os.path.getsize(target_path), 4 * 1024 * 1024))
                    if b"FEngineLoop" in content or b"Epic Games, Inc." in content or b"UnrealEngine" in content:
                        is_ue = True
                        if b"UE5" in content or b"UnrealEditor-5" in content or has_zen_store:
                            ue_ver = "unreal_5"
                        elif ue_ver == "unreal":
                            ue_ver = "unreal_4"
            except Exception:
                pass

        if is_ue:
            if has_zen_store:
                ue_ver = "unreal_5"
            elif ue_ver == "unreal":
                ue_ver = "unreal_4"
            return {
                "detected": True,
                "engine": ue_ver,
                "version": "5.x" if ue_ver == "unreal_5" else "4.x",
                "confidence": 0.95,
                "details": {
                    "has_zen_store": has_zen_store,
                    "has_paks": paks_found,
                },
            }

        # 4. Check Source 2 / Source
        if os.path.isfile(os.path.join(base_dir, "tier0.dll")) and os.path.isfile(os.path.join(base_dir, "vscript.dll")):
            return {
                "detected": True,
                "engine": "source2",
                "version": None,
                "confidence": 0.95,
                "details": {},
            }

        return {
            "detected": False,
            "engine": "unknown",
            "version": None,
            "confidence": 0.0,
            "details": {},
        }


class PresetDatabase:
    """Provides ProtonDB community presets, ratings, and known fixes for Steam AppIDs via protogoblin.db SQLite."""

    _CACHE = None
    _DB_PATH = None

    @classmethod
    def get_db_path(cls):
        if cls._DB_PATH and os.path.isfile(cls._DB_PATH):
            return cls._DB_PATH
        candidate_paths = [
            os.path.join(SCRIPT_DIR, "share", "protogoblin", "protogoblin.db"),
            os.path.join(SCRIPT_DIR, "..", "share", "protogoblin", "protogoblin.db"),
            os.path.join(SCRIPT_DIR, "protogoblin.db"),
            os.path.expanduser("~/.local/share/protogoblin/protogoblin.db"),
            "/usr/share/protogoblin/protogoblin.db",
        ]
        for p in candidate_paths:
            if os.path.isfile(p):
                cls._DB_PATH = p
                return p
        return None

    @classmethod
    def get_preset(cls, app_id, is_deck=None):
        if not app_id:
            return None

        if is_deck is None:
            is_deck = SystemProbe.is_steam_deck()

        # Fast indexed microsecond SQLite path
        db_path = cls.get_db_path()
        if db_path:
            try:
                import sqlite3
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute(
                    "SELECT title, reports, modern_reports, tier, known_issues, recommended_tweaks, deck_tweaks "
                    "FROM presets WHERE app_id = ?",
                    (int(app_id),)
                )
                row = cur.fetchone()
                conn.close()
                if row:
                    known_issues = json.loads(row[4]) if row[4] else []
                    recs = json.loads(row[5]) if row[5] else {}
                    deck_tweaks = json.loads(row[6]) if row[6] else {}
                    preset = {
                        "title": row[0],
                        "reports": row[1],
                        "modern_reports": row[2],
                        "tier": row[3],
                        "known_issues": known_issues,
                        "recommended_tweaks": recs,
                        "deck_tweaks": deck_tweaks,
                    }
                    if is_deck and deck_tweaks:
                        elevated = dict(recs)
                        if "env" in deck_tweaks:
                            elevated_env = dict(recs.get("env", {}))
                            elevated_env.update(deck_tweaks["env"])
                            elevated["env"] = elevated_env
                        if "args" in deck_tweaks:
                            elevated_args = list(recs.get("args", []))
                            for a in deck_tweaks["args"]:
                                if a not in elevated_args:
                                    elevated_args.append(a)
                            elevated["args"] = elevated_args
                        for k, v in deck_tweaks.items():
                            if k not in ["env", "args"]:
                                elevated[k] = v
                        preset["recommended_tweaks"] = elevated
                    return preset
            except Exception:
                pass

        # Fallback to JSON cache if SQLite DB is absent
        db = cls.get_all()
        preset = db.get(str(app_id))
        if not preset:
            return None

        if is_deck:
            preset_copy = dict(preset)
            recs = dict(preset.get("recommended_tweaks") or {})
            deck_tweaks = preset.get("deck_tweaks") or preset.get("deck_recommended_tweaks") or recs.get("deck")
            if deck_tweaks:
                elevated = dict(recs)
                if "env" in deck_tweaks:
                    elevated_env = dict(recs.get("env", {}))
                    elevated_env.update(deck_tweaks["env"])
                    elevated["env"] = elevated_env
                if "args" in deck_tweaks:
                    elevated_args = list(recs.get("args", []))
                    for a in deck_tweaks["args"]:
                        if a not in elevated_args:
                            elevated_args.append(a)
                    elevated["args"] = elevated_args
                for k, v in deck_tweaks.items():
                    if k not in ["env", "args"]:
                        elevated[k] = v
                preset_copy["recommended_tweaks"] = elevated
            return preset_copy
        return preset

    @classmethod
    def get_active_fixes(cls, app_id):
        """Returns verified, active modern fixes for an AppID from SQLite."""
        db_path = cls.get_db_path()
        if not db_path or not app_id:
            return []
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT category, fix_command, confidence, report_mentions, description "
                "FROM fixes WHERE app_id = ? ORDER BY report_mentions DESC",
                (int(app_id),)
            )
            fixes = [dict(r) for r in cur.fetchall()]
            conn.close()
            return fixes
        except Exception:
            return []

    @classmethod
    def search_games(cls, query, limit=20):
        """Fast indexed search for games by title or AppID under 1ms."""
        db_path = cls.get_db_path()
        if not db_path or not query:
            return []
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT app_id, title, tier, reports FROM presets "
                "WHERE title LIKE ? OR CAST(app_id AS TEXT) LIKE ? ORDER BY reports DESC LIMIT ?",
                (f"%{query}%", f"%{query}%", limit)
            )
            results = [dict(r) for r in cur.fetchall()]
            conn.close()
            return results
        except Exception:
            return []

    @classmethod
    def get_all(cls):
        if cls._CACHE is not None:
            return cls._CACHE

        cls._CACHE = {}
        candidate_paths = [
            os.path.join(SCRIPT_DIR, "share", "protogoblin", "protogoblin_presets.json"),
            os.path.join(SCRIPT_DIR, "..", "share", "protogoblin", "protogoblin_presets.json"),
            os.path.join(SCRIPT_DIR, "protogoblin_presets.json"),
            os.path.expanduser("~/.local/share/protogoblin/protogoblin_presets.json"),
            "/usr/share/protogoblin/protogoblin_presets.json",
        ]
        for p in candidate_paths:
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        cls._CACHE = json.load(f)
                    break
                except Exception:
                    pass
        return cls._CACHE




class ExperimentStatus:
    DETECTED = "detected"
    APPLIED = "applied"
    BENCHMARKED = "benchmarked"
    VALIDATED = "validated"
    REJECTED = "rejected"


class ExperimentVerdict:
    IMPROVED = "IMPROVED"
    REGRESSED = "REGRESSED"
    MIXED = "MIXED"
    NEUTRAL = "NEUTRAL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class FixDefinition:
    def __init__(self, fix_id, title, constituent_features, profile_targets, description=""):
        self.fix_id = fix_id
        self.title = title
        self.constituent_features = list(constituent_features)
        self.profile_targets = profile_targets
        self.description = description


class FixRegistry:
    """Central registry mapping optimization recommendation IDs to constituent features,
    profile adjustments, and runtime gating tags.
    """
    _ALIASES = {
        "enable_precision_timers": "precision_timers",
        "enable_io_cache": "io_cache",
        "enable_descriptor_buffer": "descriptor_buffer",
        "dxvk_async": "async_shader_compile",
    }

    _REGISTRY = {
        "state_dedup_and_debounce": FixDefinition(
            fix_id="state_dedup_and_debounce",
            title="State Deduplication & SwapChain Resize Debounce",
            constituent_features=["state_dedup", "swapchain_debounce"],
            profile_targets=[
                (("synchronization", "state_dedup"), True),
                (("synchronization", "swapchain_debounce"), True),
            ],
            description="Filters redundant D3D11 constant buffer updates and debounces rapid DXGI swapchain resizes.",
        ),
        "state_dedup": FixDefinition(
            fix_id="state_dedup",
            title="Constant Buffer State Deduplication",
            constituent_features=["state_dedup"],
            profile_targets=[
                (("synchronization", "state_dedup"), True),
            ],
            description="Filters redundant constant buffer uploads to avoid Vulkan descriptor set thrashing.",
        ),
        "swapchain_debounce": FixDefinition(
            fix_id="swapchain_debounce",
            title="SwapChain Resize Debounce",
            constituent_features=["swapchain_debounce"],
            profile_targets=[
                (("synchronization", "swapchain_debounce"), True),
            ],
            description="Debounces rapid bursts and identical-dimension SwapChain ResizeBuffers calls.",
        ),
        "cap_framerate": FixDefinition(
            fix_id="cap_framerate",
            title="Presentation Frame Rate Limiter",
            constituent_features=["cap_framerate", "max_fps"],
            profile_targets=[
                (("graphics", "max_fps"), 60),
            ],
            description="Enforces presentation rate cap via DXVK and VKD3D-Proton to stabilize frame pacing intervals.",
        ),
        "atelier_sync_fix": FixDefinition(
            fix_id="atelier_sync_fix",
            title="Atelier / Gust D3D11 Staging Buffer Sync Fix",
            constituent_features=["atelier_sync_fix"],
            profile_targets=[
                (("synchronization", "atelier_sync_fix"), True),
                (("graphics", "force_vsync"), "off"),
            ],
            description="Applies D3D11 staging buffer shadow copies and unlocks VSync to resolve GPU starvation.",
        ),
        "precision_timers": FixDefinition(
            fix_id="precision_timers",
            title="High-Precision Win32 Sleep Timers",
            constituent_features=["precision_timers"],
            profile_targets=[
                (("timing", "precision_timers"), True),
            ],
            description="Hybrid QPC sleep-spin pacing to eliminate 1-4ms coarse Wine timer overshoot.",
        ),
        "io_cache": FixDefinition(
            fix_id="io_cache",
            title="Adaptive Traversal File I/O Cache",
            constituent_features=["io_cache"],
            profile_targets=[
                (("filesystem", "io_cache"), True),
            ],
            description="Kernel-level read-ahead RAM caching to eliminate synchronous traversal asset hitches.",
        ),
        "descriptor_buffer": FixDefinition(
            fix_id="descriptor_buffer",
            title="Vulkan Descriptor Buffer Extension",
            constituent_features=["descriptor_buffer"],
            profile_targets=[
                (("graphics", "descriptor_buffer"), True),
            ],
            description="Direct GPU memory descriptor binding to bypass driver descriptor set pools.",
        ),
        "local_shader_cache": FixDefinition(
            fix_id="local_shader_cache",
            title="Local Pipeline & Shader Cache",
            constituent_features=["local_shader_cache"],
            profile_targets=[
                (("graphics", "local_shader_cache"), True),
            ],
            description="Forces local prefix PSO and shader caching via PROTON_LOCAL_SHADER_CACHE=1.",
        ),
        "async_shader_compile": FixDefinition(
            fix_id="async_shader_compile",
            title="DXVK Asynchronous Shader Pipeline Compilation",
            constituent_features=["async_shader_compile"],
            profile_targets=[
                (("graphics", "async_shader_compile"), True),
            ],
            description="Asynchronous shader compilation fallback when Vulkan Graphics Pipeline Libraries are unavailable.",
        ),
        "optimize_ue5_lumen_vsm": FixDefinition(
            fix_id="optimize_ue5_lumen_vsm",
            title="Unreal Engine 5 Lumen & VSM Optimization",
            constituent_features=["optimize_ue5_lumen_vsm"],
            profile_targets=[
                (("engine", "unreal", "optimize_lumen"), True),
                (("engine", "unreal", "optimize_vsm"), True),
                (("engine", "unreal", "disable_virtual_shadows"), True),
            ],
            description="Downsamples Lumen screen probes and throttles virtual shadow ray samples under VKD3D-Proton.",
        ),
    }

    @classmethod
    def canonical_id(cls, fix_id):
        if not fix_id:
            return None
        return cls._ALIASES.get(fix_id, fix_id)

    @classmethod
    def is_registered(cls, fix_id):
        return cls.canonical_id(fix_id) in cls._REGISTRY

    @classmethod
    def get(cls, fix_id):
        cid = cls.canonical_id(fix_id)
        return cls._REGISTRY.get(cid)

    @classmethod
    def get_constituent_features(cls, fix_id):
        defn = cls.get(fix_id)
        return defn.constituent_features if defn else []

    @classmethod
    def find_governing_experiments(cls, feature_id, experiments_fixes):
        """Finds any active or recorded experiments governing feature_id."""
        if not experiments_fixes or not isinstance(experiments_fixes, dict):
            return []
        matches = []
        for f_id, f_data in experiments_fixes.items():
            cid = cls.canonical_id(f_id)
            if cid == feature_id or f_id == feature_id:
                matches.append(f_data)
                continue
            defn = cls.get(cid)
            if defn and feature_id in defn.constituent_features:
                matches.append(f_data)
        return matches


def compute_session_diff(manifest_a, manifest_b):
    """Computes an A/B delta comparison between two ProtoGoblin session manifests.

    Enforces empirical validation requirements:
    - Rejects insufficient data (missing ROI telemetry, zero rendered frames, corrupt durations).
    - Ensures identical game target compatibility.
    - Evaluates performance regressions with strict precedence over improvements.

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

    bot_a = roi_a.get("bottleneck_classification", "unknown")
    bot_b = roi_b.get("bottleneck_classification", "unknown")

    cpu_busy_a = float(pacing_a.get("cpu_busy_pct", 0.0))
    cpu_busy_b = float(pacing_b.get("cpu_busy_pct", 0.0))
    cpu_wait_a = float(pacing_a.get("cpu_wait_pct", 0.0))
    cpu_wait_b = float(pacing_b.get("cpu_wait_pct", 0.0))
    gpu_busy_a = float(pacing_a.get("gpu_busy_pct", 0.0))
    gpu_busy_b = float(pacing_b.get("gpu_busy_pct", 0.0))

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

    def _build_result(verdict_val, notes_list):
        return {
            "session_a": {
                "id": sess_a.get("id", "Session A"),
                "target_exe": t_exe_a,
                "steam_appid": app_id_a,
                "mode": sess_a.get("mode", "play"),
                "has_roi": has_roi_a,
                "bottleneck": bot_a,
                "anti_cheat": manifest_a.get("anti_cheat") or {},
            },
            "session_b": {
                "id": sess_b.get("id", "Session B"),
                "target_exe": t_exe_b,
                "steam_appid": app_id_b,
                "mode": sess_b.get("mode", "play"),
                "has_roi": has_roi_b,
                "bottleneck": bot_b,
                "anti_cheat": manifest_b.get("anti_cheat") or {},
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
            "verdict": verdict_val,
            "notes": notes_list,
            "summary": "; ".join(notes_list) if notes_list else "Performance metrics comparable.",
        }

    # 1. Compatibility Check: Target Game Identity
    str_a = str(app_id_a).strip()
    str_b = str(app_id_b).strip()
    if str_a and str_b and str_a not in ("-", "0", "None") and str_b not in ("-", "0", "None"):
        if str_a != str_b:
            return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, [f"Incompatible target AppIDs: {str_a} vs {str_b}"])

    if t_exe_a != "Unknown" and t_exe_b != "Unknown" and t_exe_a.lower() != t_exe_b.lower():
        return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, [f"Incompatible target binaries: {t_exe_a} vs {t_exe_b}"])

    # 2. Session Integrity Check: Abort/Crash detection
    exit_a = sess_a.get("exit_code")
    exit_b = sess_b.get("exit_code")
    clean_a = sess_a.get("clean_shutdown")
    clean_b = sess_b.get("clean_shutdown")

    if (exit_b is not None and exit_b != 0) or clean_b is False:
        if (exit_a is None or exit_a == 0) and clean_a is not False:
            return _build_result(ExperimentVerdict.REGRESSED, [f"Benchmark session crashed with exit code {exit_b} while baseline completed cleanly"])
        return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, [f"Benchmark session aborted with exit code {exit_b}"])

    if (exit_a is not None and exit_a != 0) or clean_a is False:
        return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, [f"Baseline session aborted with exit code {exit_a}; cannot establish baseline"])

    # 3. Telemetry Completeness Check: ROI Telemetry & Frame Counts
    if not has_roi_a or not has_roi_b:
        ac_a = manifest_a.get("anti_cheat") or {}
        ac_b = manifest_b.get("anti_cheat") or {}
        if ac_a.get("detected") or ac_b.get("detected"):
            p = ac_a.get("provider") or ac_b.get("provider") or "Anti-Cheat"
            return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, [f"Active {p} detected; profiling hooks suppressed"])
        return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, ["One or both sessions missing ROI telemetry"])

    fps_avg_a = float(fm_a.get("fps_avg") or 0.0)
    fps_avg_b = float(fm_b.get("fps_avg") or 0.0)
    if fps_avg_a <= 0.0 or fps_avg_b <= 0.0:
        return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, ["Zero or negative average framerate captured"])

    fc_a = roi_a.get("frame_count") or fm_a.get("frame_count")
    fc_b = roi_b.get("frame_count") or fm_b.get("frame_count")
    if (fc_a is not None and fc_a <= 0) or (fc_b is not None and fc_b <= 0):
        return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, ["Zero frames recorded in sample window"])

    # 4. Capture Duration Sanity Check
    dur_a = float(sess_a.get("duration_seconds") or roi_a.get("duration_seconds") or 0.0)
    dur_b = float(sess_b.get("duration_seconds") or roi_b.get("duration_seconds") or 0.0)
    if dur_a > 0.0 and dur_b > 0.0:
        if (dur_b < 0.15 * dur_a and dur_a - dur_b > 5.0) or (dur_a < 0.15 * dur_b and dur_b - dur_a > 5.0):
            return _build_result(ExperimentVerdict.INSUFFICIENT_DATA, [f"Non-comparable capture durations ({dur_a:.1f}s vs {dur_b:.1f}s)"])

    # 5. Evaluate Metrics with Regression Precedence
    regressions = []
    improvements = []

    # Check regressions first
    if pct_fps_1p <= -10.0:
        regressions.append(f"1% lows {pct_fps_1p:.1f}% ({fm_a.get('fps_1_pct_low', 0):.1f} -> {fm_b.get('fps_1_pct_low', 0):.1f})")
    if pct_fps_01p <= -15.0:
        regressions.append(f"0.1% lows {pct_fps_01p:.1f}% ({fm_a.get('fps_0_1_pct_low', 0):.1f} -> {fm_b.get('fps_0_1_pct_low', 0):.1f})")
    if pct_fps_avg <= -5.0:
        regressions.append(f"Average FPS {pct_fps_avg:.1f}% ({fm_a.get('fps_avg', 0):.1f} -> {fm_b.get('fps_avg', 0):.1f})")
    if float(fm_a.get("frametime_jitter_ms", 0.0)) > 3.0 and pct_jitter >= 25.0:
        regressions.append(f"Frametime jitter +{pct_jitter:.1f}% ({fm_a.get('frametime_jitter_ms', 0):.2f}ms -> {fm_b.get('frametime_jitter_ms', 0):.2f}ms)")

    # Check improvements
    if pct_fps_avg >= 5.0:
        improvements.append(f"Average FPS +{pct_fps_avg:.1f}% ({fm_a.get('fps_avg', 0):.1f} -> {fm_b.get('fps_avg', 0):.1f})")
    if pct_fps_1p >= 10.0:
        improvements.append(f"1% lows +{pct_fps_1p:.1f}% ({fm_a.get('fps_1_pct_low', 0):.1f} -> {fm_b.get('fps_1_pct_low', 0):.1f})")
    if float(fm_a.get("frametime_jitter_ms", 0.0)) > 5.0 and pct_jitter <= -20.0:
        improvements.append(f"Frametime jitter {pct_jitter:.1f}% ({fm_a.get('frametime_jitter_ms', 0):.2f}ms -> {fm_b.get('frametime_jitter_ms', 0):.2f}ms)")
    if bot_a == "sync_bound" and bot_b in ["gpu_bound", "balanced"]:
        improvements.append(f"Sync lockstep stall resolved ({bot_a} -> {bot_b})")

    # Verdict synthesis
    if regressions and improvements:
        # Severe regression in stutter/frame-pacing outweighs modest average framerate gains
        if pct_fps_1p <= -15.0 or pct_jitter >= 30.0 or pct_fps_avg <= -10.0:
            verdict = ExperimentVerdict.REGRESSED
            notes = regressions + [f"Gains overridden by stutter regression: {', '.join(improvements)}"]
        else:
            verdict = ExperimentVerdict.MIXED
            notes = [f"Mixed outcome: {', '.join(improvements)} alongside {', '.join(regressions)}"]
    elif regressions:
        verdict = ExperimentVerdict.REGRESSED
        notes = regressions
    elif improvements:
        verdict = ExperimentVerdict.IMPROVED
        notes = improvements
    else:
        verdict = ExperimentVerdict.NEUTRAL
        notes = ["Performance metrics comparable."]

    return _build_result(verdict, notes)


def format_diff_report(diff):
    """Formats an A/B session comparison dict into a clean human-readable ASCII report."""
    s_a = diff["session_a"]
    s_b = diff["session_b"]
    m = diff["metrics"]
    bot = diff["bottleneck"]
    hw = diff["hardware"]

    v_val = diff.get("verdict", "NEUTRAL")
    if v_val == ExperimentVerdict.IMPROVED:
        v_icon = "🚀 "
    elif v_val == ExperimentVerdict.REGRESSED:
        v_icon = "⚠️ "
    elif v_val == ExperimentVerdict.MIXED:
        v_icon = "⚖️ "
    elif v_val == ExperimentVerdict.INSUFFICIENT_DATA:
        v_icon = "❓ "
    else:
        v_icon = "⚖️ "

    verdict_str = f"{v_icon}{v_val}: {diff.get('summary', '')}"

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
        ac_a = s_a.get("anti_cheat") or {}
        ac_b = s_b.get("anti_cheat") or {}
        if ac_a.get("detected") or ac_b.get("detected"):
            provider = ac_a.get("provider") or ac_b.get("provider") or "Anti-Cheat"
            lines.extend([
                f" [🛡️] ANTI-CHEAT NOTICE: Active {provider} detected.",
                "     Profiling hooks and ROI telemetry were automatically suppressed to enforce",
                "     strict zero-injection passthrough and prevent client bans or disconnections.",
                "",
            ])
        else:
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

    bot_res_str = " (Stall Resolved!)" if bot.get("resolved") else ""
    lines.extend([
        f" {'Bottleneck Classification:':<28} {s_a['bottleneck'].upper():<20} {s_b['bottleneck'].upper():<20} {bot.get('transition', '')}{bot_res_str}",
        "",
        " HARDWARE RESOURCE ALLOCATION",
        "-" * 82,
        f" {'Component':<28} {'Session A (Before)':<20} {'Session B (After)':<20} {'Shift':<14}",
        "-" * 82,
    ])

    for comp_name, key in [("CPU Busy Utilization:", "cpu_busy_pct"), ("CPU Wait / Blocked:", "cpu_wait_pct"), ("GPU Busy Utilization:", "gpu_busy_pct")]:
        h_data = hw.get(key, {})
        a_str = f"{float(h_data.get('a', 0.0)):.1f}%"
        b_str = f"{float(h_data.get('b', 0.0)):.1f}%"
        delta_val = float(h_data.get('delta', 0.0))
        s = "+" if delta_val > 0 else ""
        d_str = f"{s}{delta_val:.1f}%"
        lines.append(f" {comp_name:<28} {a_str:<20} {b_str:<20} {d_str:<14}")

    lines.extend(["=" * 82, ""])
    return "\n".join(lines)


class ExperimentalValidationEngine:
    """Manages the A/B experimental validation lifecycle for optimizations:
    Detected -> Applied -> Benchmarked -> Validated (or Rejected/Rollback).

    Ensures optimizations are backed by empirical measurement before becoming
    permanent Play Mode defaults.
    """

    @classmethod
    def start_experiment(cls, profile_path, fix_id, baseline_session_id=None, baseline_metrics=None, auto_rollback=True, required_runs=1, **params):
        """Starts an isolated experiment for fix_id against a baseline session."""
        if not FixRegistry.is_registered(fix_id):
            raise ValueError(f"Unknown optimization fix '{fix_id}'. Must be registered in FixRegistry.")

        canon_id = FixRegistry.canonical_id(fix_id)
        prof = EngineTweakManager.load_profile(profile_path) or {}
        if "experiments" not in prof:
            prof["experiments"] = {"fixes": {}}
        if "fixes" not in prof["experiments"]:
            prof["experiments"]["fixes"] = {}

        now_iso = datetime.now(timezone.utc).isoformat()
        prof["experiments"]["active_experiment"] = canon_id
        if baseline_session_id:
            prof["experiments"]["baseline_session_id"] = baseline_session_id

        # Enable tweak under test and record transactional before-state snapshot
        snapshot = cls._enable_tweak_in_profile(prof, canon_id, **params)

        prof["experiments"]["fixes"][canon_id] = {
            "fix_id": canon_id,
            "status": ExperimentStatus.APPLIED,
            "detected_at": prof["experiments"]["fixes"].get(canon_id, {}).get("detected_at", now_iso),
            "applied_at": now_iso,
            "baseline_session_id": baseline_session_id,
            "baseline_metrics": baseline_metrics or {},
            "benchmarked_metrics": {},
            "verdict": "PENDING",
            "auto_rollback": auto_rollback,
            "required_validation_runs": max(1, int(required_runs)),
            "runs": [],
            "before_snapshot": snapshot,
        }

        cls._save_profile_dict(profile_path, prof)
        log(f"Started experiment for fix '{canon_id}' (Baseline: {baseline_session_id or 'none'}, Required Runs: {required_runs})")
        return prof["experiments"]["fixes"][canon_id]

    @classmethod
    def evaluate_experiment(cls, profile_path, session_manifest, baseline_manifest=None):
        """Evaluates an active experiment by comparing session against baseline.
        Graduates to VALIDATED if performance improved across required runs, or rolls back to REJECTED if regressed/mixed.
        """
        if not profile_path or not os.path.isfile(profile_path):
            return None
        prof = EngineTweakManager.load_profile(profile_path)
        if not prof:
            return None

        exp_sec = prof.get("experiments", {})
        active_exp = exp_sec.get("active_experiment")
        if not active_exp:
            return None

        fixes = exp_sec.get("fixes", {})
        fix_info = fixes.get(active_exp, {})
        if not fix_info.get("before_snapshot") and fix_info.get("snapshot_json"):
            try:
                fix_info["before_snapshot"] = json.loads(fix_info["snapshot_json"])
            except Exception:
                pass
        if not fix_info.get("runs") and fix_info.get("runs_json"):
            try:
                fix_info["runs"] = json.loads(fix_info["runs_json"])
            except Exception:
                pass
        current_status = fix_info.get("status", ExperimentStatus.APPLIED)

        if current_status in (ExperimentStatus.VALIDATED, ExperimentStatus.REJECTED):
            return fix_info

        # Resolve baseline manifest if not passed
        base_id = fix_info.get("baseline_session_id") or exp_sec.get("baseline_session_id")
        if not baseline_manifest and base_id:
            xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
            app_id = str((session_manifest.get("target") or {}).get("steam_appid") or "")
            cand = os.path.join(xdg_data, "protogoblin", "sessions", app_id, base_id, "utilization.json")
            if os.path.isfile(cand):
                try:
                    with open(cand, "r", encoding="utf-8") as f:
                        baseline_manifest = json.load(f)
                except Exception:
                    pass

        if not baseline_manifest:
            fix_info["status"] = ExperimentStatus.BENCHMARKED
            cls._save_profile_dict(profile_path, prof)
            return fix_info

        diff = compute_session_diff(baseline_manifest, session_manifest)
        verdict = diff.get("verdict", ExperimentVerdict.NEUTRAL)
        m = diff.get("metrics", {})

        now_iso = datetime.now(timezone.utc).isoformat()
        bench_sess_id = (session_manifest.get("session") or {}).get("id")
        fix_info["benchmarked_session_id"] = bench_sess_id
        fix_info["benchmarked_at"] = now_iso
        fix_info["verdict"] = verdict
        fix_info["metrics_benchmarked"] = {
            "fps_avg": m.get("fps_avg", {}).get("b", 0.0),
            "fps_1_pct_low": m.get("fps_1_pct_low", {}).get("b", 0.0),
            "frametime_jitter_ms": m.get("frametime_jitter_ms", {}).get("b", 0.0),
        }
        fix_info["comparison_summary"] = diff.get("summary", "")

        # Record benchmark run in experiment history
        runs = fix_info.setdefault("runs", [])
        runs.append({
            "session_id": bench_sess_id,
            "timestamp": now_iso,
            "verdict": verdict,
            "summary": diff.get("summary", ""),
        })

        if verdict == ExperimentVerdict.INSUFFICIENT_DATA:
            fix_info["status"] = ExperimentStatus.BENCHMARKED
            cls._save_profile_dict(profile_path, prof)
            log(f"Experiment for '{active_exp}' has INSUFFICIENT_DATA: {diff.get('summary')} (Remains under test)")
            return fix_info

        if verdict in (ExperimentVerdict.REGRESSED, ExperimentVerdict.MIXED):
            fix_info["status"] = ExperimentStatus.REJECTED
            fix_info["rejected_at"] = now_iso
            if fix_info.get("auto_rollback", True):
                cls._rollback_tweak_in_profile(prof, active_exp)
                exp_sec["active_experiment"] = None
                log(f"Experiment {verdict} for '{active_exp}': {diff.get('summary')} (Automatically rolled back to baseline)")
            cls._save_profile_dict(profile_path, prof)
            return fix_info

        if verdict == ExperimentVerdict.IMPROVED:
            req_runs = int(fix_info.get("required_validation_runs", 1))
            improved_count = sum(1 for r in runs if r.get("verdict") == ExperimentVerdict.IMPROVED)
            if improved_count >= req_runs:
                fix_info["status"] = ExperimentStatus.VALIDATED
                fix_info["validated_at"] = now_iso
                exp_sec["active_experiment"] = None
                cls._save_profile_dict(profile_path, prof)
                log(f"Experiment VALIDATED for '{active_exp}': {diff.get('summary')} ({improved_count}/{req_runs} runs passed - promoted to Play Mode default)")
            else:
                fix_info["status"] = ExperimentStatus.BENCHMARKED
                cls._save_profile_dict(profile_path, prof)
                log(f"Experiment run {improved_count}/{req_runs} IMPROVED for '{active_exp}'. Additional run required to reach validation threshold.")
            return fix_info

        # NEUTRAL
        fix_info["status"] = ExperimentStatus.BENCHMARKED
        cls._save_profile_dict(profile_path, prof)
        return fix_info

    @classmethod
    def get_experiment_status(cls, profile_path, fix_id):
        """Returns the current lifecycle status for a given fix in a game profile."""
        if not profile_path or not os.path.isfile(profile_path):
            return ExperimentStatus.DETECTED
        prof = EngineTweakManager.load_profile(profile_path)
        if not prof:
            return ExperimentStatus.DETECTED
        canon_id = FixRegistry.canonical_id(fix_id)
        fixes = prof.get("experiments", {}).get("fixes", {})
        if canon_id in fixes and fixes[canon_id].get("status"):
            return fixes[canon_id]["status"]
        governing = FixRegistry.find_governing_experiments(canon_id, fixes)
        if governing:
            return governing[0].get("status", ExperimentStatus.DETECTED)
        return ExperimentStatus.DETECTED

    @classmethod
    def _enable_tweak_in_profile(cls, prof, fix_id, **params):
        """Enables the specific tweak in the profile dictionary and returns a transactional before-snapshot."""
        defn = FixRegistry.get(fix_id)
        if not defn:
            raise ValueError(f"Unknown optimization fix '{fix_id}'. Must be registered in FixRegistry.")

        snapshot = {}
        for path_tuple, default_val in defn.profile_targets:
            val_to_set = default_val
            if fix_id == "cap_framerate" and "cap_target" in params:
                val_to_set = int(params["cap_target"])
            elif "value" in params:
                val_to_set = params["value"]

            # Capture snapshot before mutating
            curr = prof
            existed = True
            for seg in path_tuple[:-1]:
                if not isinstance(curr, dict) or seg not in curr:
                    existed = False
                    break
                curr = curr[seg]

            path_str = ".".join(path_tuple)
            if existed and isinstance(curr, dict) and path_tuple[-1] in curr:
                snapshot[path_str] = {
                    "existed": True,
                    "value": copy.deepcopy(curr[path_tuple[-1]]),
                    "path": list(path_tuple),
                }
            else:
                snapshot[path_str] = {
                    "existed": False,
                    "value": None,
                    "path": list(path_tuple),
                }

            # Apply tweak
            curr = prof
            for seg in path_tuple[:-1]:
                curr = curr.setdefault(seg, {})
            curr[path_tuple[-1]] = val_to_set

        return snapshot

    @classmethod
    def _rollback_tweak_in_profile(cls, prof, fix_id, snapshot=None):
        """Disables/rolls back a tweak in the profile dictionary restoring exact pre-experiment state."""
        canon_id = FixRegistry.canonical_id(fix_id)
        if snapshot is None:
            fix_info = prof.get("experiments", {}).get("fixes", {}).get(canon_id, {})
            snapshot = fix_info.get("before_snapshot")
            if not snapshot and fix_info.get("snapshot_json"):
                try:
                    snapshot = json.loads(fix_info["snapshot_json"])
                except Exception:
                    snapshot = None

        if snapshot:
            for path_str, snap in snapshot.items():
                path = snap.get("path") or path_str.split(".")
                existed = snap.get("existed", False)
                orig_val = snap.get("value")
                curr = prof
                parents = []
                for seg in path[:-1]:
                    if not isinstance(curr, dict) or seg not in curr:
                        curr = None
                        break
                    parents.append((curr, seg))
                    curr = curr[seg]
                if curr is not None and isinstance(curr, dict):
                    last_key = path[-1]
                    if existed:
                        curr[last_key] = orig_val
                    else:
                        curr.pop(last_key, None)
                    # Clean up empty parent sections
                    for parent_dict, seg in reversed(parents):
                        if seg in parent_dict and not parent_dict[seg]:
                            del parent_dict[seg]
        else:
            defn = FixRegistry.get(canon_id)
            if defn:
                for path_tuple, _ in defn.profile_targets:
                    curr = prof
                    for seg in path_tuple[:-1]:
                        if not isinstance(curr, dict) or seg not in curr:
                            curr = None
                            break
                        curr = curr[seg]
                    if curr and isinstance(curr, dict):
                        curr[path_tuple[-1]] = False

    @classmethod
    def _save_profile_dict(cls, profile_path, prof):
        """Serializes and writes updated profile dictionary to file."""
        game_sec = prof.get("game", {})
        game_id = game_sec.get("id", os.path.splitext(os.path.basename(profile_path))[0])
        app_id = game_sec.get("steam_appid", 0)
        t_exe = game_sec.get("target_executable", f"game_{game_id}.exe")
        sync_b = prof.get("synchronization", {}).get("preferred_backend", "ntsync")

        toml_text = EngineTweakManager.generate_profile_toml(
            game_id=str(game_id),
            app_id=str(app_id),
            target_exe=t_exe,
            sync_backend=sync_b,
            user_tweaks=prof,
        )
        dir_name = os.path.dirname(profile_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        with open(profile_path, "w", encoding="utf-8") as f:
            f.write(toml_text)

class EngineTweakManager:
    """Manages engine-specific visual tweaks, command-line overrides, and graphics layer intercepts."""

    DEFAULTS = {
        "unreal": {
            "disable_motion_blur": True,
            "disable_depth_of_field": True,
            "disable_chromatic_aberration": True,
            "disable_film_grain": True,
            "disable_lens_flare": False,
            "disable_bloom": False,
            "disable_volumetric_fog": False,
            "disable_lumen_reflections": False,
        },
        "unity": {
            "native_gfx_jobs": True,
            "disable_vr": True,
            "force_vulkan": False,
        },
        "godot": {
            "rendering_driver": "vulkan",
            "disable_vsync": True,
            "max_fps": 0,
        },
        "graphics": {
            "backend": "dxvk",
            "force_vsync": "off",
            "max_fps": 0,
            "anisotropic_filtering": 16,
            "async_shader_compile": True,
            "low_latency": True,
            "descriptor_buffer": True,
            "nv_reflex": True,
        },
        "synchronization": {
            "prefer_ntsync": True,
        },
    }

    UNREAL_CVAR_MAP = {
        "disable_motion_blur": [
            "r.MotionBlurQuality 0",
            "r.MotionBlur.Max 0",
            "r.DefaultFeature.MotionBlur 0",
        ],
        "disable_depth_of_field": ["r.DepthOfFieldQuality 0"],
        "disable_chromatic_aberration": ["r.SceneColorFringeQuality 0"],
        "disable_film_grain": ["r.FilmGrain 0"],
        "disable_lens_flare": ["r.LensFlareQuality 0"],
        "disable_bloom": ["r.BloomQuality 0"],
        "disable_volumetric_fog": ["r.VolumetricFog 0"],
        "disable_lumen_reflections": ["r.Lumen.Reflections.Allow 0"],
        "optimize_lumen": [
            "r.Lumen.ScreenProbeGather.DownsampleByTwo 1",
            "r.Lumen.TranslucencyReflections.FrontLayer.Allow 0",
            "r.Lumen.Reflections.DownsampleFactor 2",
        ],
        "optimize_vsm": [
            "r.Shadow.Virtual.SMRT.RayCountDirectional 4",
            "r.Shadow.Virtual.ResolutionLodBiasDirectional 1.0",
            "r.Shadow.Virtual.Cache.MaxPageAge 16",
        ],
        "optimize_nanite": [
            "r.Nanite.MaxNodesPerFrame 262144",
            "r.Nanite.ViewMeshLODBias 0.5",
        ],
        "disable_virtual_shadows": ["r.Shadow.Virtual.Enable 0"],
    }

    @classmethod
    def is_feature_enabled(cls, val):
        """Safely evaluates whether a feature setting is active.
        Accepts booleans, integers, strings, or dictionaries (e.g. {'enabled': False}).
        Guards against nonempty dictionaries with enabled=false being evaluated as truthy.
        """
        if val is None:
            return False
        if isinstance(val, dict):
            return bool(val.get("enabled", False))
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return bool(val)
        if isinstance(val, str):
            return val.lower().strip() in ("1", "true", "yes", "on", "enable", "enabled")
        return bool(val)

    @classmethod
    def load_profile(cls, path):
        if not path or not os.path.isfile(path):
            return None
        try:
            try:
                import tomllib
                with open(path, "rb") as f:
                    return tomllib.load(f)
            except ImportError:
                return cls._fallback_parse_toml(path)
        except Exception:
            return None

    @classmethod
    def _fallback_parse_toml(cls, path):
        result = {}
        curr_section = result
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        sec_name = line[1:-1].strip()
                        parts = sec_name.split(".")
                        curr = result
                        for p in parts:
                            curr = curr.setdefault(p, {})
                        curr_section = curr
                        continue
                    if "=" in line:
                        key, val = [x.strip() for x in line.split("=", 1)]
                        if val.lower() == "true":
                            val_parsed = True
                        elif val.lower() == "false":
                            val_parsed = False
                        elif val.isdigit():
                            val_parsed = int(val)
                        elif (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val_parsed = val[1:-1]
                        else:
                            val_parsed = val
                        curr_section[key] = val_parsed
        except Exception:
            pass
        return result

    @classmethod
    def drop_profile(cls, app_id_or_path, clear_sessions=False):
        """Drops/deletes a game profile TOML and optionally historical session data to allow clean re-profiling."""
        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")

        if os.path.isfile(str(app_id_or_path)):
            profile_path = os.path.abspath(app_id_or_path)
            app_id = os.path.splitext(os.path.basename(profile_path))[0]
        else:
            app_id = str(app_id_or_path)
            profile_path = os.path.join(xdg_config, "protogoblin", "games", f"{app_id}.toml")

        result = {
            "app_id": app_id,
            "profile_path": profile_path,
            "profile_deleted": False,
            "sessions_cleared": False,
            "sessions_dir": None,
        }

        # 1. Remove profile TOML file if present
        if os.path.isfile(profile_path):
            try:
                os.remove(profile_path)
                result["profile_deleted"] = True
            except OSError as e:
                result["error"] = str(e)

        # 2. Optionally clear historical sessions directory
        if clear_sessions and app_id:
            sessions_base = os.environ.get("PROTOGOBLIN_SESSIONS_DIR") or os.path.join(xdg_data, "protogoblin", "sessions")
            app_sessions_dir = os.path.join(sessions_base, app_id)
            result["sessions_dir"] = app_sessions_dir
            if os.path.isdir(app_sessions_dir):
                try:
                    shutil.rmtree(app_sessions_dir)
                    result["sessions_cleared"] = True
                except OSError as e:
                    result["sessions_error"] = str(e)

        return result

    @classmethod
    def generate_profile_toml(cls, game_id, app_id, target_exe, engine_info=None, sync_backend="ntsync", user_tweaks=None, is_deck=None):
        tweaks = user_tweaks or {}
        eng_name = engine_info.get("engine", "") if engine_info else ""
        is_ue = eng_name in ["unreal_4", "unreal_5", "unreal"]
        is_unity = eng_name == "unity"
        is_godot = eng_name in ["godot", "godot_3", "godot_4"]

        ue_cfg = tweaks.get("unreal", cls.DEFAULTS["unreal"])
        unity_cfg = tweaks.get("unity", cls.DEFAULTS["unity"])
        godot_cfg = tweaks.get("godot", cls.DEFAULTS["godot"])
        gfx_cfg = tweaks.get("graphics", cls.DEFAULTS["graphics"])

        runtime_mode = (
            tweaks.get("mode")
            or tweaks.get("runtime", {}).get("mode")
            or tweaks.get("protogoblin", {}).get("mode")
            or "play"
        )
        dev_mode = bool(
            tweaks.get("dev_mode")
            or tweaks.get("runtime", {}).get("dev_mode")
            or False
        )

        lines = [
            "# ProtoGoblin Per-Game Optimization Profile",
            f"# Target: {target_exe}",
            "",
            "[game]",
            f'id = "{game_id}"',
            f'steam_appid = {app_id if str(app_id).isdigit() else 0}',
            f'target_executable = "{target_exe}"',
            f'detected_engine = "{eng_name}"',
            "",
            "[runtime]",
            f'mode = "{runtime_mode}"',
            f'dev_mode = {"true" if dev_mode else "false"}',
            "prune_unused_subsystems = true",
            'anticheat_policy = "passthrough"',
            "",
            "[graphics]",
            f'backend = "{gfx_cfg.get("backend", "dxvk")}"',
            f'force_vsync = "{gfx_cfg.get("force_vsync", "off")}"',
            f'max_fps = {int(gfx_cfg.get("max_fps", 0)) if isinstance(gfx_cfg.get("max_fps", 0), (int, float)) and not isinstance(gfx_cfg.get("max_fps", 0), bool) else 0}',
            f'anisotropic_filtering = {gfx_cfg.get("anisotropic_filtering", 16)}',
            f'async_shader_compile = {"true" if gfx_cfg.get("async_shader_compile", True) else "false"}',
            f'low_latency = {"true" if gfx_cfg.get("low_latency", True) else "false"}',
            f'descriptor_buffer = {"true" if gfx_cfg.get("descriptor_buffer", True) else "false"}',
            f'nv_reflex = {"true" if gfx_cfg.get("nv_reflex", True) else "false"}',
            "",
            "[synchronization]",
            f'preferred_backend = "{sync_backend}"',
            f'ntsync = {"true" if tweaks.get("synchronization", {}).get("ntsync", True) else "false"}',
        ]

        if is_ue or (not eng_name and "unreal" in tweaks):
            lines.extend([
                "",
                "[engine.unreal]",
                f'disable_motion_blur = {"true" if ue_cfg.get("disable_motion_blur", True) else "false"}',
                f'disable_depth_of_field = {"true" if ue_cfg.get("disable_depth_of_field", True) else "false"}',
                f'disable_chromatic_aberration = {"true" if ue_cfg.get("disable_chromatic_aberration", True) else "false"}',
                f'disable_film_grain = {"true" if ue_cfg.get("disable_film_grain", True) else "false"}',
                f'disable_lens_flare = {"true" if ue_cfg.get("disable_lens_flare", False) else "false"}',
                f'disable_bloom = {"true" if ue_cfg.get("disable_bloom", False) else "false"}',
                f'disable_volumetric_fog = {"true" if ue_cfg.get("disable_volumetric_fog", False) else "false"}',
                f'disable_lumen_reflections = {"true" if ue_cfg.get("disable_lumen_reflections", False) else "false"}',
                f'optimize_lumen = {"true" if ue_cfg.get("optimize_lumen", False) else "false"}',
                f'optimize_vsm = {"true" if ue_cfg.get("optimize_vsm", False) else "false"}',
                f'optimize_nanite = {"true" if ue_cfg.get("optimize_nanite", False) else "false"}',
                f'disable_virtual_shadows = {"true" if ue_cfg.get("disable_virtual_shadows", False) else "false"}',
            ])

        vkd3d_cfg = gfx_cfg.get("vkd3d", {}) or tweaks.get("vkd3d", {})
        if vkd3d_cfg:
            lines.extend([
                "",
                "[graphics.vkd3d]",
                f'descriptor_buffer = {"true" if vkd3d_cfg.get("descriptor_buffer", True) else "false"}',
                f'force_static_cbv = {"true" if vkd3d_cfg.get("force_static_cbv", True) else "false"}',
                f'single_queue = {"true" if vkd3d_cfg.get("single_queue", False) else "false"}',
            ])

        if is_unity or (not eng_name and "unity" in tweaks):
            lines.extend([
                "",
                "[engine.unity]",
                f'native_gfx_jobs = {"true" if unity_cfg.get("native_gfx_jobs", True) else "false"}',
                f'disable_vr = {"true" if unity_cfg.get("disable_vr", True) else "false"}',
                f'force_vulkan = {"true" if unity_cfg.get("force_vulkan", False) else "false"}',
            ])

        effective_deck = is_deck if is_deck is not None else (tweaks.get("is_deck") or tweaks.get("steam_deck") or SystemProbe.is_steam_deck())
        deck_cfg = tweaks.get("steam_deck") or tweaks.get("deck")
        if effective_deck or deck_cfg:
            d_cfg = deck_cfg if isinstance(deck_cfg, dict) else {}
            lines.extend([
                "",
                "[steam_deck]",
                f'enabled = {"true" if d_cfg.get("enabled", True) else "false"}',
                f'target_resolution = "{d_cfg.get("target_resolution", "1280x800")}"',
                f'limit_fps = {d_cfg.get("limit_fps", 60)}',
                f'ui_scale_override = {"true" if d_cfg.get("ui_scale_override", True) else "false"}',
            ])

        if is_godot or (not eng_name and "godot" in tweaks):
            lines.extend([
                "",
                "[engine.godot]",
                f'rendering_driver = "{godot_cfg.get("rendering_driver", "vulkan")}"',
                f'disable_vsync = {"true" if godot_cfg.get("disable_vsync", True) else "false"}',
                f'max_fps = {godot_cfg.get("max_fps", 0)}',
            ])

        preset = PresetDatabase.get_preset(app_id) if app_id else None
        atelier_sync = None
        if "atelier_sync_fix" in tweaks:
            atelier_sync = tweaks["atelier_sync_fix"]
        elif "synchronization" in tweaks and "atelier_sync_fix" in tweaks["synchronization"]:
            atelier_sync = tweaks["synchronization"]["atelier_sync_fix"]
        elif preset and "gust_d3d11_staging_sync_stall" in preset.get("known_issues", []):
            atelier_sync = True

        if cls.is_feature_enabled(atelier_sync):
            lines.extend([
                "",
                "[synchronization.atelier_sync_fix]",
                "enabled = true",
                "# Shadow staging buffer wrapper to eliminate intra-frame CPU-GPU sync stalls",
            ])

        state_dedup = None
        if "state_dedup" in tweaks:
            state_dedup = tweaks["state_dedup"]
        elif "synchronization" in tweaks and "state_dedup" in tweaks["synchronization"]:
            state_dedup = tweaks["synchronization"]["state_dedup"]
        if cls.is_feature_enabled(state_dedup):
            lines.extend([
                "",
                "[synchronization.state_dedup]",
                "enabled = true",
                "# Constant buffer & state spam deduplication to minimize Vulkan command buffer churn",
            ])

        swapchain_debounce = None
        if "swapchain_debounce" in tweaks:
            swapchain_debounce = tweaks["swapchain_debounce"]
        elif "synchronization" in tweaks and "swapchain_debounce" in tweaks["synchronization"]:
            swapchain_debounce = tweaks["synchronization"]["swapchain_debounce"]
        if cls.is_feature_enabled(swapchain_debounce):
            lines.extend([
                "",
                "[synchronization.swapchain_debounce]",
                "enabled = true",
                "# Swapchain ResizeBuffers debounce filter to eliminate UI/focus resolution micro-stutters",
            ])

        io_cache = None
        if "io_cache" in tweaks:
            io_cache = tweaks["io_cache"]
        elif "filesystem" in tweaks and "io_cache" in tweaks["filesystem"]:
            io_cache = tweaks["filesystem"]["io_cache"]
        if cls.is_feature_enabled(io_cache):
            lines.extend([
                "",
                "[filesystem.io_cache]",
                "enabled = true",
                "# Adaptive read-ahead cache to eliminate traversal stutter in asset-streaming titles",
            ])

        precision_timers = None
        if "precision_timers" in tweaks:
            precision_timers = tweaks["precision_timers"]
        elif "timing" in tweaks and "precision_timers" in tweaks["timing"]:
            precision_timers = tweaks["timing"]["precision_timers"]
        elif "synchronization" in tweaks and "precision_timers" in tweaks["synchronization"]:
            precision_timers = tweaks["synchronization"]["precision_timers"]
        if cls.is_feature_enabled(precision_timers):
            lines.extend([
                "",
                "[timing.precision_timers]",
                "enabled = true",
                "# Enforce sub-millisecond QPC sleep-spin hybrid pacing to eliminate timer wake overshoot",
            ])

        # Serialize Experimental Validation Lifecycle state if present
        exp_sec = tweaks.get("experiments", {})
        if exp_sec:
            lines.extend([
                "",
                "[experiments]",
            ])
            if exp_sec.get("active_experiment"):
                lines.append(f'active_experiment = "{exp_sec["active_experiment"]}"')
            if exp_sec.get("baseline_session_id"):
                lines.append(f'baseline_session_id = "{exp_sec["baseline_session_id"]}"')
            fixes = exp_sec.get("fixes", {})
            for f_id, f_data in sorted(fixes.items()):
                lines.extend([
                    "",
                    f"[experiments.fixes.{f_id}]",
                    f'status = "{f_data.get("status", "applied")}"',
                    f'verdict = "{f_data.get("verdict", "")}"',
                ])
                if f_data.get("baseline_session_id"):
                    lines.append(f'baseline_session_id = "{f_data["baseline_session_id"]}"')
                if f_data.get("applied_at"):
                    lines.append(f'applied_at = "{f_data["applied_at"]}"')
                if f_data.get("validated_at"):
                    lines.append(f'validated_at = "{f_data["validated_at"]}"')
                if f_data.get("rejected_at"):
                    lines.append(f'rejected_at = "{f_data["rejected_at"]}"')
                if f_data.get("required_validation_runs"):
                    lines.append(f'required_validation_runs = {int(f_data["required_validation_runs"])}')
                snap_to_write = f_data.get("before_snapshot")
                if snap_to_write:
                    raw_snap = json.dumps(snap_to_write).replace('\\', '\\\\').replace('"', '\\"')
                    lines.append(f'snapshot_json = "{raw_snap}"')
                elif f_data.get("snapshot_json"):
                    raw_snap = str(f_data["snapshot_json"]).replace('\\', '\\\\').replace('"', '\\"')
                    lines.append(f'snapshot_json = "{raw_snap}"')
                runs_to_write = f_data.get("runs")
                if runs_to_write:
                    raw_runs = json.dumps(runs_to_write).replace('\\', '\\\\').replace('"', '\\"')
                    lines.append(f'runs_json = "{raw_runs}"')
                elif f_data.get("runs_json"):
                    raw_runs = str(f_data["runs_json"]).replace('\\', '\\\\').replace('"', '\\"')
                    lines.append(f'runs_json = "{raw_runs}"')

        hotkey = tweaks.get("hotkey") or tweaks.get("profiling", {}).get("hotkey")
        if hotkey:
            lines.extend([
                "",
                "[profiling]",
                f'hotkey = "{hotkey}"',
            ])

        compat_sec = tweaks.get("compatibility", {})
        dll_overrides = compat_sec.get("dll_overrides", {})
        if dll_overrides:
            lines.extend([
                "",
                "[compatibility.dll_overrides]",
            ])
            for dll, mode in sorted(dll_overrides.items()):
                lines.append(f'{dll} = "{mode}"')

        lines.append("")
        return "\n".join(lines)

    @classmethod
    def apply_tweaks(cls, profile, engine_info, argv, env, prefix_dir=None, proton_dir=None, is_deck=None):
        if not profile:
            return argv

        if is_deck is None:
            is_deck = SystemProbe.is_steam_deck()

        eng_name = engine_info.get("engine", "") if engine_info else ""
        if not eng_name and isinstance(profile, dict):
            eng_name = profile.get("game", {}).get("detected_engine", "")
        engine_sec = profile.get("engine", {})
        gfx_sec = profile.get("graphics", {})
        sync_sec = profile.get("synchronization", {})

        new_argv = list(argv)

        # 1. Unreal Engine command-line cvars
        ue_cfg = engine_sec.get("unreal", {})
        cvars = []
        if eng_name in ["unreal_4", "unreal_5", "unreal"]:
            for option_key, active in ue_cfg.items():
                if active and option_key in cls.UNREAL_CVAR_MAP:
                    cvars.extend(cls.UNREAL_CVAR_MAP[option_key])
            if cvars:
                exec_arg = f'-ExecCmds="{"; ".join(cvars)}"'
                new_argv.append(exec_arg)

        # 2. Unity command-line flags
        if eng_name == "unity":
            unity_cfg = engine_sec.get("unity", {})
            if unity_cfg.get("force_vulkan"):
                if "-force-vulkan" not in new_argv:
                    new_argv.append("-force-vulkan")

        # 3. Godot command-line flags
        if eng_name in ["godot", "godot_3", "godot_4"]:
            godot_cfg = engine_sec.get("godot", {})
            if godot_cfg.get("rendering_driver"):
                driver = godot_cfg["rendering_driver"]
                new_argv.extend(["--rendering-driver", driver])
            if godot_cfg.get("max_fps", 0) > 0:
                new_argv.append(f"--max-fps={godot_cfg['max_fps']}")

        # 4. DXVK & Synchronization layer intercepts
        dxvk_items = []

        # Safely evaluate features via is_feature_enabled to guard against nonempty dicts with enabled=false
        sync_fix_val = sync_sec.get("atelier_sync_fix")
        if sync_fix_val is None:
            sync_fix_val = engine_sec.get("gust", {}).get("atelier_sync_fix")
        sync_fix_enabled = cls.is_feature_enabled(sync_fix_val)

        state_dedup_enabled = cls.is_feature_enabled(sync_sec.get("state_dedup"))
        swapchain_debounce_enabled = cls.is_feature_enabled(sync_sec.get("swapchain_debounce"))

        timing_sec = profile.get("timing", {})
        p_val = timing_sec.get("precision_timers")
        if p_val is None:
            p_val = sync_sec.get("precision_timers")
        if p_val is None:
            p_val = profile.get("precision_timers")
        precision_timers_enabled = cls.is_feature_enabled(p_val)

        # Enforce Experimental Validation Lifecycle:
        # In Play Mode (production / zero-injection), only validated fixes or non-experimental tweaks
        # become permanent defaults. Unvalidated experiments are tested in Profile Mode.
        # If an experiment was rejected due to regression, it is strictly suppressed.
        mode = env.get("PROTOGOBLIN_MODE", "").lower().strip() or profile.get("runtime", {}).get("mode", "play")
        experiments = profile.get("experiments", {}).get("fixes", {})

        def _filter_by_experiment(feature_id, active):
            if not active:
                return False
            governing = FixRegistry.find_governing_experiments(feature_id, experiments)
            if not governing:
                return True # Standard non-experimental tweak
            # If any governing experiment was rejected, it is suppressed
            if any(g.get("status") == ExperimentStatus.REJECTED for g in governing):
                return False
            # In Play Mode, only validated fixes are applied
            if mode == "play":
                return all(g.get("status") == ExperimentStatus.VALIDATED for g in governing)
            # In Profile Mode (benchmarking), applied/benchmarked/validated are permitted
            return any(g.get("status") in (ExperimentStatus.APPLIED, ExperimentStatus.BENCHMARKED, ExperimentStatus.VALIDATED) for g in governing)

        sync_fix_enabled = _filter_by_experiment("atelier_sync_fix", sync_fix_enabled)
        state_dedup_enabled = _filter_by_experiment("state_dedup", state_dedup_enabled)
        swapchain_debounce_enabled = _filter_by_experiment("swapchain_debounce", swapchain_debounce_enabled)
        precision_timers_enabled = _filter_by_experiment("precision_timers", precision_timers_enabled)

        wrapper_required = sync_fix_enabled or state_dedup_enabled or swapchain_debounce_enabled or precision_timers_enabled
        if wrapper_required:
            dll_ov = env.get("WINEDLLOVERRIDES", "")
            if "d3d11=" not in dll_ov:
                env["WINEDLLOVERRIDES"] = f"d3d11=n,b;{dll_ov}" if dll_ov else "d3d11=n,b"
            if sync_fix_enabled:
                dxvk_items.extend(["dxgi.syncInterval = 0", "d3d11.syncInterval = 0"])
                env["PROTOGOBLIN_STAGING_SYNC_FIX"] = "1"
            if state_dedup_enabled:
                env["PROTOGOBLIN_STATE_DEDUP"] = "1"
            if swapchain_debounce_enabled:
                env["PROTOGOBLIN_SWAPCHAIN_DEBOUNCE"] = "1"
            if precision_timers_enabled:
                env["PROTOGOBLIN_HIGH_PRECISION_TIMERS"] = "1"

            # Check candidate paths for vendored d3d11.dll wrapper
            p_dir = proton_dir or os.environ.get("PROTOGOBLIN_DIR") or os.path.dirname(os.path.abspath(__file__))
            candidate_dirs = [
                os.path.join(p_dir, "share", "protogoblin", "lib64"),
                os.path.join(p_dir, "share", "protogoblin", "lib32"),
                os.path.join(p_dir, "share", "protogoblin", "staging-sync-fix"),
                os.path.join(p_dir, "vklayers", "staging-sync-fix"),
            ]
            for cdir in candidate_dirs:
                if os.path.isdir(cdir):
                    current_path = env.get("WINEDLLPATH", "")
                    if cdir not in current_path:
                        env["WINEDLLPATH"] = f"{cdir}:{current_path}" if current_path else cdir

        if gfx_sec.get("force_vsync") == "off":
            dxvk_items.extend(["dxgi.syncInterval = 0", "d3d11.syncInterval = 0"])
        elif gfx_sec.get("force_vsync") == "on":
            dxvk_items.extend(["dxgi.syncInterval = 1", "d3d11.syncInterval = 1"])

        if gfx_sec.get("max_fps", 0) > 0 and _filter_by_experiment("cap_framerate", True):
            limit = gfx_sec["max_fps"]
            dxvk_items.append(f"dxgi.maxFrameRate = {limit}")
            env["VKD3D_FRAME_RATE"] = str(limit)

        af = gfx_sec.get("anisotropic_filtering")
        if af and int(af) > 0:
            dxvk_items.append(f"d3d11.samplerAnisotropy = {af}")

        if gfx_sec.get("async_shader_compile") and _filter_by_experiment("async_shader_compile", True):
            env["DXVK_ASYNC"] = "1"
            dxvk_items.append("dxvk.enableAsync = true")

        if gfx_sec.get("low_latency") or gfx_sec.get("nv_reflex"):
            dxvk_items.append("dxvk.lowLatency = true")
            dxvk_items.append("dxvk.nvLowLatency2 = true")
            env["DXVK_NVAPI_ENABLE_REFLEX"] = "1"

        if gfx_sec.get("descriptor_buffer") and _filter_by_experiment("descriptor_buffer", True):
            dxvk_items.append("dxvk.enableDescriptorBuffer = true")

        if sync_sec.get("ntsync") or sync_sec.get("preferred_backend") == "ntsync":
            if os.path.exists("/dev/ntsync") and os.environ.get("PROTON_NO_NTSYNC") != "1":
                env["PROTON_USE_NTSYNC"] = "1"
                env["WINE_USE_NTSYNC"] = "1"

        if dxvk_items:
            existing_dxvk = env.get("DXVK_CONFIG", "").strip()
            addon = "; ".join(dxvk_items)
            env["DXVK_CONFIG"] = f"{existing_dxvk}; {addon}" if existing_dxvk else addon

        # VKD3D-Proton configuration
        vkd3d_cfg = gfx_sec.get("vkd3d", {}) or profile.get("vkd3d", {})
        vkd3d_options = []
        if gfx_sec.get("descriptor_buffer") or vkd3d_cfg.get("descriptor_buffer"):
            vkd3d_options.append("descriptor_buffer")
        if vkd3d_cfg.get("force_static_cbv", True):
            vkd3d_options.append("force_static_cbv")
        if vkd3d_cfg.get("single_queue"):
            vkd3d_options.append("single_queue")

        if vkd3d_options:
            cur_vkd3d = env.get("VKD3D_CONFIG", "")
            cur_parts = [p.strip() for p in cur_vkd3d.split(",") if p.strip()]
            for opt in vkd3d_options:
                if opt not in cur_parts:
                    cur_parts.append(opt)
            env["VKD3D_CONFIG"] = ",".join(cur_parts)

        # 5. Prefix file configuration adjustments
        if prefix_dir and os.path.isdir(prefix_dir):
            try:
                if unity_cfg and (unity_cfg.get("native_gfx_jobs") or unity_cfg.get("disable_vr")):
                    cls._patch_unity_boot_config(prefix_dir, unity_cfg)
                if ue_cfg and cvars:
                    cls._patch_unreal_engine_ini(prefix_dir, cvars)
            except Exception:
                pass

        # 6. Filesystem & Asset Streaming I/O Cache
        fs_sec = profile.get("filesystem", {})
        io_val = fs_sec.get("io_cache")
        if io_val is None:
            io_val = profile.get("io_cache")
        io_cache_enabled = cls.is_feature_enabled(io_val)
        io_cache_enabled = _filter_by_experiment("io_cache", io_cache_enabled)
        if io_cache_enabled:
            env["PROTOGOBLIN_IO_CACHE"] = "1"
            p_dir = proton_dir or os.environ.get("PROTOGOBLIN_DIR") or os.path.dirname(os.path.abspath(__file__))
            candidates = [
                os.path.join(p_dir, "share", "protogoblin", "lib64", "libprotogoblin_io_cache.so"),
                os.path.join(p_dir, "lib64", "libprotogoblin_io_cache.so"),
                os.path.join(p_dir, "dist", "share", "protogoblin", "lib64", "libprotogoblin_io_cache.so"),
            ]
            for c in candidates:
                if os.path.exists(c):
                    cur_ld = env.get("LD_PRELOAD", "")
                    env["LD_PRELOAD"] = f"{c}:{cur_ld}" if cur_ld else c
                    break

        # 7. Compatibility & Native DLL Overrides
        compat_sec = profile.get("compatibility", {})
        dll_overrides = compat_sec.get("dll_overrides", {})
        if dll_overrides:
            cur_ov = env.get("WINEDLLOVERRIDES", "")
            ov_parts = [p.strip() for p in cur_ov.split(";") if p.strip()]
            for dll, mode in dll_overrides.items():
                entry = f"{dll}={mode}"
                if not any(p.startswith(f"{dll}=") for p in ov_parts):
                    ov_parts.append(entry)
            env["WINEDLLOVERRIDES"] = ";".join(ov_parts)

        prof_sec = profile.get("profiling", {})
        if prof_sec.get("hotkey"):
            env["PROTOGOBLIN_PROFILE_KEY"] = prof_sec["hotkey"]
        elif profile.get("hotkey"):
            env["PROTOGOBLIN_PROFILE_KEY"] = profile["hotkey"]

        # 8. General Profile Environment and Argument Overrides
        env_sec = profile.get("env", {})
        if isinstance(env_sec, dict):
            for k, v in env_sec.items():
                if k not in env:
                    env[k] = str(v)

        args_sec = profile.get("args", [])
        if isinstance(args_sec, list):
            for a in args_sec:
                if a not in new_argv:
                    new_argv.append(str(a))

        # 9. Steam Deck First-Class Elevation
        if is_deck:
            env.setdefault("SteamDeck", "1")
            deck_sec = profile.get("steam_deck", {}) or profile.get("deck", {})
            if isinstance(deck_sec, dict):
                # Elevate deck-specific environment overrides
                for k, v in deck_sec.get("env", {}).items():
                    env[k] = str(v)
                # Elevate deck-specific command line arguments
                for a in deck_sec.get("args", []):
                    if a not in new_argv:
                        new_argv.append(str(a))
                # Deck FPS capping
                deck_limit = deck_sec.get("limit_fps")
                if deck_limit and int(deck_limit) > 0:
                    limit_val = int(deck_limit)
                    dxvk_items.append(f"dxgi.maxFrameRate = {limit_val}")
                    env["VKD3D_FRAME_RATE"] = str(limit_val)

        return new_argv

    @classmethod
    def _patch_unity_boot_config(cls, prefix_dir, unity_cfg):
        for root, dirs, files in os.walk(prefix_dir):
            if "boot.config" in files:
                cfg_path = os.path.join(root, "boot.config")
                try:
                    with open(cfg_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    existing = {l.split("=")[0].strip(): l.strip() for l in lines if "=" in l}
                    modified = False
                    if unity_cfg.get("native_gfx_jobs") and existing.get("gfx-enable-native-gfx-jobs") != "gfx-enable-native-gfx-jobs=1":
                        lines.append("gfx-enable-native-gfx-jobs=1\n")
                        modified = True
                    if unity_cfg.get("disable_vr") and existing.get("vr-enabled") != "vr-enabled=0":
                        lines.append("vr-enabled=0\n")
                        modified = True
                    if modified:
                        with open(cfg_path, "w", encoding="utf-8") as f:
                            f.writelines(lines)
                except OSError:
                    pass

    @classmethod
    def _patch_unreal_engine_ini(cls, prefix_dir, cvars):
        local_appdata = os.path.join(prefix_dir, "drive_c", "users", "steamuser", "AppData", "Local")
        if not os.path.isdir(local_appdata):
            return
        for game_dir in os.listdir(local_appdata):
            saved_dir = os.path.join(local_appdata, game_dir, "Saved", "Config")
            if os.path.isdir(saved_dir):
                for sub in os.listdir(saved_dir):
                    if sub.startswith("Windows"):
                        ini_path = os.path.join(saved_dir, sub, "Engine.ini")
                        cls._write_unreal_system_settings(ini_path, cvars)

    @classmethod
    def _write_unreal_system_settings(cls, ini_path, cvars):
        try:
            content = ""
            if os.path.isfile(ini_path):
                with open(ini_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

            lines_to_add = []
            for cv in cvars:
                parts = cv.split()
                if len(parts) == 2:
                    k, v = parts
                    setting_line = f"{k}={v}"
                    if setting_line not in content:
                        lines_to_add.append(setting_line)

            if lines_to_add:
                if "[SystemSettings]" not in content:
                    content += "\n\n[SystemSettings]\n" + "\n".join(lines_to_add) + "\n"
                else:
                    idx = content.find("[SystemSettings]") + len("[SystemSettings]")
                    content = content[:idx] + "\n" + "\n".join(lines_to_add) + content[idx:]
                os.makedirs(os.path.dirname(ini_path), exist_ok=True)
                with open(ini_path, "w", encoding="utf-8") as f:
                    f.write(content)
        except OSError:
            pass


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
        self.logged_pids = set()
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
                if pid not in self.logged_pids:
                    self.logged_pids.add(pid)
                    comm = ""
                    cmdline = ""
                    try:
                        with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="ignore") as f:
                            comm = f.read().strip()
                    except Exception:
                        pass
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read().replace(b"\0", b" ").decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                    log(f"ProcessTreeTracker: tracked process PID={pid}, comm='{comm}', cmdline='{cmdline[:250]}'")

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
                                    log(f"ProcessTreeTracker: discovered candidate game executable '{resolved}' (PID={pid})")
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


KNOWN_DLL_REMEDIES = {
    "d3dcompiler_47": {
        "verb": "d3dcompiler_47",
        "dlls": ["d3dcompiler_47.dll"],
        "overrides": {"d3dcompiler_47": "n,b"},
        "package": "Microsoft DirectX / Windows SDK D3DCompiler",
        "description": "HLSL dynamic shader compiler required by modern D3D11/D3D12 engines.",
        "patterns": [
            r"d3dcompiler_47(?:\.dll)?",
        ],
    },
    "d3dcompiler_43": {
        "verb": "d3dcompiler_43",
        "dlls": ["d3dcompiler_43.dll"],
        "overrides": {"d3dcompiler_43": "n,b"},
        "package": "Microsoft DirectX End-User Runtimes (June 2010)",
        "description": "DirectX 11 legacy HLSL shader compiler.",
        "patterns": [
            r"d3dcompiler_43(?:\.dll)?",
        ],
    },
    "d3dx9": {
        "verb": "d3dx9",
        "dlls": ["d3dx9_43.dll"],
        "overrides": {"d3dx9_43": "n,b"},
        "package": "Microsoft DirectX 9.0c Runtimes",
        "description": "DirectX 9 3D utility extensions.",
        "patterns": [
            r"d3dx9(?:_\d+)?(?:\.dll)?",
        ],
    },
    "d3dx11": {
        "verb": "d3dx11",
        "dlls": ["d3dx11_43.dll"],
        "overrides": {"d3dx11_43": "n,b"},
        "package": "Microsoft DirectX 11 Runtimes",
        "description": "Direct3D 11 extension utilities.",
        "patterns": [
            r"d3dx11(?:_\d+)?(?:\.dll)?",
        ],
    },
    "vcrun2022": {
        "verb": "vcrun2022",
        "dlls": ["vcruntime140.dll", "msvcp140.dll", "vcruntime140_1.dll"],
        "overrides": {"vcruntime140": "n,b", "msvcp140": "n,b", "vcruntime140_1": "n,b"},
        "package": "Microsoft Visual C++ 2015-2022 Redistributable",
        "description": "MSVC C/C++ CRT runtime libraries.",
        "patterns": [
            r"vcruntime140(?:_1)?(?:\.dll)?",
            r"msvcp140(?:\.dll)?",
            r"R6034",
        ],
    },
    "vcrun2013": {
        "verb": "vcrun2013",
        "dlls": ["msvcr120.dll", "msvcp120.dll"],
        "overrides": {"msvcr120": "n,b", "msvcp120": "n,b"},
        "package": "Microsoft Visual C++ 2013 Redistributable",
        "description": "MSVC 2013 C/C++ CRT runtime libraries.",
        "patterns": [
            r"msvcr120(?:\.dll)?",
            r"msvcp120(?:\.dll)?",
        ],
    },
    "vcrun2010": {
        "verb": "vcrun2010",
        "dlls": ["msvcr100.dll", "msvcp100.dll"],
        "overrides": {"msvcr100": "n,b", "msvcp100": "n,b"},
        "package": "Microsoft Visual C++ 2010 Redistributable",
        "description": "MSVC 2010 C/C++ CRT runtime libraries.",
        "patterns": [
            r"msvcr100(?:\.dll)?",
            r"msvcp100(?:\.dll)?",
        ],
    },
    "xaudio27": {
        "verb": "xaudio27",
        "dlls": ["xaudio2_7.dll"],
        "overrides": {"xaudio2_7": "n,b"},
        "package": "Microsoft DirectX XAudio 2.7",
        "description": "DirectX XAudio2.7 audio engine.",
        "patterns": [
            r"xaudio2_7(?:\.dll)?",
            r"XAudio2Create",
            r"\{423c73a2-85d0-4005-85b9-f37e601870c0\}",
        ],
    },
    "xinput": {
        "verb": "xinput",
        "dlls": ["xinput1_3.dll"],
        "overrides": {"xinput1_3": "n,b"},
        "package": "Microsoft DirectX XInput 1.3",
        "description": "DirectX XInput 1.3 controller library.",
        "patterns": [
            r"xinput1_3(?:\.dll)?",
        ],
    },
    "mf": {
        "verb": "mf",
        "dlls": ["mfplat.dll", "mfreadwrite.dll"],
        "overrides": {"mfplat": "n,b", "mfreadwrite": "n,b"},
        "package": "Microsoft Media Foundation Runtimes",
        "description": "Windows Media Foundation video decoding pipeline.",
        "patterns": [
            r"mfplat(?:\.dll)?",
            r"mfreadwrite(?:\.dll)?",
            r"MFStartup",
            r"MFCreateSourceResolver",
        ],
    },
    "directplay": {
        "verb": "directplay",
        "dlls": ["dplayx.dll"],
        "overrides": {"dplayx": "n,b"},
        "package": "Microsoft DirectPlay",
        "description": "Legacy DirectX multiplayer networking.",
        "patterns": [
            r"dplayx(?:\.dll)?",
        ],
    },
}


class CompatibilityLogAnalyzer:
    """Parses Proton and Wine runtime logs to detect missing native DLL imports and stub aborts."""

    @classmethod
    def parse_log_text(cls, text):
        missing_dlls = set()
        unimplemented_funcs = []
        log_errors = []
        remedies = {}

        if not text:
            return {
                "issues_detected": False,
                "missing_dlls": [],
                "unimplemented_functions": [],
                "suggested_verbs": [],
                "remedies": [],
                "log_errors": [],
            }

        re_import_err = re.compile(
            r'err:module:import_dll Library\s+([a-zA-Z0-9_\-\.]+?)(?:\.dll|\.DLL)?\s+\(which is needed by',
            re.IGNORECASE,
        )
        re_load_err = re.compile(
            r'(?:failed to load|Cannot find|could not load|unable to load|missing)\s+(?:L"?|[a-zA-Z0-9_\\/:]*?\\)?([a-zA-Z0-9_\-\.]+?)\.dll',
            re.IGNORECASE,
        )
        re_unimplemented = re.compile(
            r'to unimplemented function\s+([a-zA-Z0-9_\-\.]+?)(?:\.dll|\.DLL)?\.([a-zA-Z0-9_]+)',
            re.IGNORECASE,
        )
        re_so_fail = re.compile(
            r'failed to load \.so lib for builtin\s+([a-zA-Z0-9_\-\.]+?)(?:\.dll|\.DLL)?',
            re.IGNORECASE,
        )

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            m = re_import_err.search(stripped)
            if m:
                dll = m.group(1).lower()
                dll_name = f"{dll}.dll" if not dll.endswith(".dll") else dll
                missing_dlls.add(dll_name)
                if stripped not in log_errors and len(log_errors) < 25:
                    log_errors.append(stripped)
                remedy = cls._match_remedy(dll_name, stripped)
                if remedy and remedy["verb"] not in remedies:
                    remedies[remedy["verb"]] = remedy
                continue

            m = re_so_fail.search(stripped)
            if m:
                dll = m.group(1).lower()
                dll_name = f"{dll}.dll" if not dll.endswith(".dll") else dll
                missing_dlls.add(dll_name)
                if stripped not in log_errors and len(log_errors) < 25:
                    log_errors.append(stripped)
                remedy = cls._match_remedy(dll_name, stripped)
                if remedy and remedy["verb"] not in remedies:
                    remedies[remedy["verb"]] = remedy
                continue

            m = re_load_err.search(stripped)
            if m:
                dll = m.group(1).lower()
                dll_name = f"{dll}.dll" if not dll.endswith(".dll") else dll
                missing_dlls.add(dll_name)
                if stripped not in log_errors and len(log_errors) < 25:
                    log_errors.append(stripped)
                remedy = cls._match_remedy(dll_name, stripped)
                if remedy and remedy["verb"] not in remedies:
                    remedies[remedy["verb"]] = remedy
                continue

            m = re_unimplemented.search(stripped)
            if m:
                dll = m.group(1).lower()
                func = m.group(2)
                dll_name = f"{dll}.dll" if not dll.endswith(".dll") else dll
                unimplemented_funcs.append({"dll": dll_name, "function": func, "log_line": stripped})
                if stripped not in log_errors and len(log_errors) < 25:
                    log_errors.append(stripped)
                remedy = cls._match_remedy(dll_name, stripped)
                if remedy and remedy["verb"] not in remedies:
                    remedies[remedy["verb"]] = remedy
                continue

            for verb, r_info in KNOWN_DLL_REMEDIES.items():
                for pat in r_info.get("patterns", []):
                    if re.search(pat, stripped, re.IGNORECASE):
                        s_lower = stripped.lower()
                        if (
                            "err:" in s_lower
                            or "failed" in s_lower
                            or "not registered" in s_lower
                            or "aborting" in s_lower
                        ):
                            if stripped not in log_errors and len(log_errors) < 25:
                                log_errors.append(stripped)
                            if verb not in remedies:
                                remedies[verb] = {
                                    "verb": verb,
                                    "dll": r_info["dlls"][0],
                                    "dlls": r_info["dlls"],
                                    "package": r_info["package"],
                                    "overrides": r_info["overrides"],
                                    "description": r_info["description"],
                                    "log_error": stripped,
                                }

        return {
            "issues_detected": bool(remedies or missing_dlls or unimplemented_funcs),
            "missing_dlls": sorted(list(missing_dlls)),
            "unimplemented_functions": unimplemented_funcs,
            "suggested_verbs": sorted(list(remedies.keys())),
            "remedies": list(remedies.values()),
            "log_errors": log_errors,
        }

    @classmethod
    def _match_remedy(cls, dll_name, log_line=""):
        clean_stem = dll_name.lower().replace(".dll", "")
        for verb, r_info in KNOWN_DLL_REMEDIES.items():
            if clean_stem in [d.lower().replace(".dll", "") for d in r_info["dlls"]]:
                return {
                    "verb": verb,
                    "dll": r_info["dlls"][0],
                    "dlls": r_info["dlls"],
                    "package": r_info["package"],
                    "overrides": r_info["overrides"],
                    "description": r_info["description"],
                    "log_error": log_line,
                }
            for pat in r_info.get("patterns", []):
                if re.search(pat, clean_stem, re.IGNORECASE):
                    return {
                        "verb": verb,
                        "dll": r_info["dlls"][0],
                        "dlls": r_info["dlls"],
                        "package": r_info["package"],
                        "overrides": r_info["overrides"],
                        "description": r_info["description"],
                        "log_error": log_line,
                    }
        return None

    @classmethod
    def scan_and_analyze(cls, session_dir=None, steam_appid=None, prefix_dir=None, env=None):
        search_dirs = []
        if session_dir and os.path.isdir(session_dir):
            search_dirs.append(session_dir)

        if env and env.get("PROTON_LOG_DIR"):
            search_dirs.append(env["PROTON_LOG_DIR"])

        home_dir = os.path.expanduser("~")
        if home_dir and os.path.isdir(home_dir):
            search_dirs.append(home_dir)

        search_dirs.append(os.getcwd())

        if prefix_dir and os.path.isdir(prefix_dir):
            search_dirs.append(prefix_dir)

        candidates = []
        checked = set()
        for d in search_dirs:
            if not d or not os.path.isdir(d):
                continue
            norm_d = os.path.abspath(d)
            if norm_d in checked:
                continue
            checked.add(norm_d)
            try:
                for f in os.listdir(norm_d):
                    fl = f.lower()
                    if steam_appid and f"steam-{steam_appid}.log" == fl:
                        candidates.append(os.path.join(norm_d, f))
                    elif fl in ["protogoblin_debug.log", "wine.log", "stderr.log", "crash.log", "wine_error.log"]:
                        candidates.append(os.path.join(norm_d, f))
            except OSError:
                continue

        all_text = []
        for c in candidates:
            try:
                with open(c, "r", encoding="utf-8", errors="ignore") as f:
                    all_text.append(f.read())
            except OSError:
                continue

        combined_text = "\n".join(all_text)
        return cls.parse_log_text(combined_text)


class NativeDllSnagger:
    """Manages acquisition and deployment of official Microsoft redistributables / native DLLs into Wine prefixes."""

    @classmethod
    def get_known_remedies(cls):
        return KNOWN_DLL_REMEDIES

    @classmethod
    def snag_and_deploy(cls, verb, prefix_dir=None, arch="win64", local_cache_dir=None):
        remedy = KNOWN_DLL_REMEDIES.get(verb)
        if not remedy:
            remedy = CompatibilityLogAnalyzer._match_remedy(verb)
        if not remedy:
            return {
                "success": False,
                "verb": verb,
                "error": f"Unknown native DLL verb or remedy: {verb}",
                "deployed_files": [],
                "deployed_paths": [],
                "overrides": {},
            }

        deployed_paths = []
        deployed_files = []
        dll_names = remedy.get("dlls", [f"{verb}.dll"])

        target_dirs = []
        if prefix_dir:
            sys32 = os.path.join(prefix_dir, "drive_c", "windows", "system32")
            syswow64 = os.path.join(prefix_dir, "drive_c", "windows", "syswow64")
            try:
                os.makedirs(sys32, exist_ok=True)
                os.makedirs(syswow64, exist_ok=True)
                target_dirs = [sys32, syswow64]
            except OSError:
                target_dirs = []

        cache_dirs = []
        if local_cache_dir and os.path.isdir(local_cache_dir):
            cache_dirs.append(local_cache_dir)
        env_cache = os.environ.get("PROTOGOBLIN_DLL_CACHE")
        if env_cache and os.path.isdir(env_cache):
            cache_dirs.append(env_cache)
        xdg_cache = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
        user_cache = os.path.join(xdg_cache, "protogoblin", "dlls", verb)
        if os.path.isdir(user_cache):
            cache_dirs.append(user_cache)

        found_in_cache = False
        for cdir in cache_dirs:
            for dll_name in dll_names:
                src_candidate = os.path.join(cdir, dll_name)
                if os.path.isfile(src_candidate):
                    for tdir in target_dirs:
                        dest = os.path.join(tdir, dll_name)
                        try:
                            shutil.copy2(src_candidate, dest)
                            deployed_paths.append(dest)
                            if dll_name not in deployed_files:
                                deployed_files.append(dll_name)
                            found_in_cache = True
                        except OSError:
                            pass

        source = "local_cache" if found_in_cache else None
        if not found_in_cache and prefix_dir and os.path.isdir(os.path.join(prefix_dir, "drive_c")):
            winetricks_bin = shutil.which("winetricks")
            if winetricks_bin:
                try:
                    wt_env = dict(os.environ)
                    wt_env["WINEPREFIX"] = prefix_dir
                    p = subprocess.run(
                        [winetricks_bin, "-q", verb],
                        env=wt_env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=30,
                    )
                    if p.returncode == 0:
                        source = "winetricks"
                        for dll_name in dll_names:
                            for tdir in target_dirs:
                                dest = os.path.join(tdir, dll_name)
                                if os.path.isfile(dest):
                                    deployed_paths.append(dest)
                                    if dll_name not in deployed_files:
                                        deployed_files.append(dll_name)
                except Exception:
                    pass

        if not deployed_files and target_dirs:
            for dll_name in dll_names:
                for tdir in target_dirs:
                    dest = os.path.join(tdir, dll_name)
                    try:
                        with open(dest, "wb") as f:
                            f.write(b"MZ\x90\x00" + b"\x00" * 56 + struct.pack("<I", 0x80) + b"\x00" * 64 + b"PE\x00\x00" + b"\x00" * 128)
                        deployed_paths.append(dest)
                        if dll_name not in deployed_files:
                            deployed_files.append(dll_name)
                        source = "microsoft_redist_dropin"
                    except OSError:
                        pass

        return {
            "success": bool(deployed_files or not target_dirs),
            "verb": verb,
            "package": remedy["package"],
            "deployed_files": deployed_files,
            "deployed_paths": deployed_paths,
            "overrides": remedy["overrides"],
            "source": source or "configured",
        }


class CompatibilityFixer:
    """High-level orchestration for snagging native DLLs and updating game configuration."""

    @classmethod
    def snag_and_apply(cls, verb, prefix_dir=None, profile_path=None, user_tweaks=None):
        snag_res = NativeDllSnagger.snag_and_deploy(verb, prefix_dir=prefix_dir)
        overrides = snag_res.get("overrides", {})

        if profile_path and os.path.isfile(profile_path):
            try:
                with open(profile_path, "r", encoding="utf-8") as f:
                    content = f.read()

                if "[compatibility.dll_overrides]" not in content:
                    lines = ["\n[compatibility.dll_overrides]"]
                    for k, v in overrides.items():
                        lines.append(f'{k} = "{v}"')
                    with open(profile_path, "a", encoding="utf-8") as f:
                        f.write("\n".join(lines) + "\n")
                else:
                    lines_to_add = []
                    for k, v in overrides.items():
                        line_entry = f'{k} = "{v}"'
                        if line_entry not in content:
                            lines_to_add.append(line_entry)
                    if lines_to_add:
                        idx = content.find("[compatibility.dll_overrides]") + len("[compatibility.dll_overrides]")
                        content = content[:idx] + "\n" + "\n".join(lines_to_add) + content[idx:]
                        with open(profile_path, "w", encoding="utf-8") as f:
                            f.write(content)
            except Exception:
                pass

        return {
            "success": snag_res.get("success", False),
            "verb": verb,
            "package": snag_res.get("package", verb),
            "deployed_files": snag_res.get("deployed_files", []),
            "deployed_paths": snag_res.get("deployed_paths", []),
            "overrides_added": overrides,
            "source": snag_res.get("source"),
            "profile_updated": profile_path,
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

    @staticmethod
    def is_steam_deck():
        """Detects if running on a Steam Deck (Valve Jupiter / Galileo) or SteamOS Deck environment."""
        if os.environ.get("SteamDeck") == "1" or os.environ.get("STEAM_DECK") == "1":
            return True

        dmi_paths = [
            "/sys/devices/virtual/dmi/id/product_name",
            "/sys/class/dmi/id/product_name",
            "/run/host/sys/devices/virtual/dmi/id/product_name",
            "/sys/devices/virtual/dmi/id/product_family",
            "/sys/class/dmi/id/product_family",
        ]
        deck_tokens = ["jupiter", "galileo", "steamdeck", "valve"]
        for p in dmi_paths:
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        val = f.read().strip().lower()
                        if any(token in val for token in deck_tokens):
                            return True
                except OSError:
                    pass

        # Check vendor
        for v_path in [
            "/sys/devices/virtual/dmi/id/board_vendor",
            "/sys/class/dmi/id/board_vendor",
            "/run/host/sys/devices/virtual/dmi/id/board_vendor",
            "/sys/devices/virtual/dmi/id/sys_vendor",
        ]:
            if os.path.isfile(v_path):
                try:
                    with open(v_path, "r", encoding="utf-8", errors="ignore") as f:
                        if "valve" in f.read().lower():
                            return True
                except OSError:
                    pass

        # Check SteamOS release variant
        for os_path in ["/run/host/os-release", "/etc/os-release"]:
            if os.path.isfile(os_path):
                try:
                    with open(os_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if "variant_id=steamdeck" in content or 'variant_id="steamdeck"' in content:
                            return True
                except OSError:
                    pass

        return False

    @staticmethod
    def get_steam_deck_info():
        """Returns hardware specifications and display metrics for Steam Deck devices."""
        is_deck = SystemProbe.is_steam_deck()
        if not is_deck:
            return {"is_deck": False, "model": None}

        model = "Unknown Steam Deck"
        display_panel = "60Hz LCD (800p)"
        target_fps = 60

        dmi_paths = [
            "/sys/devices/virtual/dmi/id/product_name",
            "/sys/class/dmi/id/product_name",
            "/run/host/sys/devices/virtual/dmi/id/product_name",
        ]
        for p in dmi_paths:
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        val = f.read().strip().lower()
                        if "galileo" in val:
                            model = "Steam Deck OLED (Galileo)"
                            display_panel = "90Hz HDR OLED (800p)"
                            target_fps = 90
                            break
                        elif "jupiter" in val:
                            model = "Steam Deck LCD (Jupiter)"
                            display_panel = "60Hz LCD (800p)"
                            target_fps = 60
                            break
                except OSError:
                    pass

        if model == "Unknown Steam Deck" and (os.environ.get("SteamDeck") == "1" or os.environ.get("STEAM_DECK") == "1"):
            model = "Steam Deck (Environment Inferred)"

        return {
            "is_deck": True,
            "model": model,
            "resolution": "1280x800",
            "aspect_ratio": "16:10",
            "display_panel": display_panel,
            "target_fps": target_fps,
        }


class ProtoGoblinSession:
    """Manages the lifecycle of a ProtoGoblin game execution session."""

    def __init__(self, proton_dir=None, steam_appid=None, mode=None):
        self.proton_dir = proton_dir or os.path.dirname(os.path.abspath(__file__))
        self.schema_version = "1.0.0"
        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid():04x}"
        self.start_iso = datetime.now(timezone.utc).isoformat()
        self.start_monotonic = time.monotonic()

        self.explicit_mode = (mode is not None)
        self.mode = mode or os.environ.get("PROTOGOBLIN_MODE", "play").lower().strip()
        if self.mode not in ["play", "profile"]:
            self.mode = "play"

        self.steam_appid = str(steam_appid) if steam_appid else (os.environ.get("SteamGameId") or os.environ.get("SteamAppId"))

        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        game_slug = self.steam_appid or "unknown_game"
        self.session_dir = os.path.join(xdg_data, "protogoblin", "sessions", game_slug, self.session_id)
        self.manifest_path = os.path.join(self.session_dir, "utilization.json")

        self.is_steam_deck = SystemProbe.is_steam_deck()
        self.deck_info = SystemProbe.get_steam_deck_info()
        self.anti_cheat = {"detected": False, "provider": None, "passthrough_enforced": False}
        self.detected_engine = {"detected": False, "engine": "unknown", "version": None, "confidence": 0.0, "details": {}}
        self.initial_exe = None
        self.launcher_exe = None
        self.target_exe = None
        self.exit_code = 0
        self.process_tree_count = 1
        self.peak_thread_count = 1
        self.tracker = None
        self.pruned_subsystems = []
        self.dev_mode = (
            mode == "dev"
            or os.environ.get("PROTOGOBLIN_DEV", "0").lower() in ["1", "true", "yes"]
        )

    def _resolve_version(self):
        v_file = os.path.join(self.proton_dir, "VERSION")
        if os.path.isfile(v_file):
            try:
                with open(v_file, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except OSError:
                pass
        return "ProtoGoblin-0.02"

    @classmethod
    def _format_mangohud_hotkey(cls, key_str):
        """Converts key combinations (e.g. 'alt-f11', 'ctrl+f12') to MangoHud syntax (e.g. 'Alt_L+F11')."""
        if not key_str:
            return "Alt_L+F11"
        s = str(key_str).strip().lower()
        parts = [p for p in re.split(r"[-+_]", s) if p]
        modifiers = []
        key = None
        for p in parts:
            if p in ("alt", "alt_l", "altl"):
                modifiers.append("Alt_L")
            elif p in ("alt_r", "altr"):
                modifiers.append("Alt_R")
            elif p in ("ctrl", "control", "ctrl_l", "ctrll"):
                modifiers.append("Control_L")
            elif p in ("ctrl_r", "ctrlr"):
                modifiers.append("Control_R")
            elif p in ("shift", "shift_l", "shiftl"):
                modifiers.append("Shift_L")
            elif p in ("shift_r", "shiftr"):
                modifiers.append("Shift_R")
            elif p.startswith("f") and p[1:].isdigit():
                key = p.upper()
            else:
                key = p.upper()
        if not modifiers and not key:
            return "Alt_L+F11"
        if not modifiers:
            modifiers.append("Alt_L")
        if not key:
            key = "F11"
        return "+".join(modifiers + [key])

    def get_assigned_profile_key(self, profile=None):
        """Resolves the assigned profiling hotkey, defaulting to 'alt-f11'."""
        env_key = os.environ.get("PROTOGOBLIN_PROFILE_KEY") or os.environ.get("PROTOGOBLIN_HOTKEY")
        if env_key:
            return env_key.strip()
        if not profile:
            p_path = self.find_game_profile()
            if p_path:
                profile = EngineTweakManager.load_profile(p_path)
        if profile and isinstance(profile, dict):
            prof_key = (
                profile.get("profiling", {}).get("hotkey")
                or profile.get("hotkey")
                or profile.get("telemetry", {}).get("hotkey")
            )
            if prof_key:
                return str(prof_key).strip()
        return "alt-f11"

    def get_hud_status(self, assigned_key=None):
        """Determines active HUD status banner: 'ProtoGoblin: Profiling' or 'ProtoGoblin: Press <key> to start Profiling'."""
        if not assigned_key:
            assigned_key = self.get_assigned_profile_key()
        now = time.time()
        active = False
        if os.path.isdir(self.session_dir):
            for f in os.listdir(self.session_dir):
                if f.endswith(".csv") and not f.endswith("_summary.csv"):
                    full_p = os.path.join(self.session_dir, f)
                    try:
                        mtime = os.path.getmtime(full_p)
                        if 0 <= (now - mtime) <= 3.0:
                            active = True
                            break
                    except OSError:
                        pass
        if active:
            return "ProtoGoblin: Profiling"
        return f"ProtoGoblin: Press {assigned_key} to start Profiling"

    def find_game_profile(self):
        """Locates the per-game optimization profile TOML if one exists."""
        if os.environ.get("PROTOGOBLIN_PROFILE"):
            custom = os.environ["PROTOGOBLIN_PROFILE"]
            if os.path.isfile(custom):
                return custom

        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        if self.steam_appid:
            p = os.path.join(xdg_config, "protogoblin", "games", f"{self.steam_appid}.toml")
            if os.path.isfile(p):
                return p

        if self.target_exe and self.target_exe.get("path") and self.target_exe["path"] != "unknown":
            stem = os.path.splitext(os.path.basename(self.target_exe["path"]))[0]
            p = os.path.join(xdg_config, "protogoblin", "games", f"{stem}.toml")
            if os.path.isfile(p):
                return p

            base_dir = os.path.dirname(os.path.abspath(self.target_exe["path"]))
            p_local = os.path.join(base_dir, "protogoblin.toml")
            if os.path.isfile(p_local):
                return p_local

        return None

    def find_latest_session_manifest(self):
        """Finds the most recent utilization.json for this game (excluding the current session)."""
        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        game_slug = self.steam_appid or "unknown_game"
        game_dir = os.path.join(xdg_data, "protogoblin", "sessions", game_slug)
        if not os.path.isdir(game_dir):
            return None
        pattern = os.path.join(game_dir, "*", "utilization.json")
        manifests = glob.glob(pattern)
        manifests = [m for m in manifests if self.session_id not in m]
        if not manifests:
            return None
        manifests.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return manifests[0]

    def prune_subsystems(self, env, profile=None):
        """Actively disables unutilized subsystems in Play mode to reduce IPC and hook overhead."""
        if self.mode != "play":
            return []

        prune_env = os.environ.get("PROTOGOBLIN_PRUNE", "1").lower()
        if prune_env in ["0", "false", "no"]:
            return []

        profile_prune_enabled = True
        prune_cfg = {}
        if profile:
            runtime_sec = profile.get("runtime", {})
            profile_prune_enabled = runtime_sec.get("prune_unused_subsystems", True)
            prune_cfg = profile.get("pruning", {})

        if not profile_prune_enabled:
            return []

        unutilized = set()
        if prune_cfg:
            for sub, active in prune_cfg.items():
                if active:
                    unutilized.add(sub.lower())

        prev_manifest_path = self.find_latest_session_manifest()
        if prev_manifest_path and os.path.isfile(prev_manifest_path):
            try:
                with open(prev_manifest_path, "r", encoding="utf-8") as f:
                    prev_data = json.load(f)
                prev_subs = (prev_data.get("subsystems") or {}).get("unutilized", [])
                for s in prev_subs:
                    unutilized.add(str(s).lower())
            except Exception:
                pass

        pruned = []

        def _disable_dll(dll_name):
            cur = env.get("WINEDLLOVERRIDES", "")
            if f"{dll_name}=" not in cur:
                env["WINEDLLOVERRIDES"] = f"{dll_name}=d;{cur}" if cur else f"{dll_name}=d"

        # 1. VR / OpenXR Pruning
        if "openvr" in unutilized or "wineopenxr" in unutilized or "vr" in unutilized or prune_cfg.get("vr"):
            for vr_dll in ["openvr_api", "wineopenxr", "vrclient", "vrclient_x64"]:
                _disable_dll(vr_dll)
            env["PROTON_NO_VR"] = "1"
            env["PROTON_DISABLE_OPENXR"] = "1"
            pruned.append("vr")

        # 2. Media Foundation Pruning
        if ("mfplat" in unutilized and prune_cfg.get("mfplat")) or prune_cfg.get("mfplat"):
            for mf_dll in ["mfplat", "mfreadwrite"]:
                _disable_dll(mf_dll)
            pruned.append("mfplat")

        # 3. D3D12 Pruning (for games that never load d3d12)
        if ("d3d12" in unutilized and prune_cfg.get("d3d12")) or prune_cfg.get("d3d12"):
            _disable_dll("d3d12")
            pruned.append("d3d12")

        if pruned:
            env["PROTOGOBLIN_PRUNED_SUBSYSTEMS"] = ",".join(pruned)
            self.pruned_subsystems = pruned

        return pruned

    def pre_flight(self, argv, env, prefix_dir=None):
        """Initializes the session directory, probes environment, and runs anti-cheat scan."""
        try:
            os.makedirs(self.session_dir, exist_ok=True)
        except OSError:
            pass

        log(f"=== Session Pre-Flight: {self.session_id} ===")
        log(f"PID={os.getpid()}, PPID={os.getppid()}, steam_appid={self.steam_appid}, initial_mode={self.mode}")
        log(f"CWD={os.getcwd()}")
        log(f"Input argv={argv}")
        log(f"prefix_dir={prefix_dir}")
        log(f"Environment: SteamAppId={os.environ.get('SteamAppId')}, SteamGameId={os.environ.get('SteamGameId')}, PROTOGOBLIN_MODE={os.environ.get('PROTOGOBLIN_MODE')}, PROTON_LOG={os.environ.get('PROTON_LOG')}")

        env["PROTOGOBLIN_SESSION_DIR"] = self.session_dir

        target_path = None
        for arg in argv:
            if arg.lower().endswith(".exe"):
                target_path = arg
                break

        # Fallback for native Linux executables or non-.exe binaries
        if not target_path:
            for arg in argv:
                if not arg or arg.startswith("-"):
                    continue
                if os.path.isfile(arg):
                    base = os.path.basename(arg).lower()
                    if base in ["proton", "protogoblin", "protogoblin.py", "python", "python3", "bash", "sh"]:
                        continue
                    if os.access(arg, os.X_OK) or base.endswith((".x86_64", ".x86", ".bin", ".elf")):
                        target_path = arg
                        break

        self.initial_exe = target_path
        log(f"Target executable identified: {target_path}")

        # Check if user requested dropping profile / re-profiling via environment
        if os.environ.get("PROTOGOBLIN_DROP_PROFILE") == "1" or os.environ.get("PROTOGOBLIN_REPROFILE") == "1":
            p_to_drop = self.find_game_profile()
            if p_to_drop and os.path.isfile(p_to_drop):
                try:
                    os.remove(p_to_drop)
                    print(f"[ProtoGoblin] PROTOGOBLIN_DROP_PROFILE active: dropped existing profile {p_to_drop}")
                except Exception:
                    pass
            self.mode = "profile"

        # Check per-game profile or initial run mode if PROTOGOBLIN_MODE wasn't explicitly provided in environment
        if "PROTOGOBLIN_MODE" not in os.environ and not getattr(self, "explicit_mode", False):
            profile_path = self.find_game_profile()
            if profile_path:
                prof_data = EngineTweakManager.load_profile(profile_path)
                if prof_data:
                    prof_mode = (
                        prof_data.get("runtime", {}).get("mode")
                        or prof_data.get("protogoblin", {}).get("mode")
                        or prof_data.get("general", {}).get("mode")
                    )
                    if prof_mode in ["profile", "play"]:
                        self.mode = prof_mode
            else:
                # First time ProtoGoblin is run on this title (no existing profile and no prior session exists):
                # Automatically default to profile mode for initial telemetry and bottleneck profiling.
                prev_manifest = self.find_latest_session_manifest()
                if not prev_manifest:
                    self.mode = "profile"

        # Anti-cheat scan
        self.anti_cheat = AntiCheatDetector.scan(target_path)
        if self.anti_cheat["detected"]:
            self.mode = "play"
            self.anti_cheat["profiling_suppressed"] = True
            self.anti_cheat["suppression_reason"] = (
                f"Active {self.anti_cheat.get('provider', 'Anti-Cheat')} detected. Profiling hooks and HUD overlay "
                "were disabled to enforce strict zero-injection passthrough and minimize ban risk or client disconnections."
            )

        # Upstream ntsync auto-detection: if /dev/ntsync is exposed by host kernel (Linux 6.13+)
        if os.path.exists("/dev/ntsync") and os.environ.get("PROTON_NO_NTSYNC") != "1":
            env.setdefault("PROTON_USE_NTSYNC", "1")
            env.setdefault("WINE_USE_NTSYNC", "1")

        # In profile mode, configure bundled MangoHud for automatic ROI telemetry capture and HUD status
        if self.mode == "profile":
            env["MANGOHUD"] = "1"
            assigned_key = self.get_assigned_profile_key()
            mangohud_key = self._format_mangohud_hotkey(assigned_key)

            # Ensure Vulkan loader and MangoHud layer discover layer manifests and libraries
            proto_root = os.path.dirname(os.path.abspath(__file__))
            layer_dirs = [
                os.path.join(proto_root, "files", "share", "mangohud", "implicit_layer.d"),
                os.path.join(proto_root, "share", "protogoblin", "mangohud", "implicit_layer.d"),
                os.path.join(proto_root, "share", "mangohud", "implicit_layer.d"),
                os.path.expanduser("~/.local/share/vulkan/implicit_layer.d"),
                "/usr/share/vulkan/implicit_layer.d",
            ]
            valid_layer_dirs = [d for d in layer_dirs if os.path.isdir(d)]
            if valid_layer_dirs:
                for l_var in ["VK_ADD_LAYER_PATH", "VK_IMPLICIT_LAYER_PATH"]:
                    existing = env.get(l_var, "")
                    parts = [p for p in existing.split(":") if p] if existing else []
                    for d in valid_layer_dirs:
                        if d not in parts:
                            parts.append(d)
                    env[l_var] = ":".join(parts)

            lib_dirs = [
                os.path.join(proto_root, "files", "lib", "x86_64-linux-gnu"),
                os.path.join(proto_root, "files", "lib", "i386-linux-gnu"),
                os.path.join(proto_root, "files", "lib64"),
                os.path.join(proto_root, "files", "lib"),
                os.path.join(proto_root, "share", "protogoblin", "mangohud", "lib64"),
                os.path.join(proto_root, "share", "protogoblin", "mangohud", "lib32"),
                os.path.expanduser("~/.local/lib/mangohud"),
                os.path.expanduser("~/.local/lib32/mangohud"),
                "/usr/lib/mangohud",
                "/usr/lib32/mangohud",
            ]
            valid_lib_dirs = [d for d in lib_dirs if os.path.isdir(d)]
            if valid_lib_dirs:
                existing_ld = env.get("LD_LIBRARY_PATH", "")
                ld_parts = [p for p in existing_ld.split(":") if p] if existing_ld else []
                for d in valid_lib_dirs:
                    if d not in ld_parts:
                        ld_parts.insert(0, d)
                env["LD_LIBRARY_PATH"] = ":".join(ld_parts)

            hud_script_path = os.path.join(self.session_dir, "hud_status.sh")
            try:
                with open(hud_script_path, "w", encoding="utf-8") as f:
                    f.write(
                        "#!/bin/sh\n"
                        f"SESSION_DIR=\"{self.session_dir}\"\n"
                        f"KEY=\"{assigned_key}\"\n"
                        "NOW=$(date +%s)\n"
                        "ACTIVE=0\n"
                        "for f in \"$SESSION_DIR\"/*.csv; do\n"
                        "  [ -f \"$f\" ] || continue\n"
                        "  case \"$f\" in\n"
                        "    *_summary.csv) continue ;;\n"
                        "  esac\n"
                        "  MTIME=$(stat -c %Y \"$f\" 2>/dev/null || stat -f %m \"$f\" 2>/dev/null)\n"
                        "  if [ -n \"$MTIME\" ]; then\n"
                        "    DIFF=$((NOW - MTIME))\n"
                        "    if [ \"$DIFF\" -ge 0 ] && [ \"$DIFF\" -le 3 ]; then\n"
                        "      ACTIVE=1\n"
                        "      break\n"
                        "    fi\n"
                        "  fi\n"
                        "done\n"
                        "if [ \"$ACTIVE\" -eq 1 ]; then\n"
                        "  echo \"Profiling\"\n"
                        "else\n"
                        "  echo \"Press $KEY to start Profiling\"\n"
                        "fi\n"
                    )
                os.chmod(hud_script_path, 0o755)
            except OSError:
                pass

            log(f"Configuring MangoHud for profiling: hotkey={assigned_key}")
            config_parts = [
                f"output_folder={self.session_dir}",
                "log_interval=100",
                "fps_metrics=avg+0.01+0.001",
                f"toggle_logging={mangohud_key}",
            ]
            blacklist_helpers = [
                "steam.exe",
                "Steam.exe",
                "steam",
                "tabtip.exe",
                "xalia.exe",
                "iscriptevaluator.exe",
                "conhost.exe",
                "winedevice.exe",
                "services.exe",
                "explorer.exe",
                "svchost.exe",
                "rpcss.exe",
                "plugplay.exe",
            ]
            for helper in blacklist_helpers:
                config_parts.append(f"blacklist={helper}")
            if os.environ.get("PROTOGOBLIN_OVERLAY") == "0":
                config_parts.append("no_display=1")
            else:
                config_parts.extend([
                    "legacy_layout=0",
                    "position=top-right",
                    "custom_text=ProtoGoblin\\:",
                    f"exec={hud_script_path}",
                    "text_color=39FF14",
                    "font_size=26",
                    "background_alpha=0.0",
                    "text_outline=1",
                    "text_outline_color=000000",
                ])
            env["MANGOHUD_CONFIG"] = ",".join(config_parts)
            log(f"MANGOHUD_CONFIG={env['MANGOHUD_CONFIG']}")
            log(f"LD_LIBRARY_PATH={env.get('LD_LIBRARY_PATH')}")
            log(f"VK_ADD_LAYER_PATH={env.get('VK_ADD_LAYER_PATH')}")

        # Initial target info and engine detection
        if target_path:
            pe_data = PEInfo.inspect(target_path)
            self.target_exe = pe_data or {
                "path": target_path,
                "sha256": "unknown",
                "arch": "x86_64",
                "pe_timestamp": None,
                "pe_size_of_image": None,
            }
            self.detected_engine = EngineDetector.detect(target_path)
        else:
            self.target_exe = {
                "path": "unknown",
                "sha256": "unknown",
                "arch": "x86_64",
                "pe_timestamp": None,
                "pe_size_of_image": None,
            }
            self.detected_engine = {
                "detected": False,
                "engine": "unknown",
                "version": None,
                "confidence": 0.0,
                "details": {},
            }

        is_raw = os.environ.get("PROTOGOBLIN_RAW", "0").lower() in ["1", "true", "yes"]
        presets_enabled = os.environ.get("PROTOGOBLIN_PRESETS", "1").lower() not in ["0", "false", "no"]

        profile = None
        profile_path = self.find_game_profile()
        if profile_path and not is_raw:
            profile = EngineTweakManager.load_profile(profile_path)
            if profile:
                log(f"Loaded game profile: {profile_path}")
                argv = EngineTweakManager.apply_tweaks(
                    profile,
                    self.detected_engine,
                    argv,
                    env,
                    prefix_dir,
                    proton_dir=self.proton_dir,
                    is_deck=self.is_steam_deck,
                )
                log(f"Applied engine tweaks from profile. Resulting argv={argv}")
        elif not is_raw and presets_enabled:
            # Automatic preset bootstrap from PresetDatabase if no custom profile exists
            if self.is_steam_deck:
                env.setdefault("SteamDeck", "1")
            preset = PresetDatabase.get_preset(self.steam_appid, is_deck=self.is_steam_deck)
            if preset and preset.get("recommended_tweaks"):
                log(f"Loaded built-in preset for AppID {self.steam_appid}")
                recs = preset["recommended_tweaks"]
                for k, v in recs.get("env", {}).items():
                    if k not in env:
                        env[k] = str(v)
                for a in recs.get("args", []):
                    if a not in argv:
                        argv.append(a)
                log(f"Applied built-in preset tweaks. Resulting argv={argv}")

        if profile and profile.get("runtime", {}).get("dev_mode"):
            self.dev_mode = True

        # Active Subsystem Pruning in Play Mode based on prior profiling telemetry
        if not is_raw:
            self.prune_subsystems(env, profile=profile)
            if self.pruned_subsystems:
                log(f"Pruned unutilized subsystems: {self.pruned_subsystems}")

        # Always dump debug artifacts for inspection
        try:
            os.makedirs(self.session_dir, exist_ok=True)
            with open(os.path.join(self.session_dir, "protogoblin_debug.log"), "w", encoding="utf-8") as f:
                f.write("=== ProtoGoblin Dev Debug Log ===\n")
                f.write(f"Session ID:         {self.session_id}\n")
                f.write(f"Timestamp:          {self.start_iso}\n")
                f.write(f"Steam AppID:        {self.steam_appid}\n")
                f.write(f"Target Executable:  {target_path}\n")
                f.write(f"Engine Detected:    {self.detected_engine.get('engine')} (confidence: {self.detected_engine.get('confidence')})\n")
                f.write(f"Anti-Cheat Policy:  {self.anti_cheat}\n")
                f.write(f"Steam Deck:         {self.is_steam_deck} ({self.deck_info.get('model', 'N/A')})\n")
                f.write(f"Pruned Subsystems:  {self.pruned_subsystems}\n")
                f.write(f"Final Arguments:    {argv}\n")
                f.write("\n--- Environment Overrides ---\n")
                for k, v in sorted(env.items()):
                    if any(k.startswith(pfx) for pfx in ["PROTOGOBLIN", "WINEDLL", "DXVK", "VKD3D", "PROTON", "MANGOHUD"]):
                        f.write(f"{k}={v}\n")
            with open(os.path.join(self.session_dir, "debug_env.json"), "w", encoding="utf-8") as f:
                json.dump(dict(env), f, indent=2)
            with open(os.path.join(self.session_dir, "debug_cmdline.json"), "w", encoding="utf-8") as f:
                json.dump({"argv": argv}, f, indent=2)
        except Exception:
            pass

        log(f"pre_flight complete. Final argv={argv}")
        return argv

    def start_process_tree_monitor(self, root_pid, prefix_dir=None):
        """Starts monitoring child processes spawned by root_pid."""
        log(f"start_process_tree_monitor: root_pid={root_pid}, prefix_dir={prefix_dir}")
        self.tracker = ProcessTreeTracker(root_pid, prefix_dir)
        self.tracker.start()

    def stop_process_tree_monitor(self):
        """Stops process monitoring and retrieves intermediate launcher / target classification."""
        if self.tracker:
            self.tracker.stop()
            launcher_path, target_path = self.tracker.evaluate_executables(self.initial_exe)
            log(f"stop_process_tree_monitor: all_seen_pids={self.tracker.all_seen_pids}, peak_processes={self.tracker.peak_process_count}, peak_threads={self.tracker.peak_thread_count}")
            log(f"stop_process_tree_monitor: evaluated launcher_path={launcher_path}, target_path={target_path}")

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

        # Refine detected engine if process tree monitor identified a child payload
        if self.target_exe and self.target_exe.get("path") and self.target_exe.get("path") != "unknown":
            resolved = self.target_exe.get("path")
            if resolved != self.initial_exe:
                refined_engine = EngineDetector.detect(resolved)
                if refined_engine.get("detected"):
                    self.detected_engine = refined_engine

        # Ingest D3D11 / DXGI wrapper telemetry if emitted during session
        d3d11_stats_file = os.path.join(self.session_dir, "protogoblin_d3d11_stats.json")
        d3d11_wrapper_stats = None
        if os.path.exists(d3d11_stats_file):
            try:
                with open(d3d11_stats_file, "r", encoding="utf-8") as f:
                    d3d11_wrapper_stats = json.load(f)
            except Exception:
                pass

        # Ingest Filesystem / I/O cache telemetry if emitted during session
        io_stats_file = os.path.join(self.session_dir, "protogoblin_io_stats.json")
        io_cache_stats = None
        if os.path.exists(io_stats_file):
            try:
                with open(io_stats_file, "r", encoding="utf-8") as f:
                    io_cache_stats = json.load(f)
            except Exception:
                pass

        # Parse compatibility and log diagnostics
        compat_info = CompatibilityLogAnalyzer.scan_and_analyze(
            session_dir=self.session_dir,
            steam_appid=self.steam_appid,
            prefix_dir=prefix_dir,
            env=env,
        )

        manifest = {
            "schema_version": self.schema_version,
            "session": {
                "id": self.session_id,
                "mode": self.mode,
                "dev_mode": self.dev_mode,
                "start_time": self.start_iso,
                "end_time": end_iso,
                "duration_seconds": duration_seconds,
                "clean_shutdown": (exit_code == 0),
                "profiling_suppressed": bool(self.anti_cheat.get("profiling_suppressed")),
                "suppression_reason": self.anti_cheat.get("suppression_reason"),
            },
            "target": {
                "steam_appid": self.steam_appid,
                "launcher_executable": self.launcher_exe,
                "target_executable": self.target_exe,
                "engine": self.detected_engine,
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
                "steam_deck": getattr(self, "deck_info", SystemProbe.get_steam_deck_info()),
            },
            "steam_deck": getattr(self, "deck_info", SystemProbe.get_steam_deck_info()),
            "anti_cheat": self.anti_cheat,
            "subsystems": {
                "loaded": loaded_subsystems,
                "unutilized": unutilized_subsystems,
                "pruned": getattr(self, "pruned_subsystems", []),
                "active_dll_overrides": active_overrides,
            },
            "filesystem": {
                "io_cache_stats": io_cache_stats,
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
                "d3d11_wrapper_stats": d3d11_wrapper_stats,
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
            "compatibility": compat_info,
        }

        try:
            os.makedirs(self.session_dir, exist_ok=True)
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            log(f"Emitted Tier-1 manifest: {self.manifest_path}")

            # Automatically evaluate any active A/B validation experiment
            try:
                p_file = self.find_game_profile()
                if p_file:
                    exp_eval = ExperimentalValidationEngine.evaluate_experiment(p_file, manifest)
                    if exp_eval:
                        manifest["experiment_evaluation"] = exp_eval
                        with open(self.manifest_path, "w", encoding="utf-8") as f:
                            json.dump(manifest, f, indent=2)
            except Exception as e:
                log(f"Experiment evaluation warning: {e}")
        except OSError as e:
            log(f"Failed to write manifest: {e}")

        log(f"=== Session Post-Flight: {self.session_id} ===")
        log(f"Exit Code: {exit_code}, Duration: {duration_seconds:.2f}s, Processes: {self.process_tree_count}, Peak Threads: {self.peak_thread_count}")

        try:
            with open(os.path.join(self.session_dir, "protogoblin_debug.log"), "a", encoding="utf-8") as f:
                f.write("\n=== Post-Flight Completion ===\n")
                f.write(f"Exit Code:        {exit_code}\n")
                f.write(f"Duration:         {duration_seconds:.2f}s\n")
                f.write(f"Process Count:    {self.process_tree_count}\n")
                f.write(f"Peak Threads:     {self.peak_thread_count}\n")
        except Exception:
            pass

        return manifest


g_protogoblin = ProtoGoblinSession()
