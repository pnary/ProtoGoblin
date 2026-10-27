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

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


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
    """Provides ProtonDB community presets, ratings, and known fixes for Steam AppIDs."""

    _CACHE = None

    @classmethod
    def get_preset(cls, app_id):
        if not app_id:
            return None
        db = cls.get_all()
        return db.get(str(app_id))

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
    }

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
    def generate_profile_toml(cls, game_id, app_id, target_exe, engine_info=None, sync_backend="ntsync", user_tweaks=None):
        tweaks = user_tweaks or {}
        eng_name = engine_info.get("engine", "") if engine_info else ""
        is_ue = eng_name in ["unreal_4", "unreal_5", "unreal"]
        is_unity = eng_name == "unity"
        is_godot = eng_name == "godot"

        ue_cfg = tweaks.get("unreal", cls.DEFAULTS["unreal"])
        unity_cfg = tweaks.get("unity", cls.DEFAULTS["unity"])
        godot_cfg = tweaks.get("godot", cls.DEFAULTS["godot"])
        gfx_cfg = tweaks.get("graphics", cls.DEFAULTS["graphics"])

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
            'mode = "play"',
            "prune_unused_subsystems = true",
            'anticheat_policy = "passthrough"',
            "",
            "[graphics]",
            f'backend = "{gfx_cfg.get("backend", "dxvk")}"',
            f'force_vsync = "{gfx_cfg.get("force_vsync", "off")}"',
            f'max_fps = {gfx_cfg.get("max_fps", 0)}',
            f'anisotropic_filtering = {gfx_cfg.get("anisotropic_filtering", 16)}',
            f'async_shader_compile = {"true" if gfx_cfg.get("async_shader_compile", True) else "false"}',
            f'low_latency = {"true" if gfx_cfg.get("low_latency", True) else "false"}',
            "",
            "[synchronization]",
            f'preferred_backend = "{sync_backend}"',
        ]

        if is_ue or "unreal" in tweaks:
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
            ])

        if is_unity or "unity" in tweaks:
            lines.extend([
                "",
                "[engine.unity]",
                f'native_gfx_jobs = {"true" if unity_cfg.get("native_gfx_jobs", True) else "false"}',
                f'disable_vr = {"true" if unity_cfg.get("disable_vr", True) else "false"}',
                f'force_vulkan = {"true" if unity_cfg.get("force_vulkan", False) else "false"}',
            ])

        if is_godot or "godot" in tweaks:
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

        if atelier_sync:
            lines.extend([
                "",
                "[synchronization.atelier_sync_fix]",
                "enabled = true",
                "# Shadow staging buffer wrapper to eliminate intra-frame CPU-GPU sync stalls",
            ])

        lines.append("")
        return "\n".join(lines)

    @classmethod
    def apply_tweaks(cls, profile, engine_info, argv, env, prefix_dir=None):
        if not profile:
            return argv

        eng_name = engine_info.get("engine", "") if engine_info else ""
        engine_sec = profile.get("engine", {})
        gfx_sec = profile.get("graphics", {})
        sync_sec = profile.get("synchronization", {})

        new_argv = list(argv)

        # 1. Unreal Engine command-line cvars
        ue_cfg = engine_sec.get("unreal", {})
        cvars = []
        if ue_cfg or eng_name in ["unreal_4", "unreal_5", "unreal"]:
            for option_key, active in ue_cfg.items():
                if active and option_key in cls.UNREAL_CVAR_MAP:
                    cvars.extend(cls.UNREAL_CVAR_MAP[option_key])
            if cvars:
                exec_arg = f'-ExecCmds="{"; ".join(cvars)}"'
                new_argv.append(exec_arg)

        # 2. Unity command-line flags
        unity_cfg = engine_sec.get("unity", {})
        if unity_cfg.get("force_vulkan"):
            if "-force-vulkan" not in new_argv:
                new_argv.append("-force-vulkan")

        # 3. Godot command-line flags
        godot_cfg = engine_sec.get("godot", {})
        if godot_cfg.get("rendering_driver"):
            driver = godot_cfg["rendering_driver"]
            new_argv.extend(["--rendering-driver", driver])
        if godot_cfg.get("max_fps", 0) > 0:
            new_argv.append(f"--max-fps={godot_cfg['max_fps']}")

        # 4. DXVK & Synchronization layer intercepts
        dxvk_items = []

        # Check for Atelier staging buffer sync fix
        sync_fix_enabled = (
            sync_sec.get("atelier_sync_fix")
            or (isinstance(sync_sec.get("atelier_sync_fix"), dict) and sync_sec["atelier_sync_fix"].get("enabled"))
            or (isinstance(sync_sec, dict) and sync_sec.get("enabled") and "atelier" in str(sync_sec))
            or engine_sec.get("gust", {}).get("atelier_sync_fix")
        )
        if sync_fix_enabled:
            dll_ov = env.get("WINEDLLOVERRIDES", "")
            if "d3d11=" not in dll_ov:
                env["WINEDLLOVERRIDES"] = f"d3d11=n,b;{dll_ov}" if dll_ov else "d3d11=n,b"
            dxvk_items.extend(["dxgi.syncInterval = 0", "d3d11.syncInterval = 0"])

        if gfx_sec.get("force_vsync") == "off":
            dxvk_items.extend(["dxgi.syncInterval = 0", "d3d11.syncInterval = 0"])
        elif gfx_sec.get("force_vsync") == "on":
            dxvk_items.extend(["dxgi.syncInterval = 1", "d3d11.syncInterval = 1"])

        if gfx_sec.get("max_fps", 0) > 0:
            limit = gfx_sec["max_fps"]
            dxvk_items.append(f"dxgi.maxFrameRate = {limit}")
            env["VKD3D_FRAME_RATE"] = str(limit)

        af = gfx_sec.get("anisotropic_filtering")
        if af and int(af) > 0:
            dxvk_items.append(f"d3d11.samplerAnisotropy = {af}")

        if gfx_sec.get("async_shader_compile"):
            env["DXVK_ASYNC"] = "1"
            dxvk_items.append("dxvk.enableAsync = true")

        if gfx_sec.get("low_latency"):
            dxvk_items.append("dxvk.lowLatency = true")

        if dxvk_items:
            existing_dxvk = env.get("DXVK_CONFIG", "").strip()
            addon = "; ".join(dxvk_items)
            env["DXVK_CONFIG"] = f"{existing_dxvk}; {addon}" if existing_dxvk else addon

        # 5. Prefix file configuration adjustments
        if prefix_dir and os.path.isdir(prefix_dir):
            try:
                if unity_cfg and (unity_cfg.get("native_gfx_jobs") or unity_cfg.get("disable_vr")):
                    cls._patch_unity_boot_config(prefix_dir, unity_cfg)
                if ue_cfg and cvars:
                    cls._patch_unreal_engine_ini(prefix_dir, cvars)
            except Exception:
                pass

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
        self.detected_engine = {"detected": False, "engine": "unknown", "version": None, "confidence": 0.0, "details": {}}
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

    def pre_flight(self, argv, env, prefix_dir=None):
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

        # In profile mode, configure bundled MangoHud for automatic ROI telemetry capture and HUD status
        if self.mode == "profile":
            env["MANGOHUD"] = "1"
            config_parts = [
                f"output_folder={self.session_dir}",
                "log_interval=100",
                "benchmark_percentiles=0.001;0.01;0.97;0.99",
            ]
            if os.environ.get("PROTOGOBLIN_OVERLAY") == "0":
                config_parts.append("no_display=1")
            else:
                config_parts.extend([
                    "legacy_layout=0",
                    "position=top-right",
                    "custom_text=Goblin-ing",
                    "text_color=39FF14",
                    "font_size=26",
                    "background_alpha=0.0",
                    "text_outline=1",
                    "text_outline_color=000000",
                ])
            env["MANGOHUD_CONFIG"] = ",".join(config_parts)

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

        # Apply Game Profile (engine-specific visual & performance overrides)
        profile_path = self.find_game_profile()
        if profile_path:
            profile = EngineTweakManager.load_profile(profile_path)
            if profile:
                argv = EngineTweakManager.apply_tweaks(
                    profile,
                    self.detected_engine,
                    argv,
                    env,
                    prefix_dir,
                )

        return argv

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

        # Refine detected engine if process tree monitor identified a child payload
        if self.target_exe and self.target_exe.get("path") and self.target_exe.get("path") != "unknown":
            resolved = self.target_exe.get("path")
            if resolved != self.initial_exe:
                refined_engine = EngineDetector.detect(resolved)
                if refined_engine.get("detected"):
                    self.detected_engine = refined_engine

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
