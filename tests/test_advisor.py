#!/usr/bin/env python3
"""
Unit tests for ProtoGoblin Command DiagnosticAdvisor and EngineDetector
"""

import json
import os
import shutil
import sys
import tempfile
import time
import tkinter as tk
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protogoblin import (
    CompatibilityFixer,
    CompatibilityLogAnalyzer,
    EngineDetector,
    EngineTweakManager,
    ExperimentStatus,
    ExperimentVerdict,
    ExperimentalValidationEngine,
    FixRegistry,
    NativeDllSnagger,
    PresetDatabase,
    ProtoGoblinSession,
    SystemProbe,
)
from protogoblin_command import (
    DiagnosticAdvisor,
    ProtoGoblinCommandApp,
    compute_session_diff,
    format_diff_report,
    generate_debug_dump,
    format_debug_dump,
)


def setUpModule():
    global _MODULE_TEMP_DIR, _ORIG_XDG_DATA, _ORIG_XDG_CONFIG, _ORIG_SESSIONS_DIR
    _MODULE_TEMP_DIR = tempfile.TemporaryDirectory()
    _ORIG_XDG_DATA = os.environ.get("XDG_DATA_HOME")
    _ORIG_XDG_CONFIG = os.environ.get("XDG_CONFIG_HOME")
    _ORIG_SESSIONS_DIR = os.environ.get("PROTOGOBLIN_SESSIONS_DIR")
    os.environ["XDG_DATA_HOME"] = os.path.join(_MODULE_TEMP_DIR.name, "data")
    os.environ["XDG_CONFIG_HOME"] = os.path.join(_MODULE_TEMP_DIR.name, "config")
    os.environ["PROTOGOBLIN_SESSIONS_DIR"] = os.path.join(_MODULE_TEMP_DIR.name, "data", "protogoblin", "sessions")


def tearDownModule():
    _MODULE_TEMP_DIR.cleanup()
    if _ORIG_XDG_DATA is not None:
        os.environ["XDG_DATA_HOME"] = _ORIG_XDG_DATA
    else:
        os.environ.pop("XDG_DATA_HOME", None)
    if _ORIG_XDG_CONFIG is not None:
        os.environ["XDG_CONFIG_HOME"] = _ORIG_XDG_CONFIG
    else:
        os.environ.pop("XDG_CONFIG_HOME", None)
    if _ORIG_SESSIONS_DIR is not None:
        os.environ["PROTOGOBLIN_SESSIONS_DIR"] = _ORIG_SESSIONS_DIR
    else:
        os.environ.pop("PROTOGOBLIN_SESSIONS_DIR", None)


class TestDiagnosticAdvisor(unittest.TestCase):
    def test_optimal_fastpath_session(self):
        manifest = {
            "session": {"mode": "profile"},
            "synchronization": {"sync_backend": "ntsync"},
            "graphics": {"active_backend": "dxvk"},
            "anti_cheat": {"detected": False},
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["level"], "success")
        self.assertIn("Optimal Fast-Path Sync Active (NTSYNC)", suggestions[0]["title"])

    def test_wineserver_rpc_fallback_detected(self):
        manifest = {
            "synchronization": {"sync_backend": "wineserver_rpc"},
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Slow Wineserver RPC" in t for t in titles))
        self.assertTrue(any(s["level"] == "error" for s in suggestions))

    def test_anti_cheat_passthrough(self):
        manifest = {
            "anti_cheat": {"detected": True, "provider": "Easy Anti-Cheat"},
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Anti-Cheat Active (Easy Anti-Cheat)" in t for t in titles))
        self.assertTrue(any("Profiling Suppressed" in t for t in titles))
        self.assertTrue(any("zero-injection passthrough" in s["description"].lower() for s in suggestions))
        self.assertTrue(any(s["level"] == "warning" for s in suggestions))

    def test_shader_compilation_stalls(self):
        manifest = {
            "graphics": {
                "active_backend": "dxvk",
                "shader_compiles": {
                    "count": 120,
                    "total_time_ms": 850.5,
                    "pipeline_cache_hit_rate": 0.45,
                },
            }
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Shader Compilation Stuttering Observed" in t for t in titles))
        self.assertTrue(any(s["level"] == "warning" for s in suggestions))

    def test_pacing_volatility_frametime(self):
        manifest = {
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "gpu_bound",
                "frame_metrics": {
                    "fps_avg": 90.0,
                    "fps_1_pct_low": 40.0,
                    "frametime_jitter_ms": 8.5,
                },
                "pacing": {"gpu_busy_pct": 98.0},
            }
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Significant Frame Pacing Volatility" in t for t in titles))
        self.assertTrue(any("GPU Bound" in t for t in titles))

    def test_frametime_jitter_tightened_rule(self):
        manifest = {
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {
                    "fps_avg": 60.0,
                    "fps_1_pct_low": 55.0,
                    "frametime_jitter_ms": 12.4,
                },
            }
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        # Tightened rule: Jitter alone does not prove constant buffer or swapchain issues.
        # It must propose frame rate pacing and avoid premature wrapper shims.
        jitter_suggs = [s for s in suggestions if "Elevated Presentation Frametime Jitter" in s["title"]]
        self.assertEqual(len(jitter_suggs), 1)
        self.assertEqual(jitter_suggs[0]["fix_id"], "cap_framerate")
        self.assertFalse(any(s.get("fix_id") == "state_dedup_and_debounce" for s in suggestions))

    def test_direct_d3d11_wrapper_stats_cb_spam(self):
        # 1. Unoptimized case: state_dedup_active = False -> warning + fix action
        m_unopt = {
            "graphics": {
                "d3d11_wrapper_stats": {
                    "state_dedup_active": False,
                    "swapchain_debounce_active": False,
                    "constant_buffers": {
                        "updates_total": 6000,
                        "updates_redundant": 4200,
                        "redundancy_rate_pct": 70.0,
                    },
                }
            }
        }
        suggs = DiagnosticAdvisor.analyze(m_unopt)
        spam_suggs = [s for s in suggs if "Constant Buffer State Spam" in s["title"]]
        self.assertEqual(len(spam_suggs), 1)
        self.assertEqual(spam_suggs[0]["level"], "warning")
        self.assertEqual(spam_suggs[0]["fix_id"], "state_dedup_and_debounce")

        # 2. Optimized case: state_dedup_active = True -> success metric
        m_opt = {
            "graphics": {
                "d3d11_wrapper_stats": {
                    "state_dedup_active": True,
                    "swapchain_debounce_active": False,
                    "constant_buffers": {
                        "updates_total": 6000,
                        "updates_redundant": 4200,
                        "redundancy_rate_pct": 70.0,
                    },
                }
            }
        }
        suggs_opt = DiagnosticAdvisor.analyze(m_opt)
        active_suggs = [s for s in suggs_opt if "Constant Buffer Deduplication Active" in s["title"]]
        self.assertEqual(len(active_suggs), 1)
        self.assertEqual(active_suggs[0]["level"], "success")

    def test_direct_d3d11_wrapper_stats_swapchain_choke(self):
        # 1. Unoptimized case -> warning
        m_unopt = {
            "graphics": {
                "d3d11_wrapper_stats": {
                    "state_dedup_active": False,
                    "swapchain_debounce_active": False,
                    "swapchain": {
                        "resizes_total": 10,
                        "resizes_identical": 7,
                        "resizes_rapid": 2,
                    },
                }
            }
        }
        suggs = DiagnosticAdvisor.analyze(m_unopt)
        choke_suggs = [s for s in suggs if "SwapChain Resize Choke Detected" in s["title"]]
        self.assertEqual(len(choke_suggs), 1)
        self.assertEqual(choke_suggs[0]["level"], "warning")
        self.assertEqual(choke_suggs[0]["fix_id"], "state_dedup_and_debounce")

        # 2. Optimized case -> success
        m_opt = {
            "graphics": {
                "d3d11_wrapper_stats": {
                    "state_dedup_active": False,
                    "swapchain_debounce_active": True,
                    "swapchain": {
                        "resizes_total": 10,
                        "resizes_identical": 7,
                        "resizes_rapid": 2,
                    },
                }
            }
        }
        suggs_opt = DiagnosticAdvisor.analyze(m_opt)
        active_suggs = [s for s in suggs_opt if "SwapChain Debounce Active" in s["title"]]
        self.assertEqual(len(active_suggs), 1)
        self.assertEqual(active_suggs[0]["level"], "success")

    def test_direct_io_stats_unoptimized_warning(self):
        m_unopt = {
            "filesystem": {
                "io_cache_stats": {
                    "io_cache_active": False,
                    "tracked_archives_count": 5,
                    "reads_total": 4500,
                    "reads_cached_hits": 0,
                    "hit_rate_pct": 0.0,
                    "bytes_read_total": 15000000,
                    "bytes_cached_saved": 0,
                    "estimated_latency_saved_ms": 0.0,
                }
            }
        }
        suggs = DiagnosticAdvisor.analyze(m_unopt)
        io_suggs = [s for s in suggs if "Synchronous Traversal File I/O Overhead" in s["title"]]
        self.assertEqual(len(io_suggs), 1)
        self.assertEqual(io_suggs[0]["level"], "warning")
        self.assertEqual(io_suggs[0]["fix_id"], "enable_io_cache")
        self.assertIn("Enable Traversal File I/O Cache", io_suggs[0]["fix_button_text"])

    def test_direct_io_stats_optimized_success(self):
        m_opt = {
            "filesystem": {
                "io_cache_stats": {
                    "io_cache_active": True,
                    "tracked_archives_count": 5,
                    "reads_total": 4500,
                    "reads_cached_hits": 3600,
                    "hit_rate_pct": 80.0,
                    "bytes_read_total": 15000000,
                    "bytes_cached_saved": 12000000,
                    "estimated_latency_saved_ms": 54.0,
                }
            }
        }
        suggs = DiagnosticAdvisor.analyze(m_opt)
        io_suggs = [s for s in suggs if "Traversal File I/O Cache Active" in s["title"]]
        self.assertEqual(len(io_suggs), 1)
        self.assertEqual(io_suggs[0]["level"], "success")

    def test_direct_precision_timers_unoptimized_warning(self):
        m_unopt = {
            "graphics": {
                "d3d11_wrapper_stats": {
                    "timing": {
                        "high_precision_timers_active": False,
                        "sleep_calls_total": 2400,
                        "sleep_spin_hybrid_calls": 0,
                        "overshoot_prevented_calls": 0,
                        "overshoot_avoided_ms": 0.0,
                    }
                }
            }
        }
        suggs = DiagnosticAdvisor.analyze(m_unopt)
        timer_suggs = [s for s in suggs if "High Game-Loop Sleep Timer Activity" in s["title"]]
        self.assertEqual(len(timer_suggs), 1)
        self.assertEqual(timer_suggs[0]["level"], "warning")
        self.assertEqual(timer_suggs[0]["fix_id"], "enable_precision_timers")
        self.assertIn("Enable High-Precision Sleep Timers", timer_suggs[0]["fix_button_text"])

    def test_direct_precision_timers_optimized_success(self):
        m_opt = {
            "graphics": {
                "d3d11_wrapper_stats": {
                    "timing": {
                        "high_precision_timers_active": True,
                        "sleep_calls_total": 2400,
                        "sleep_spin_hybrid_calls": 2400,
                        "overshoot_prevented_calls": 2100,
                        "overshoot_avoided_ms": 4200.0,
                    }
                }
            }
        }
        suggs = DiagnosticAdvisor.analyze(m_opt)
        timer_suggs = [s for s in suggs if "High-Precision Sleep Timers Active" in s["title"]]
        self.assertEqual(len(timer_suggs), 1)
        self.assertEqual(timer_suggs[0]["level"], "success")

    def test_subsystem_pruning_opportunity(self):
        manifest = {
            "subsystems": {
                "unutilized": ["vr", "rawinput", "mfplat"],
            }
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Subsystem Pruning Available" in t for t in titles))
        self.assertTrue(any(s["level"] == "info" for s in suggestions))

    def test_engine_recommendations(self):
        # Unreal Engine 5
        m_ue5 = {"target": {"engine": {"detected": True, "engine": "unreal_5"}}}
        s_ue5 = DiagnosticAdvisor.analyze(m_ue5)
        self.assertTrue(any("Unreal Engine 5 Optimization Profile" in s["title"] for s in s_ue5))

        # Unity
        m_unity = {"target": {"engine": {"detected": True, "engine": "unity", "details": {"backend": "il2cpp"}}}}
        s_unity = DiagnosticAdvisor.analyze(m_unity)
        self.assertTrue(any("Unity Engine Detected (il2cpp)" in s["title"] for s in s_unity))

        # Godot
        m_godot = {"target": {"engine": {"detected": True, "engine": "godot"}}}
        s_godot = DiagnosticAdvisor.analyze(m_godot)
        self.assertTrue(any("Godot Engine Detected" in s["title"] for s in s_godot))

    def test_advisor_ue5_lumen_vsm_heavy_workload(self):
        manifest = {
            "target": {"engine": {"detected": True, "engine": "unreal_5"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "gpu_bound",
                "frame_metrics": {"fps_avg": 55.0, "fps_1_pct_low": 32.0},
            },
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        ue5_sug = [s for s in suggestions if s.get("fix_id") == "optimize_ue5_lumen_vsm"]
        self.assertEqual(len(ue5_sug), 1)
        self.assertEqual(ue5_sug[0]["level"], "warning")
        self.assertIn("Optimize UE5 Lumen & Virtual Shadow Maps", ue5_sug[0]["title"])

    def test_intra_frame_staging_sync_stall_detection(self):
        # Simulation of Gust / Atelier staging sync flaw: low GPU and low CPU despite active gameplay
        manifest = {
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "sync_bound",
                "frame_metrics": {"fps_avg": 34.0, "fps_1_pct_low": 18.0},
                "pacing": {"gpu_busy_pct": 32.0, "cpu_busy_pct": 28.0},
            }
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Intra-Frame CPU-GPU Staging Synchronization Stall" in t for t in titles))
        self.assertTrue(any(s["level"] == "error" for s in suggestions))

    def test_preset_database_and_gust_flaw_flag(self):
        # Check PresetDatabase loads Atelier Ryza (1121560)
        preset = PresetDatabase.get_preset("1121560")
        self.assertIsNotNone(preset)
        self.assertIn("gust_d3d11_staging_sync_stall", preset.get("known_issues", []))

        # Check DiagnosticAdvisor flags the documented flaw for this Steam AppID
        manifest = {"target": {"steam_appid": 1121560}}
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Documented Gust Engine D3D11 Sync Stall" in t for t in titles))

    def test_immortals_of_aveum_demo_preset_and_advisor(self):
        # Immortals of Aveum Demo AppID 2555360
        preset = PresetDatabase.get_preset("2555360")
        self.assertIsNotNone(preset)
        self.assertIn("ue5_fsr_frame_gen_crash", preset.get("known_issues", []))
        self.assertIn("ue5_nanite_lumen_heavy_load", preset.get("known_issues", []))

        manifest = {"target": {"steam_appid": 2555360}}
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("FSR3 Frame Generation Crash Trap" in t for t in titles))
        self.assertTrue(any("Heavy UE5 Nanite & Lumen Translation Overhead" in t for t in titles))

    def test_auto_preset_injection_in_preflight(self):
        # Session without existing TOML config should auto-apply preset recommendations
        sess = ProtoGoblinSession(mode="play", steam_appid=2555360)
        env = {}
        argv = ["ImmortalsOfAveum.exe"]
        out_argv = sess.pre_flight(argv, env)

        self.assertEqual(env.get("VKD3D_FRAME_RATE"), "60")
        self.assertTrue(any("r.MotionBlurQuality 0" in arg for arg in out_argv))

    def test_raw_mode_bypass_presets(self):
        # Setting PROTOGOBLIN_RAW=1 bypasses presets for clean defect profiling
        os.environ["PROTOGOBLIN_RAW"] = "1"
        try:
            sess = ProtoGoblinSession(mode="profile", steam_appid=2555360)
            env = {}
            argv = ["ImmortalsOfAveum.exe"]
            out_argv = sess.pre_flight(argv, env)

            self.assertIsNone(env.get("VKD3D_FRAME_RATE"))
            self.assertFalse(any("r.MotionBlurQuality 0" in arg for arg in out_argv))
            self.assertEqual(out_argv, ["ImmortalsOfAveum.exe"])
        finally:
            del os.environ["PROTOGOBLIN_RAW"]


class TestEngineDetector(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_detect_unity(self):
        game_exe = os.path.join(self.test_dir, "MyGame.exe")
        with open(game_exe, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 100)

        # Create Unity _Data directory with il2cpp_data
        data_dir = os.path.join(self.test_dir, "MyGame_Data", "il2cpp_data")
        os.makedirs(data_dir, exist_ok=True)

        res = EngineDetector.detect(game_exe)
        self.assertTrue(res["detected"])
        self.assertEqual(res["engine"], "unity")
        self.assertEqual(res["details"]["backend"], "il2cpp")

    def test_detect_godot(self):
        game_exe = os.path.join(self.test_dir, "Brotato.exe")
        with open(game_exe, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 100)

        # Sibling PCK file
        pck_file = os.path.join(self.test_dir, "Brotato.pck")
        with open(pck_file, "wb") as f:
            f.write(b"GDPC\x00\x00\x00\x00")

        res = EngineDetector.detect(game_exe)
        self.assertTrue(res["detected"])
        self.assertEqual(res["engine"], "godot")
        self.assertEqual(res["details"]["pck_file"], "Brotato.pck")

    def test_detect_unreal_engine_5(self):
        # UE directory hierarchy: <GameRoot>/Binaries/Win64/<Game>-Win64-Shipping.exe
        bin_dir = os.path.join(self.test_dir, "Game", "Binaries", "Win64")
        paks_dir = os.path.join(self.test_dir, "Game", "Content", "Paks")
        os.makedirs(bin_dir, exist_ok=True)
        os.makedirs(paks_dir, exist_ok=True)

        game_exe = os.path.join(bin_dir, "Game-Win64-Shipping.exe")
        with open(game_exe, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 100 + b"FEngineLoop" + b"\x00" * 50)

        # Create UE5 Zen Store container file
        with open(os.path.join(paks_dir, "global.ucas"), "wb") as f:
            f.write(b"UCAS")

        res = EngineDetector.detect(game_exe)
        self.assertTrue(res["detected"])
        self.assertEqual(res["engine"], "unreal_5")
        self.assertTrue(res["details"]["has_zen_store"])


class TestProfileBannerHUD(unittest.TestCase):
    def test_profile_mode_mangohud_banner(self):
        old_mode = os.environ.get("PROTOGOBLIN_MODE")
        old_overlay = os.environ.get("PROTOGOBLIN_OVERLAY")
        try:
            os.environ["PROTOGOBLIN_MODE"] = "profile"
            os.environ.pop("PROTOGOBLIN_OVERLAY", None)
            session = ProtoGoblinSession()
            env = {}
            session.pre_flight(["dummy.exe"], env)

            self.assertEqual(env.get("MANGOHUD"), "1")
            config = env.get("MANGOHUD_CONFIG", "")
            self.assertIn("custom_text=ProtoGoblin\\:", config)
            self.assertIn("toggle_logging=Alt_L+F11", config)
            self.assertIn("exec=", config)
            self.assertIn("position=top-right", config)
            self.assertIn("text_color=39FF14", config)
            self.assertIn("blacklist=steam.exe", config)
            self.assertIn("blacklist=tabtip.exe", config)
            self.assertIn("blacklist=iscriptevaluator.exe", config)
            self.assertIn("blacklist=winedevice.exe", config)

            # Inactive profiling banner
            self.assertEqual(session.get_hud_status(), "ProtoGoblin: Press alt-f11 to start Profiling")

            # Active profiling banner
            active_csv = os.path.join(session.session_dir, "Game_20261028_090000.csv")
            with open(active_csv, "w") as f:
                f.write("Frame,Frametime\n1,16.6\n")
            self.assertEqual(session.get_hud_status(), "ProtoGoblin: Profiling")

            # Post-active profiling with summary
            with open(os.path.join(session.session_dir, "Game_20261028_090000_summary.csv"), "w") as f:
                f.write("summary")
            os.utime(active_csv, (time.time() - 10, time.time() - 10))
            self.assertEqual(session.get_hud_status(), "ProtoGoblin: Press alt-f11 to start Profiling")
        finally:
            if old_mode is not None:
                os.environ["PROTOGOBLIN_MODE"] = old_mode
            else:
                os.environ.pop("PROTOGOBLIN_MODE", None)
            if old_overlay is not None:
                os.environ["PROTOGOBLIN_OVERLAY"] = old_overlay

    def test_profile_mode_custom_assigned_key(self):
        old_mode = os.environ.get("PROTOGOBLIN_MODE")
        old_key = os.environ.get("PROTOGOBLIN_PROFILE_KEY")
        try:
            os.environ["PROTOGOBLIN_MODE"] = "profile"
            os.environ["PROTOGOBLIN_PROFILE_KEY"] = "ctrl-f12"
            session = ProtoGoblinSession()
            env = {}
            session.pre_flight(["dummy.exe"], env)

            config = env.get("MANGOHUD_CONFIG", "")
            self.assertIn("toggle_logging=Control_L+F12", config)
            self.assertEqual(session.get_hud_status(), "ProtoGoblin: Press ctrl-f12 to start Profiling")
        finally:
            if old_mode is not None:
                os.environ["PROTOGOBLIN_MODE"] = old_mode
            else:
                os.environ.pop("PROTOGOBLIN_MODE", None)
            if old_key is not None:
                os.environ["PROTOGOBLIN_PROFILE_KEY"] = old_key
            else:
                os.environ.pop("PROTOGOBLIN_PROFILE_KEY", None)

    def test_profile_mode_overlay_disabled(self):
        old_mode = os.environ.get("PROTOGOBLIN_MODE")
        old_overlay = os.environ.get("PROTOGOBLIN_OVERLAY")
        try:
            os.environ["PROTOGOBLIN_MODE"] = "profile"
            os.environ["PROTOGOBLIN_OVERLAY"] = "0"
            session = ProtoGoblinSession()
            env = {}
            session.pre_flight(["dummy.exe"], env)

            self.assertEqual(env.get("MANGOHUD"), "1")
            config = env.get("MANGOHUD_CONFIG", "")
            self.assertIn("no_display=1", config)
            self.assertNotIn("custom_text=ProtoGoblin", config)
        finally:
            if old_mode is not None:
                os.environ["PROTOGOBLIN_MODE"] = old_mode
            else:
                os.environ.pop("PROTOGOBLIN_MODE", None)
            if old_overlay is not None:
                os.environ["PROTOGOBLIN_OVERLAY"] = old_overlay
            else:
                os.environ.pop("PROTOGOBLIN_OVERLAY", None)


class TestSessionInitialModeSelection(unittest.TestCase):
    def test_first_run_defaults_to_profile_mode(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg_data = os.environ.get("XDG_DATA_HOME")
            old_xdg_cfg = os.environ.get("XDG_CONFIG_HOME")
            old_mode_env = os.environ.pop("PROTOGOBLIN_MODE", None)
            os.environ["XDG_DATA_HOME"] = os.path.join(td, "data")
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, "config")
            try:
                sess = ProtoGoblinSession(steam_appid=44444)
                env = {}
                sess.pre_flight(["BrandNewGame.exe"], env)
                self.assertEqual(sess.mode, "profile")
                self.assertEqual(env.get("MANGOHUD"), "1")
                self.assertIn("custom_text=ProtoGoblin\\:", env.get("MANGOHUD_CONFIG", ""))
            finally:
                if old_mode_env:
                    os.environ["PROTOGOBLIN_MODE"] = old_mode_env
                if old_xdg_data:
                    os.environ["XDG_DATA_HOME"] = old_xdg_data
                else:
                    os.environ.pop("XDG_DATA_HOME", None)
                if old_xdg_cfg:
                    os.environ["XDG_CONFIG_HOME"] = old_xdg_cfg
                else:
                    os.environ.pop("XDG_CONFIG_HOME", None)

    def test_subsequent_run_without_profile_defaults_to_play_mode(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg_data = os.environ.get("XDG_DATA_HOME")
            old_xdg_cfg = os.environ.get("XDG_CONFIG_HOME")
            old_mode_env = os.environ.pop("PROTOGOBLIN_MODE", None)
            data_dir = os.path.join(td, "data")
            os.environ["XDG_DATA_HOME"] = data_dir
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, "config")
            try:
                # Simulate prior session manifest existing
                prior_sess_dir = os.path.join(data_dir, "protogoblin", "sessions", "44444", "20261028T010000Z-0001")
                os.makedirs(prior_sess_dir, exist_ok=True)
                with open(os.path.join(prior_sess_dir, "utilization.json"), "w", encoding="utf-8") as f:
                    json.dump({"session": {"mode": "profile"}}, f)

                sess = ProtoGoblinSession(steam_appid=44444)
                env = {}
                sess.pre_flight(["BrandNewGame.exe"], env)
                self.assertEqual(sess.mode, "play")
                self.assertIsNone(env.get("MANGOHUD"))
            finally:
                if old_mode_env:
                    os.environ["PROTOGOBLIN_MODE"] = old_mode_env
                if old_xdg_data:
                    os.environ["XDG_DATA_HOME"] = old_xdg_data
                else:
                    os.environ.pop("XDG_DATA_HOME", None)
                if old_xdg_cfg:
                    os.environ["XDG_CONFIG_HOME"] = old_xdg_cfg
                else:
                    os.environ.pop("XDG_CONFIG_HOME", None)

    def test_explicit_play_mode_override_on_first_run(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg_data = os.environ.get("XDG_DATA_HOME")
            old_xdg_cfg = os.environ.get("XDG_CONFIG_HOME")
            old_mode_env = os.environ.get("PROTOGOBLIN_MODE")
            os.environ["PROTOGOBLIN_MODE"] = "play"
            os.environ["XDG_DATA_HOME"] = os.path.join(td, "data")
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, "config")
            try:
                sess = ProtoGoblinSession(steam_appid=44444)
                env = {}
                sess.pre_flight(["BrandNewGame.exe"], env)
                self.assertEqual(sess.mode, "play")
                self.assertIsNone(env.get("MANGOHUD"))
            finally:
                if old_mode_env:
                    os.environ["PROTOGOBLIN_MODE"] = old_mode_env
                else:
                    os.environ.pop("PROTOGOBLIN_MODE", None)
                if old_xdg_data:
                    os.environ["XDG_DATA_HOME"] = old_xdg_data
                else:
                    os.environ.pop("XDG_DATA_HOME", None)
                if old_xdg_cfg:
                    os.environ["XDG_CONFIG_HOME"] = old_xdg_cfg
                else:
                    os.environ.pop("XDG_CONFIG_HOME", None)

    def test_non_exe_binary_detection_and_layer_paths(self):
        with tempfile.TemporaryDirectory() as td:
            dummy_bin = os.path.join(td, "MinamiLane.x86_64")
            with open(dummy_bin, "wb") as f:
                f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
            os.chmod(dummy_bin, 0o755)

            sess = ProtoGoblinSession(steam_appid=2678990)
            env = {}
            sess.pre_flight([dummy_bin], env)
            self.assertEqual(sess.initial_exe, dummy_bin)
            self.assertEqual(sess.target_exe.get("arch"), "x86_64")
            if sess.mode == "profile":
                self.assertIn("VK_ADD_LAYER_PATH", env)
                self.assertIn("LD_LIBRARY_PATH", env)

    def test_first_run_with_anticheat_suppresses_profiling(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg_data = os.environ.get("XDG_DATA_HOME")
            old_xdg_cfg = os.environ.get("XDG_CONFIG_HOME")
            old_mode_env = os.environ.pop("PROTOGOBLIN_MODE", None)
            os.environ["XDG_DATA_HOME"] = os.path.join(td, "data")
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, "config")
            try:
                game_dir = os.path.join(td, "game")
                os.makedirs(game_dir, exist_ok=True)
                exe_path = os.path.join(game_dir, "Game.exe")
                with open(exe_path, "wb") as f:
                    f.write(b"MZ\x90\x00" + b"\x00" * 100)
                eac_dll = os.path.join(game_dir, "easyanticheat_x64.so")
                with open(eac_dll, "wb") as f:
                    f.write(b"\x7fELF")

                sess = ProtoGoblinSession(steam_appid=55555)
                env = {}
                sess.pre_flight([exe_path], env)
                self.assertEqual(sess.mode, "play")
                self.assertTrue(sess.anti_cheat.get("profiling_suppressed"))
                self.assertIsNone(env.get("MANGOHUD"))

                manifest = sess.post_flight(0, env=env)
                self.assertTrue(manifest["session"]["profiling_suppressed"])
                self.assertIn("EasyAntiCheat", manifest["session"]["suppression_reason"])
            finally:
                if old_mode_env:
                    os.environ["PROTOGOBLIN_MODE"] = old_mode_env
                if old_xdg_data:
                    os.environ["XDG_DATA_HOME"] = old_xdg_data
                else:
                    os.environ.pop("XDG_DATA_HOME", None)
                if old_xdg_cfg:
                    os.environ["XDG_CONFIG_HOME"] = old_xdg_cfg
                else:
                    os.environ.pop("XDG_CONFIG_HOME", None)


class TestEngineTweakManager(unittest.TestCase):
    def test_unreal_engine_tweak_injection(self):
        profile = {
            "engine": {
                "unreal": {
                    "disable_motion_blur": True,
                    "disable_depth_of_field": True,
                    "disable_chromatic_aberration": True,
                    "disable_film_grain": True,
                }
            }
        }
        argv = ["Game-Win64-Shipping.exe"]
        env = {}
        new_argv = EngineTweakManager.apply_tweaks(profile, {"engine": "unreal_5"}, argv, env)

        self.assertEqual(len(new_argv), 2)
        exec_arg = new_argv[1]
        self.assertTrue(exec_arg.startswith('-ExecCmds="'))
        self.assertIn("r.MotionBlurQuality 0", exec_arg)
        self.assertIn("r.DepthOfFieldQuality 0", exec_arg)
        self.assertIn("r.SceneColorFringeQuality 0", exec_arg)
        self.assertIn("r.FilmGrain 0", exec_arg)

    def test_ue5_lumen_and_vsm_cvar_injection(self):
        profile = {
            "engine": {
                "unreal": {
                    "optimize_lumen": True,
                    "optimize_vsm": True,
                    "optimize_nanite": True,
                    "disable_virtual_shadows": True,
                }
            }
        }
        argv = ["Game-Win64-Shipping.exe"]
        env = {}
        new_argv = EngineTweakManager.apply_tweaks(profile, {"engine": "unreal_5"}, argv, env)

        self.assertEqual(len(new_argv), 2)
        exec_arg = new_argv[1]
        self.assertTrue(exec_arg.startswith('-ExecCmds="'))
        # Lumen optimizations
        self.assertIn("r.Lumen.ScreenProbeGather.DownsampleByTwo 1", exec_arg)
        self.assertIn("r.Lumen.TranslucencyReflections.FrontLayer.Allow 0", exec_arg)
        self.assertIn("r.Lumen.Reflections.DownsampleFactor 2", exec_arg)
        # VSM optimizations
        self.assertIn("r.Shadow.Virtual.SMRT.RayCountDirectional 4", exec_arg)
        self.assertIn("r.Shadow.Virtual.ResolutionLodBiasDirectional 1.0", exec_arg)
        self.assertIn("r.Shadow.Virtual.Cache.MaxPageAge 16", exec_arg)
        # Nanite optimizations
        self.assertIn("r.Nanite.MaxNodesPerFrame 262144", exec_arg)
        self.assertIn("r.Nanite.ViewMeshLODBias 0.5", exec_arg)
        # Disable VSM
        self.assertIn("r.Shadow.Virtual.Enable 0", exec_arg)

    def test_vkd3d_config_injection(self):
        profile = {
            "graphics": {
                "backend": "vkd3d",
                "vkd3d": {
                    "descriptor_buffer": True,
                    "force_static_cbv": True,
                    "single_queue": True,
                }
            }
        }
        env = {"VKD3D_CONFIG": "no_upload_hvv"}
        EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env)
        vkd3d_cfg = env.get("VKD3D_CONFIG", "").split(",")
        self.assertIn("no_upload_hvv", vkd3d_cfg)
        self.assertIn("descriptor_buffer", vkd3d_cfg)
        self.assertIn("force_static_cbv", vkd3d_cfg)
        self.assertIn("single_queue", vkd3d_cfg)

    def test_generate_profile_toml_ue5_and_vkd3d(self):
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="99999",
            app_id=99999,
            target_exe="UE5Game.exe",
            engine_info={"engine": "unreal_5"},
            user_tweaks={
                "unreal": {
                    "optimize_lumen": True,
                    "optimize_vsm": True,
                    "optimize_nanite": True,
                    "disable_virtual_shadows": True,
                },
                "graphics": {
                    "vkd3d": {
                        "descriptor_buffer": True,
                        "force_static_cbv": True,
                        "single_queue": True,
                    }
                }
            },
        )
        self.assertIn("[engine.unreal]", toml_text)
        self.assertIn("optimize_lumen = true", toml_text)
        self.assertIn("optimize_vsm = true", toml_text)
        self.assertIn("optimize_nanite = true", toml_text)
        self.assertIn("disable_virtual_shadows = true", toml_text)
        self.assertIn("[graphics.vkd3d]", toml_text)
        self.assertIn("force_static_cbv = true", toml_text)
        self.assertIn("single_queue = true", toml_text)

    def test_unity_and_godot_tweak_injection(self):
        profile = {
            "engine": {
                "unity": {"force_vulkan": True},
                "godot": {"rendering_driver": "vulkan", "max_fps": 120},
            }
        }
        # Unity
        u_argv = EngineTweakManager.apply_tweaks(profile, {"engine": "unity"}, ["Game.exe"], {})
        self.assertIn("-force-vulkan", u_argv)

        # Godot
        g_argv = EngineTweakManager.apply_tweaks(profile, {"engine": "godot"}, ["Brotato.exe"], {})
        self.assertIn("--rendering-driver", g_argv)
        self.assertIn("vulkan", g_argv)
        self.assertIn("--max-fps=120", g_argv)

    def test_engine_tweak_guarding_for_unknown_engines(self):
        profile = {
            "game": {"detected_engine": "unknown"},
            "engine": {
                "unreal": {"disable_motion_blur": True},
                "unity": {"force_vulkan": True},
                "godot": {"rendering_driver": "vulkan", "max_fps": 120},
            }
        }
        # When engine is unknown, no engine-specific argv flags should be injected
        out_argv = EngineTweakManager.apply_tweaks(profile, {"engine": "unknown"}, ["Game.exe"], {})
        self.assertEqual(out_argv, ["Game.exe"])

        # Also when engine_info is empty
        out_argv2 = EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], {})
        self.assertEqual(out_argv2, ["Game.exe"])

    def test_generate_profile_toml_omits_irrelevant_engines(self):
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="386140",
            app_id=386140,
            target_exe="Game.exe",
            engine_info={"engine": "unknown"},
            user_tweaks={"mode": "profile"},
        )
        self.assertNotIn("[engine.unreal]", toml_text)
        self.assertNotIn("[engine.unity]", toml_text)
        self.assertNotIn("[engine.godot]", toml_text)

    def test_dxvk_graphics_intercepts(self):
        profile = {
            "graphics": {
                "force_vsync": "off",
                "max_fps": 144,
                "anisotropic_filtering": 16,
                "async_shader_compile": True,
                "low_latency": True,
            }
        }
        env = {}
        EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env)

        self.assertEqual(env.get("DXVK_ASYNC"), "1")
        self.assertEqual(env.get("VKD3D_FRAME_RATE"), "144")
        dxvk_cfg = env.get("DXVK_CONFIG", "")
        self.assertIn("dxgi.syncInterval = 0", dxvk_cfg)
        self.assertIn("d3d11.samplerAnisotropy = 16", dxvk_cfg)
        self.assertIn("dxgi.maxFrameRate = 144", dxvk_cfg)
        self.assertIn("dxvk.enableAsync = true", dxvk_cfg)
        self.assertIn("dxvk.lowLatency = true", dxvk_cfg)

    def test_dxvk_27_descriptor_buffer_and_reflex(self):
        profile = {
            "graphics": {
                "descriptor_buffer": True,
                "nv_reflex": True,
            }
        }
        env = {}
        EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env)
        dxvk_cfg = env.get("DXVK_CONFIG", "")
        self.assertIn("dxvk.enableDescriptorBuffer = true", dxvk_cfg)
        self.assertIn("dxvk.nvLowLatency2 = true", dxvk_cfg)
        self.assertEqual(env.get("DXVK_NVAPI_ENABLE_REFLEX"), "1")

    def test_cpu_bound_descriptor_buffer_suggestion(self):
        manifest = {
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "cpu_bound",
                "pacing": {"cpu_busy_pct": 92.0, "gpu_busy_pct": 45.0},
            },
            "environment": {"cpu": {"logical_cores": 8}},
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        db_sugg = [s for s in suggestions if s.get("fix_id") == "enable_descriptor_buffer"]
        self.assertTrue(len(db_sugg) > 0)
        self.assertIn("Enable Vulkan Descriptor Buffers", db_sugg[0]["fix_button_text"])

    def test_generate_and_load_profile_toml(self):
        with tempfile.TemporaryDirectory() as td:
            p_file = os.path.join(td, "game.toml")
            toml_text = EngineTweakManager.generate_profile_toml(
                game_id="12345",
                app_id=12345,
                target_exe="Game.exe",
                engine_info={"engine": "unreal_5"},
                sync_backend="ntsync",
                user_tweaks={
                    "unreal": {"disable_motion_blur": True},
                    "graphics": {"force_vsync": "off", "anisotropic_filtering": 16},
                },
            )
            with open(p_file, "w", encoding="utf-8") as f:
                f.write(toml_text)

            loaded = EngineTweakManager.load_profile(p_file)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["game"]["steam_appid"], 12345)
            self.assertTrue(loaded["engine"]["unreal"]["disable_motion_blur"])
            self.assertEqual(loaded["graphics"]["force_vsync"], "off")

    def test_atelier_sync_fix_pipeline(self):
        # 1. Profile Telemetry detection produces fix_id "atelier_sync_fix"
        manifest = {
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "sync_bound",
                "frame_metrics": {"fps_avg": 25.0, "fps_1_pct_low": 12.0},
                "pacing": {"gpu_busy_pct": 28.0, "cpu_busy_pct": 30.0},
            }
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        sync_suggestions = [s for s in suggestions if s.get("fix_id") == "atelier_sync_fix"]
        self.assertTrue(len(sync_suggestions) > 0)
        self.assertIn("Apply Staging Buffer Sync Fix", sync_suggestions[0]["fix_button_text"])

        # 2. TOML profile generation with atelier_sync_fix
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="1121560",
            app_id=1121560,
            target_exe="Atelier_Ryza.exe",
            user_tweaks={"atelier_sync_fix": True, "graphics": {"force_vsync": "off"}},
        )
        self.assertIn("[synchronization.atelier_sync_fix]", toml_text)
        self.assertIn("enabled = true", toml_text)

        # 3. Applying tweaks injects WINEDLLOVERRIDES="d3d11=n,b" and syncInterval=0
        profile = {
            "synchronization": {"atelier_sync_fix": {"enabled": True}},
            "graphics": {"force_vsync": "off"},
        }
        env = {}
        EngineTweakManager.apply_tweaks(profile, {}, ["Atelier_Ryza.exe"], env)
        self.assertIn("d3d11=n,b", env.get("WINEDLLOVERRIDES", ""))
        self.assertIn("dxgi.syncInterval = 0", env.get("DXVK_CONFIG", ""))
        self.assertEqual(env.get("PROTOGOBLIN_STAGING_SYNC_FIX"), "1")

    def test_vendored_staging_sync_fix_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            lib64 = os.path.join(td, "share", "protogoblin", "lib64")
            os.makedirs(lib64, exist_ok=True)
            profile = {
                "synchronization": {"atelier_sync_fix": {"enabled": True}},
            }
            env = {}
            EngineTweakManager.apply_tweaks(profile, {}, ["Atelier_Ryza.exe"], env, proton_dir=td)
            self.assertIn("d3d11=n,b", env.get("WINEDLLOVERRIDES", ""))
            self.assertEqual(env.get("PROTOGOBLIN_STAGING_SYNC_FIX"), "1")
            self.assertIn(lib64, env.get("WINEDLLPATH", ""))

    def test_state_dedup_and_swapchain_debounce_pipeline(self):
        # 1. TOML profile generation with state_dedup and swapchain_debounce
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="2555360",
            app_id=2555360,
            target_exe="Game.exe",
            user_tweaks={
                "synchronization": {
                    "state_dedup": True,
                    "swapchain_debounce": True,
                }
            },
        )
        self.assertIn("[synchronization.state_dedup]", toml_text)
        self.assertIn("[synchronization.swapchain_debounce]", toml_text)
        self.assertIn("enabled = true", toml_text)

        # 2. Applying tweaks injects overrides and flags
        profile = {
            "synchronization": {
                "state_dedup": {"enabled": True},
                "swapchain_debounce": {"enabled": True},
            }
        }
        env = {}
        EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env)
        self.assertIn("d3d11=n,b", env.get("WINEDLLOVERRIDES", ""))
        self.assertEqual(env.get("PROTOGOBLIN_STATE_DEDUP"), "1")
        self.assertEqual(env.get("PROTOGOBLIN_SWAPCHAIN_DEBOUNCE"), "1")

    def test_vendored_state_dedup_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            lib64 = os.path.join(td, "share", "protogoblin", "lib64")
            os.makedirs(lib64, exist_ok=True)
            profile = {
                "synchronization": {"state_dedup": {"enabled": True}},
            }
            env = {}
            EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env, proton_dir=td)
            self.assertIn("d3d11=n,b", env.get("WINEDLLOVERRIDES", ""))
            self.assertEqual(env.get("PROTOGOBLIN_STATE_DEDUP"), "1")
            self.assertIn(lib64, env.get("WINEDLLPATH", ""))

    def test_post_flight_ingests_d3d11_wrapper_stats(self):
        with tempfile.TemporaryDirectory() as td:
            old_base = os.environ.get("PROTOGOBLIN_SESSIONS_DIR")
            os.environ["PROTOGOBLIN_SESSIONS_DIR"] = td
            try:
                sess = ProtoGoblinSession(steam_appid=12345)
                env = {}
                sess.pre_flight(["Game.exe"], env)
                self.assertEqual(env.get("PROTOGOBLIN_SESSION_DIR"), sess.session_dir)

                # Simulate D3D11 wrapper emitting stats file
                stats_path = os.path.join(sess.session_dir, "protogoblin_d3d11_stats.json")
                wrapper_stats = {
                    "state_dedup_active": True,
                    "swapchain_debounce_active": True,
                    "constant_buffers": {
                        "updates_total": 5000,
                        "updates_redundant": 3000,
                        "redundancy_rate_pct": 60.0,
                    },
                    "swapchain": {
                        "resizes_total": 5,
                        "resizes_identical": 4,
                        "resizes_rapid": 1,
                    },
                }
                with open(stats_path, "w", encoding="utf-8") as f:
                    json.dump(wrapper_stats, f)

                manifest = sess.post_flight(0, env=env)
                self.assertIsNotNone(manifest)
                d3d11_metrics = manifest.get("graphics", {}).get("d3d11_wrapper_stats")
                self.assertIsNotNone(d3d11_metrics)
                self.assertTrue(d3d11_metrics["state_dedup_active"])
                self.assertEqual(d3d11_metrics["constant_buffers"]["updates_redundant"], 3000)
            finally:
                if old_base:
                    os.environ["PROTOGOBLIN_SESSIONS_DIR"] = old_base
                else:
                    os.environ.pop("PROTOGOBLIN_SESSIONS_DIR", None)

    def test_io_cache_profile_and_env_injection(self):
        # 1. Profile generation
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="2555360",
            app_id=2555360,
            target_exe="Game.exe",
            user_tweaks={"filesystem": {"io_cache": True}},
        )
        self.assertIn("[filesystem.io_cache]", toml_text)
        self.assertIn("enabled = true", toml_text)

        # 2. Applying tweaks injects PROTOGOBLIN_IO_CACHE=1 and LD_PRELOAD if .so found
        with tempfile.TemporaryDirectory() as td:
            lib64 = os.path.join(td, "share", "protogoblin", "lib64")
            os.makedirs(lib64, exist_ok=True)
            so_file = os.path.join(lib64, "libprotogoblin_io_cache.so")
            with open(so_file, "w") as f:
                f.write("mock")

            profile = {"filesystem": {"io_cache": {"enabled": True}}}
            env = {}
            EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env, proton_dir=td)
            self.assertEqual(env.get("PROTOGOBLIN_IO_CACHE"), "1")
            self.assertIn(so_file, env.get("LD_PRELOAD", ""))

    def test_post_flight_ingests_io_cache_stats(self):
        with tempfile.TemporaryDirectory() as td:
            old_base = os.environ.get("PROTOGOBLIN_SESSIONS_DIR")
            os.environ["PROTOGOBLIN_SESSIONS_DIR"] = td
            try:
                sess = ProtoGoblinSession(steam_appid=55555)
                env = {}
                sess.pre_flight(["Game.exe"], env)

                # Simulate I/O cache emitting stats
                io_stats_path = os.path.join(sess.session_dir, "protogoblin_io_stats.json")
                stats_payload = {
                    "io_cache_active": True,
                    "tracked_archives_count": 8,
                    "reads_total": 12000,
                    "reads_cached_hits": 9500,
                    "hit_rate_pct": 79.17,
                    "bytes_read_total": 50000000,
                    "bytes_cached_saved": 40000000,
                    "estimated_latency_saved_ms": 142.5,
                }
                with open(io_stats_path, "w", encoding="utf-8") as f:
                    json.dump(stats_payload, f)

                manifest = sess.post_flight(0, env=env)
                self.assertIsNotNone(manifest)
                fs_metrics = manifest.get("filesystem", {}).get("io_cache_stats")
                self.assertIsNotNone(fs_metrics)
                self.assertTrue(fs_metrics["io_cache_active"])
                self.assertEqual(fs_metrics["reads_cached_hits"], 9500)
            finally:
                if old_base:
                    os.environ["PROTOGOBLIN_SESSIONS_DIR"] = old_base
                else:
                    os.environ.pop("PROTOGOBLIN_SESSIONS_DIR", None)

    def test_precision_timers_profile_and_env_injection(self):
        # 1. Profile generation
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="2555360",
            app_id=2555360,
            target_exe="Game.exe",
            user_tweaks={"timing": {"precision_timers": True}},
        )
        self.assertIn("[timing.precision_timers]", toml_text)
        self.assertIn("enabled = true", toml_text)

        # 2. Applying tweaks injects PROTOGOBLIN_HIGH_PRECISION_TIMERS=1 and d3d11 override
        profile = {"timing": {"precision_timers": {"enabled": True}}}
        env = {}
        EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env)
        self.assertEqual(env.get("PROTOGOBLIN_HIGH_PRECISION_TIMERS"), "1")
        self.assertIn("d3d11=n,b", env.get("WINEDLLOVERRIDES", ""))

    def test_profile_mode_in_profile_toml(self):
        with tempfile.TemporaryDirectory() as td:
            p_file = os.path.join(td, "99999.toml")
            toml_text = EngineTweakManager.generate_profile_toml(
                game_id="99999",
                app_id=99999,
                target_exe="TestGame.exe",
                user_tweaks={"mode": "profile"},
            )
            self.assertIn('mode = "profile"', toml_text)
            with open(p_file, "w", encoding="utf-8") as f:
                f.write(toml_text)

            old_mode_env = os.environ.pop("PROTOGOBLIN_MODE", None)
            os.environ["PROTOGOBLIN_PROFILE"] = p_file
            try:
                sess = ProtoGoblinSession(steam_appid=99999)
                env = {}
                sess.pre_flight(["TestGame.exe"], env)
                self.assertEqual(sess.mode, "profile")
                self.assertEqual(env.get("MANGOHUD"), "1")
                self.assertIn("custom_text=ProtoGoblin\\:", env.get("MANGOHUD_CONFIG", ""))
            finally:
                os.environ.pop("PROTOGOBLIN_PROFILE", None)
                if old_mode_env:
                    os.environ["PROTOGOBLIN_MODE"] = old_mode_env


class TestSessionComparison(unittest.TestCase):
    def test_session_diff_improved(self):
        manifest_a = {
            "session": {"id": "sess_a_1000", "mode": "profile"},
            "target": {"steam_appid": "1121560", "target_executable": {"path": "C:\\Games\\Atelier_Ryza.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "sync_bound",
                "frame_metrics": {
                    "fps_avg": 54.2,
                    "fps_1_pct_low": 22.4,
                    "fps_0_1_pct_low": 14.1,
                    "frametime_avg_ms": 18.45,
                    "frametime_jitter_ms": 18.40,
                },
                "pacing": {
                    "cpu_busy_pct": 15.0,
                    "cpu_wait_pct": 45.0,
                    "gpu_busy_pct": 35.0,
                },
            },
        }

        manifest_b = {
            "session": {"id": "sess_b_1015", "mode": "profile"},
            "target": {"steam_appid": "1121560", "target_executable": {"path": "C:\\Games\\Atelier_Ryza.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "gpu_bound",
                "frame_metrics": {
                    "fps_avg": 89.6,
                    "fps_1_pct_low": 61.1,
                    "fps_0_1_pct_low": 45.0,
                    "frametime_avg_ms": 11.16,
                    "frametime_jitter_ms": 2.10,
                },
                "pacing": {
                    "cpu_busy_pct": 22.0,
                    "cpu_wait_pct": 4.0,
                    "gpu_busy_pct": 98.0,
                },
            },
        }

        diff = compute_session_diff(manifest_a, manifest_b)
        self.assertEqual(diff["verdict"], "IMPROVED")
        self.assertTrue(diff["bottleneck"]["resolved"])
        self.assertEqual(diff["bottleneck"]["transition"], "sync_bound -> gpu_bound")
        self.assertAlmostEqual(diff["metrics"]["fps_avg"]["delta"], 35.4, places=1)
        self.assertAlmostEqual(diff["metrics"]["fps_avg"]["pct"], 65.3, places=1)
        self.assertAlmostEqual(diff["metrics"]["frametime_jitter_ms"]["delta"], -16.3, places=1)
        self.assertAlmostEqual(diff["hardware"]["cpu_wait_pct"]["delta"], -41.0, places=1)

        report = format_diff_report(diff)
        self.assertIn("IMPROVED", report)
        self.assertIn("Stall Resolved!", report)
        self.assertIn("Average Framerate:", report)
        self.assertIn("Hardware Resource Allocation".upper(), report)

    def test_session_diff_regressed(self):
        manifest_a = {
            "session": {"id": "sess_a", "mode": "profile"},
            "target": {"steam_appid": "12345", "target_executable": {"path": "Game.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "gpu_bound",
                "frame_metrics": {
                    "fps_avg": 100.0,
                    "fps_1_pct_low": 75.0,
                    "fps_0_1_pct_low": 60.0,
                    "frametime_avg_ms": 10.0,
                    "frametime_jitter_ms": 1.0,
                },
                "pacing": {"cpu_busy_pct": 50.0, "cpu_wait_pct": 5.0, "gpu_busy_pct": 99.0},
            },
        }

        manifest_b = {
            "session": {"id": "sess_b", "mode": "profile"},
            "target": {"steam_appid": "12345", "target_executable": {"path": "Game.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "bottleneck_classification": "cpu_bound",
                "frame_metrics": {
                    "fps_avg": 45.0,
                    "fps_1_pct_low": 25.0,
                    "fps_0_1_pct_low": 15.0,
                    "frametime_avg_ms": 22.2,
                    "frametime_jitter_ms": 6.5,
                },
                "pacing": {"cpu_busy_pct": 95.0, "cpu_wait_pct": 2.0, "gpu_busy_pct": 40.0},
            },
        }

        diff = compute_session_diff(manifest_a, manifest_b)
        self.assertEqual(diff["verdict"], "REGRESSED")
        self.assertFalse(diff["bottleneck"]["resolved"])
        self.assertAlmostEqual(diff["metrics"]["fps_avg"]["delta"], -55.0, places=1)
        self.assertAlmostEqual(diff["metrics"]["fps_avg"]["pct"], -55.0, places=1)

        report = format_diff_report(diff)
        self.assertIn("REGRESSED", report)

    def test_session_diff_missing_roi(self):
        manifest_a = {
            "session": {"id": "sess_play", "mode": "play"},
            "target": {"steam_appid": "111", "target_executable": {"path": "Game.exe"}},
            "roi_telemetry": None,
        }
        manifest_b = {
            "session": {"id": "sess_prof", "mode": "profile"},
            "target": {"steam_appid": "111", "target_executable": {"path": "Game.exe"}},
            "roi_telemetry": None,
        }

        diff = compute_session_diff(manifest_a, manifest_b)
        self.assertEqual(diff["verdict"], "INSUFFICIENT_DATA")
        report = format_diff_report(diff)
        self.assertIn("NOTICE: One or both sessions were executed in PLAY mode", report)

    def test_session_diff_with_anti_cheat_notice(self):
        manifest_a = {
            "session": {"id": "sess_ac", "mode": "play"},
            "target": {"steam_appid": "111", "target_executable": {"path": "Game.exe"}},
            "anti_cheat": {"detected": True, "provider": "BattlEye"},
            "roi_telemetry": None,
        }
        manifest_b = {
            "session": {"id": "sess_clean", "mode": "play"},
            "target": {"steam_appid": "111", "target_executable": {"path": "Game.exe"}},
            "roi_telemetry": None,
        }
        diff = compute_session_diff(manifest_a, manifest_b)
        report = format_diff_report(diff)
        self.assertIn("ANTI-CHEAT NOTICE: Active BattlEye detected", report)
        self.assertIn("Profiling hooks and ROI telemetry were automatically suppressed", report)


class TestSubsystemPruning(unittest.TestCase):
    def test_subsystem_pruning_play_mode_from_prior_session(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = td
            try:
                # Create prior profiling session with unutilized subsystems
                game_dir = os.path.join(td, "protogoblin", "sessions", "12345", "prior_session")
                os.makedirs(game_dir, exist_ok=True)
                prior_manifest = {
                    "session": {"id": "prior_session", "mode": "profile"},
                    "subsystems": {
                        "loaded": ["kernel32", "dxgi", "d3d11"],
                        "unutilized": ["openvr", "wineopenxr", "d3d12"],
                    },
                }
                with open(os.path.join(game_dir, "utilization.json"), "w", encoding="utf-8") as f:
                    json.dump(prior_manifest, f)

                # Run session in play mode
                sess = ProtoGoblinSession(steam_appid=12345, mode="play")
                env = {}
                sess.pre_flight(["Game.exe"], env)

                self.assertIn("vr", sess.pruned_subsystems)
                self.assertIn("openvr_api=d", env.get("WINEDLLOVERRIDES", ""))
                self.assertIn("wineopenxr=d", env.get("WINEDLLOVERRIDES", ""))
                self.assertEqual(env.get("PROTON_NO_VR"), "1")
                self.assertEqual(env.get("PROTON_DISABLE_OPENXR"), "1")
                self.assertIn("vr", env.get("PROTOGOBLIN_PRUNED_SUBSYSTEMS", ""))
            finally:
                if old_xdg:
                    os.environ["XDG_DATA_HOME"] = old_xdg
                else:
                    os.environ.pop("XDG_DATA_HOME", None)

    def test_subsystem_pruning_disabled_in_profile_mode(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = td
            try:
                game_dir = os.path.join(td, "protogoblin", "sessions", "12345", "prior_session")
                os.makedirs(game_dir, exist_ok=True)
                prior_manifest = {
                    "session": {"id": "prior_session"},
                    "subsystems": {"unutilized": ["openvr", "wineopenxr"]},
                }
                with open(os.path.join(game_dir, "utilization.json"), "w", encoding="utf-8") as f:
                    json.dump(prior_manifest, f)

                # In profile mode, pruning should NOT occur
                sess = ProtoGoblinSession(steam_appid=12345, mode="profile")
                env = {}
                sess.pre_flight(["Game.exe"], env)

                self.assertEqual(sess.pruned_subsystems, [])
                self.assertNotIn("openvr_api=d", env.get("WINEDLLOVERRIDES", ""))
                self.assertNotIn("PROTON_NO_VR", env)
            finally:
                if old_xdg:
                    os.environ["XDG_DATA_HOME"] = old_xdg
                else:
                    os.environ.pop("XDG_DATA_HOME", None)

    def test_subsystem_pruning_disabled_via_env(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            old_prune = os.environ.get("PROTOGOBLIN_PRUNE")
            os.environ["XDG_DATA_HOME"] = td
            os.environ["PROTOGOBLIN_PRUNE"] = "0"
            try:
                game_dir = os.path.join(td, "protogoblin", "sessions", "12345", "prior_session")
                os.makedirs(game_dir, exist_ok=True)
                prior_manifest = {
                    "session": {"id": "prior_session"},
                    "subsystems": {"unutilized": ["openvr", "wineopenxr"]},
                }
                with open(os.path.join(game_dir, "utilization.json"), "w", encoding="utf-8") as f:
                    json.dump(prior_manifest, f)

                sess = ProtoGoblinSession(steam_appid=12345, mode="play")
                env = {}
                sess.pre_flight(["Game.exe"], env)

                self.assertEqual(sess.pruned_subsystems, [])
                self.assertNotIn("openvr_api=d", env.get("WINEDLLOVERRIDES", ""))
            finally:
                if old_xdg:
                    os.environ["XDG_DATA_HOME"] = old_xdg
                else:
                    os.environ.pop("XDG_DATA_HOME", None)
                if old_prune is not None:
                    os.environ["PROTOGOBLIN_PRUNE"] = old_prune
                else:
                    os.environ.pop("PROTOGOBLIN_PRUNE", None)

    def test_subsystem_pruning_via_profile_config(self):
        sess = ProtoGoblinSession(steam_appid=55555, mode="play")
        env = {}
        profile = {
            "runtime": {"prune_unused_subsystems": True},
            "pruning": {"vr": True, "mfplat": True, "d3d12": True},
        }
        pruned = sess.prune_subsystems(env, profile=profile)
        self.assertIn("vr", pruned)
        self.assertIn("mfplat", pruned)
        self.assertIn("d3d12", pruned)
        self.assertIn("openvr_api=d", env.get("WINEDLLOVERRIDES", ""))
        self.assertIn("mfplat=d", env.get("WINEDLLOVERRIDES", ""))
        self.assertIn("d3d12=d", env.get("WINEDLLOVERRIDES", ""))
        self.assertEqual(env.get("PROTON_NO_VR"), "1")


class TestDevModeAndDebugDump(unittest.TestCase):
    def test_generate_debug_dump(self):
        dump = generate_debug_dump(manifest=None)
        self.assertIn("host", dump)
        self.assertIn("tool_files", dump)
        self.assertIn("environment", dump)
        self.assertIn("python_version", dump["host"])

        report = format_debug_dump(dump)
        self.assertIn("PROTOGOBLIN DEVELOPER DIAGNOSTIC DUMP", report)
        self.assertIn("HOST ENVIRONMENT", report)
        self.assertIn("PROTOGOBLIN INSTALLATION & ASSETS", report)

    def test_generate_debug_dump_with_session(self):
        manifest = {
            "session": {"id": "test_sess_1", "mode": "play", "dev_mode": True},
            "target": {
                "steam_appid": "12345",
                "target_executable": {"path": "C:\\Games\\TestGame.exe"},
                "engine": {"engine": "unreal_5", "confidence": 0.95},
            },
            "subsystems": {
                "loaded": ["d3d11", "dxgi"],
                "unutilized": ["openvr"],
                "pruned": ["vr"],
            },
        }
        dump = generate_debug_dump(manifest=manifest)
        self.assertIsNotNone(dump.get("active_session"))
        self.assertEqual(dump["active_session"]["session_id"], "test_sess_1")
        self.assertTrue(dump["active_session"]["dev_mode"])
        self.assertIn("vr", dump["active_session"]["subsystems_pruned"])

        report = format_debug_dump(dump)
        self.assertIn("ACTIVE SELECTED SESSION INTERNALS", report)
        self.assertIn("test_sess_1 [Dev Mode: ON]", report)
        self.assertIn("Subsystems Pruned:   vr", report)

    def test_dev_mode_session_logging_and_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = td
            try:
                sess = ProtoGoblinSession(steam_appid=777, mode="dev")
                self.assertTrue(sess.dev_mode)

                env = {"WINEDLLOVERRIDES": "d3d11=n,b", "PATH": "/usr/bin"}
                sess.pre_flight(["MyGame.exe"], env)

                debug_log = os.path.join(sess.session_dir, "protogoblin_debug.log")
                debug_env = os.path.join(sess.session_dir, "debug_env.json")
                debug_argv = os.path.join(sess.session_dir, "debug_cmdline.json")

                self.assertTrue(os.path.isfile(debug_log))
                self.assertTrue(os.path.isfile(debug_env))
                self.assertTrue(os.path.isfile(debug_argv))

                with open(debug_log, "r", encoding="utf-8") as f:
                    log_content = f.read()
                self.assertIn("ProtoGoblin Dev Debug Log", log_content)
                self.assertIn("Session ID:", log_content)
                self.assertIn("MyGame.exe", log_content)

                manifest = sess.post_flight(exit_code=0, env=env)
                self.assertTrue(manifest["session"]["dev_mode"])

                with open(debug_log, "r", encoding="utf-8") as f:
                    updated_log = f.read()
                self.assertIn("Post-Flight Completion", updated_log)
                self.assertIn("Exit Code:", updated_log)
            finally:
                if old_xdg:
                    os.environ["XDG_DATA_HOME"] = old_xdg
                else:
                    os.environ.pop("XDG_DATA_HOME", None)

    def test_generate_profile_toml_dev_mode(self):
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="88888",
            app_id=88888,
            target_exe="Game.exe",
            user_tweaks={"dev_mode": True},
        )
        self.assertIn("dev_mode = true", toml_text)


class TestCompatibilityAndDllSnagging(unittest.TestCase):
    def test_log_analyzer_import_error_detection(self):
        log_sample = (
            '0024:fixme:kernelbase:AppPolicyGetProcessTerminationMethod (0xFFFFFFFFFFFFFFFA, 0x000000000011ED80)\n'
            '0024:err:module:import_dll Library d3dcompiler_47.dll (which is needed by L"C:\\Games\\UE5Game\\UE5Game.exe") not found\n'
            '0024:err:module:loader_init importing DLLs for L"C:\\Games\\UE5Game\\UE5Game.exe" failed, status c0000135\n'
        )
        res = CompatibilityLogAnalyzer.parse_log_text(log_sample)
        self.assertTrue(res["issues_detected"])
        self.assertIn("d3dcompiler_47.dll", res["missing_dlls"])
        self.assertIn("d3dcompiler_47", res["suggested_verbs"])
        self.assertEqual(len(res["remedies"]), 1)
        remedy = res["remedies"][0]
        self.assertEqual(remedy["verb"], "d3dcompiler_47")
        self.assertIn("d3dcompiler_47", remedy["overrides"])

    def test_log_analyzer_unimplemented_stub_detection(self):
        log_sample = (
            '0108:fixme:xaudio2:XAudio2Create stub!\n'
            '0108:wine: Call from 000000017004B182 to unimplemented function xaudio2_7.dll.XAudio2Create, aborting\n'
        )
        res = CompatibilityLogAnalyzer.parse_log_text(log_sample)
        self.assertTrue(res["issues_detected"])
        self.assertIn("xaudio27", res["suggested_verbs"])
        self.assertTrue(any(u["function"] == "XAudio2Create" for u in res["unimplemented_functions"]))

    def test_native_dll_snagger_deployment(self):
        with tempfile.TemporaryDirectory() as td:
            prefix_dir = td
            res = NativeDllSnagger.snag_and_deploy("d3dcompiler_47", prefix_dir=prefix_dir)
            self.assertTrue(res["success"])
            self.assertIn("d3dcompiler_47.dll", res["deployed_files"])

            sys32_dll = os.path.join(prefix_dir, "drive_c", "windows", "system32", "d3dcompiler_47.dll")
            syswow64_dll = os.path.join(prefix_dir, "drive_c", "windows", "syswow64", "d3dcompiler_47.dll")
            self.assertTrue(os.path.isfile(sys32_dll))
            self.assertTrue(os.path.isfile(syswow64_dll))

            # Verify PE header bytes
            with open(sys32_dll, "rb") as f:
                header = f.read(2)
            self.assertEqual(header, b"MZ")

    def test_compatibility_fixer_profile_update(self):
        with tempfile.TemporaryDirectory() as td:
            prefix_dir = os.path.join(td, "pfx")
            prof_file = os.path.join(td, "profile.toml")
            with open(prof_file, "w", encoding="utf-8") as f:
                f.write('[game]\nid = "test"\n')

            res = CompatibilityFixer.snag_and_apply("d3dcompiler_47", prefix_dir=prefix_dir, profile_path=prof_file)
            self.assertTrue(res["success"])
            self.assertIn("d3dcompiler_47", res["overrides_added"])

            with open(prof_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("[compatibility.dll_overrides]", content)
            self.assertIn('d3dcompiler_47 = "n,b"', content)

    def test_engine_tweak_manager_compatibility_overrides(self):
        profile = {
            "compatibility": {
                "dll_overrides": {
                    "d3dcompiler_47": "n,b",
                    "xaudio2_7": "n,b",
                }
            }
        }
        env = {"WINEDLLOVERRIDES": "dxgi=n,b"}
        EngineTweakManager.apply_tweaks(profile, {}, ["Game.exe"], env)
        ov = env.get("WINEDLLOVERRIDES", "")
        self.assertIn("dxgi=n,b", ov)
        self.assertIn("d3dcompiler_47=n,b", ov)
        self.assertIn("xaudio2_7=n,b", ov)

    def test_generate_profile_toml_compatibility(self):
        toml_text = EngineTweakManager.generate_profile_toml(
            game_id="77777",
            app_id=77777,
            target_exe="Game.exe",
            user_tweaks={
                "compatibility": {
                    "dll_overrides": {"d3dcompiler_47": "n,b", "xaudio2_7": "n,b"}
                }
            },
        )
        self.assertIn("[compatibility.dll_overrides]", toml_text)
        self.assertIn('d3dcompiler_47 = "n,b"', toml_text)
        self.assertIn('xaudio2_7 = "n,b"', toml_text)

    def test_advisor_compatibility_suggestion_on_crash(self):
        manifest = {
            "session": {"clean_shutdown": False, "exit_code": 1},
            "compatibility": {
                "issues_detected": True,
                "missing_dlls": ["d3dcompiler_47.dll"],
                "remedies": [
                    {
                        "verb": "d3dcompiler_47",
                        "dll": "d3dcompiler_47.dll",
                        "package": "Microsoft DirectX / Windows SDK D3DCompiler",
                        "log_error": "err:module:import_dll Library d3dcompiler_47.dll not found",
                        "overrides": {"d3dcompiler_47": "n,b"},
                    }
                ],
            },
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        compat_sug = [s for s in suggestions if s.get("fix_id") == "snag_dll_d3dcompiler_47"]
        self.assertEqual(len(compat_sug), 1)
        self.assertEqual(compat_sug[0]["level"], "error")
        self.assertIn("Missing Microsoft Native DLL: d3dcompiler_47.dll", compat_sug[0]["title"])
        self.assertIn("Snag & Deploy Microsoft d3dcompiler_47.dll", compat_sug[0]["fix_button_text"])

    def test_post_flight_ingests_compatibility_log_errors(self):
        with tempfile.TemporaryDirectory() as td:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = td
            try:
                sess = ProtoGoblinSession(steam_appid=11111)
                env = {}
                sess.pre_flight(["Game.exe"], env)

                # Write a mock wine.log with an error
                wine_log = os.path.join(sess.session_dir, "wine.log")
                with open(wine_log, "w", encoding="utf-8") as f:
                    f.write('0024:err:module:import_dll Library d3dcompiler_47.dll (which is needed by L"Game.exe") not found\n')

                manifest = sess.post_flight(exit_code=1, env=env)
                self.assertIsNotNone(manifest)
                compat = manifest.get("compatibility")
                self.assertIsNotNone(compat)
                self.assertTrue(compat["issues_detected"])
                self.assertIn("d3dcompiler_47.dll", compat["missing_dlls"])
                self.assertIn("d3dcompiler_47", compat["suggested_verbs"])
            finally:
                if old_xdg is not None:
                    os.environ["XDG_DATA_HOME"] = old_xdg
                else:
                    os.environ.pop("XDG_DATA_HOME", None)


class TestCommanderRecommendationInteraction(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.old_xdg_data = os.environ.get("XDG_DATA_HOME")
        self.old_xdg_config = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_DATA_HOME"] = self.td.name
        os.environ["XDG_CONFIG_HOME"] = self.td.name

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = ProtoGoblinCommandApp(self.root)
        self.app.current_manifest = {
            "target": {
                "steam_appid": 12345,
                "target_executable": {"path": "C:\\Games\\TestGame\\game.exe"},
            },
            "session": {"mode": "profile"},
        }

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass
        self.td.cleanup()
        if self.old_xdg_data is not None:
            os.environ["XDG_DATA_HOME"] = self.old_xdg_data
        else:
            os.environ.pop("XDG_DATA_HOME", None)
        if self.old_xdg_config is not None:
            os.environ["XDG_CONFIG_HOME"] = self.old_xdg_config
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)

    def test_builtin_suggestion_toggles(self):
        # 1. Descriptor buffer (defaults to True on initial GUI boot)
        s_desc = {"fix_id": "enable_descriptor_buffer", "title": "Test Descriptor Buffer"}
        self.assertTrue(self.app.is_suggestion_enabled(s_desc))
        self.app.set_suggestion_enabled(s_desc, False)
        self.assertFalse(self.app.is_suggestion_enabled(s_desc))
        self.assertFalse(self.app.var_gfx_descriptor_buffer.get())
        self.app.set_suggestion_enabled(s_desc, True)
        self.assertTrue(self.app.is_suggestion_enabled(s_desc))
        self.assertTrue(self.app.var_gfx_descriptor_buffer.get())

        # 2. Cap framerate
        s_cap = {"fix_id": "cap_framerate", "cap_target": 60, "title": "Cap 60 FPS"}
        self.assertFalse(self.app.is_suggestion_enabled(s_cap))
        self.app.set_suggestion_enabled(s_cap, True)
        self.assertTrue(self.app.is_suggestion_enabled(s_cap))
        self.assertEqual(self.app.var_gfx_max_fps.get(), "60")
        self.app.set_suggestion_enabled(s_cap, False)
        self.assertFalse(self.app.is_suggestion_enabled(s_cap))
        self.assertEqual(self.app.var_gfx_max_fps.get(), "0")

        # 3. Atelier sync fix (also sets vsync off)
        s_atelier = {"fix_id": "atelier_sync_fix", "title": "Atelier Sync Fix"}
        self.assertFalse(self.app.is_suggestion_enabled(s_atelier))
        self.app.set_suggestion_enabled(s_atelier, True)
        self.assertTrue(self.app.is_suggestion_enabled(s_atelier))
        self.assertTrue(self.app.var_atelier_sync_fix.get())
        self.assertTrue(self.app.var_gfx_vsync_off.get())
        self.app.set_suggestion_enabled(s_atelier, False)
        self.assertFalse(self.app.is_suggestion_enabled(s_atelier))

        # 4. Async shader compile (defaults to True)
        s_async = {"fix_id": "async_shader_compile", "title": "Async Shaders"}
        self.assertTrue(self.app.is_suggestion_enabled(s_async))
        self.app.set_suggestion_enabled(s_async, False)
        self.assertFalse(self.app.is_suggestion_enabled(s_async))
        self.assertFalse(self.app.var_gfx_async_shader.get())
        self.app.set_suggestion_enabled(s_async, True)
        self.assertTrue(self.app.is_suggestion_enabled(s_async))

        # 5. UE5 Lumen and VSM (defaults to True)
        s_ue5 = {"fix_id": "optimize_ue5_lumen_vsm", "title": "Optimize UE5"}
        self.assertTrue(self.app.is_suggestion_enabled(s_ue5))
        self.app.set_suggestion_enabled(s_ue5, False)
        self.assertFalse(self.app.is_suggestion_enabled(s_ue5))
        self.assertFalse(self.app.var_ue_optimize_lumen.get())
        self.assertFalse(self.app.var_ue_optimize_vsm.get())
        self.app.set_suggestion_enabled(s_ue5, True)
        self.assertTrue(self.app.is_suggestion_enabled(s_ue5))

        # 6. Custom recommendation without fix_id
        s_custom = {"title": "Disable In-Game VSync in Menu"}
        self.assertFalse(self.app.is_suggestion_enabled(s_custom))
        self.app.set_suggestion_enabled(s_custom, True)
        self.assertTrue(self.app.is_suggestion_enabled(s_custom))
        self.app.set_suggestion_enabled(s_custom, False)
        self.assertFalse(self.app.is_suggestion_enabled(s_custom))

        # 7. Microsoft Native DLL Snag suggestion
        s_dll = {
            "fix_id": "snag_dll_d3dcompiler_47",
            "title": "Missing Microsoft Native DLL: d3dcompiler_47.dll",
            "remedy": {"verb": "d3dcompiler_47", "dll": "d3dcompiler_47.dll"},
        }
        self.assertFalse(self.app.is_suggestion_enabled(s_dll))
        self.app.var_compat_d3dcompiler_47.set(True)
        self.assertTrue(self.app.is_suggestion_enabled(s_dll))
        self.app.var_compat_d3dcompiler_47.set(False)
        self.assertFalse(self.app.is_suggestion_enabled(s_dll))

    def test_on_suggestion_checkbox_toggled(self):
        s = {"fix_id": "enable_io_cache", "title": "Enable I/O Cache"}
        cb_var = tk.BooleanVar(value=True)
        self.app._on_suggestion_checkbox_toggled(s, cb_var)
        self.assertTrue(self.app.var_fs_io_cache.get())
        self.assertTrue(self.app.is_suggestion_enabled(s))

        cb_var.set(False)
        self.app._on_suggestion_checkbox_toggled(s, cb_var)
        self.assertFalse(self.app.var_fs_io_cache.get())
        self.assertFalse(self.app.is_suggestion_enabled(s))

    def test_open_suggestion_detail_window(self):
        s = {
            "level": "warning",
            "fix_id": "vkd3d_single_queue",
            "title": "VKD3D Queue Stalls Detected",
            "description": "Session logs revealed repeated VKD3D multi-queue sync stalls.",
            "action": "Force VKD3D Single Queue submission.",
        }
        cb_var = tk.BooleanVar(value=False)
        self.app.open_suggestion_detail_window(s, cb_var)
        self.root.update_idletasks()

        # Find the opened Toplevel window
        toplevels = [w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel)]
        self.assertEqual(len(toplevels), 1)
        win = toplevels[0]

        # Verify title and widgets
        self.assertIn("VKD3D Queue Stalls", win.title())

        # Find the Checkbutton inside the detail window
        checkbuttons = []
        def find_checkbuttons(widget):
            for child in widget.winfo_children():
                if isinstance(child, tk.Checkbutton):
                    checkbuttons.append(child)
                find_checkbuttons(child)
        find_checkbuttons(win)
        self.assertGreaterEqual(len(checkbuttons), 1)

        # Toggle checkbutton via invoke()
        modal_cb = checkbuttons[0]
        modal_cb.invoke()
        self.assertTrue(self.app.var_vkd3d_single_queue.get())
        self.assertTrue(cb_var.get())
        self.assertTrue(self.app.is_suggestion_enabled(s))

        # Toggle again to disable
        modal_cb.invoke()
        self.assertFalse(self.app.var_vkd3d_single_queue.get())
        self.assertFalse(cb_var.get())
        self.assertFalse(self.app.is_suggestion_enabled(s))

        win.destroy()


class TestCommanderSteamGroupExplorer(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.old_xdg_data = os.environ.get("XDG_DATA_HOME")
        self.old_xdg_config = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_DATA_HOME"] = self.td.name
        os.environ["XDG_CONFIG_HOME"] = self.td.name

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = ProtoGoblinCommandApp(self.root)

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass
        self.td.cleanup()
        if self.old_xdg_data is not None:
            os.environ["XDG_DATA_HOME"] = self.old_xdg_data
        else:
            os.environ.pop("XDG_DATA_HOME", None)
        if self.old_xdg_config is not None:
            os.environ["XDG_CONFIG_HOME"] = self.old_xdg_config
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)

    def test_resolve_game_name(self):
        # 1. PresetDatabase resolution
        self.assertIn("Immortals of Aveum", self.app.resolve_game_name("2555360"))
        self.assertIn("Atelier Ryza", self.app.resolve_game_name("1121560"))

        # 2. Unknown or non-Steam
        self.assertEqual(self.app.resolve_game_name("unknown_game"), "Custom / Non-Steam Game")
        self.assertEqual(self.app.resolve_game_name("-"), "Custom / Non-Steam Game")
        self.assertEqual(self.app.resolve_game_name(None), "Custom / Non-Steam Game")

        # 3. Numeric unregistered fallback
        self.assertEqual(self.app.resolve_game_name("888888"), "Steam App 888888")

        # 4. Mock ACF file
        mock_steam = os.path.join(self.td.name, "mock_steam", "steamapps")
        os.makedirs(mock_steam, exist_ok=True)
        acf_path = os.path.join(mock_steam, "appmanifest_99999.acf")
        with open(acf_path, "w", encoding="utf-8") as f:
            f.write('"AppState"\n{\n\t"appid"\t"99999"\n\t"name"\t"My Awesome Steam Game"\n}\n')
        self.app._steam_libs_cache = [mock_steam]
        self.app._game_name_cache.clear()
        self.assertEqual(self.app.resolve_game_name("99999"), "My Awesome Steam Game")

    def test_sessions_grouped_by_steam_id_and_display_name(self):
        base = os.path.join(self.td.name, "protogoblin", "sessions")

        # Session 1: 2555360 (cmd.exe)
        s1_dir = os.path.join(base, "2555360", "20261028T080000Z-1111")
        os.makedirs(s1_dir, exist_ok=True)
        with open(os.path.join(s1_dir, "utilization.json"), "w", encoding="utf-8") as f:
            json.dump({
                "session": {"id": "20261028T080000Z-1111", "mode": "play", "start_time": "2026-10-28T08:00:00Z"},
                "target": {"steam_appid": "2555360", "target_executable": {"path": "C:\\Games\\cmd.exe"}},
            }, f)

        # Session 2: 2555360 (ImmortalsOfAveum.exe)
        s2_dir = os.path.join(base, "2555360", "20261028T090000Z-2222")
        os.makedirs(s2_dir, exist_ok=True)
        with open(os.path.join(s2_dir, "utilization.json"), "w", encoding="utf-8") as f:
            json.dump({
                "session": {"id": "20261028T090000Z-2222", "mode": "profile", "start_time": "2026-10-28T09:00:00Z"},
                "target": {"steam_appid": "2555360", "target_executable": {"path": "C:\\Games\\ImmortalsOfAveum.exe"}},
            }, f)

        # Session 3: 1121560 (Atelier_Ryza.exe)
        s3_dir = os.path.join(base, "1121560", "20261028T070000Z-3333")
        os.makedirs(s3_dir, exist_ok=True)
        with open(os.path.join(s3_dir, "utilization.json"), "w", encoding="utf-8") as f:
            json.dump({
                "session": {"id": "20261028T070000Z-3333", "mode": "play", "start_time": "2026-10-28T07:00:00Z"},
                "target": {"steam_appid": "1121560", "target_executable": {"path": "C:\\Games\\Atelier_Ryza.exe"}},
            }, f)

        self.app.refresh_sessions()

        # Check Treeview groups
        root_nodes = self.app.sessions_tree.get_children()
        self.assertEqual(len(root_nodes), 2)

        # Group titles should have: Game Name (Steam ID)
        aveum_group = next((nid for nid in root_nodes if "2555360" in self.app.sessions_tree.item(nid, "text")), None)
        ryza_group = next((nid for nid in root_nodes if "1121560" in self.app.sessions_tree.item(nid, "text")), None)

        self.assertIsNotNone(aveum_group)
        self.assertIsNotNone(ryza_group)
        self.assertIn("Immortals of Aveum", self.app.sessions_tree.item(aveum_group, "text"))
        self.assertTrue(self.app.sessions_tree.item(aveum_group, "text").endswith("(2555360)"))

        self.assertIn("Atelier Ryza", self.app.sessions_tree.item(ryza_group, "text"))
        self.assertTrue(self.app.sessions_tree.item(ryza_group, "text").endswith("(1121560)"))

        # Check executables grouped under 2555360
        aveum_children = self.app.sessions_tree.get_children(aveum_group)
        self.assertEqual(len(aveum_children), 2)
        aveum_child_texts = [self.app.sessions_tree.item(cid, "text") for cid in aveum_children]
        self.assertTrue(any("ImmortalsOfAveum.exe" in t for t in aveum_child_texts))
        self.assertTrue(any("cmd.exe" in t for t in aveum_child_texts))

        # Check executable grouped under 1121560
        ryza_children = self.app.sessions_tree.get_children(ryza_group)
        self.assertEqual(len(ryza_children), 1)
        self.assertIn("Atelier_Ryza.exe", self.app.sessions_tree.item(ryza_children[0], "text"))

        # Test selecting a child executable loads the session manifest
        self.app.sessions_tree.selection_set(ryza_children[0])
        self.app.on_session_selected(None)
        self.assertEqual(self.app.current_manifest["target"]["steam_appid"], "1121560")
        self.assertIn("Atelier Ryza", self.app.diag_header_lbl.cget("text"))

        # Test search filter by Steam ID
        self.app.search_var.set("1121560")
        filtered_roots = self.app.sessions_tree.get_children()
        self.assertEqual(len(filtered_roots), 1)
        self.assertIn("Atelier Ryza", self.app.sessions_tree.item(filtered_roots[0], "text"))

        # Test search filter by executable name
        self.app.search_var.set("ImmortalsOfAveum")
        filtered_roots = self.app.sessions_tree.get_children()
        self.assertEqual(len(filtered_roots), 1)
        self.assertIn("2555360", self.app.sessions_tree.item(filtered_roots[0], "text"))
        children = self.app.sessions_tree.get_children(filtered_roots[0])
        self.assertEqual(len(children), 1)
        self.assertIn("ImmortalsOfAveum.exe", self.app.sessions_tree.item(children[0], "text"))

    def test_render_manifest_with_null_pe_fields(self):
        # Manifest with null PE fields and null stats (as seen in real sessions with cmd.exe)
        manifest = {
            "session": {"id": "null_test_sess", "mode": "play"},
            "target": {
                "steam_appid": "2555360",
                "target_executable": {
                    "path": "cmd.exe",
                    "sha256": "unknown",
                    "arch": "x86_64",
                    "pe_timestamp": None,
                    "pe_size_of_image": None,
                },
                "engine": {"detected": False, "engine": "unknown"},
            },
            "graphics": {
                "active_backend": "dxvk",
                "shader_compiles": None,
                "d3d11_wrapper_stats": None,
            },
            "filesystem": {"io_cache_stats": None},
        }
        # Should render cleanly without TypeError formatting NoneType
        self.app._render_manifest_data(manifest, "/dummy/path.json")
        self.assertIn("cmd.exe", self.app.diag_header_lbl.cget("text"))
        self.assertIn("0 bytes", self.app.sys_text.get("1.0", tk.END))


class TestProfileDropAndReprofiling(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.old_xdg_data = os.environ.get("XDG_DATA_HOME")
        self.old_xdg_config = os.environ.get("XDG_CONFIG_HOME")
        self.old_sessions_dir = os.environ.get("PROTOGOBLIN_SESSIONS_DIR")
        os.environ["XDG_DATA_HOME"] = os.path.join(self.td.name, "data")
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.td.name, "config")
        os.environ["PROTOGOBLIN_SESSIONS_DIR"] = os.path.join(self.td.name, "data", "protogoblin", "sessions")

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = ProtoGoblinCommandApp(self.root)

    def tearDown(self):
        try:
            self.root.destroy()
        except Exception:
            pass
        self.td.cleanup()
        if self.old_xdg_data is not None:
            os.environ["XDG_DATA_HOME"] = self.old_xdg_data
        else:
            os.environ.pop("XDG_DATA_HOME", None)
        if self.old_xdg_config is not None:
            os.environ["XDG_CONFIG_HOME"] = self.old_xdg_config
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)
        if self.old_sessions_dir is not None:
            os.environ["PROTOGOBLIN_SESSIONS_DIR"] = self.old_sessions_dir
        else:
            os.environ.pop("PROTOGOBLIN_SESSIONS_DIR", None)

    def test_engine_tweak_manager_drop_profile(self):
        p_dir = os.path.join(self.td.name, "config", "protogoblin", "games")
        os.makedirs(p_dir, exist_ok=True)
        p_file = os.path.join(p_dir, "77777.toml")
        with open(p_file, "w", encoding="utf-8") as f:
            f.write('[runtime]\nmode = "play"\n')

        s_dir = os.path.join(self.td.name, "data", "protogoblin", "sessions", "77777")
        os.makedirs(s_dir, exist_ok=True)

        self.assertTrue(os.path.isfile(p_file))
        self.assertTrue(os.path.isdir(s_dir))

        # Drop profile without clearing sessions
        res1 = EngineTweakManager.drop_profile("77777", clear_sessions=False)
        self.assertTrue(res1["profile_deleted"])
        self.assertFalse(res1["sessions_cleared"])
        self.assertFalse(os.path.isfile(p_file))
        self.assertTrue(os.path.isdir(s_dir))

        # Drop profile again with clearing sessions
        res2 = EngineTweakManager.drop_profile("77777", clear_sessions=True)
        self.assertFalse(res2["profile_deleted"])
        self.assertTrue(res2["sessions_cleared"])
        self.assertFalse(os.path.isdir(s_dir))

    def test_protogoblin_session_drop_profile_env(self):
        p_dir = os.path.join(self.td.name, "config", "protogoblin", "games")
        os.makedirs(p_dir, exist_ok=True)
        p_file = os.path.join(p_dir, "88888.toml")
        with open(p_file, "w", encoding="utf-8") as f:
            f.write('[runtime]\nmode = "play"\n')

        old_drop = os.environ.get("PROTOGOBLIN_DROP_PROFILE")
        try:
            os.environ["PROTOGOBLIN_DROP_PROFILE"] = "1"
            sess = ProtoGoblinSession(steam_appid=88888)
            env = {}
            sess.pre_flight(["Game.exe"], env)
            self.assertFalse(os.path.isfile(p_file))
            self.assertEqual(sess.mode, "profile")
        finally:
            if old_drop is not None:
                os.environ["PROTOGOBLIN_DROP_PROFILE"] = old_drop
            else:
                os.environ.pop("PROTOGOBLIN_DROP_PROFILE", None)

    def test_commander_drop_current_profile_ui(self):
        self.app.current_manifest = {
            "target": {
                "steam_appid": 66666,
                "target_executable": {"path": "C:\\Games\\TestGame\\test.exe"},
            },
            "session": {"mode": "play"},
        }
        p_file = self.app.generate_profile_toml(silent=True)
        self.assertTrue(os.path.isfile(p_file))

        self.app.var_gfx_vsync_off.set(True)
        self.app.var_gfx_descriptor_buffer.set(True)

        res = self.app.drop_current_profile(prompt=False)
        self.assertTrue(res)
        self.assertFalse(os.path.isfile(p_file))
        self.assertFalse(self.app.var_gfx_vsync_off.get())
        self.assertFalse(self.app.var_gfx_descriptor_buffer.get())


class TestSteamDeckIntegration(unittest.TestCase):
    def test_steam_deck_environment_probe(self):
        old_val = os.environ.get("SteamDeck")
        try:
            os.environ["SteamDeck"] = "1"
            self.assertTrue(SystemProbe.is_steam_deck())
            info = SystemProbe.get_steam_deck_info()
            self.assertTrue(info["is_deck"])
            self.assertEqual(info["resolution"], "1280x800")
            self.assertEqual(info["aspect_ratio"], "16:10")
        finally:
            if old_val is None:
                os.environ.pop("SteamDeck", None)
            else:
                os.environ["SteamDeck"] = old_val

    def test_steam_deck_preset_elevation(self):
        dummy_db = {
            "999999": {
                "title": "Deck Test Game",
                "recommended_tweaks": {
                    "env": {"BASE_FLAG": "1"},
                    "args": ["-base_arg"],
                },
                "deck_tweaks": {
                    "env": {"SteamDeck": "1", "DECK_PERF": "high"},
                    "args": ["-deck_arg"],
                },
            }
        }
        old_cache = PresetDatabase._CACHE
        try:
            PresetDatabase._CACHE = dummy_db
            # Standard preset
            standard = PresetDatabase.get_preset("999999", is_deck=False)
            self.assertEqual(standard["recommended_tweaks"]["env"], {"BASE_FLAG": "1"})
            self.assertEqual(standard["recommended_tweaks"]["args"], ["-base_arg"])

            # Elevated preset on Steam Deck
            deck = PresetDatabase.get_preset("999999", is_deck=True)
            self.assertEqual(deck["recommended_tweaks"]["env"]["BASE_FLAG"], "1")
            self.assertEqual(deck["recommended_tweaks"]["env"]["SteamDeck"], "1")
            self.assertEqual(deck["recommended_tweaks"]["env"]["DECK_PERF"], "high")
            self.assertIn("-base_arg", deck["recommended_tweaks"]["args"])
            self.assertIn("-deck_arg", deck["recommended_tweaks"]["args"])
        finally:
            PresetDatabase._CACHE = old_cache

    def test_steam_deck_profile_application(self):
        profile = {
            "game": {"id": "test_game", "steam_appid": 1234},
            "graphics": {"backend": "dxvk"},
            "steam_deck": {
                "enabled": True,
                "env": {"DXVK_FRAME_RATE": "45"},
                "args": ["-deck_mode"],
                "limit_fps": 45,
            },
        }
        env = {}
        argv = ["game.exe"]
        new_argv = EngineTweakManager.apply_tweaks(profile, {"engine": "generic"}, argv, env, is_deck=True)
        self.assertEqual(env.get("SteamDeck"), "1")
        self.assertEqual(env.get("DXVK_FRAME_RATE"), "45")
        self.assertEqual(env.get("VKD3D_FRAME_RATE"), "45")
        self.assertIn("-deck_mode", new_argv)

    def test_steam_deck_diagnostic_advisor(self):
        manifest = {
            "steam_deck": {
                "is_deck": True,
                "model": "Steam Deck OLED (Galileo)",
            }
        }
        suggestions = DiagnosticAdvisor.analyze(manifest)
        titles = [s["title"] for s in suggestions]
        self.assertTrue(any("Steam Deck Environment Active" in t for t in titles))
        self.assertTrue(any("Galileo" in t for t in titles))

    def test_protogoblin_sqlite_db_lookup_and_fixes(self):
        db_path = PresetDatabase.get_db_path()
        self.assertIsNotNone(db_path)
        self.assertTrue(os.path.isfile(db_path))

        # Test preset lookup via SQLite
        preset = PresetDatabase.get_preset(409710)
        self.assertIsNotNone(preset)
        self.assertEqual(preset["title"], "BioShock Remastered")
        self.assertIn("PROTON_NO_ESYNC", str(preset["recommended_tweaks"]))

        # Test active fixes (forward-only, zero deprecated)
        fixes = PresetDatabase.get_active_fixes(409710)
        self.assertGreaterEqual(len(fixes), 1)
        commands = [f["fix_command"] for f in fixes]
        self.assertIn("PROTON_NO_ESYNC=1", commands)
        # Verify deprecated D9VK is not present
        self.assertNotIn("PROTON_USE_D9VK=1", commands)

        # Test search under 1ms
        results = PresetDatabase.search_games("Witcher", limit=5)
        self.assertGreater(len(results), 0)
        titles = [r["title"] for r in results]
        self.assertTrue(any("Witcher" in t for t in titles))




class TestCommanderGameLauncherAndLiveUpdate(unittest.TestCase):
    """Tests for game launching (Steam & non-Steam), profiling mode toggling, and live UI updating."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.old_xdg_data = os.environ.get("XDG_DATA_HOME")
        self.old_xdg_config = os.environ.get("XDG_CONFIG_HOME")
        self.old_steam_dir = os.environ.get("STEAM_DIR")
        self.old_steam_lib = os.environ.get("STEAM_LIBRARY")

        os.environ["XDG_DATA_HOME"] = os.path.join(self.td.name, "data")
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.td.name, "config")
        os.makedirs(os.environ["XDG_DATA_HOME"], exist_ok=True)
        os.makedirs(os.environ["XDG_CONFIG_HOME"], exist_ok=True)

        self.steam_lib_dir = os.path.join(self.td.name, "steamapps")
        os.makedirs(self.steam_lib_dir, exist_ok=True)
        os.environ["STEAM_LIBRARY"] = self.steam_lib_dir

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = ProtoGoblinCommandApp(self.root, auto_refresh=False)

        # Mock process launcher
        self.launched_commands = []
        def mock_launcher(cmd, **kwargs):
            self.launched_commands.append((cmd, kwargs))
            class MockProc:
                pid = 9999
            return MockProc()
        self.app.process_launcher = mock_launcher

    def tearDown(self):
        self.app.stop_auto_refresh()
        try:
            self.root.destroy()
        except Exception:
            pass
        self.td.cleanup()
        if self.old_xdg_data is not None:
            os.environ["XDG_DATA_HOME"] = self.old_xdg_data
        else:
            os.environ.pop("XDG_DATA_HOME", None)
        if self.old_xdg_config is not None:
            os.environ["XDG_CONFIG_HOME"] = self.old_xdg_config
        else:
            os.environ.pop("XDG_CONFIG_HOME", None)
        if self.old_steam_dir is not None:
            os.environ["STEAM_DIR"] = self.old_steam_dir
        else:
            os.environ.pop("STEAM_DIR", None)
        if self.old_steam_lib is not None:
            os.environ["STEAM_LIBRARY"] = self.old_steam_lib
        else:
            os.environ.pop("STEAM_LIBRARY", None)

    def test_get_installed_steam_games(self):
        # Create mock appmanifest files
        acf_1 = os.path.join(self.steam_lib_dir, "appmanifest_480.acf")
        with open(acf_1, "w", encoding="utf-8") as f:
            f.write('"AppState" { "appid" "480" "name" "Spacewar" "installdir" "Spacewar" }')

        acf_2 = os.path.join(self.steam_lib_dir, "appmanifest_2555360.acf")
        with open(acf_2, "w", encoding="utf-8") as f:
            f.write('"AppState" { "appid" "2555360" "name" "Immortals of Aveum Demo" "installdir" "Aveum" }')

        self.app._steam_libs_cache = None
        games = self.app.get_installed_steam_games()
        app_ids = [g["app_id"] for g in games]
        names = [g["name"] for g in games]

        self.assertIn("480", app_ids)
        self.assertIn("2555360", app_ids)
        self.assertIn("Spacewar", names)
        self.assertIn("Immortals of Aveum Demo", names)

    def test_get_profiled_non_steam_games(self):
        # 1. Create a non-steam session manifest
        sess_dir = os.path.join(os.environ["XDG_DATA_HOME"], "protogoblin", "sessions", "custom_game", "sess_custom")
        os.makedirs(sess_dir, exist_ok=True)
        manifest_path = os.path.join(sess_dir, "utilization.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({
                "session": {"id": "sess_custom", "mode": "play", "prefix_dir": "/opt/prefix"},
                "target": {
                    "steam_appid": "custom_game",
                    "target_executable": {"path": "/opt/games/indie/IndieGame.exe"},
                    "working_directory": "/opt/games/indie",
                },
            }, f)

        # 2. Create a non-steam profile TOML
        prof_dir = os.path.join(os.environ["XDG_CONFIG_HOME"], "protogoblin", "games")
        os.makedirs(prof_dir, exist_ok=True)
        prof_file = os.path.join(prof_dir, "my_rpg.toml")
        with open(prof_file, "w", encoding="utf-8") as f:
            f.write('''[game]
app_id = "my_rpg"
target_exe = "/home/user/games/rpg.exe"
prefix_dir = "/home/user/prefixes/rpg"
[runtime]
mode = "profile"
''')

        self.app.manifest_paths = [manifest_path]
        non_steam = self.app.get_profiled_non_steam_games()
        self.assertGreaterEqual(len(non_steam), 2)
        exes = [g["target_exe"] for g in non_steam]
        self.assertIn("/opt/games/indie/IndieGame.exe", exes)
        self.assertIn("/home/user/games/rpg.exe", exes)

    def test_profile_mode_toggling_and_persistence(self):
        # Initially play
        mode_initial = self.app.get_game_profile_mode("480")
        self.assertEqual(mode_initial, "play")

        # Toggle to profile
        p_path = self.app.set_game_profile_mode("480", "profile")
        self.assertTrue(os.path.isfile(p_path))
        self.assertEqual(self.app.get_game_profile_mode("480"), "profile")

        with open(p_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('mode = "profile"', content)

        # Toggle back to play
        self.app.set_game_profile_mode("480", "play")
        self.assertEqual(self.app.get_game_profile_mode("480"), "play")

    def test_launch_installed_steam_game(self):
        res = self.app.launch_game(480, game_name="Spacewar")
        self.assertTrue(res["success"])
        self.assertEqual(len(self.launched_commands), 1)
        cmd, _ = self.launched_commands[0]
        cmd_str = " ".join(cmd)
        self.assertIn("steam://rungameid/480", cmd_str)
        self.assertIn("Spacewar", self.app.status_bar_lbl.cget("text"))

    def test_launch_profiled_non_steam_game(self):
        target = "C:\\Games\\MyGame\\Game.exe"
        res = self.app.launch_game(
            "custom_app",
            target_exe=target,
            argv=[target, "--debug"],
            prefix_dir="C:\\Prefixes\\MyGame",
            game_name="My Custom Game",
        )
        self.assertTrue(res["success"])
        self.assertEqual(len(self.launched_commands), 1)
        cmd, kwargs = self.launched_commands[0]
        cmd_str = " ".join(cmd)
        self.assertIn("Game.exe", cmd_str)
        self.assertIn("My Custom Game", self.app.status_bar_lbl.cget("text"))

    def test_live_ui_update_on_new_session_without_restart(self):
        # 1. Setup initial session
        sess1_dir = os.path.join(os.environ["XDG_DATA_HOME"], "protogoblin", "sessions", "12345", "sess_01")
        os.makedirs(sess1_dir, exist_ok=True)
        sess1_file = os.path.join(sess1_dir, "utilization.json")
        with open(sess1_file, "w", encoding="utf-8") as f:
            json.dump({
                "session": {"id": "sess_01", "mode": "play", "start_time": "2026-10-29T08:00:00Z"},
                "target": {"steam_appid": 12345, "target_executable": {"path": "C:\\Game\\test.exe"}},
            }, f)
        # Touch timestamp
        os.utime(sess1_file, (1000000, 1000000))

        self.app.refresh_sessions()
        self.assertIsNotNone(self.app.current_manifest)
        self.assertEqual(self.app.current_manifest["session"]["id"], "sess_01")

        # 2. Simulate running a profiling session while GUI is open
        sess2_dir = os.path.join(os.environ["XDG_DATA_HOME"], "protogoblin", "sessions", "12345", "sess_02")
        os.makedirs(sess2_dir, exist_ok=True)
        sess2_file = os.path.join(sess2_dir, "utilization.json")
        with open(sess2_file, "w", encoding="utf-8") as f:
            json.dump({
                "session": {"id": "sess_02", "mode": "profile", "start_time": "2026-10-29T08:15:00Z"},
                "target": {"steam_appid": 12345, "target_executable": {"path": "C:\\Game\\test.exe"}},
            }, f)
        os.utime(sess2_file, (2000000, 2000000))

        # 3. Trigger auto-refresh check
        self.app._auto_refresh_check()

        # 4. Verify GUI updated to sess_02 without closing and reopening!
        self.assertEqual(self.app.current_manifest["session"]["id"], "sess_02")
        self.assertEqual(self.app.current_manifest["session"]["mode"], "profile")
        self.assertIn("sess_02", self.app.diag_header_lbl.cget("text"))
        self.assertIn("Dashboard auto-updated", self.app.status_bar_lbl.cget("text"))

    def test_game_launcher_dialog(self):
        from protogoblin_command import GameLauncherDialog

        # Create mock installed Steam game
        acf = os.path.join(self.steam_lib_dir, "appmanifest_480.acf")
        with open(acf, "w", encoding="utf-8") as f:
            f.write('"AppState" { "appid" "480" "name" "Spacewar" "installdir" "Spacewar" }')
        self.app._steam_libs_cache = None

        dlg = GameLauncherDialog(self.app)
        self.assertGreaterEqual(len(dlg.visible_games), 1)

        # Toggle profiling mode in dialog
        dlg.tree.selection_set("0")
        dlg.on_select_changed()
        initial_mode = dlg.visible_games[0]["mode"]
        dlg.on_toggle_mode_clicked()
        new_mode = dlg.visible_games[0]["mode"]
        self.assertNotEqual(initial_mode, new_mode)

        # Test launch from dialog
        dlg.on_launch_clicked()
        self.assertEqual(len(self.launched_commands), 1)
        cmd, _ = self.launched_commands[0]
        self.assertIn("steam://rungameid/480", " ".join(cmd))




class TestExperimentalValidationLifecycleAndBugFixes(unittest.TestCase):
    """Tests for the Experimental Validation Engine, tightened diagnostic rules, and bug fixes."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.profile_path = os.path.join(self.td.name, "test_game.toml")

    def tearDown(self):
        self.td.cleanup()

    def test_apply_tweaks_dictionary_enabled_false_bugfix(self):
        """Tests that nonempty dicts with enabled=false do NOT activate features (bugfix)."""
        # Profile has dictionary with enabled = false
        profile = {
            "synchronization": {
                "state_dedup": {"enabled": False},
                "swapchain_debounce": {"enabled": False},
                "atelier_sync_fix": {"enabled": False},
            },
            "timing": {
                "precision_timers": {"enabled": False},
            },
            "filesystem": {
                "io_cache": {"enabled": False},
            },
            "graphics": {
                "async_shader_compile": False,
            },
        }

        env = {}
        new_argv = EngineTweakManager.apply_tweaks(
            profile=profile,
            engine_info={"engine": "unreal_4"},
            argv=["game.exe"],
            env=env,
        )

        # None of the wrapper shims or env flags should be enabled!
        self.assertNotIn("PROTOGOBLIN_STATE_DEDUP", env)
        self.assertNotIn("PROTOGOBLIN_SWAPCHAIN_DEBOUNCE", env)
        self.assertNotIn("PROTOGOBLIN_STAGING_SYNC_FIX", env)
        self.assertNotIn("PROTOGOBLIN_HIGH_PRECISION_TIMERS", env)
        self.assertNotIn("PROTOGOBLIN_IO_CACHE", env)
        self.assertNotIn("DXVK_ASYNC", env)
        self.assertNotIn("d3d11=n,b", env.get("WINEDLLOVERRIDES", ""))

    def test_apply_tweaks_dictionary_enabled_true_active(self):
        """Tests that dicts with enabled=true or boolean True properly activate features."""
        profile = {
            "synchronization": {
                "state_dedup": {"enabled": True},
                "swapchain_debounce": True,
            },
            "timing": {
                "precision_timers": {"enabled": True},
            },
            "runtime": {
                "mode": "profile",
            },
        }

        env = {}
        EngineTweakManager.apply_tweaks(
            profile=profile,
            engine_info={"engine": "generic"},
            argv=["game.exe"],
            env=env,
        )

        self.assertEqual(env.get("PROTOGOBLIN_STATE_DEDUP"), "1")
        self.assertEqual(env.get("PROTOGOBLIN_SWAPCHAIN_DEBOUNCE"), "1")
        self.assertEqual(env.get("PROTOGOBLIN_HIGH_PRECISION_TIMERS"), "1")
        self.assertIn("d3d11=n,b", env.get("WINEDLLOVERRIDES", ""))

    def test_experimental_validation_lifecycle_workflow(self):
        """Tests the full lifecycle: Detected -> Applied -> Benchmarked -> Validated / Rollback."""
        # Initial baseline profile
        init_toml = EngineTweakManager.generate_profile_toml(
            game_id="12345",
            app_id="12345",
            target_exe="game.exe",
        )
        with open(self.profile_path, "w", encoding="utf-8") as f:
            f.write(init_toml)

        # 1. State: DETECTED initially
        st = ExperimentalValidationEngine.get_experiment_status(self.profile_path, "state_dedup")
        self.assertEqual(st, ExperimentStatus.DETECTED)

        # 2. Start experiment -> APPLIED
        baseline_metrics = {"fps_avg": 50.0, "fps_1_pct_low": 30.0, "frametime_jitter_ms": 10.0}
        exp_info = ExperimentalValidationEngine.start_experiment(
            profile_path=self.profile_path,
            fix_id="state_dedup",
            baseline_session_id="baseline_sess_01",
            baseline_metrics=baseline_metrics,
        )
        self.assertEqual(exp_info["status"], ExperimentStatus.APPLIED)
        self.assertEqual(ExperimentalValidationEngine.get_experiment_status(self.profile_path, "state_dedup"), ExperimentStatus.APPLIED)

        # 3. Enforce: In Play Mode, unvalidated experiment is NOT active
        env_play = {}
        prof_curr = EngineTweakManager.load_profile(self.profile_path)
        EngineTweakManager.apply_tweaks(
            profile=prof_curr,
            engine_info={"engine": "generic"},
            argv=["game.exe"],
            env=env_play,
        )
        # Since it's play mode and status is 'applied' (unvalidated), it should NOT be active
        self.assertNotIn("PROTOGOBLIN_STATE_DEDUP", env_play)

        # In Profile Mode (benchmark test), it IS active
        env_prof = {"PROTOGOBLIN_MODE": "profile"}
        EngineTweakManager.apply_tweaks(
            profile=prof_curr,
            engine_info={"engine": "generic"},
            argv=["game.exe"],
            env=env_prof,
        )
        self.assertEqual(env_prof.get("PROTOGOBLIN_STATE_DEDUP"), "1")

        # 4. Evaluate experiment with IMPROVED metrics -> VALIDATED
        baseline_manifest = {
            "session": {"id": "baseline_sess_01", "mode": "profile"},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": baseline_metrics,
            },
        }
        improved_manifest = {
            "session": {"id": "benchmark_sess_02", "mode": "profile"},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {"fps_avg": 55.0, "fps_1_pct_low": 38.0, "frametime_jitter_ms": 6.0},
            },
        }
        res = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=improved_manifest,
            baseline_manifest=baseline_manifest,
        )
        self.assertEqual(res["status"], ExperimentStatus.VALIDATED)
        self.assertEqual(res["verdict"], "IMPROVED")

        # Now in Play mode, the VALIDATED fix IS applied as permanent default!
        env_play_validated = {}
        prof_val = EngineTweakManager.load_profile(self.profile_path)
        EngineTweakManager.apply_tweaks(
            profile=prof_val,
            engine_info={"engine": "generic"},
            argv=["game.exe"],
            env=env_play_validated,
        )
        self.assertEqual(env_play_validated.get("PROTOGOBLIN_STATE_DEDUP"), "1")

    def test_experimental_validation_rollback_on_regression(self):
        """Tests that an experiment with regressed metrics is automatically rolled back."""
        init_toml = EngineTweakManager.generate_profile_toml(
            game_id="777",
            app_id="777",
            target_exe="game.exe",
        )
        with open(self.profile_path, "w", encoding="utf-8") as f:
            f.write(init_toml)

        # Start experiment
        ExperimentalValidationEngine.start_experiment(
            profile_path=self.profile_path,
            fix_id="swapchain_debounce",
            baseline_session_id="base_01",
        )

        baseline_manifest = {
            "session": {"id": "base_01", "mode": "profile"},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {"fps_avg": 60.0, "fps_1_pct_low": 50.0, "frametime_jitter_ms": 4.0},
            },
        }
        # Regressed manifest: average FPS dropped by 10%
        regressed_manifest = {
            "session": {"id": "bench_02", "mode": "profile"},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {"fps_avg": 53.0, "fps_1_pct_low": 42.0, "frametime_jitter_ms": 9.0},
            },
        }

        res = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=regressed_manifest,
            baseline_manifest=baseline_manifest,
        )
        self.assertEqual(res["status"], ExperimentStatus.REJECTED)
        self.assertEqual(res["verdict"], "REGRESSED")

        # Verify automatic rollback disabled the tweak in profile
        prof_after = EngineTweakManager.load_profile(self.profile_path)
        self.assertFalse(EngineTweakManager.is_feature_enabled(prof_after.get("synchronization", {}).get("swapchain_debounce")))

    def test_insufficient_data_safeguards(self):
        """Verifies that incomplete, non-comparable, or corrupt sessions cannot produce successful validation."""
        # Case A: Target binary mismatch
        manifest_a = {
            "session": {"id": "base", "mode": "profile"},
            "target": {"steam_appid": "12345", "target_executable": {"path": "GameA.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 60.0}},
        }
        manifest_b = {
            "session": {"id": "bench", "mode": "profile"},
            "target": {"steam_appid": "12345", "target_executable": {"path": "DifferentGameB.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 80.0}},
        }
        diff = compute_session_diff(manifest_a, manifest_b)
        self.assertEqual(diff["verdict"], ExperimentVerdict.INSUFFICIENT_DATA)
        self.assertIn("Incompatible target binaries", diff["summary"])

        # Case B: Zero rendered frames
        manifest_zero_frames = {
            "session": {"id": "bench2", "mode": "profile"},
            "target": {"steam_appid": "12345", "target_executable": {"path": "GameA.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_count": 0, "frame_metrics": {"fps_avg": 0.0}},
        }
        diff2 = compute_session_diff(manifest_a, manifest_zero_frames)
        self.assertEqual(diff2["verdict"], ExperimentVerdict.INSUFFICIENT_DATA)

        # Case C: Non-comparable capture durations (e.g. 1.0s vs 60.0s)
        manifest_short = {
            "session": {"id": "bench3", "mode": "profile", "duration_seconds": 1.0},
            "target": {"steam_appid": "12345", "target_executable": {"path": "GameA.exe"}},
            "roi_telemetry": {"roi_enabled": True, "duration_seconds": 1.0, "frame_metrics": {"fps_avg": 90.0}},
        }
        manifest_long = {
            "session": {"id": "base3", "mode": "profile", "duration_seconds": 60.0},
            "target": {"steam_appid": "12345", "target_executable": {"path": "GameA.exe"}},
            "roi_telemetry": {"roi_enabled": True, "duration_seconds": 60.0, "frame_metrics": {"fps_avg": 50.0}},
        }
        diff3 = compute_session_diff(manifest_long, manifest_short)
        self.assertEqual(diff3["verdict"], ExperimentVerdict.INSUFFICIENT_DATA)
        self.assertIn("Non-comparable capture durations", diff3["summary"])

    def test_regression_priority_over_improvement(self):
        """Verifies that severe frame-pacing / stutter regression strictly overrides modest average FPS gains."""
        manifest_a = {
            "session": {"id": "base", "mode": "profile"},
            "target": {"steam_appid": "100", "target_executable": {"path": "Game.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {"fps_avg": 60.0, "fps_1_pct_low": 45.0, "frametime_jitter_ms": 3.0},
            },
        }
        # Average FPS +6.7% (60 -> 64), but 1% lows -28.9% (45 -> 32)
        manifest_b = {
            "session": {"id": "bench", "mode": "profile"},
            "target": {"steam_appid": "100", "target_executable": {"path": "Game.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {"fps_avg": 64.0, "fps_1_pct_low": 32.0, "frametime_jitter_ms": 7.0},
            },
        }
        diff = compute_session_diff(manifest_a, manifest_b)
        self.assertEqual(diff["verdict"], ExperimentVerdict.REGRESSED)
        self.assertIn("1% lows", diff["summary"])

    def test_mixed_verdict_prevents_play_mode_promotion(self):
        """Verifies that mixed performance outcomes are flagged and trigger rejection instead of promotion."""
        init_toml = EngineTweakManager.generate_profile_toml(
            game_id="300",
            app_id="300",
            target_exe="game.exe",
        )
        with open(self.profile_path, "w", encoding="utf-8") as f:
            f.write(init_toml)

        ExperimentalValidationEngine.start_experiment(
            profile_path=self.profile_path,
            fix_id="state_dedup",
            baseline_session_id="base_300",
        )

        manifest_a = {
            "session": {"id": "base_300", "mode": "profile"},
            "target": {"steam_appid": "300", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {"fps_avg": 50.0, "fps_1_pct_low": 40.0, "frametime_jitter_ms": 2.0},
            },
        }
        # Average FPS +10% (50 -> 55), but 1% low -12.5% (40 -> 35)
        manifest_b = {
            "session": {"id": "bench_300", "mode": "profile"},
            "target": {"steam_appid": "300", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {
                "roi_enabled": True,
                "frame_metrics": {"fps_avg": 55.0, "fps_1_pct_low": 35.0, "frametime_jitter_ms": 2.2},
            },
        }

        res = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=manifest_b,
            baseline_manifest=manifest_a,
        )
        self.assertEqual(res["status"], ExperimentStatus.REJECTED)
        self.assertEqual(res["verdict"], ExperimentVerdict.MIXED)

    def test_transactional_rollback_preserves_custom_settings(self):
        """Verifies that rollback restores pre-existing custom values (e.g. max_fps = 144) rather than blindly disabling them."""
        # Initialize profile with a pre-existing custom setting
        init_toml = EngineTweakManager.generate_profile_toml(
            game_id="400",
            app_id="400",
            target_exe="game.exe",
            user_tweaks={"graphics": {"max_fps": 144}},
        )
        with open(self.profile_path, "w", encoding="utf-8") as f:
            f.write(init_toml)

        prof_initial = EngineTweakManager.load_profile(self.profile_path)
        self.assertEqual(prof_initial.get("graphics", {}).get("max_fps"), 144)

        # Start cap_framerate experiment (overwrites max_fps with 60)
        ExperimentalValidationEngine.start_experiment(
            profile_path=self.profile_path,
            fix_id="cap_framerate",
            baseline_session_id="base_400",
            cap_target=60,
        )
        prof_during = EngineTweakManager.load_profile(self.profile_path)
        self.assertEqual(prof_during.get("graphics", {}).get("max_fps"), 60)

        # Regress & trigger rollback
        manifest_a = {
            "session": {"id": "base_400", "mode": "profile"},
            "target": {"steam_appid": "400", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 140.0, "fps_1_pct_low": 100.0}},
        }
        manifest_b = {
            "session": {"id": "bench_400", "mode": "profile"},
            "target": {"steam_appid": "400", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 59.0, "fps_1_pct_low": 50.0}},
        }
        res = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=manifest_b,
            baseline_manifest=manifest_a,
        )
        self.assertEqual(res["status"], ExperimentStatus.REJECTED)

        # Verify max_fps was restored to exactly 144!
        prof_rolled_back = EngineTweakManager.load_profile(self.profile_path)
        self.assertEqual(prof_rolled_back.get("graphics", {}).get("max_fps"), 144)

    def test_composite_fix_registry_gating(self):
        """Verifies that a composite recommendation (state_dedup_and_debounce) gates all constituent features."""
        init_toml = EngineTweakManager.generate_profile_toml(
            game_id="500",
            app_id="500",
            target_exe="game.exe",
        )
        with open(self.profile_path, "w", encoding="utf-8") as f:
            f.write(init_toml)

        # Start composite experiment
        ExperimentalValidationEngine.start_experiment(
            profile_path=self.profile_path,
            fix_id="state_dedup_and_debounce",
            baseline_session_id="base_500",
        )

        prof = EngineTweakManager.load_profile(self.profile_path)

        # In Play Mode: neither constituent feature should be applied
        env_play = {}
        EngineTweakManager.apply_tweaks(
            profile=prof,
            engine_info={"engine": "generic"},
            argv=["game.exe"],
            env=env_play,
        )
        self.assertNotIn("PROTOGOBLIN_STATE_DEDUP", env_play)
        self.assertNotIn("PROTOGOBLIN_SWAPCHAIN_DEBOUNCE", env_play)

        # In Profile Mode: BOTH constituent features should be applied for benchmark
        env_prof = {"PROTOGOBLIN_MODE": "profile"}
        EngineTweakManager.apply_tweaks(
            profile=prof,
            engine_info={"engine": "generic"},
            argv=["game.exe"],
            env=env_prof,
        )
        self.assertEqual(env_prof.get("PROTOGOBLIN_STATE_DEDUP"), "1")
        self.assertEqual(env_prof.get("PROTOGOBLIN_SWAPCHAIN_DEBOUNCE"), "1")

        # Evaluate experiment with IMPROVED metrics
        manifest_a = {
            "session": {"id": "base_500", "mode": "profile"},
            "target": {"steam_appid": "500", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 50.0, "fps_1_pct_low": 30.0}},
        }
        manifest_b = {
            "session": {"id": "bench_500", "mode": "profile"},
            "target": {"steam_appid": "500", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 58.0, "fps_1_pct_low": 42.0}},
        }
        res = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=manifest_b,
            baseline_manifest=manifest_a,
        )
        self.assertEqual(res["status"], ExperimentStatus.VALIDATED)

        # Now in Play Mode, BOTH are validated and active as permanent defaults!
        env_play_val = {}
        prof_val = EngineTweakManager.load_profile(self.profile_path)
        EngineTweakManager.apply_tweaks(
            profile=prof_val,
            engine_info={"engine": "generic"},
            argv=["game.exe"],
            env=env_play_val,
        )
        self.assertEqual(env_play_val.get("PROTOGOBLIN_STATE_DEDUP"), "1")
        self.assertEqual(env_play_val.get("PROTOGOBLIN_SWAPCHAIN_DEBOUNCE"), "1")

    def test_multi_run_validation_confidence(self):
        """Verifies multi-run validation tracking requiring 2 consecutive improvements before promotion."""
        init_toml = EngineTweakManager.generate_profile_toml(
            game_id="600",
            app_id="600",
            target_exe="game.exe",
        )
        with open(self.profile_path, "w", encoding="utf-8") as f:
            f.write(init_toml)

        ExperimentalValidationEngine.start_experiment(
            profile_path=self.profile_path,
            fix_id="state_dedup",
            baseline_session_id="base_600",
            required_runs=2,
        )

        manifest_base = {
            "session": {"id": "base_600", "mode": "profile"},
            "target": {"steam_appid": "600", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 50.0, "fps_1_pct_low": 30.0}},
        }
        manifest_run1 = {
            "session": {"id": "bench_run1", "mode": "profile"},
            "target": {"steam_appid": "600", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 55.0, "fps_1_pct_low": 38.0}},
        }

        # Run 1: IMPROVED, but requires 2 runs, so remains BENCHMARKED
        res1 = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=manifest_run1,
            baseline_manifest=manifest_base,
        )
        self.assertEqual(res1["status"], ExperimentStatus.BENCHMARKED)
        self.assertEqual(res1["verdict"], ExperimentVerdict.IMPROVED)

        # Run 2: IMPROVED, reaches required 2 runs -> graduates to VALIDATED
        manifest_run2 = {
            "session": {"id": "bench_run2", "mode": "profile"},
            "target": {"steam_appid": "600", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 56.0, "fps_1_pct_low": 39.0}},
        }
        res2 = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=manifest_run2,
            baseline_manifest=manifest_base,
        )
        self.assertEqual(res2["status"], ExperimentStatus.VALIDATED)

    def test_unknown_fix_id_fails_explicitly(self):
        """Verifies that attempting to start an experiment for an unknown fix raises ValueError."""
        with self.assertRaises(ValueError):
            ExperimentalValidationEngine.start_experiment(
                profile_path=self.profile_path,
                fix_id="nonexistent_fictional_optimization_fix",
            )

    def test_target_crash_during_experiment_triggers_regression(self):
        """Verifies that an unhandled crash during an experiment marks it as REGRESSED and rolls back."""
        init_toml = EngineTweakManager.generate_profile_toml(
            game_id="700",
            app_id="700",
            target_exe="game.exe",
        )
        with open(self.profile_path, "w", encoding="utf-8") as f:
            f.write(init_toml)

        ExperimentalValidationEngine.start_experiment(
            profile_path=self.profile_path,
            fix_id="io_cache",
            baseline_session_id="base_clean",
        )

        manifest_clean_base = {
            "session": {"id": "base_clean", "mode": "profile", "exit_code": 0, "clean_shutdown": True},
            "target": {"steam_appid": "700", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 60.0, "fps_1_pct_low": 40.0}},
        }
        manifest_crashed_target = {
            "session": {"id": "bench_crash", "mode": "profile", "exit_code": 1, "clean_shutdown": False},
            "target": {"steam_appid": "700", "target_executable": {"path": "game.exe"}},
            "roi_telemetry": {"roi_enabled": True, "frame_metrics": {"fps_avg": 70.0, "fps_1_pct_low": 50.0}},
        }

        res = ExperimentalValidationEngine.evaluate_experiment(
            profile_path=self.profile_path,
            session_manifest=manifest_crashed_target,
            baseline_manifest=manifest_clean_base,
        )
        self.assertEqual(res["status"], ExperimentStatus.REJECTED)
        self.assertEqual(res["verdict"], ExperimentVerdict.REGRESSED)


class TestSimulationAndCpuOptimizations(unittest.TestCase):
    """Tests for multi-CCD CPU core pinning, Unity Mono GC nursery tuning, and mimalloc heap allocator."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.profile_path = os.path.join(self.temp_dir, "test_game.toml")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cpu_probe_vcache_and_affinity_detection(self):
        """Validates detection of AMD X3D / multi-CCD CPUs and recommended affinity masks."""
        with mock.patch("os.path.isfile", side_effect=lambda p: p == "/proc/cpuinfo"):
            fake_proc_cpuinfo = "model name : AMD Ryzen 9 7950X3D 16-Core Processor\n" * 32
            with mock.patch("builtins.open", mock.mock_open(read_data=fake_proc_cpuinfo)):
                with mock.patch("os.cpu_count", return_value=32):
                    info = SystemProbe.get_cpu_info()
                    self.assertTrue(info["is_vcache"])
                    self.assertTrue(info["is_multi_ccd"])
                    self.assertEqual(info["recommended_affinity"], "0-15")

    def test_apply_tweaks_pin_performance_cores(self):
        """Verifies core pinning via taskset and WINE_CPU_TOPOLOGY."""
        profile = {
            "cpu": {
                "pin_performance_cores": True,
                "affinity_mask": "0-7",
            }
        }
        env = {}
        argv = ["game.exe"]
        with mock.patch("shutil.which", return_value="/usr/bin/taskset"):
            new_argv = EngineTweakManager.apply_tweaks(profile, {}, argv, env)
            self.assertEqual(env.get("PROTOGOBLIN_CPU_AFFINITY"), "0-7")
            self.assertEqual(env.get("WINE_CPU_TOPOLOGY"), "8:0,1,2,3,4,5,6,7")
            self.assertEqual(new_argv[:3], ["taskset", "-c", "0-7"])
            self.assertEqual(new_argv[3:], ["game.exe"])

    def test_apply_tweaks_unity_mono_gc_tuning(self):
        """Verifies MONO_GC_PARAMS expansion to 64MB for Unity simulations."""
        profile = {
            "engine": {
                "unity": {
                    "mono_gc_tuning": True,
                    "mono_nursery_size_mb": 64,
                }
            }
        }
        env = {"MONO_GC_PARAMS": "soft-heap-limit=2g"}
        EngineTweakManager.apply_tweaks(profile, {"engine": "unity"}, ["UnityGame.exe"], env)
        self.assertEqual(env.get("PROTOGOBLIN_MONO_GC_TUNING"), "1")
        self.assertEqual(env.get("MONO_GC_PARAMS"), "soft-heap-limit=2g,nursery-size=64m")

    def test_apply_tweaks_enable_mimalloc(self):
        """Verifies mimalloc preloading and large OS page environment settings."""
        profile = {
            "memory": {
                "allocator": "mimalloc",
            }
        }
        env = {}
        with mock.patch("os.path.exists", return_value=True):
            EngineTweakManager.apply_tweaks(profile, {}, ["SimGame.exe"], env)
            self.assertEqual(env.get("PROTOGOBLIN_ALLOCATOR"), "mimalloc")
            self.assertEqual(env.get("MIMALLOC_LARGE_OS_PAGES"), "1")
            self.assertEqual(env.get("MIMALLOC_PAGE_RESET"), "0")
            self.assertIn("libmimalloc.so", env.get("LD_PRELOAD", ""))

    def test_advisor_emits_simulation_and_affinity_recommendations(self):
        """Verifies advisor flags CPU-bound simulation workloads for affinity, mimalloc, and Mono GC."""
        roi = {
            "roi_enabled": True,
            "sample_count": 300,
            "bottleneck_classification": "cpu_bound",
            "pacing_metrics": {
                "cpu_busy_pct": 94.0,
                "gpu_busy_pct": 32.0,
            },
            "frame_metrics": {
                "fps_avg": 55.0,
            },
        }
        with mock.patch.object(SystemProbe, "get_cpu_info", return_value={"logical_cores": 16, "model": "AMD Ryzen 9 5950X", "is_multi_ccd": True, "recommended_affinity": "0-7"}):
            # Test 1: CPU-bound generic game -> pin_performance_cores + enable_mimalloc
            manifest_generic = {
                "roi_telemetry": roi,
                "target": {"engine": {"engine": "custom"}},
            }
            suggestions = DiagnosticAdvisor.analyze(manifest_generic)
            fix_ids = [s.get("fix_id") for s in suggestions if s.get("fix_id")]
            self.assertIn("pin_performance_cores", fix_ids)
            self.assertIn("enable_mimalloc", fix_ids)

            # Test 2: Unity simulation title -> unity_mono_gc_tuning
            manifest_unity = {
                "roi_telemetry": roi,
                "target": {"engine": {"engine": "unity"}},
            }
            unity_suggestions = DiagnosticAdvisor.analyze(manifest_unity)
            unity_fix_ids = [s.get("fix_id") for s in unity_suggestions if s.get("fix_id")]
            self.assertIn("unity_mono_gc_tuning", unity_fix_ids)

    def test_experimental_validation_lifecycle_for_new_fixes(self):
        """Verifies that all three new fixes integrate cleanly with the A/B validation engine."""
        new_fixes = ["pin_performance_cores", "unity_mono_gc_tuning", "enable_mimalloc"]
        for fix_id in new_fixes:
            init_toml = EngineTweakManager.generate_profile_toml(
                game_id="800",
                app_id="800",
                target_exe="game.exe",
            )
            with open(self.profile_path, "w", encoding="utf-8") as f:
                f.write(init_toml)

            # Start experiment
            exp_info = ExperimentalValidationEngine.start_experiment(
                profile_path=self.profile_path,
                fix_id=fix_id,
                baseline_session_id="base_sess",
                required_runs=1,
            )
            self.assertEqual(exp_info["status"], ExperimentStatus.APPLIED)
            self.assertEqual(ExperimentalValidationEngine.get_experiment_status(self.profile_path, fix_id), ExperimentStatus.APPLIED)

            # Evaluate with improvement
            manifest_base = {
                "session": {"id": "base_sess", "mode": "profile", "duration_seconds": 60, "exit_code": 0, "clean_shutdown": True},
                "target": {"steam_appid": "800", "target_executable": {"path": "game.exe"}},
                "roi_telemetry": {"roi_enabled": True, "sample_count": 500, "frame_metrics": {"fps_avg": 50.0, "fps_1_pct_low": 30.0}},
            }
            manifest_bench = {
                "session": {"id": f"bench_{fix_id}", "mode": "profile", "duration_seconds": 60, "exit_code": 0, "clean_shutdown": True},
                "target": {"steam_appid": "800", "target_executable": {"path": "game.exe"}},
                "roi_telemetry": {"roi_enabled": True, "sample_count": 500, "frame_metrics": {"fps_avg": 62.0, "fps_1_pct_low": 42.0}},
            }
            res = ExperimentalValidationEngine.evaluate_experiment(
                profile_path=self.profile_path,
                session_manifest=manifest_bench,
                baseline_manifest=manifest_base,
            )
            self.assertEqual(res["status"], ExperimentStatus.VALIDATED)
            self.assertEqual(res["verdict"], ExperimentVerdict.IMPROVED)


if __name__ == "__main__":
    unittest.main()
