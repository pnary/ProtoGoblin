#!/usr/bin/env python3
"""
Unit tests for ProtoGoblin Command DiagnosticAdvisor and EngineDetector
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protogoblin import (
    CompatibilityFixer,
    CompatibilityLogAnalyzer,
    EngineDetector,
    EngineTweakManager,
    NativeDllSnagger,
    PresetDatabase,
    ProtoGoblinSession,
)
from protogoblin_command import (
    DiagnosticAdvisor,
    compute_session_diff,
    format_diff_report,
    generate_debug_dump,
    format_debug_dump,
)


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

    def test_frametime_jitter_state_dedup_suggestion(self):
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
        jitter_suggs = [s for s in suggestions if s.get("fix_id") == "state_dedup_and_debounce"]
        self.assertEqual(len(jitter_suggs), 1)
        self.assertIn("Elevated Presentation & SwapChain Jitter Detected", jitter_suggs[0]["title"])
        self.assertIn("Enable State Dedup & Debounce", jitter_suggs[0]["fix_button_text"])

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
            self.assertIn("custom_text=Goblin-ing", config)
            self.assertIn("position=top-right", config)
            self.assertIn("text_color=39FF14", config)
        finally:
            if old_mode is not None:
                os.environ["PROTOGOBLIN_MODE"] = old_mode
            else:
                os.environ.pop("PROTOGOBLIN_MODE", None)
            if old_overlay is not None:
                os.environ["PROTOGOBLIN_OVERLAY"] = old_overlay

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
            self.assertNotIn("custom_text=Goblin-ing", config)
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
                self.assertIn("custom_text=Goblin-ing", env.get("MANGOHUD_CONFIG", ""))
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
                self.assertIn("custom_text=Goblin-ing", env.get("MANGOHUD_CONFIG", ""))
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
        self.assertEqual(diff["verdict"], "NEUTRAL")
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


if __name__ == "__main__":
    unittest.main()
