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
    EngineDetector,
    EngineTweakManager,
    PresetDatabase,
    ProtoGoblinSession,
)
from protogoblin_command import (
    DiagnosticAdvisor,
    compute_session_diff,
    format_diff_report,
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


if __name__ == "__main__":
    unittest.main()
