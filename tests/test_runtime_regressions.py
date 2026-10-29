"""Behavioral checks for launch isolation and evidence-based diagnostics."""

import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import protogoblin as runtime
from protogoblin_command import DiagnosticAdvisor
from tools.normalize_mangohud_manifest import normalize


class RuntimeRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_DATA_HOME": str(self.root / "data"),
            "PROTOGOBLIN_NOTIFY": "0",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        logger = patch.object(runtime, "log")
        logger.start()
        self.addCleanup(logger.stop)

    def test_tracker_can_monitor_a_real_child(self):
        child = subprocess.Popen(["sleep", "10"])
        self.addCleanup(child.wait)
        self.addCleanup(child.terminate)
        tracker = runtime.ProcessTreeTracker(child.pid)
        tracker.start()
        self.addCleanup(tracker.stop)
        tracker._poll()
        tracker.stop()
        self.assertIn(child.pid, tracker.all_seen_pids)
        self.assertGreaterEqual(tracker.peak_thread_count, 1)
        self.assertFalse(tracker.thread.is_alive())
        self.assertEqual(tracker.discovered_executables, {})

    def test_observer_failure_still_waits_for_game(self):
        # Compile the actual launcher method without invoking Proton's CLI.
        tree = ast.parse(Path("proton").read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Session")
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "run_proc")
        namespace = {"protogoblin": Mock(), "subprocess": Mock()}
        namespace["protogoblin"].g_protogoblin.start_process_tree_monitor.side_effect = RuntimeError("observer failed")
        process = namespace["subprocess"].Popen.return_value
        process.wait.return_value = 7
        exec(compile(ast.Module(body=[method], type_ignores=[]), "proton", "exec"), namespace)
        session = Mock(env={}, log_file=None)
        self.assertEqual(namespace["run_proc"](session, ["game"]), 7)
        process.wait.assert_called_once()

    def test_false_feature_tables_do_not_enable_hooks(self):
        profile = {
            "synchronization": {key: {"enabled": False} for key in (
                "atelier_sync_fix", "state_dedup", "swapchain_debounce", "precision_timers",
            )},
            "timing": {"precision_timers": {"enabled": False}},
            "filesystem": {"io_cache": {"enabled": False}},
        }
        env = {}
        runtime.EngineTweakManager.apply_tweaks(profile, {}, ["game.exe"], env)
        for key in ("WINEDLLOVERRIDES", "WINEDLLPATH", "LD_PRELOAD", "PROTOGOBLIN_IO_CACHE",
                    "PROTOGOBLIN_STATE_DEDUP", "PROTOGOBLIN_HIGH_PRECISION_TIMERS"):
            self.assertNotIn(key, env)

    def test_generator_respects_disabled_feature_tables(self):
        text = runtime.EngineTweakManager.generate_profile_toml(
            "test", "2130460", "FATAL_FRAME_MOL.exe", user_tweaks={
                "filesystem": {"io_cache": {"enabled": False}},
                "synchronization": {"state_dedup": {"enabled": False}},
            })
        self.assertNotIn("[filesystem.io_cache]", text)
        self.assertNotIn("[synchronization.state_dedup]", text)

    def test_wine_library_drive_is_resolved(self):
        prefix = self.root / "prefix"
        (prefix / "dosdevices").mkdir(parents=True)
        library = self.root / "library"
        library.mkdir()
        (library / "FATAL_FRAME_MOL.exe").touch()
        (prefix / "dosdevices/s:").symlink_to(library, target_is_directory=True)
        self.assertEqual(runtime.ProcessTreeTracker.resolve_wine_path(
            r"S:\FATAL_FRAME_MOL.exe", str(prefix)), str(library / "FATAL_FRAME_MOL.exe"))

    def test_anti_cheat_suppresses_profiles_presets_and_inherited_hooks(self):
        profile = self.root / "game.toml"
        profile.write_text('[synchronization.state_dedup]\nenabled = true\n[pruning]\nvr = true\n')
        env = {
            "MANGOHUD": "1", "MANGOHUD_CONFIG": "test",
            "PROTOGOBLIN_IO_CACHE": "1", "PROTOGOBLIN_STATE_DEDUP": "1",
            "LD_PRELOAD": "/tool/libMangoHud.so:/tool/libprotogoblin_io_cache.so:/steam/overlay.so",
        }
        session = runtime.ProtoGoblinSession(steam_appid="regression", mode="profile")
        with patch.dict(os.environ, {"PROTOGOBLIN_PROFILE": str(profile)}), \
             patch.object(runtime.AntiCheatDetector, "scan", return_value={"detected": True, "provider": "EAC", "passthrough_enforced": True}), \
             patch.object(runtime.EngineTweakManager, "apply_tweaks") as apply:
            session.pre_flight(["game.exe"], env)
        apply.assert_not_called()
        self.assertEqual(session.mode, "play")
        self.assertEqual(env["MANGOHUD"], "0")
        self.assertEqual(env["LD_PRELOAD"], "/steam/overlay.so")
        self.assertNotIn("PROTOGOBLIN_IO_CACHE", env)
        self.assertNotIn("PROTOGOBLIN_STATE_DEDUP", env)
        self.assertNotIn("PROTON_NO_VR", env)
        suggestions = DiagnosticAdvisor.analyze({"anti_cheat": session.anti_cheat})
        self.assertFalse(any(s.get("fix_id") for s in suggestions))

    def test_capture_absence_does_not_claim_dx11_or_unused_vr(self):
        session = runtime.ProtoGoblinSession(steam_appid="2130460", mode="profile")
        session.target_exe = {"path": "FATAL_FRAME_MOL.exe"}
        with patch.object(runtime.GraphicsLogParser, "scan_and_parse", return_value=None):
            manifest = session.post_flight(1, {})
        self.assertEqual(manifest["roi_telemetry"]["bottleneck_classification"], "unknown")
        self.assertEqual(manifest["subsystems"]["unutilized"], [])
        self.assertEqual(manifest["graphics"]["d3d_api_versions"], [])

    def test_previous_unobserved_subsystems_do_not_disable_vr(self):
        session = runtime.ProtoGoblinSession(steam_appid="regression", mode="play")
        previous = Path(session.session_dir).parent / "previous" / "utilization.json"
        previous.parent.mkdir(parents=True)
        previous.write_text(json.dumps({"subsystems": {"unutilized": ["openvr", "wineopenxr"]}}))
        env = {}
        self.assertEqual(session.prune_subsystems(env), [])
        self.assertNotIn("PROTON_NO_VR", env)


class CaptureRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def capture(self, contents, name="game.csv"):
        (self.root / name).write_text(contents)
        return runtime.MangoHudLogParser.parse_session(self.root, 120)

    def test_detail_utilization_is_parsed(self):
        roi = self.capture('fps,frametime,cpu_load,gpu_load\n60,16.67,20,98\n60,16.67,20,98\n')
        self.assertEqual(roi["bottleneck_classification"], "gpu_bound")
        self.assertEqual(roi["pacing"]["gpu_busy_pct"], 98)
        self.assertIsNone(roi["pacing"]["cpu_wait_pct"])
        self.assertEqual(roi["frame_metrics"]["frametime_jitter_ms"], 0)
        self.assertIsNone(roi["frame_metrics"]["total_frames"])
        self.assertEqual(roi["frame_metrics"]["sample_count"], 2)

    def test_missing_load_is_unknown_and_never_a_staging_diagnosis(self):
        roi = self.capture('fps,frametime\n30,33.33\n')
        self.assertEqual(roi["bottleneck_classification"], "unknown")
        self.assertIsNone(roi["pacing"]["gpu_busy_pct"])
        self.assertIsNone(roi["frame_metrics"]["fps_1_pct_low"])
        suggestions = DiagnosticAdvisor.analyze({"roi_telemetry": roi})
        self.assertFalse(any(s.get("fix_id") == "atelier_sync_fix" for s in suggestions))
    def test_multiple_captures_and_preamble_are_aggregated(self):
        self.capture('OS,CPU\nLinux,Test\nfps,frametime,cpu_load,gpu_load\n60,10,20,90\n', 'a.csv')
        roi = self.capture('fps,frametime,cpu_load,gpu_load\n30,30,40,100\n', 'b.csv')
        self.assertEqual(roi["frame_metrics"]["sample_count"], 2)
        self.assertEqual(roi["frame_metrics"]["frametime_avg_ms"], 20)
        self.assertEqual(roi["pacing"]["gpu_busy_pct"], 95)

    def test_invalid_numbers_do_not_poison_metrics(self):
        roi = self.capture('fps,frametime,cpu_load,gpu_load\nnan,inf,nan,-1\n60,16,20,90\n')
        self.assertEqual(roi["pacing"]["gpu_busy_pct"], 90)
        self.assertEqual(roi["frame_metrics"]["sample_count"], 1)

    def test_summary_only_does_not_invent_percentiles(self):
        roi = self.capture('Average FPS,CPU Load,GPU Load\n60,20,98\n', 'game_summary.csv')
        self.assertIsNone(roi["frame_metrics"]["frametime_p99_ms"])
        self.assertIsNone(roi["frame_metrics"]["frametime_jitter_ms"])

    def test_low_utilization_alone_does_not_offer_native_fix(self):
        roi = self.capture('fps,frametime,cpu_load,gpu_load\n20,50,20,20\n')
        self.assertEqual(roi["bottleneck_classification"], "underutilized")
        suggestions = DiagnosticAdvisor.analyze({"roi_telemetry": roi})
        self.assertTrue(any(s["title"] == "Low CPU and GPU Utilization" for s in suggestions))
        self.assertFalse(any(s.get("fix_id") == "atelier_sync_fix" for s in suggestions))


class ManifestRegressions(unittest.TestCase):
    def test_bundled_layers_cannot_both_load_the_same_architecture(self):
        manifests = Path("share/protogoblin/mangohud/implicit_layer.d")
        for name, arch in (("MangoHud.x86.json", "32"), ("MangoHud.x86_64.json", "64")):
            data = json.loads((manifests / name).read_text())
            self.assertEqual(data["layer"]["library_arch"], arch)
            self.assertEqual(data["file_format_version"], "1.2.1")

    def test_build_manifests_are_portable_and_architecture_specific(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "original.json"
            destination = Path(directory) / "installed.json"
            source.write_text(json.dumps({"file_format_version": "1.0.0", "layer": {
                "name": "VK_LAYER_MANGOHUD_overlay_x86_64", "library_path": "/build/lib/libMangoHud.so",
            }}))
            normalize(source, destination, "64")
            data = json.loads(destination.read_text())
            self.assertEqual(data["layer"]["library_path"], "libMangoHud.so")
            self.assertEqual(data["layer"]["library_arch"], "64")

