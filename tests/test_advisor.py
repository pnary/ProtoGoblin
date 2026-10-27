#!/usr/bin/env python3
"""
Unit tests for ProtoGoblin Command DiagnosticAdvisor
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protogoblin_command import DiagnosticAdvisor


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


if __name__ == "__main__":
    unittest.main()
