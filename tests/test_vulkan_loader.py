"""Probe the actual bundled layer with an imported, architecture-less manifest."""

import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import protogoblin


PROBE = r'''
import ctypes as c
class CreateInfo(c.Structure):
    _fields_ = [("sType", c.c_uint32), ("pNext", c.c_void_p), ("flags", c.c_uint32),
        ("application", c.c_void_p), ("layerCount", c.c_uint32), ("layers", c.c_void_p),
        ("extensionCount", c.c_uint32), ("extensions", c.c_void_p)]
vulkan = c.CDLL("libvulkan.so.1")
vulkan.vkCreateInstance.argtypes = [c.POINTER(CreateInfo), c.c_void_p, c.POINTER(c.c_void_p)]
vulkan.vkCreateInstance.restype = c.c_int32
vulkan.vkDestroyInstance.argtypes = [c.c_void_p, c.c_void_p]
instance = c.c_void_p()
result = vulkan.vkCreateInstance(c.byref(CreateInfo(sType=1)), None, c.byref(instance))
print("RETURN", result, flush=True)
if result == 0:
    vulkan.vkDestroyInstance(instance, None)
'''


@unittest.skipUnless(ctypes.sizeof(ctypes.c_void_p) == 8 and ctypes.util.find_library("vulkan"),
                     "requires a 64-bit Vulkan loader")
class VulkanLayerTests(unittest.TestCase):
    def test_imported_x86_manifest_cannot_reenter_64_bit_layer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifests = Path("share/protogoblin/mangohud/implicit_layer.d")
            stale = json.loads((manifests / "MangoHud.x86.json").read_text())
            stale["file_format_version"] = "1.0.0"
            stale["layer"].pop("library_arch")
            (root / "MangoHud.x86.json").write_text(json.dumps(stale))
            env = dict(os.environ)
            env.update({"VK_IMPLICIT_LAYER_PATH": directory,
                        "VK_LOADER_LAYERS_DISABLE": "VK_LAYER_example",
                        "VK_LOADER_DEBUG": "layer"})
            with patch.dict(os.environ, {"XDG_DATA_HOME": directory, "XDG_CONFIG_HOME": directory,
                                         "PROTOGOBLIN_OVERLAY": "0", "PROTOGOBLIN_NOTIFY": "0"}), \
                 patch.object(protogoblin, "log"):
                session = protogoblin.ProtoGoblinSession(steam_appid="loader-test", mode="profile")
                session.pre_flight(["game.exe"], env)
            self.assertIn("VK_LAYER_example", env["VK_LOADER_LAYERS_DISABLE"])
            result = subprocess.run([sys.executable, "-c", PROBE], env=env,
                                    capture_output=True, text=True, timeout=8)
            if "RETURN -9" in result.stdout:
                self.skipTest("Vulkan instance unavailable on this host")
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            self.assertIn("RETURN 0", result.stdout)
            self.assertEqual(result.stderr.count('Insert instance layer "VK_LAYER_MANGOHUD_overlay_x86_64"'), 1)
            self.assertNotIn('Insert instance layer "VK_LAYER_MANGOHUD_overlay_x86"', result.stderr)
