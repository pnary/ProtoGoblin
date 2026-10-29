# Local runtime validation

Validated on 2026-10-28 with Fatal Frame / Project Zero: Mask of the Lunar
Eclipse, Steam AppID 2130460, installed build 10935296. The test machine uses
an Intel Core i5-8265U, Intel UHD Graphics 620, Mesa 26.2.2, and kernel
6.18.49-1-MANJARO. The local deployment uses Steam Runtime 4 and DXVK
v3.1.1-97-ga78a467cadb22be.

## Startup failure and reproduction

The profile launch stopped at a white window before the first frame. A render
thread backtrace showed MangoHud's instance dispatch-table initialization
calling back into `overlay_GetInstanceProcAddr` indefinitely. A clean play
launch, with tweaks and MangoHud disabled, reached the title screen.

A minimal native `vkCreateInstance` probe reproduced the distinction:

| Manifest configuration | Result |
| --- | --- |
| Bundled architecture-specific manifests | Success |
| Bundled manifests plus the old global architecture-less x86 manifest | Hang |
| Same imported manifest, with the incompatible MangoHud layer excluded | Success |

The old installer had written MangoHud manifests globally. Pressure-vessel
imported them into its Vulkan override directory. Both architecture-named
layers could then resolve the same `libMangoHud.so`, wiring MangoHud back to
itself. The corrected launcher selects one bundled directory and excludes
the incompatible layer even in inherited runtime directories. Installation
now stays inside the selected compatibility tool and compares binary contents
when checking for updates.

Bundled and build-generated manifests declare their architecture using
[`library_arch` in manifest format 1.2.1](https://github.com/KhronosGroup/Vulkan-Loader/blob/main/docs/LoaderLayerInterface.md#layer-manifest-file-format).
The executable loader regression in `tests/test_vulkan_loader.py` includes a
synthetic old imported manifest and a timeout so this failure cannot pass as a
successful capture.

## Successful profile launch

After the layer selection fix, Fatal Frame reached its title screen with the
profiling HUD active and wrote frame CSVs. The captured session is
`20261028T160137Z-1080c`. The logs confirm D3D11 and the Intel Vulkan device.
Live-validation logs and screenshots are under
`/tmp/protogoblin-fatal-frame-validation` on the test machine; desktop
screenshots are deliberately not committed.

The launch used `PROTOGOBLIN_MODE=profile`, `PROTOGOBLIN_RAW=1`,
`PROTOGOBLIN_NOTIFY=0`, and `PROTON_LOG=1`, through Runtime 4's entry point.
Raw mode excludes profile tweaks; profile mode still records measurements.
The existing game prefix was used after stopping its orphaned Wine server.
This was not a clean-prefix or upstream-Proton comparison.

Startup/menu samples prove capture works, but do not establish the game's
separate performance defect. For that investigation, capture a repeatable
gameplay interval and compare one change at a time. Missing utilization stays
unknown, interval samples are not counted as rendered frames, and low
aggregate utilization alone does not establish a staging-buffer stall.

## Checks

Run the Python, installer, compiled I/O-cache, and Vulkan-layer checks with:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests
```

GUI tests require a desktop display; they skip when Tk cannot connect. The
Vulkan test requires the loader and skips if instance creation is unavailable.

The D3D11 wrapper contract check can run without a GPU through Wine:

```bash
wineg++ -std=c++17 -DNOMINMAX tests/test_d3d11_forwarding.cpp \
  -o /tmp/protogoblin-d3d11-forwarding.exe -luuid -ldxguid
mkdir -p /tmp/protogoblin-native-test-prefix
WINEPREFIX=/tmp/protogoblin-native-test-prefix WINEDEBUG=-all \
  /tmp/protogoblin-d3d11-forwarding.exe
```

That check verifies forwarding of real copies, mappings, unmaps, resize errors,
and nonblocking map results. The stale shadow-buffer replacement was removed;
explicit native readback capture uses `[telemetry.d3d11] enabled = true`.
The optional native wrapper was compiled and contract-tested, but was not
enabled in the successful Fatal Frame launch. A full containerized Proton
release build and gameplay validation of optional native hooks remain separate
checks.
