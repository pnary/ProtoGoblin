# ProtoGoblin Third-Party Attributions & Open-Source Lineage

ProtoGoblin integrates, adapts, and builds upon pioneering open-source projects in the Linux gaming, translation layer, graphics hooking, and engine reverse-engineering ecosystems. 

This document attributes the upstream authors, copyright holders, source repositories, and licenses for technologies, interfaces, and architectural techniques incorporated into or referenced by ProtoGoblin.

---

## Summary of Incorporated & Referenced Technologies

| Project | Upstream Repository | License | Area of Influence in ProtoGoblin |
| :--- | :--- | :--- | :--- |
| **Valve Proton & GE-Proton** | [ValveSoftware/Proton](https://github.com/ValveSoftware/Proton)<br>[GloriousEggroll/proton-ge-custom](https://github.com/GloriousEggroll/proton-ge-custom) | BSD-3-Clause / LGPL-2.1+ / zlib | Base compatibility tool harness, launcher script, Wine prefix management, runtime patches. |
| **MangoHud** | [flightlessmango/MangoHud](https://github.com/flightlessmango/MangoHud) | MIT | Bundled Vulkan/OpenGL telemetry layer (`vklayers/`), ROI HUD banner, frame time percentile logging. |
| **Intel PresentMon** | [GameTechDev/PresentMon](https://github.com/GameTechDev/PresentMon) | MIT | Telemetry schema architecture, `TimeInPresent`, `CPUBusy`/`GPUBusy` ratios, frame pacing models. |
| **DXVK** | [doitsujin/dxvk](https://github.com/doitsujin/dxvk) | zlib/libpng | Direct3D 8/9/10/11 to Vulkan translation, live log parser, asynchronous shader pipeline compiles. |
| **VKD3D-Proton** | [HansKristian-Work/vkd3d-proton](https://github.com/HansKristian-Work/vkd3d-proton) | LGPL-2.1+ | Direct3D 12 to Vulkan translation, swapchain presentation telemetry, memory allocation tracking. |
| **Special K** | [SpecialSK/SpecialK](https://github.com/SpecialSK/SpecialK) | GPL-3.0 | User-space DXGI/D3D/Vulkan hooking, frame pacing, timer resolution mitigation, engine heuristics. |
| **OptiScaler** | [optiscaler/OptiScaler](https://github.com/optiscaler/OptiScaler) | GPL-3.0 | DXGI swapchain proxying (`Present`/`Present1`), upscaler decoupling, vendor-agnostic frame generation. |
| **RE-UE4SS** | [UE4SS-RE/RE-UE4SS](https://github.com/UE4SS-RE/RE-UE4SS) | MIT | Unreal Engine 4/5 introspection, `FConsoleManager` / `GUObjectArray` scanning, runtime CVar overrides. |
| **BepInEx** | [BepInEx/BepInEx](https://github.com/BepInEx/BepInEx) | LGPL-2.1 / MIT | Unity lifecycle interception (`UnityPlayer.dll`, `UnityMain`), Mono/IL2CPP domain shimming. |
| **godot-mod-loader** | [GodotModding/godot-mod-loader](https://github.com/GodotModding/godot-mod-loader) | MIT | Godot 3.x/4.x `.pck` file structure, runtime script hooking, `override.cfg` injection. |
| **LatencyFleX** | [ishitatsuyuki/LatencyFleX](https://github.com/ishitatsuyuki/LatencyFleX) | Apache-2.0 | Vendor-agnostic latency reduction, Reflex-compatible frame pacing, render queue minimization. |
| **Microsoft Detours** | [microsoft/Detours](https://github.com/microsoft/Detours) | MIT | User-space x86/x64 API trampoline hooking, PE import table redirection. |

---

## Detailed Project Attributions & Credits

### 1. Valve Proton & GE-Proton
- **Upstream:** [https://github.com/ValveSoftware/Proton](https://github.com/ValveSoftware/Proton) & [https://github.com/GloriousEggroll/proton-ge-custom](https://github.com/GloriousEggroll/proton-ge-custom)
- **Copyright:** (c) 2018-2026 Valve Corporation, Thomas Crider (GloriousEggroll), and Wine/Proton contributors.
- **License:** BSD-3-Clause / LGPL-2.1+ / zlib
- **Usage in ProtoGoblin:** Forms the baseline execution environment, prefix initialization scripts, containerized build harness (`Makefile.in`, `configure.sh`), and runtime DLL override mappings.

### 2. MangoHud
- **Upstream:** [https://github.com/flightlessmango/MangoHud](https://github.com/flightlessmango/MangoHud)
- **Copyright:** (c) 2019-2026 FlightlessMango and MangoHud contributors.
- **License:** MIT
- **Usage in ProtoGoblin:** Bundled directly under `vklayers/` as a built-in Vulkan implicit layer. Powers automatic Region-of-Interest (ROI) telemetry capture, frametime percentile calculation (P50, P90, P99, 1% lows), and the active profile HUD banner (`ProtoGoblin`).

### 3. Intel PresentMon
- **Upstream:** [https://github.com/GameTechDev/PresentMon](https://github.com/GameTechDev/PresentMon)
- **Copyright:** (c) 2017-2026 Intel Corporation.
- **License:** MIT
- **Usage in ProtoGoblin:** Telemetry data model and metric definitions in `.plan/schemas/utilization.schema.json` follow PresentMon's presentation pipeline tracking (measuring execution delays across presentation queues, GPU render time, and driver spin-waits).

### 4. DXVK & VKD3D-Proton
- **Upstream:** [https://github.com/doitsujin/dxvk](https://github.com/doitsujin/dxvk) & [https://github.com/HansKristian-Work/vkd3d-proton](https://github.com/HansKristian-Work/vkd3d-proton)
- **Copyright:** (c) 2017-2026 Philip Rebohle (doitsujin), Hans-Kristian Arntzen, Joshua Ashton, and VKD3D contributors.
- **License:** zlib/libpng (DXVK) and LGPL-2.1+ (VKD3D-Proton)
- **Usage in ProtoGoblin:** Used as primary D3D-to-Vulkan translation backends. `protogoblin.py` includes dedicated live log stream parsers (`GraphicsLogParser`) monitoring DXVK and VKD3D shader compilation queues, device capabilities, swapchain modes, and memory pools.

### 5. Special K
- **Upstream:** [https://github.com/SpecialSK/SpecialK](https://github.com/SpecialSK/SpecialK)
- **Copyright:** (c) 2015-2026 Kaldaien.
- **License:** GPL-3.0
- **Usage in ProtoGoblin:** Informs user-space graphics shimming, waitable swapchain latency reduction, presentation pacing, and engine heuristic detection for commercial PC engines.

### 6. OptiScaler
- **Upstream:** [https://github.com/optiscaler/OptiScaler](https://github.com/optiscaler/OptiScaler)
- **Copyright:** (c) 2023-2026 OptiScaler contributors.
- **License:** GPL-3.0
- **Usage in ProtoGoblin:** Techniques for intercepting DXGI swapchain buffers without requiring game source modifications, decoupling resolution from presentation, and capturing vendor-agnostic frame delivery metrics.

### 7. RE-UE4SS
- **Upstream:** [https://github.com/UE4SS-RE/RE-UE4SS](https://github.com/UE4SS-RE/RE-UE4SS)
- **Copyright:** (c) 2022-2026 RE-UE4SS contributors.
- **License:** MIT
- **Usage in ProtoGoblin:** Guides Unreal Engine 4 and 5 detection patterns (identifying Zen Store `.ucas`/`.utoc` containers vs `.pak` archives), PE section signatures (`FEngineLoop`, `GUObjectArray`), and console variable (`CVar`) override syntax for visual quality and performance tuning.

### 8. BepInEx
- **Upstream:** [https://github.com/BepInEx/BepInEx](https://github.com/BepInEx/BepInEx)
- **Copyright:** (c) 2018-2026 BepInEx Team.
- **License:** LGPL-2.1 / MIT
- **Usage in ProtoGoblin:** Informs Unity runtime detection (distinguishing Mono BleedingEdge vs IL2CPP metadata), `UnityPlayer.dll` export lifecycle interception, and `boot.config` performance optimizations (`gfx-enable-native-gfx-jobs=1`).

### 9. godot-mod-loader
- **Upstream:** [https://github.com/GodotModding/godot-mod-loader](https://github.com/GodotModding/godot-mod-loader)
- **Copyright:** (c) 2021-2026 GodotModding team.
- **License:** MIT
- **Usage in ProtoGoblin:** Informs Godot engine detection (identifying `0x43504447` / `GDPC` headers and sibling `.pck` packages) and `override.cfg` injection for forcing Vulkan Forward+ backends and disabling VSync.

### 10. LatencyFleX
- **Upstream:** [https://github.com/ishitatsuyuki/LatencyFleX](https://github.com/ishitatsuyuki/LatencyFleX)
- **Copyright:** (c) 2021-2026 Tatsuyuki Ishi.
- **License:** Apache-2.0
- **Usage in ProtoGoblin:** Vendor-agnostic latency optimization principles, input lag queue regulation, and safe handling of engine loops in games protected by anti-cheat.

### 11. Microsoft Detours
- **Upstream:** [https://github.com/microsoft/Detours](https://github.com/microsoft/Detours)
- **Copyright:** (c) 1999-2026 Microsoft Corporation.
- **License:** MIT
- **Usage in ProtoGoblin:** x86/x64 in-process function hooking and trampoline redirection techniques.
