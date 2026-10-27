#!/usr/bin/env python3
"""
ProtoGoblin Command - Graphical Optimization & Diagnostic Dashboard
"""

import glob
import json
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Ensure local modules can be loaded
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import protogoblin


class DiagnosticAdvisor:
    """Evaluates session manifests and generates actionable recommendations and fixes."""

    @staticmethod
    def analyze(manifest):
        if not manifest:
            return []

        suggestions = []
        sync = manifest.get("synchronization", {})
        gfx = manifest.get("graphics", {})
        roi = manifest.get("roi_telemetry")
        ac = manifest.get("anti_cheat", {})
        env = manifest.get("environment", {})
        sub = manifest.get("subsystems", {})
        tgt = manifest.get("target", {})

        # 1. Anti-Cheat Passthrough
        if ac.get("detected"):
            provider = ac.get("provider", "Anti-Cheat")
            suggestions.append(
                {
                    "level": "warning",
                    "title": f"Anti-Cheat Active ({provider})",
                    "description": f"Game is protected by {provider}. Zero-injection passthrough mode is enforced. Do not apply in-process Detours/shims or invasive binary patches to prevent disconnection or bans.",
                    "action": "Ensure anticheat_policy = 'passthrough' in game profile.",
                }
            )

        # 2. Synchronization Backend
        sync_backend = sync.get("sync_backend", "")
        if sync_backend == "wineserver_rpc":
            suggestions.append(
                {
                    "level": "error",
                    "title": "Slow Wineserver RPC Synchronization Fallback",
                    "description": "Kernel fast-path synchronization (ntsync/fsync) is disabled, causing synchronization primitives to fall back to slow wineserver socket IPC round-trips. This often induces heavy frame stutter in multithreaded engines.",
                    "action": "Verify Linux kernel ntsync module (/dev/ntsync) or launch with WINEFSYNC=1 in Steam Launch Options.",
                }
            )
        elif sync_backend in ["ntsync", "fsync"]:
            suggestions.append(
                {
                    "level": "success",
                    "title": f"Optimal Fast-Path Sync Active ({sync_backend.upper()})",
                    "description": f"Synchronization primitives are executing directly via Linux kernel fast-path ({sync_backend}), bypassing wineserver IPC bottlenecks.",
                    "action": "No synchronization action needed.",
                }
            )

        # 3. Shader Compilation Stalls
        sh = gfx.get("shader_compiles", {})
        count = sh.get("count", 0)
        time_ms = sh.get("total_time_ms", 0.0)
        hit_rate = sh.get("pipeline_cache_hit_rate", 1.0)
        if count > 50 and time_ms > 200:
            suggestions.append(
                {
                    "level": "warning",
                    "title": "Shader Compilation Stuttering Observed",
                    "description": f"{count} pipelines compiled during session taking {time_ms:.1f}ms total. Pipeline cache hit rate was {hit_rate:.1%}.",
                    "action": "Enable local shader caching (PROTON_LOCAL_SHADER_CACHE=1) or asynchronous compilation (DXVK_ASYNC=1) to prevent gameplay hitching.",
                }
            )

        # 4. Bottleneck & CPU Core Pinning
        if roi and roi.get("roi_enabled"):
            b_class = roi.get("bottleneck_classification")
            fm = roi.get("frame_metrics") or {}
            pacing = roi.get("pacing") or {}
            cores = env.get("cpu", {}).get("logical_cores", 1)

            if b_class == "cpu_bound":
                if cores >= 12:
                    suggestions.append(
                        {
                            "level": "info",
                            "title": "CPU-Bound Workload on High-Core CPU",
                            "description": f"Session CPU load reached {pacing.get('cpu_busy_pct', 0)}% while GPU was underutilized. On multi-CCD processors (e.g. AMD Ryzen 9 / X3D), cross-CCD cache latency degrades performance.",
                            "action": "Pin game threads to the high-cache CCD using PROTON_CPU_TOPOLOGY or taskset in your game profile.",
                        }
                    )
                else:
                    suggestions.append(
                        {
                            "level": "info",
                            "title": "CPU-Bound Game Execution",
                            "description": "Game is CPU execution limited. Check thread count and CPU governor frequency scaling.",
                            "action": "Ensure Linux CPU governor is set to 'performance'.",
                        }
                    )
            elif b_class == "gpu_bound":
                suggestions.append(
                    {
                        "level": "info",
                        "title": "GPU Bound (Full Graphics Utilization)",
                        "description": f"GPU load was {pacing.get('gpu_busy_pct', 0)}%. Compatibility translation layer is keeping the GPU fully fed.",
                        "action": "If higher framerates are desired, consider FSR upscaling (WINE_FULLSCREEN_FSR=1) or reducing in-game render resolution.",
                    }
                )
            elif b_class == "sync_bound":
                suggestions.append(
                    {
                        "level": "warning",
                        "title": "Thread Starvation / Synchronization Waits",
                        "description": "Both CPU and GPU reported low utilization despite active gameplay. Threads are likely blocked on internal locks or waiting on timer intervals.",
                        "action": "Test adaptive wait policies or check if frame rate limiter is set below monitor refresh rate.",
                    }
                )

            # Frame Pacing & 1% Lows
            fps_avg = fm.get("fps_avg", 0)
            fps_1 = fm.get("fps_1_pct_low", 0)
            jitter = fm.get("frametime_jitter_ms", 0)
            if fps_avg > 0 and fps_1 > 0 and (fps_1 / fps_avg) < 0.65:
                suggestions.append(
                    {
                        "level": "warning",
                        "title": "Significant Frame Pacing Volatility",
                        "description": f"1% Low FPS ({fps_1:.1f}) dropped to {fps_1/fps_avg:.0%} of average FPS ({fps_avg:.1f}). Frametime jitter was {jitter:.1f}ms.",
                        "action": f"Set a clean frame rate cap via DXVK_FRAME_RATE={int(fps_avg)} to stabilize frame presentation intervals.",
                    }
                )

        # 5. Subsystem Pruning
        unutilized = sub.get("unutilized", [])
        if unutilized:
            suggestions.append(
                {
                    "level": "info",
                    "title": f"Subsystem Pruning Available ({len(unutilized)} unused)",
                    "description": f"The target binary never loaded the following subsystems: {', '.join(unutilized[:5])}.",
                    "action": "In Play mode, ProtoGoblin can skip initializing these shims to reduce startup latency and prefix memory footprint.",
                }
            )

        # 6. Intermediate Launcher Detected
        if tgt.get("launcher_executable"):
            l_name = os.path.basename(tgt["launcher_executable"].get("path", "Launcher"))
            t_name = os.path.basename(tgt["target_executable"].get("path", "Game"))
            suggestions.append(
                {
                    "level": "info",
                    "title": f"Multi-Stage Launcher Managed ({l_name} -> {t_name})",
                    "description": f"ProtoGoblin successfully tracked through intermediate bootstrapper {l_name} and bound instrumentation to true target binary {t_name}.",
                    "action": "No action needed. Session tracking cleanly waited for the true game payload to exit.",
                }
            )

        return suggestions


class ProtoGoblinCommandApp:
    """Main Application Window for ProtoGoblin Command GUI."""

    def __init__(self, root, initial_session_id=None):
        self.root = root
        self.root.title("ProtoGoblin Command - Optimization & Diagnostics")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        # Configure style
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Color palette
        self.bg_color = "#1e1e24"
        self.fg_color = "#f0f0f5"
        self.card_bg = "#282832"
        self.accent_color = "#4a90e2"
        self.success_color = "#2ecc71"
        self.warning_color = "#f39c12"
        self.error_color = "#e74c3c"

        self.root.configure(bg=self.bg_color)

        self.manifest_paths = []
        self.current_manifest = None
        self.initial_session_id = initial_session_id

        self._build_ui()
        if self.initial_session_id:
            self.search_var.set(self.initial_session_id)
        self.refresh_sessions()

    def _build_ui(self):
        # Top Header Bar
        header = tk.Frame(self.root, bg="#18181e", height=50)
        header.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(
            header,
            text="ProtoGoblin Command",
            font=("Segoe UI", 14, "bold"),
            bg="#18181e",
            fg="#58a6ff",
        )
        title_lbl.pack(side=tk.LEFT, padx=15, pady=10)

        subtitle_lbl = tk.Label(
            header,
            text="Game Profiling, Diagnostics & Optimization",
            font=("Segoe UI", 9),
            bg="#18181e",
            fg="#8b949e",
        )
        subtitle_lbl.pack(side=tk.LEFT, padx=5, pady=12)

        # Header Action Buttons
        btn_refresh = tk.Button(
            header,
            text="🔄 Refresh",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.refresh_sessions,
        )
        btn_refresh.pack(side=tk.RIGHT, padx=10, pady=10)

        btn_inspect = tk.Button(
            header,
            text="🔍 Inspect .EXE...",
            bg="#21262d",
            fg="#c9d1d9",
            activebackground="#30363d",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.inspect_file_dialog,
        )
        btn_inspect.pack(side=tk.RIGHT, padx=5, pady=10)

        btn_gen_profile = tk.Button(
            header,
            text="⚙️ Generate Profile TOML",
            bg="#238636",
            fg="#ffffff",
            activebackground="#2ea043",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            command=self.generate_profile_toml,
        )
        btn_gen_profile.pack(side=tk.RIGHT, padx=5, pady=10)

        # Main Content Panes
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.bg_color, sashrelief=tk.FLAT)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left Pane: Session / Game List
        left_frame = tk.Frame(paned, bg=self.card_bg, width=320)
        paned.add(left_frame, minsize=260)

        lbl_list = tk.Label(
            left_frame,
            text="Recorded Game Sessions",
            font=("Segoe UI", 10, "bold"),
            bg=self.card_bg,
            fg="#c9d1d9",
        )
        lbl_list.pack(anchor=tk.W, padx=10, pady=(10, 5))

        # Search Bar
        search_frame = tk.Frame(left_frame, bg=self.card_bg)
        search_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._filter_session_list())
        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            bg="#161b22",
            fg="#c9d1d9",
            insertbackground="#ffffff",
            relief=tk.FLAT,
        )
        search_entry.pack(fill=tk.X, ipady=3)

        # Sessions Listbox with scrollbar
        list_container = tk.Frame(left_frame, bg=self.card_bg)
        list_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        scrollbar = tk.Scrollbar(list_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.sessions_listbox = tk.Listbox(
            list_container,
            bg="#161b22",
            fg="#c9d1d9",
            selectbackground="#1f6feb",
            selectforeground="#ffffff",
            relief=tk.FLAT,
            font=("Consolas", 9),
            yscrollcommand=scrollbar.set,
        )
        self.sessions_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.sessions_listbox.yview)

        self.sessions_listbox.bind("<<ListboxSelect>>", self.on_session_selected)

        # Right Pane: Notebook Dashboard
        right_frame = tk.Frame(paned, bg=self.bg_color)
        paned.add(right_frame, minsize=500)

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Diagnostics & Suggestions
        self.tab_diag = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_diag, text="  🩺 Diagnostics & Suggested Fixes  ")

        # Tab 2: Performance & Frame Metrics
        self.tab_perf = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_perf, text="  📊 Performance & Pacing  ")

        # Tab 3: System & Translation Details
        self.tab_sys = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_sys, text="  ⚙️ Graphics & Subsystems  ")

        # Tab 4: Raw JSON Manifest
        self.tab_json = tk.Frame(self.notebook, bg=self.card_bg)
        self.notebook.add(self.tab_json, text="  📄 Raw Manifest (JSON)  ")

        # Build individual tab views
        self._build_diag_tab()
        self._build_perf_tab()
        self._build_sys_tab()
        self._build_json_tab()

    def _build_diag_tab(self):
        # Summary Header
        self.diag_header_lbl = tk.Label(
            self.tab_diag,
            text="Select a game session to view analysis.",
            font=("Segoe UI", 11, "bold"),
            bg=self.card_bg,
            fg="#58a6ff",
            anchor=tk.W,
        )
        self.diag_header_lbl.pack(fill=tk.X, padx=15, pady=(15, 5))

        # Canvas & scrollable container for suggestions
        canvas_frame = tk.Frame(self.tab_diag, bg=self.card_bg)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.diag_canvas = tk.Canvas(canvas_frame, bg=self.card_bg, highlightthickness=0)
        diag_scrollbar = tk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.diag_canvas.yview)
        self.diag_cards_container = tk.Frame(self.diag_canvas, bg=self.card_bg)

        self.diag_cards_container.bind(
            "<Configure>",
            lambda e: self.diag_canvas.configure(scrollregion=self.diag_canvas.bbox("all")),
        )
        self.diag_canvas.create_window((0, 0), window=self.diag_cards_container, anchor="nw", width=620)
        self.diag_canvas.configure(yscrollcommand=diag_scrollbar.set)

        self.diag_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        diag_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_perf_tab(self):
        self.perf_text = tk.Text(
            self.tab_perf,
            bg="#161b22",
            fg="#c9d1d9",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
        )
        self.perf_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_sys_tab(self):
        self.sys_text = tk.Text(
            self.tab_sys,
            bg="#161b22",
            fg="#c9d1d9",
            font=("Consolas", 10),
            relief=tk.FLAT,
            padx=15,
            pady=15,
        )
        self.sys_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_json_tab(self):
        self.json_text = tk.Text(
            self.tab_json,
            bg="#0d1117",
            fg="#c9d1d9",
            font=("Consolas", 9),
            relief=tk.FLAT,
            padx=15,
            pady=15,
        )
        self.json_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def refresh_sessions(self):
        """Scans for all utilization.json files across ProtoGoblin sessions."""
        xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
        base = os.path.join(xdg_data, "protogoblin", "sessions")

        pattern = os.path.join(base, "*", "*", "utilization.json")
        self.manifest_paths = glob.glob(pattern)
        self.manifest_paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)

        self._filter_session_list()

    def _filter_session_list(self):
        self.sessions_listbox.delete(0, tk.END)
        query = self.search_var.get().lower().strip()

        for idx, path in enumerate(self.manifest_paths):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sess = data.get("session", {})
                tgt = data.get("target", {})
                t_exe = os.path.basename(tgt.get("target_executable", {}).get("path", "Unknown"))
                app_id = tgt.get("steam_appid") or "-"
                mode = sess.get("mode", "play").upper()

                display = f"[{mode:<7}] {t_exe:<18} ({app_id})"
                if not query or query in display.lower() or query in path.lower():
                    self.sessions_listbox.insert(tk.END, display)
            except Exception:
                continue

        if self.sessions_listbox.size() > 0:
            self.sessions_listbox.select_set(0)
            self.on_session_selected(None)

    def on_session_selected(self, event):
        sel = self.sessions_listbox.curselection()
        if not sel:
            return

        idx = sel[0]
        # Match displayed index with filtered list
        if idx < len(self.manifest_paths):
            path = self.manifest_paths[idx]
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.current_manifest = json.load(f)
                self._render_manifest_data(self.current_manifest, path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load manifest: {e}")

    def _render_manifest_data(self, data, path):
        sess = data.get("session", {})
        tgt = data.get("target", {})
        t_exe = tgt.get("target_executable", {}) or {}
        l_exe = tgt.get("launcher_executable")
        env = data.get("environment", {})
        gfx = data.get("graphics", {})
        sync = data.get("synchronization", {})
        roi = data.get("roi_telemetry")
        sub = data.get("subsystems", {})

        # Tab 1: Diagnostics & Suggestions
        t_name = os.path.basename(t_exe.get("path", "Target"))
        self.diag_header_lbl.config(
            text=f"Target: {t_name} | Mode: {sess.get('mode', 'play').upper()} | Session: {sess.get('id')}"
        )

        for widget in self.diag_cards_container.winfo_children():
            widget.destroy()

        suggestions = DiagnosticAdvisor.analyze(data)

        if not suggestions:
            card = tk.Label(
                self.diag_cards_container,
                text="No optimization interventions required. Runtime health is clean.",
                bg="#161b22",
                fg="#2ecc71",
                font=("Segoe UI", 10),
                padx=15,
                pady=15,
            )
            card.pack(fill=tk.X, pady=5)
        else:
            for s in suggestions:
                lvl = s["level"]
                border_color = (
                    self.error_color
                    if lvl == "error"
                    else self.warning_color
                    if lvl == "warning"
                    else self.success_color
                    if lvl == "success"
                    else "#58a6ff"
                )

                card_frame = tk.Frame(
                    self.diag_cards_container,
                    bg="#161b22",
                    highlightbackground=border_color,
                    highlightthickness=1,
                    padx=12,
                    pady=10,
                )
                card_frame.pack(fill=tk.X, pady=6)

                lbl_t = tk.Label(
                    card_frame,
                    text=s["title"],
                    font=("Segoe UI", 10, "bold"),
                    bg="#161b22",
                    fg=border_color,
                    anchor=tk.W,
                )
                lbl_t.pack(fill=tk.X)

                lbl_d = tk.Label(
                    card_frame,
                    text=s["description"],
                    font=("Segoe UI", 9),
                    bg="#161b22",
                    fg="#c9d1d9",
                    wraplength=580,
                    justify=tk.LEFT,
                    anchor=tk.W,
                )
                lbl_d.pack(fill=tk.X, pady=(4, 6))

                lbl_a = tk.Label(
                    card_frame,
                    text="👉 Recommendation: " + s["action"],
                    font=("Segoe UI", 9, "bold"),
                    bg="#161b22",
                    fg="#f0f6fc",
                    wraplength=580,
                    justify=tk.LEFT,
                    anchor=tk.W,
                )
                lbl_a.pack(fill=tk.X)

        # Tab 2: Performance
        self.perf_text.delete("1.0", tk.END)
        p_lines = [
            "=" * 60,
            f" PERFORMANCE REPORT: {sess.get('id')}",
            "=" * 60,
            f"Execution Duration:   {sess.get('duration_seconds', 0):.2f} seconds",
            f"Process Exit Status:  {'Clean (0)' if sess.get('clean_shutdown') else f'Error ({tgt.get('exit_code')})'}",
            f"Process Tree Size:    {tgt.get('process_tree_count', 1)} processes spawned",
            f"Peak Thread Count:    {tgt.get('peak_thread_count', 1)} threads",
            "",
        ]

        if roi and roi.get("roi_enabled"):
            fm = roi.get("frame_metrics") or {}
            pacing = roi.get("pacing") or {}
            p_lines.extend(
                [
                    "REGION-OF-INTEREST (ROI) FRAMETIME TELEMETRY",
                    "-" * 60,
                    f"Bottleneck Status:    {roi.get('bottleneck_classification', 'balanced').upper()}",
                    f"Average Framerate:    {fm.get('fps_avg', 0):.1f} FPS",
                    f"1% Low Framerate:     {fm.get('fps_1_pct_low', 0):.1f} FPS",
                    f"0.1% Low Framerate:   {fm.get('fps_0_1_pct_low', 0):.1f} FPS",
                    f"Average Frametime:    {fm.get('frametime_avg_ms', 0):.2f} ms",
                    f"Frametime Percentiles:p95 = {fm.get('frametime_p95_ms', 0)} ms | p99 = {fm.get('frametime_p99_ms', 0)} ms",
                    f"Frametime Jitter:     {fm.get('frametime_jitter_ms', 0):.2f} ms (StdDev)",
                    f"Total Frames Scanned: {fm.get('total_frames', 0):,}",
                    "",
                    "HARDWARE RESOURCE ALLOCATION",
                    "-" * 60,
                    f"CPU Busy Utilization: {pacing.get('cpu_busy_pct', 0)}%",
                    f"CPU Wait/Blocked:     {pacing.get('cpu_wait_pct', 0)}%",
                    f"GPU Busy Utilization: {pacing.get('gpu_busy_pct', 0)}%",
                ]
            )
        else:
            p_lines.extend(
                [
                    "ROI Telemetry: Not recorded (Session was launched in PLAY mode).",
                    "To collect frame percentiles and latency breakdown, launch with:",
                    "  PROTOGOBLIN_MODE=profile %command%",
                ]
            )

        self.perf_text.insert(tk.END, "\n".join(p_lines))

        # Tab 3: System & Translation
        self.sys_text.delete("1.0", tk.END)
        s_lines = [
            "=" * 60,
            " COMPATIBILITY & TRANSLATION TELEMETRY",
            "=" * 60,
            f"Target Binary:        {t_exe.get('path', 'unknown')}",
            f"Architecture:         {t_exe.get('arch', 'unknown').upper()}",
            f"Target SHA256:        {t_exe.get('sha256', 'unknown')}",
            f"PE Timestamp:         {t_exe.get('pe_timestamp', 'None')}",
            f"PE Size of Image:     {t_exe.get('pe_size_of_image', 0):,} bytes",
            "",
            "INTERMEDIATE LAUNCHER",
            "-" * 60,
            f"Launcher Present:     {'Yes' if l_exe else 'No (Direct Execution)'}",
        ]
        if l_exe:
            s_lines.extend(
                [
                    f"Launcher Path:        {l_exe.get('path')}",
                    f"Launcher Arch:        {l_exe.get('arch')}",
                ]
            )

        s_lines.extend(
            [
                "",
                "GRAPHICS TRANSLATION (DXVK / VKD3D)",
                "-" * 60,
                f"Active Backend:       {gfx.get('active_backend', 'unknown').upper()}",
                f"D3D APIs Detected:    {', '.join(gfx.get('d3d_api_versions', []))}",
                f"Swapchain Mode:       {gfx.get('presentation_model', 'unknown')} ({gfx.get('present_mode', 'unknown')})",
                f"Resolution:           {gfx.get('resolution', 'unknown')}",
                f"Shader Pipelines:     {gfx.get('shader_compiles', {}).get('count', 0)} compiled ({gfx.get('shader_compiles', {}).get('total_time_ms', 0):.1f} ms)",
                f"VRAM Allocated:       {gfx.get('memory', {}).get('vram_used_mb') or 'N/A'} MB",
                "",
                "SYNCHRONIZATION & SUBSYSTEMS",
                "-" * 60,
                f"Sync Backend:         {sync.get('sync_backend', 'unknown').upper()}",
                f"Kernel Fast Path:     {'Enabled' if sync.get('fast_path_enabled') else 'Disabled'}",
                f"Subsystems Loaded:    {', '.join(sub.get('loaded', []))}",
                f"Subsystems Unutilized:{', '.join(sub.get('unutilized', []))}",
            ]
        )
        self.sys_text.insert(tk.END, "\n".join(s_lines))

        # Tab 4: Raw JSON
        self.json_text.delete("1.0", tk.END)
        self.json_text.insert(tk.END, json.dumps(data, indent=2))

    def inspect_file_dialog(self):
        f = filedialog.askopenfilename(
            title="Inspect Windows Executable",
            filetypes=[("Executable Files", "*.exe *.dll"), ("All Files", "*.*")],
        )
        if not f:
            return

        pe = protogoblin.PEInfo.inspect(f)
        ac = protogoblin.AntiCheatDetector.scan(f)

        msg = (
            f"File: {f}\n\n"
            f"Architecture: {pe.get('arch', 'unknown')}\n"
            f"SHA256: {pe.get('sha256', 'unknown')}\n"
            f"PE Timestamp: {pe.get('pe_timestamp') or 'None'}\n"
            f"PE Size of Image: {pe.get('pe_size_of_image', 0):,} bytes\n\n"
            f"Anti-Cheat Detected: {'YES (' + ac.get('provider') + ')' if ac.get('detected') else 'Clean (None)'}"
        )
        messagebox.showinfo("PE Binary Inspection", msg)

    def generate_profile_toml(self):
        if not self.current_manifest:
            messagebox.showwarning("Notice", "Select a session first to generate a profile.")
            return

        tgt = self.current_manifest.get("target", {})
        t_exe = tgt.get("target_executable", {}) or {}
        steam_id = tgt.get("steam_appid") or "custom-game"
        t_path = os.path.basename(t_exe.get("path", "Game.exe"))

        xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        profile_dir = os.path.join(xdg_config, "protogoblin", "games")
        os.makedirs(profile_dir, exist_ok=True)
        profile_file = os.path.join(profile_dir, f"{steam_id}.toml")

        toml_content = f"""# ProtoGoblin Per-Game Optimization Profile
# Auto-generated from session: {self.current_manifest.get('session', {}).get('id')}

[game]
id = "{steam_id}"
steam_appid = {steam_id if steam_id.isdigit() else 0}
target_executable = "{t_path}"
verified_sha256 = ["{t_exe.get('sha256', '')}"]
pe_timestamp = "{t_exe.get('pe_timestamp', '')}"
pe_size_of_image = {t_exe.get('pe_size_of_image', 0)}

[runtime]
mode = "play"
prune_unused_subsystems = true
anticheat_policy = "passthrough"

[graphics]
backend = "{self.current_manifest.get('graphics', {}).get('active_backend', 'dxvk')}"
frame_limit = 0

[synchronization]
preferred_backend = "{self.current_manifest.get('synchronization', {}).get('sync_backend', 'ntsync')}"
"""

        try:
            with open(profile_file, "w", encoding="utf-8") as pf:
                pf.write(toml_content)
            messagebox.showinfo(
                "Profile Created",
                f"Generated optimization profile at:\n{profile_file}",
            )
        except OSError as e:
            messagebox.showerror("Error", f"Failed to save profile: {e}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ProtoGoblin Command - Graphical Optimization & Diagnostic Dashboard"
    )
    parser.add_argument("--session", dest="session_id", default=None, help="Initial session ID or AppID to select")
    args, _ = parser.parse_known_args()

    root = tk.Tk()
    app = ProtoGoblinCommandApp(root, initial_session_id=args.session_id)
    root.mainloop()


if __name__ == "__main__":
    main()
