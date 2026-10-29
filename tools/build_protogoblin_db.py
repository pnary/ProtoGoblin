#!/usr/bin/env python3
"""
Build ProtoGoblin's runtime SQLite database (share/protogoblin/protogoblin.db).
Forward-only architecture: Contains ONLY active, modern fixes and profiles. No historical/deprecated entries.
"""

import json
import os
import sqlite3
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
SHARE_DIR = os.path.join(REPO_ROOT, "share", "protogoblin")
OUTPUT_DB = os.path.join(SHARE_DIR, "protogoblin.db")
PRESETS_JSON = os.path.join(SHARE_DIR, "protogoblin_presets.json")
COMPAT_SQLITE = os.path.join(REPO_ROOT, ".ref", "compat_telemetry.sqlite")

print(f"Building ProtoGoblin runtime SQLite database at {OUTPUT_DB}...")

if os.path.exists(OUTPUT_DB):
    os.remove(OUTPUT_DB)

conn = sqlite3.connect(OUTPUT_DB)
cur = conn.cursor()

# Performance optimizations
cur.execute("PRAGMA synchronous = OFF;")
cur.execute("PRAGMA journal_mode = MEMORY;")

# 1. Presets Table
cur.execute("""
CREATE TABLE presets (
    app_id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    reports INTEGER DEFAULT 0,
    modern_reports INTEGER DEFAULT 0,
    tier TEXT,
    known_issues TEXT,
    recommended_tweaks TEXT,
    deck_tweaks TEXT
);
""")

# 2. Active Modern Fixes Table (Zero legacy/deprecated records)
cur.execute("""
CREATE TABLE fixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    fix_command TEXT NOT NULL,
    confidence TEXT NOT NULL,
    report_mentions INTEGER DEFAULT 1,
    description TEXT
);
""")

# 3. MangoHud Profiles Table
cur.execute("""
CREATE TABLE mangohud_profiles (
    app_id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    fps_limit INTEGER DEFAULT 0,
    vsync INTEGER DEFAULT -1,
    vulkan_present_mode TEXT DEFAULT 'mailbox',
    conf_text TEXT
);
""")

# 4. Steam Deck Handheld Profiles Table
cur.execute("""
CREATE TABLE steam_deck_profiles (
    app_id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT DEFAULT 'playable',
    target_fps INTEGER DEFAULT 60,
    tdp_watts INTEGER DEFAULT 15,
    env_overrides TEXT,
    cli_args TEXT,
    recommended_profile_toml TEXT
);
""")

# Ingest presets from PRESETS_JSON
with open(PRESETS_JSON, "r", encoding="utf-8") as f:
    presets = json.load(f)

preset_rows = []
mangohud_rows = []
deck_rows = []

for app_id_str, data in presets.items():
    app_id = int(app_id_str)
    title = data.get("title", f"Game {app_id}")
    reports = data.get("reports", 0)
    modern_reports = data.get("modern_reports", 0)
    tier = data.get("tier", "unknown")
    known_issues = json.dumps(data.get("known_issues", []))
    recs_obj = data.get("recommended_tweaks", {})
    deck_obj = data.get("deck_tweaks", {})

    recs_json = json.dumps(recs_obj)
    deck_json = json.dumps(deck_obj)

    preset_rows.append((
        app_id, title, reports, modern_reports, tier, known_issues, recs_json, deck_json
    ))

    # MangoHud profile
    target_fps = recs_obj.get("max_fps", 0)
    vsync = 1 if (recs_obj.get("force_vsync") == "off" or "gust_d3d11_staging_sync_stall" in data.get("known_issues", [])) else -1
    conf_lines = [
        f"### ProtoGoblin MangoHud Profile: {title} ({app_id})",
        f"fps_limit={target_fps}",
        f"vsync={vsync}",
        "vulkan_present_mode=mailbox",
        "frametime=1",
        "cpu_stats=1",
        "gpu_stats=1"
    ]
    mangohud_rows.append((
        app_id, title, target_fps, vsync, "mailbox", "\n".join(conf_lines)
    ))

    # Steam Deck profile
    deck_fps = deck_obj.get("limit_fps", 60)
    deck_tdp = 12 if deck_fps <= 60 else 15
    deck_env = json.dumps(deck_obj.get("env", {"SteamDeck": "1"}))
    deck_args = json.dumps(deck_obj.get("args", []))
    profile_toml = (
        f"# ProtoGoblin Steam Deck Profile for {title}\n"
        f"[game]\nsteam_appid = {app_id}\nid = \"{title.lower().replace(' ', '_')}\"\n\n"
        f"[steam_deck]\nenabled = true\ntarget_resolution = \"1280x800\"\nlimit_fps = {deck_fps}\ntdp_limit_watts = {deck_tdp}\n\n"
        f"[graphics]\nforce_vsync = \"off\"\nmax_fps = {deck_fps}\nasync_shader_compile = true\n"
    )
    deck_rows.append((
        app_id, title, "verified" if tier in ["platinum", "gold"] else "playable",
        deck_fps, deck_tdp, deck_env, deck_args, profile_toml
    ))

cur.executemany("""
INSERT INTO presets (app_id, title, reports, modern_reports, tier, known_issues, recommended_tweaks, deck_tweaks)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
""", preset_rows)
print(f"Inserted {len(preset_rows):,} games into presets table.")

cur.executemany("""
INSERT INTO mangohud_profiles (app_id, title, fps_limit, vsync, vulkan_present_mode, conf_text)
VALUES (?, ?, ?, ?, ?, ?);
""", mangohud_rows)
print(f"Inserted {len(mangohud_rows):,} games into mangohud_profiles table.")

cur.executemany("""
INSERT INTO steam_deck_profiles (app_id, title, status, target_fps, tdp_watts, env_overrides, cli_args, recommended_profile_toml)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
""", deck_rows)
print(f"Inserted {len(deck_rows):,} games into steam_deck_profiles table.")

# Ingest ONLY ACTIVE modern fixes from COMPAT_SQLITE
active_fixes_count = 0
if os.path.isfile(COMPAT_SQLITE):
    compat_conn = sqlite3.connect(COMPAT_SQLITE)
    compat_cur = compat_conn.cursor()
    # Query strictly ACTIVE fixes
    compat_cur.execute("""
    SELECT app_id, title, category, fix_command, confidence, report_mentions, description
    FROM proton_fixes
    WHERE status = 'ACTIVE'
    ORDER BY app_id, report_mentions DESC
    """)
    active_fixes = compat_cur.fetchall()
    compat_conn.close()

    cur.executemany("""
    INSERT INTO fixes (app_id, title, category, fix_command, confidence, report_mentions, description)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, active_fixes)
    active_fixes_count = len(active_fixes)
    print(f"Inserted {active_fixes_count:,} strictly ACTIVE modern fixes (0 historical/deprecated).")

# High-performance B-tree indexes for microsecond lookups
cur.execute("CREATE INDEX idx_presets_title ON presets(title COLLATE NOCASE);")
cur.execute("CREATE INDEX idx_fixes_appid ON fixes(app_id);")
cur.execute("CREATE INDEX idx_fixes_category ON fixes(category);")
cur.execute("CREATE INDEX idx_fixes_title ON fixes(title COLLATE NOCASE);")

conn.commit()
conn.close()

db_size = os.path.getsize(OUTPUT_DB) / (1024 * 1024)
print(f"Complete! Generated {OUTPUT_DB} ({db_size:.2f} MB).")
