#!/usr/bin/env python3
"""
CLI & Library for querying the local Compatibility Telemetry & Fixes SQLite database (.ref/compat_telemetry.sqlite).
"""

import argparse
import os
import sqlite3
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(REPO_ROOT, ".ref", "compat_telemetry.sqlite")


def get_connection(db_path=None):
    path = db_path or DB_PATH
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Database not found at {path}. Run build_compat_telemetry_db.py first.")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def query_app(app_id, db_path=None):
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT * FROM proton_fixes WHERE app_id = ? ORDER BY report_mentions DESC", (app_id,))
    fixes = cur.fetchall()

    cur.execute("SELECT * FROM mangohud_profiles WHERE app_id = ?", (app_id,))
    mangohud = cur.fetchone()

    cur.execute("SELECT * FROM telemetry_baselines WHERE app_id = ?", (app_id,))
    telemetry = cur.fetchone()

    cur.execute("SELECT * FROM steam_deck_profiles WHERE app_id = ?", (app_id,))
    deck = cur.fetchone()

    return {
        "fixes": fixes,
        "mangohud": mangohud,
        "telemetry": telemetry,
        "deck": deck,
    }


def search_games(keyword, db_path=None, limit=15):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
    SELECT DISTINCT app_id, title FROM telemetry_baselines 
    WHERE title LIKE ? OR CAST(app_id AS TEXT) LIKE ?
    LIMIT ?
    """, (f"%{keyword}%", f"%{keyword}%", limit))
    return cur.fetchall()


def main():
    parser = argparse.ArgumentParser(description="Query Compatibility Telemetry & Fixes SQLite Database")
    parser.add_argument("--app-id", type=int, help="Steam AppID to inspect")
    parser.add_argument("--search", type=str, help="Search game title or AppID")
    parser.add_argument("--deck", action="store_true", help="Print full Steam Deck TOML profile")
    parser.add_argument("--mangohud", action="store_true", help="Print full MangoHud.conf profile")
    args = parser.parse_args()

    if not args.app_id and not args.search:
        parser.print_help()
        sys.exit(1)

    if args.search:
        results = search_games(args.search)
        print(f"\nFound {len(results)} matches for '{args.search}':")
        print(f"{'AppID':<12} {'Title'}")
        print("-" * 50)
        for r in results:
            print(f"{r['app_id']:<12} {r['title']}")
        return

    if args.app_id:
        data = query_app(args.app_id)
        tel = data["telemetry"]
        title = tel["title"] if tel else f"Game {args.app_id}"

        print("\n" + "=" * 65)
        print(f"AppID: {args.app_id} | Title: {title}")
        print("=" * 65)

        if tel:
            print(f"\n--- Telemetry & Performance Baseline ---")
            print(f"  Target Framerate:       {tel['target_fps'] or 'Uncapped (VSync / Monitor native)'}")
            print(f"  Frametime Target:       {tel['frametime_target_ms']} ms (Expected Jitter: <{tel['expected_jitter_ms']} ms)")
            print(f"  Bottleneck Signature:   {tel['bottleneck_tendency']}")
            print(f"  Sync Stall Risk:        {tel['sync_stall_risk']}")
            print(f"  DXVK Async Recommended: {'Yes' if tel['dxvk_async_recommended'] else 'No'}")

        if data["fixes"]:
            print(f"\n--- Curated Time-Aware Proton Fixes ({len(data['fixes'])} found) ---")
            for f in data["fixes"]:
                timeline = f"{f['first_seen_year']}-{f['last_seen_year']}" if f['first_seen_year'] else "historical"
                status_badge = "ACTIVE" if f['status'] == "ACTIVE" else "DEPRECATED (Resolved Upstream)"
                print(f"  [{status_badge}] [{f['confidence']}] ({f['category']}) {f['fix_command']}")
                print(f"      Timeline: {timeline} | Mentions: {f['report_mentions']}x | {f['description']}")
        else:
            print("\n--- Curated Proton Fixes ---")
            print("  No special overrides needed (works out-of-the-box).")

        deck = data["deck"]
        if deck:
            print(f"\n--- Steam Deck Hardware Profile ---")
            print(f"  Deck Status:      {deck['status'].upper()}")
            print(f"  Target Resolution:{deck['resolution']} (16:10 Native)")
            print(f"  Target FPS:       {deck['target_fps']} FPS")
            print(f"  TDP Envelope:     {deck['tdp_watts']}W")
            print(f"  Env Overrides:    {deck['env_overrides']}")

        if args.mangohud and data["mangohud"]:
            print("\n--- MangoHud Configuration File (MangoHud.conf) ---")
            print(data["mangohud"]["conf_text"])

        if args.deck and deck:
            print("\n--- Recommended ProtoGoblin Steam Deck Profile TOML ---")
            print(deck["recommended_profile_toml"])


if __name__ == "__main__":
    main()
