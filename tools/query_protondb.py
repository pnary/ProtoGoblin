#!/usr/bin/env python3
"""
CLI & Library for fast querying of local ProtonDB SQLite database.
"""

import argparse
import os
import sqlite3
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_DB = os.path.join(REPO_ROOT, ".ref", "protondb.sqlite")


def get_connection(db_path=None):
    path = db_path or DEFAULT_DB
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"ProtonDB SQLite database not found at {path}.\n"
            f"Run python tools/convert_protondb_to_sqlite.py first."
        )
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def query_game(app_id=None, title=None, db_path=None):
    conn = get_connection(db_path)
    cur = conn.cursor()

    if app_id:
        cur.execute("SELECT * FROM games WHERE app_id = ?", (app_id,))
        game = cur.fetchone()
        cur.execute("SELECT * FROM reports WHERE app_id = ? ORDER BY timestamp DESC", (app_id,))
        reports = cur.fetchall()
        return game, reports

    if title:
        cur.execute("SELECT * FROM games WHERE title LIKE ? ORDER BY report_count DESC LIMIT 25", (f"%{title}%",))
        games = cur.fetchall()
        return games, []

    return None, []


def main():
    parser = argparse.ArgumentParser(description="Query local ProtonDB SQLite database")
    parser.add_argument("--app-id", type=int, help="Steam AppID to inspect")
    parser.add_argument("--search", type=str, help="Search game title")
    parser.add_argument("--limit", type=int, default=10, help="Max reports to show")
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to SQLite db")
    args = parser.parse_args()

    if not args.app_id and not args.search:
        parser.print_help()
        sys.exit(1)

    try:
        conn = get_connection(args.db)
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)

    if args.search:
        games, _ = query_game(title=args.search, db_path=args.db)
        print(f"\nFound {len(games)} matches for '{args.search}':")
        print(f"{'AppID':<12} {'Reports':<10} {'Rating':<10} {'Title'}")
        print("-" * 75)
        for g in games:
            print(f"{g['app_id']:<12} {g['report_count']:<10} {g['top_rating'] or '-':<10} {g['title']}")
        return

    if args.app_id:
        game, reports = query_game(app_id=args.app_id, db_path=args.db)
        if not game:
            print(f"No game found for AppID {args.app_id}")
            return

        print(f"\n============================================================")
        print(f"AppID: {game['app_id']} | Title: {game['title']}")
        print(f"Total Reports: {game['report_count']} | Rating: {game['top_rating']}")
        print(f"============================================================\n")

        # Custom parameters tally
        params = [r['custom_parameters'] for r in reports if r['custom_parameters']]
        if params:
            print("Community Custom Parameters / Launch Options:")
            for p in sorted(set(params)):
                count = params.count(p)
                print(f"  [{count}x] {p}")
            print()

        print(f"Latest {min(len(reports), args.limit)} Reports:")
        for idx, r in enumerate(reports[:args.limit]):
            print(f"\n--- Report #{idx+1} (Proton: {r['proton_version'] or 'N/A'}, Verdict: {r['rating'] or 'N/A'}) ---")
            if r['gpu'] or r['os']:
                print(f"Hardware: GPU: {r['gpu'] or 'N/A'} | OS: {r['os'] or 'N/A'}")
            if r['verdict_notes']:
                print(f"Verdict: {r['verdict_notes']}")
            if r['significant_bugs']:
                print(f"Bugs: {r['significant_bugs']}")
            if r['performance_faults']:
                print(f"Performance: {r['performance_faults']}")
            if r['graphical_faults']:
                print(f"Graphics: {r['graphical_faults']}")
            if r['stability_faults']:
                print(f"Stability: {r['stability_faults']}")


if __name__ == "__main__":
    main()
