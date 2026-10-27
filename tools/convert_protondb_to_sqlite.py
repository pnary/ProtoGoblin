#!/usr/bin/env python3
"""
Convert ProtonDB JSON dump archive into a high-performance local SQLite database.
Enables sub-millisecond querying of all ~400k reports.
"""

import argparse
import json
import os
import sqlite3
import sys
import tarfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_ARCHIVE = os.path.join(REPO_ROOT, ".ref", "protondb-data", "reports", "reports_oct1_2026.tar.gz")
DEFAULT_DB = os.path.join(REPO_ROOT, ".ref", "protondb.sqlite")


def convert(archive_path=DEFAULT_ARCHIVE, db_path=DEFAULT_DB):
    if not os.path.isfile(archive_path):
        print(f"Archive not found: {archive_path}")
        sys.exit(1)

    print(f"Extracting and loading {archive_path}...")
    t0 = time.time()
    with tarfile.open(archive_path, "r:gz") as tar:
        member_name = "reports_piiremoved.json"
        if member_name not in tar.getnames():
            member_name = tar.getnames()[0]
        f = tar.extractfile(member_name)
        raw_reports = json.load(f)

    print(f"Loaded {len(raw_reports):,} reports into memory in {time.time() - t0:.2f}s.")

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # High performance pragmas for initial bulk population
    cur.execute("PRAGMA synchronous = OFF;")
    cur.execute("PRAGMA journal_mode = MEMORY;")
    cur.execute("PRAGMA cache_size = 100000;")

    cur.execute("""
    CREATE TABLE reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_id INTEGER NOT NULL,
        title TEXT,
        rating TEXT,
        proton_version TEXT,
        custom_parameters TEXT,
        verdict_notes TEXT,
        significant_bugs TEXT,
        performance_faults TEXT,
        graphical_faults TEXT,
        audio_faults TEXT,
        stability_faults TEXT,
        gpu TEXT,
        cpu TEXT,
        os TEXT,
        kernel TEXT,
        ram TEXT,
        timestamp INTEGER,
        raw_notes TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE games (
        app_id INTEGER PRIMARY KEY,
        title TEXT,
        report_count INTEGER,
        top_rating TEXT
    );
    """)

    rows = []
    game_stats = {}

    for r in raw_reports:
        app = r.get("app") or {}
        steam = app.get("steam") or {}
        app_id_raw = steam.get("appId") or app.get("appId")
        try:
            app_id = int(app_id_raw) if app_id_raw is not None else 0
        except ValueError:
            app_id = 0

        title = app.get("title") or steam.get("title") or ""

        resp = r.get("responses") or {}
        rating = resp.get("rating") or resp.get("verdict")
        proton_ver = resp.get("protonVersion")
        custom_params = resp.get("customParameters")

        notes = resp.get("notes") or {}
        if isinstance(notes, dict):
            verdict_notes = notes.get("verdict")
            significant_bugs = notes.get("significantBugs")
            performance_faults = notes.get("performanceFaults")
            graphical_faults = notes.get("graphicalFaults")
            audio_faults = notes.get("audioFaults")
            stability_faults = notes.get("stabilityFaults")
            raw_notes = json.dumps(notes, ensure_ascii=False)
        elif isinstance(notes, str):
            verdict_notes = notes
            significant_bugs = None
            performance_faults = None
            graphical_faults = None
            audio_faults = None
            stability_faults = None
            raw_notes = notes
        else:
            verdict_notes = None
            significant_bugs = None
            performance_faults = None
            graphical_faults = None
            audio_faults = None
            stability_faults = None
            raw_notes = None

        sys_info = r.get("systemInfo") or {}
        gpu = sys_info.get("gpu")
        cpu = sys_info.get("cpu")
        os_info = sys_info.get("os")
        kernel = sys_info.get("kernel")
        ram = sys_info.get("ram")
        ts = r.get("timestamp")

        rows.append((
            app_id,
            title,
            rating,
            proton_ver,
            custom_params,
            verdict_notes,
            significant_bugs,
            performance_faults,
            graphical_faults,
            audio_faults,
            stability_faults,
            gpu,
            cpu,
            os_info,
            kernel,
            ram,
            ts,
            raw_notes
        ))

        if app_id:
            if app_id not in game_stats:
                game_stats[app_id] = {"title": title, "count": 0, "ratings": []}
            game_stats[app_id]["count"] += 1
            if title and not game_stats[app_id]["title"]:
                game_stats[app_id]["title"] = title
            if rating:
                game_stats[app_id]["ratings"].append(rating)

    print(f"Inserting {len(rows):,} rows into SQLite...")
    t1 = time.time()
    cur.executemany("""
    INSERT INTO reports (
        app_id, title, rating, proton_version, custom_parameters,
        verdict_notes, significant_bugs, performance_faults, graphical_faults,
        audio_faults, stability_faults, gpu, cpu, os, kernel, ram, timestamp, raw_notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, rows)

    # Insert game summary rows
    game_rows = []
    for g_id, g_info in game_stats.items():
        ratings = g_info["ratings"]
        top_rating = max(set(ratings), key=ratings.count) if ratings else None
        game_rows.append((g_id, g_info["title"], g_info["count"], top_rating))

    cur.executemany("INSERT INTO games (app_id, title, report_count, top_rating) VALUES (?, ?, ?, ?);", game_rows)

    print(f"Creating indexes...")
    cur.execute("CREATE INDEX idx_reports_app_id ON reports(app_id);")
    cur.execute("CREATE INDEX idx_reports_title ON reports(title COLLATE NOCASE);")
    cur.execute("CREATE INDEX idx_reports_params ON reports(app_id) WHERE custom_parameters IS NOT NULL;")
    cur.execute("CREATE INDEX idx_games_title ON games(title COLLATE NOCASE);")
    cur.execute("CREATE INDEX idx_games_count ON games(report_count DESC);")

    conn.commit()
    conn.close()

    db_size_mb = os.path.getsize(db_path) / (1024 * 1024)
    print(f"Complete in {time.time() - t0:.2f}s! SQLite Database size: {db_size_mb:.1f} MB -> {db_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert ProtonDB JSON archive to SQLite")
    parser.add_argument("--archive", default=DEFAULT_ARCHIVE, help="Path to reports_*.tar.gz")
    parser.add_argument("--db", default=DEFAULT_DB, help="Target SQLite file path")
    args = parser.parse_args()
    convert(args.archive, args.db)
