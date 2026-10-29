#!/usr/bin/env python3
"""Make a bundled MangoHud manifest portable and architecture-specific."""

import argparse
import json
from pathlib import Path


def normalize(source, destination, architecture):
    document = json.loads(Path(source).read_text())
    document["file_format_version"] = "1.2.1"
    document["layer"]["library_arch"] = architecture
    document["layer"]["library_path"] = "libMangoHud.so"
    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    Path(destination).write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("architecture", choices=("32", "64"))
    args = parser.parse_args()
    normalize(args.source, args.destination, args.architecture)
