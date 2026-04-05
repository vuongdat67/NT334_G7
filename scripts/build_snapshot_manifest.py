import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser
from src.data.manifest import build_manifest, write_manifest_csv, write_manifest_json


def _env_or_default(env_key: str, fallback: str) -> str:
    value = os.getenv(env_key)
    if value is None or value.strip() == "":
        return fallback
    return value.strip()


if __name__ == "__main__":
    load_dotenv()

    parser = build_standard_parser(
        prog="build_snapshot_manifest.py",
        description="Scan dataset folders and build snapshot manifest JSON/CSV.",
        examples=[
            "python scripts/build_snapshot_manifest.py --data-dir data --out-json results/snapshot_manifest.json --out-csv results/snapshot_manifest.csv",
        ],
    )
    parser.add_argument(
        "--data-dir",
        default=_env_or_default("MEMORY_DUMP_FOLDER", "data"),
        help="Directory containing .elf snapshots",
    )
    parser.add_argument("--out-json", default="results/snapshot_manifest.json", help="Output manifest JSON")
    parser.add_argument("--out-csv", default="results/snapshot_manifest.csv", help="Output manifest CSV")
    args = parser.parse_args()

    rows = build_manifest(args.data_dir)
    write_manifest_json(rows, args.out_json)
    write_manifest_csv(rows, args.out_csv)

    summary = {
        "total_files": len(rows),
        "counts_by_category": {},
    }
    for r in rows:
        cat = str(r.get("category", "unknown"))
        summary["counts_by_category"][cat] = summary["counts_by_category"].get(cat, 0) + 1

    print(json.dumps(summary, ensure_ascii=True, indent=2))
