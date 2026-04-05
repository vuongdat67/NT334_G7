import argparse
import csv
import json
import random
from pathlib import Path
from typing import Any, Dict, List

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["file_name", "file_path", "executable", "category"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _sample(rows: List[Dict[str, Any]], k: int, rng: random.Random) -> List[Dict[str, Any]]:
    if k <= 0 or len(rows) <= k:
        return list(rows)
    return rng.sample(rows, k)


if __name__ == "__main__":
    parser = build_standard_parser(
        prog="build_benchmark_subset_manifest.py",
        description="Create a balanced subset manifest for lightweight benchmark runs.",
        examples=[
            "python scripts/build_benchmark_subset_manifest.py --manifest results/snapshot_manifest.json --out-json results/snapshot_manifest_subset.json --max-benign 5 --max-benign-tool 5 --max-ransomware-per-family 3",
        ],
    )
    parser.add_argument("--manifest", default="results/snapshot_manifest.json")
    parser.add_argument("--out-json", default="results/snapshot_manifest_subset.json")
    parser.add_argument("--out-csv", default="results/snapshot_manifest_subset.csv")
    parser.add_argument("--max-benign", type=int, default=5)
    parser.add_argument("--max-benign-tool", type=int, default=5)
    parser.add_argument("--max-ransomware-per-family", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)

    manifest_rows = _read_json(args.manifest)
    if not isinstance(manifest_rows, list):
        raise ValueError("Manifest must be a JSON list")

    benign_rows = [r for r in manifest_rows if str(r.get("category", "")) == "benign"]
    benign_tool_rows = [r for r in manifest_rows if str(r.get("category", "")) == "benign-tool"]
    ransomware_rows = [r for r in manifest_rows if str(r.get("category", "")) == "ransomware"]

    picked: List[Dict[str, Any]] = []
    picked.extend(_sample(benign_rows, args.max_benign, rng))
    picked.extend(_sample(benign_tool_rows, args.max_benign_tool, rng))

    family_map: Dict[str, List[Dict[str, Any]]] = {}
    for row in ransomware_rows:
        fam = str(row.get("executable", "Unknown"))
        family_map.setdefault(fam, []).append(row)

    for fam_rows in family_map.values():
        picked.extend(_sample(fam_rows, args.max_ransomware_per_family, rng))

    picked.sort(key=lambda x: (str(x.get("category", "")), str(x.get("executable", "")), str(x.get("file_name", ""))))

    out_json = Path(args.out_json)
    out_csv = Path(args.out_csv)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(picked, ensure_ascii=True, indent=2), encoding="utf-8")
    _write_csv(out_csv, picked)

    category_counts: Dict[str, int] = {}
    family_counts: Dict[str, int] = {}
    for row in picked:
        category = str(row.get("category", "unknown"))
        family = str(row.get("executable", "Unknown"))
        category_counts[category] = category_counts.get(category, 0) + 1
        family_counts[family] = family_counts.get(family, 0) + 1

    print(
        json.dumps(
            {
                "rows": len(picked),
                "out_json": str(out_json),
                "out_csv": str(out_csv),
                "category_counts": category_counts,
                "family_counts": dict(sorted(family_counts.items(), key=lambda x: x[0])),
            },
            ensure_ascii=True,
            indent=2,
        )
    )
