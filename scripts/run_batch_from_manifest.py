import argparse
import json
import os
import sys
from copy import deepcopy
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser
from src.config.loader import load_json
from src.pipeline.runner import run_pipeline_config


def _env_or_default(env_key: str, fallback: str) -> str:
    value = os.getenv(env_key)
    if value is None or value.strip() == "":
        return fallback
    return value.strip()


def _category_counts(rows):
    counts = {}
    for row in rows:
        cat = str(row.get("category", "unknown"))
        counts[cat] = counts.get(cat, 0) + 1
    return counts


if __name__ == "__main__":
    load_dotenv()

    parser = build_standard_parser(
        prog="run_batch_from_manifest.py",
        description="Run batch triage for snapshots listed in a manifest JSON.",
        examples=[
            "python scripts/run_batch_from_manifest.py --config config/config.json --manifest results/snapshot_manifest.json --category all --limit 10",
        ],
    )
    parser.add_argument(
        "--config",
        default=_env_or_default("BASE_CONFIG_FILE", "config/config.json"),
        help="Base config JSON",
    )
    parser.add_argument(
        "--manifest",
        default=_env_or_default("SNAPSHOT_MANIFEST_FILE", "results/snapshot_manifest.json"),
        help="Snapshot manifest JSON",
    )
    parser.add_argument(
        "--category",
        default=_env_or_default("SNAPSHOT_CATEGORY", "all"),
        choices=["all", "benign", "ransomware", "benign-tool", "unknown"],
        help="Only process rows from this category",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=int(_env_or_default("SNAPSHOT_LIMIT", "0")),
        help="Max number of snapshots to run (0 = all)",
    )
    parser.add_argument(
        "--out-dir",
        default=_env_or_default("BATCH_OUTPUT_DIR", "results/batch"),
        help="Output directory for per-snapshot reports",
    )
    args = parser.parse_args()

    base_cfg = load_json(args.config)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    selected = []
    for row in manifest:
        cat = str(row.get("category", "unknown"))
        if args.category != "all" and cat != args.category:
            continue
        selected.append(row)

    if args.limit > 0:
        selected = selected[: args.limit]

    if len(selected) == 0:
        print(
            json.dumps(
                {
                    "total_selected": 0,
                    "processed": 0,
                    "failed": 0,
                    "category": args.category,
                    "available_category_counts": _category_counts(manifest),
                    "hint": "Run build_snapshot_manifest again and check your category filter",
                },
                ensure_ascii=True,
                indent=2,
            )
        )
        sys.exit(0)

    summary = {
        "total_selected": len(selected),
        "processed": 0,
        "failed": 0,
        "items": [],
    }

    for row in selected:
        file_name = str(row.get("file_name", "unknown.elf"))
        file_stem = Path(file_name).stem
        memory_path = str(row.get("file_path"))

        cfg = deepcopy(base_cfg)
        cfg["memory_dump_path"] = memory_path
        cfg["output_report_path"] = str(out_dir / f"{file_stem}.report.json")
        cfg["output_votes_path"] = str(out_dir / f"{file_stem}.votes.json")
        cfg["output_artifacts_path"] = str(out_dir / f"{file_stem}.artifacts.json")

        item_result = {
            "file_name": file_name,
            "memory_dump_path": memory_path,
            "output_report_path": cfg["output_report_path"],
            "status": "ok",
            "error": None,
        }

        try:
            report = run_pipeline_config(cfg)
            item_result["suspicious_count"] = len(report.get("suspicious_processes", []))
            summary["processed"] += 1
        except Exception as e:  # noqa: BLE001
            item_result["status"] = "error"
            item_result["error"] = str(e)
            summary["failed"] += 1

        summary["items"].append(item_result)

    (out_dir / "batch_summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    print(json.dumps({
        "total_selected": summary["total_selected"],
        "processed": summary["processed"],
        "failed": summary["failed"],
        "summary_path": str(out_dir / "batch_summary.json"),
    }, ensure_ascii=True, indent=2))
