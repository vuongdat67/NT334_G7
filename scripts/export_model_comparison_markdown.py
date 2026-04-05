import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _load_manifest_map(manifest_path: str) -> Dict[str, Dict[str, Any]]:
    path = Path(manifest_path)
    if not path.exists():
        return {}
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("file_name", "")).strip()
        if not name:
            continue
        out[name] = row
    return out


def _fp_level(benign_avg_suspicious: float, error_rate: float) -> str:
    if error_rate >= 1.0:
        return "invalid (all runs failed)"
    if benign_avg_suspicious <= 0.1:
        return "low"
    if benign_avg_suspicious <= 1.0:
        return "medium"
    return "high"


def _render_markdown(rows: list[Dict[str, Any]], report_title: str) -> str:
    lines: list[str] = []
    lines.append(f"# {report_title}")
    lines.append("")
    lines.append("## Overall Metrics")
    lines.append("")
    lines.append("| Model | Provider | Runs | Error runs | Error rate | Avg suspicious | Avg dropped | Avg runtime (s) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        lines.append(
            "| "
            f"{r['model']} | {r['provider']} | {r['runs']} | {r['error_runs']} | "
            f"{r['error_rate']:.2%} | {r['avg_suspicious_count']:.3f} | "
            f"{r['avg_dropped_by_post_filter']:.3f} | {r['avg_runtime_seconds']:.3f} |"
        )

    lines.append("")
    lines.append("## False Positive Proxy (Benign snapshots)")
    lines.append("")
    lines.append("| Model | Benign runs | Benign avg suspicious | Benign flag rate | FP level |")
    lines.append("|---|---:|---:|---:|---|")
    for r in rows:
        lines.append(
            "| "
            f"{r['model']} | {r['benign_runs']} | {r['benign_avg_suspicious']:.3f} | "
            f"{r['benign_flag_rate']:.2%} | {r['fp_level']} |"
        )

    lines.append("")
    lines.append("## Detection Proxy (Ransomware snapshots)")
    lines.append("")
    lines.append("| Model | Ransomware runs | Ransomware hit rate |")
    lines.append("|---|---:|---:|")
    for r in rows:
        lines.append(
            "| "
            f"{r['model']} | {r['ransomware_runs']} | {r['ransomware_hit_rate']:.2%} |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Benign avg suspicious is used as an FP proxy because benign snapshots should ideally have 0 suspicious processes.")
    lines.append("- Ransomware hit rate is a detection proxy (at least one suspicious process predicted).")
    lines.append("- If error rate is high, model quality conclusions are unreliable.")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = build_standard_parser(
        prog="export_model_comparison_markdown.py",
        description="Export tracker CSV into a human-readable markdown comparison report.",
        examples=[
            "python scripts/export_model_comparison_markdown.py --tracker-csv results/experiments/default/tracker/experiment_tracker.csv --manifest results/snapshot_manifest.json",
        ],
    )
    parser.add_argument(
        "--tracker-csv",
        required=True,
        help="Path to experiment_tracker.csv",
    )
    parser.add_argument(
        "--manifest",
        default="results/snapshot_manifest.json",
        help="Path to snapshot manifest JSON",
    )
    parser.add_argument(
        "--out-md",
        default="",
        help="Output Markdown report path (default: sibling of tracker csv)",
    )
    parser.add_argument(
        "--title",
        default="Model Comparison Report",
        help="Markdown title",
    )
    args = parser.parse_args()

    tracker_path = Path(args.tracker_csv)
    if not tracker_path.exists():
        raise FileNotFoundError(f"Tracker CSV not found: {args.tracker_csv}")

    manifest_map = _load_manifest_map(args.manifest)

    by_model: Dict[str, Dict[str, Any]] = {}
    with tracker_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            model = str(row.get("model", "")).strip()
            if not model:
                continue

            provider = str(row.get("provider", "")).strip()
            snapshot = str(row.get("snapshot", "")).strip()
            suspicious = int(_to_float(row.get("suspicious_count"), 0))
            dropped = int(_to_float(row.get("dropped_by_post_filter"), 0))
            runtime = _to_float(row.get("runtime_seconds"), 0.0)
            has_error = bool(str(row.get("parse_error/api_error", "")).strip())

            cat = "unknown"
            if snapshot in manifest_map:
                cat = str(manifest_map[snapshot].get("category", "unknown"))

            cur = by_model.setdefault(
                model,
                {
                    "model": model,
                    "provider": provider or "unknown",
                    "runs": 0,
                    "error_runs": 0,
                    "sum_suspicious": 0.0,
                    "sum_dropped": 0.0,
                    "sum_runtime": 0.0,
                    "benign_runs": 0,
                    "benign_sum_suspicious": 0.0,
                    "benign_flag_runs": 0,
                    "ransomware_runs": 0,
                    "ransomware_hit_runs": 0,
                },
            )

            cur["runs"] += 1
            cur["error_runs"] += 1 if has_error else 0
            cur["sum_suspicious"] += suspicious
            cur["sum_dropped"] += dropped
            cur["sum_runtime"] += runtime

            if cat in {"benign", "benign-tool"}:
                cur["benign_runs"] += 1
                cur["benign_sum_suspicious"] += suspicious
                if suspicious > 0:
                    cur["benign_flag_runs"] += 1
            elif cat == "ransomware":
                cur["ransomware_runs"] += 1
                if suspicious > 0:
                    cur["ransomware_hit_runs"] += 1

    out_rows: list[Dict[str, Any]] = []
    for _, cur in by_model.items():
        runs = max(1, int(cur["runs"]))
        benign_runs = max(1, int(cur["benign_runs"])) if int(cur["benign_runs"]) > 0 else 0
        ransomware_runs = (
            max(1, int(cur["ransomware_runs"])) if int(cur["ransomware_runs"]) > 0 else 0
        )

        error_rate = cur["error_runs"] / runs
        avg_suspicious = cur["sum_suspicious"] / runs
        avg_dropped = cur["sum_dropped"] / runs
        avg_runtime = cur["sum_runtime"] / runs

        benign_avg_suspicious = (
            cur["benign_sum_suspicious"] / benign_runs if benign_runs > 0 else 0.0
        )
        benign_flag_rate = (
            cur["benign_flag_runs"] / benign_runs if benign_runs > 0 else 0.0
        )
        ransomware_hit_rate = (
            cur["ransomware_hit_runs"] / ransomware_runs if ransomware_runs > 0 else 0.0
        )

        out_rows.append(
            {
                "model": cur["model"],
                "provider": cur["provider"],
                "runs": cur["runs"],
                "error_runs": cur["error_runs"],
                "error_rate": error_rate,
                "avg_suspicious_count": avg_suspicious,
                "avg_dropped_by_post_filter": avg_dropped,
                "avg_runtime_seconds": avg_runtime,
                "benign_runs": cur["benign_runs"],
                "benign_avg_suspicious": benign_avg_suspicious,
                "benign_flag_rate": benign_flag_rate,
                "ransomware_runs": cur["ransomware_runs"],
                "ransomware_hit_rate": ransomware_hit_rate,
                "fp_level": _fp_level(benign_avg_suspicious, error_rate),
            }
        )

    out_rows.sort(
        key=lambda x: (
            x["error_rate"],
            x["benign_avg_suspicious"],
            -x["ransomware_hit_rate"],
            x["avg_runtime_seconds"],
        )
    )

    report = _render_markdown(out_rows, args.title)

    if args.out_md:
        out_path = Path(args.out_md)
    else:
        out_path = tracker_path.parent / "model_comparison_report.md"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")

    print(
        json.dumps(
            {
                "models": len(out_rows),
                "report_path": str(out_path),
            },
            ensure_ascii=True,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
