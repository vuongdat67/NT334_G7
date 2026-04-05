import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.evaluation.hallucination import analyze_hallucination_taxonomy
from src.cli.help_format import build_standard_parser


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _safe_div(a: float, b: float) -> float:
    if b == 0:
        return 0.0
    return a / b


def _metrics(pred: Set[int], all_pids: Set[int], malicious: Set[int]) -> Dict[str, float]:
    benign = all_pids - malicious
    tp = len(pred & malicious)
    fp = len(pred & benign)
    fn = len((all_pids - pred) & malicious)
    tn = len((all_pids - pred) & benign)
    total = tp + fp + fn + tn

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "accuracy": _safe_div(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "triage_efficiency": _safe_div(tp + fp, total),
    }


def _build_manifest_index(manifest_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx = {}
    for r in manifest_rows:
        file_name = str(r.get("file_name", ""))
        stem = Path(file_name).stem
        idx[stem] = r
    return idx


def _avg(rows: List[Dict[str, Any]], key: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(x.get(key, 0.0) or 0.0) for x in rows) / len(rows), 6)


def _write_csv(path: str, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    parser = build_standard_parser(
        prog="run_family_benchmark.py",
        description="Compute family-level and overall benchmark metrics from experiment tracker outputs.",
        examples=[
            "python scripts/run_family_benchmark.py --tracker-json results/experiments/default/tracker/experiment_tracker.json --manifest results/snapshot_manifest.json --labels-dir results/labels",
        ],
    )
    parser.add_argument(
        "--tracker-json",
        required=True,
        help="experiment_tracker.json from run_model_comparison",
    )
    parser.add_argument("--manifest", default="results/snapshot_manifest.json")
    parser.add_argument("--labels-dir", default="results/labels")
    parser.add_argument("--paper-model", default="")
    parser.add_argument("--out-dir", default="results/benchmark")
    args = parser.parse_args()

    tracker_rows = _read_json(args.tracker_json)
    manifest_rows = _read_json(args.manifest)
    manifest_idx = _build_manifest_index(manifest_rows)

    snapshot_rows: List[Dict[str, Any]] = []

    for row in tracker_rows:
        snapshot = str(row.get("snapshot", ""))
        snapshot_stem = Path(snapshot).stem
        report_path = str(row.get("report_path", ""))
        model = str(row.get("model", "unknown"))
        provider = str(row.get("provider", "unknown"))

        label_path = Path(args.labels_dir) / f"{snapshot_stem}.labels.json"
        if not Path(report_path).exists() or not label_path.exists():
            continue

        report = _read_json(report_path)
        label = _read_json(str(label_path))
        mrow = manifest_idx.get(snapshot_stem, {})
        family = str(mrow.get("executable", label.get("family", "Unknown")))
        category = str(mrow.get("category", "unknown"))

        suspicious = report.get("suspicious_processes", [])
        pred_pids: Set[int] = set()
        for x in suspicious:
            pid_val = x.get("pid") if isinstance(x, dict) else None
            if isinstance(pid_val, int):
                pred_pids.add(pid_val)

        all_pids = set(int(x) for x in label.get("all_pids", []) if isinstance(x, int))
        malicious = set(int(x) for x in label.get("malicious_pids", []) if isinstance(x, int))

        if len(all_pids) == 0:
            continue

        metrics = _metrics(pred_pids, all_pids, malicious)
        process_by_pid: Dict[int, Dict[str, Any]] = {}
        for p in label.get("processes", []):
            pid_val = p.get("pid") if isinstance(p, dict) else None
            if isinstance(p, dict) and isinstance(pid_val, int):
                process_by_pid[pid_val] = p

        halluc = analyze_hallucination_taxonomy(suspicious, malicious, process_by_pid)

        snapshot_rows.append(
            {
                "snapshot": snapshot,
                "model": model,
                "provider": provider,
                "family": family,
                "category": category,
                **metrics,
                **halluc,
            }
        )

    # Aggregate by model + family.
    by_model_family: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    by_model: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in snapshot_rows:
        by_model_family[f"{r['model']}::{r['family']}"].append(r)
        by_model[r["model"]].append(r)

    family_summary: List[Dict[str, Any]] = []
    for key, rows in by_model_family.items():
        model, family = key.split("::", 1)
        family_summary.append(
            {
                "model": model,
                "family": family,
                "samples": len(rows),
                "accuracy": _avg(rows, "accuracy"),
                "precision": _avg(rows, "precision"),
                "recall": _avg(rows, "recall"),
                "f1": _avg(rows, "f1"),
                "triage_efficiency": _avg(rows, "triage_efficiency"),
                "hallucination_rate": _avg(rows, "hallucination_rate"),
                "type_name_count": sum(int(x.get("type_name_count", 0)) for x in rows),
                "type_relationship_count": sum(int(x.get("type_relationship_count", 0)) for x in rows),
                "type_cascade_count": sum(int(x.get("type_cascade_count", 0)) for x in rows),
            }
        )

    overall_summary: List[Dict[str, Any]] = []
    for model, rows in by_model.items():
        overall_summary.append(
            {
                "model": model,
                "samples": len(rows),
                "accuracy": _avg(rows, "accuracy"),
                "precision": _avg(rows, "precision"),
                "recall": _avg(rows, "recall"),
                "f1": _avg(rows, "f1"),
                "triage_efficiency": _avg(rows, "triage_efficiency"),
                "hallucination_rate": _avg(rows, "hallucination_rate"),
            }
        )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    snapshot_csv = out_dir / "snapshot_metrics.csv"
    family_csv = out_dir / "family_summary.csv"
    overall_csv = out_dir / "overall_summary.csv"
    paper_csv = out_dir / "paper_style_table.csv"
    paper_md = out_dir / "paper_style_table.md"

    _write_csv(
        str(snapshot_csv),
        snapshot_rows,
        [
            "snapshot",
            "model",
            "provider",
            "family",
            "category",
            "tp",
            "fp",
            "fn",
            "tn",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "triage_efficiency",
            "fp_total",
            "type_name_count",
            "type_relationship_count",
            "type_cascade_count",
            "hallucination_rate",
        ],
    )
    _write_csv(
        str(family_csv),
        family_summary,
        [
            "model",
            "family",
            "samples",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "triage_efficiency",
            "hallucination_rate",
            "type_name_count",
            "type_relationship_count",
            "type_cascade_count",
        ],
    )
    _write_csv(
        str(overall_csv),
        overall_summary,
        [
            "model",
            "samples",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "triage_efficiency",
            "hallucination_rate",
        ],
    )

    selected_model = args.paper_model.strip() if args.paper_model else (overall_summary[0]["model"] if overall_summary else "")
    paper_rows = [r for r in family_summary if r.get("model") == selected_model]
    _write_csv(
        str(paper_csv),
        paper_rows,
        ["family", "samples", "accuracy", "precision", "recall", "f1", "triage_efficiency", "hallucination_rate"],
    )

    md_lines = [
        f"# Paper-style Family Benchmark ({selected_model})",
        "",
        "| Family | Samples | Accuracy | Precision | Recall | F1 | Triage Efficiency | Hallucination Rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in paper_rows:
        md_lines.append(
            "| {family} | {samples} | {accuracy:.4f} | {precision:.4f} | {recall:.4f} | {f1:.4f} | {triage_efficiency:.4f} | {hallucination_rate:.4f} |".format(
                **r
            )
        )
    paper_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "snapshot_csv": str(snapshot_csv),
                "family_csv": str(family_csv),
                "overall_csv": str(overall_csv),
                "paper_csv": str(paper_csv),
                "paper_md": str(paper_md),
                "rows": len(snapshot_rows),
            },
            ensure_ascii=True,
            indent=2,
        )
    )