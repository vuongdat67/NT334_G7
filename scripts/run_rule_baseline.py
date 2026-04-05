import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.baselines.rule import run_rule_baseline
from src.cli.help_format import build_standard_parser
from src.config.loader import load_json
from src.forensics.volatility import VolatilityRunner


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _safe_div(a: float, b: float) -> float:
    if b == 0:
        return 0.0
    return a / b


def _evaluate(pred: Set[int], all_pids: Set[int], malicious: Set[int]) -> Dict[str, float]:
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


def _family_candidates(family: str, gt_cfg: Dict[str, Any]) -> List[str]:
    fam_map = gt_cfg.get("family_process_names", {})
    if family in fam_map:
        return list(fam_map[family])
    lower_map = {k.lower(): v for k, v in fam_map.items()}
    return list(lower_map.get(family.lower(), gt_cfg.get("default_candidates", [])))


if __name__ == "__main__":
    parser = build_standard_parser(
        prog="run_rule_baseline.py",
        description="Run deterministic rule baseline and export snapshot/family metrics.",
        examples=[
            "python scripts/run_rule_baseline.py --config config/config.json --manifest results/snapshot_manifest.json --labels-dir results/labels",
        ],
    )
    parser.add_argument("--config", default="config/config.json")
    parser.add_argument("--manifest", default="results/snapshot_manifest.json")
    parser.add_argument("--labels-dir", default="results/labels")
    parser.add_argument("--ground-truth-config", default="config/ground_truth_process_names.json")
    parser.add_argument("--category", default="all", choices=["all", "benign", "ransomware", "benign-tool", "unknown"])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out-dir", default="results/baseline_rule")
    args = parser.parse_args()

    cfg = load_json(args.config)
    manifest = _read_json(args.manifest)
    gt_cfg = _read_json(args.ground_truth_config)

    selected = []
    for row in manifest:
        cat = str(row.get("category", "unknown"))
        if args.category != "all" and cat != args.category:
            continue
        selected.append(row)
    if args.limit > 0:
        selected = selected[: args.limit]

    vol = VolatilityRunner(
        cfg["volatility_script_path"],
        plugin_timeout_seconds=cfg.get("volatility_plugin_timeout_seconds"),
    )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for row in selected:
        snapshot = str(row.get("file_name"))
        snapshot_stem = Path(snapshot).stem
        dump_path = str(row.get("file_path"))
        family = str(row.get("executable", "Unknown"))
        label_path = Path(args.labels_dir) / f"{snapshot_stem}.labels.json"

        if not label_path.exists():
            continue

        try:
            artifacts = vol.collect(dump_path, ["windows.pslist", "windows.vadinfo", "windows.malfind"])
            report = run_rule_baseline(artifacts, _family_candidates(family, gt_cfg))
            report_path = out_dir / f"{snapshot_stem}.report.json"
            report_path.write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding="utf-8")

            labels = _read_json(str(label_path))
            pred = {x.get("pid") for x in report.get("suspicious_processes", []) if isinstance(x.get("pid"), int)}
            all_pids = set(int(x) for x in labels.get("all_pids", []) if isinstance(x, int))
            malicious = set(int(x) for x in labels.get("malicious_pids", []) if isinstance(x, int))
            metrics = _evaluate(pred, all_pids, malicious)

            rows.append(
                {
                    "snapshot": snapshot,
                    "family": family,
                    "category": row.get("category", "unknown"),
                    **metrics,
                    "report_path": str(report_path),
                }
            )
        except Exception as e:  # noqa: BLE001
            rows.append(
                {
                    "snapshot": snapshot,
                    "family": family,
                    "category": row.get("category", "unknown"),
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "tn": 0,
                    "accuracy": 0,
                    "precision": 0,
                    "recall": 0,
                    "f1": 0,
                    "triage_efficiency": 0,
                    "report_path": "",
                    "error": str(e),
                }
            )

    metrics_csv = out_dir / "baseline_snapshot_metrics.csv"
    with metrics_csv.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "snapshot",
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
            "report_path",
            "error",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Family summary for easy comparison in report.
    by_family: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_family.setdefault(str(r.get("family", "Unknown")), []).append(r)

    summary_rows = []
    for family, items in by_family.items():
        summary_rows.append(
            {
                "family": family,
                "samples": len(items),
                "accuracy": round(sum(float(x.get("accuracy", 0)) for x in items) / max(1, len(items)), 6),
                "precision": round(sum(float(x.get("precision", 0)) for x in items) / max(1, len(items)), 6),
                "recall": round(sum(float(x.get("recall", 0)) for x in items) / max(1, len(items)), 6),
                "f1": round(sum(float(x.get("f1", 0)) for x in items) / max(1, len(items)), 6),
                "triage_efficiency": round(sum(float(x.get("triage_efficiency", 0)) for x in items) / max(1, len(items)), 6),
            }
        )

    summary_csv = out_dir / "baseline_family_summary.csv"
    with summary_csv.open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["family", "samples", "accuracy", "precision", "recall", "f1", "triage_efficiency"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

    print(
        json.dumps(
            {
                "rows": len(rows),
                "snapshot_csv": str(metrics_csv),
                "family_csv": str(summary_csv),
            },
            ensure_ascii=True,
            indent=2,
        )
    )