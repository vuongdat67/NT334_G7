import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser
from src.evaluation.explanation_rubric import score_report_explanations
from src.evaluation.metrics import consistency_score, evaluate, evaluate_multi
from src.evaluation.significance import build_contingency, mcnemar_test


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _pid_set_from_report(path: Path) -> Set[int]:
    data = _read_json(path)
    items = data.get("suspicious_processes", []) if isinstance(data, dict) else []
    out: Set[int] = set()
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            pid = item.get("pid")
            if isinstance(pid, int):
                out.add(pid)
    return out


def _malicious_set_from_labels(path: Path) -> Set[int]:
    data = _read_json(path)
    pids = data.get("malicious_pids", []) if isinstance(data, dict) else []
    out: Set[int] = set()
    if isinstance(pids, list):
        for pid in pids:
            if isinstance(pid, int):
                out.add(pid)
    return out


def _collect_snapshot_entries(results_dir: Path, labels_dir: Path) -> Dict[str, Any]:
    report_files = sorted(results_dir.glob("*.report.json"))
    per_snapshot: List[Dict[str, Any]] = []
    family_results: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []

    for report_path in report_files:
        stem = report_path.name[: -len(".report.json")]
        labels_path = labels_dir / f"{stem}.labels.json"
        votes_path = results_dir / f"{stem}.votes.json"

        if not labels_path.exists():
            skipped.append(
                {
                    "snapshot": stem,
                    "reason": f"labels_not_found:{labels_path}",
                }
            )
            continue

        metrics = evaluate(str(report_path), str(labels_path))

        report_data = _read_json(report_path)
        suspicious_items = []
        if isinstance(report_data, dict):
            items = report_data.get("suspicious_processes", [])
            if isinstance(items, list):
                suspicious_items = items
        explanation = score_report_explanations(suspicious_items)

        consistency: Optional[Dict[str, Any]] = None
        if votes_path.exists():
            votes = _read_json(votes_path)
            if isinstance(votes, list):
                consistency = consistency_score(votes)

        labels_data = _read_json(labels_path)
        family = "unknown"
        if isinstance(labels_data, dict):
            family = str(labels_data.get("family", "unknown"))

        per_snapshot.append(
            {
                "snapshot": stem,
                "family": family,
                "report_path": str(report_path),
                "labels_path": str(labels_path),
                "votes_path": str(votes_path) if votes_path.exists() else "",
                "metrics": metrics,
                "consistency": consistency,
                "explanation": {
                    "mean_total": explanation.get("mean_total", 0.0),
                    "mean_accuracy": explanation.get("mean_accuracy", 0.0),
                    "mean_specificity": explanation.get("mean_specificity", 0.0),
                    "mean_actionability": explanation.get("mean_actionability", 0.0),
                    "band_distribution": explanation.get("band_distribution", {}),
                },
            }
        )

        family_results.append(
            {
                "family": family,
                "pred_report_path": str(report_path),
                "labels_path": str(labels_path),
            }
        )

    aggregated = evaluate_multi(family_results)

    consistency_values = [
        float(x["consistency"]["mean_agreement_rate"])
        for x in per_snapshot
        if isinstance(x.get("consistency"), dict)
    ]
    explanation_totals = [
        float(x["explanation"]["mean_total"])
        for x in per_snapshot
        if isinstance(x.get("explanation"), dict)
    ]

    overall = {
        "snapshot_count": len(per_snapshot),
        "mean_consistency_agreement": round(
            sum(consistency_values) / len(consistency_values), 6
        )
        if consistency_values
        else 0.0,
        "mean_explanation_total": round(
            sum(explanation_totals) / len(explanation_totals), 6
        )
        if explanation_totals
        else 0.0,
    }

    return {
        "results_dir": str(results_dir),
        "labels_dir": str(labels_dir),
        "overall": overall,
        "family_metrics": aggregated,
        "per_snapshot": per_snapshot,
        "skipped": skipped,
    }


def _build_mcnemar_section(
    baseline_dir: Path,
    candidate_dir: Path,
    labels_dir: Path,
) -> Dict[str, Any]:
    baseline_reports = {
        p.name[: -len(".report.json")]: p for p in baseline_dir.glob("*.report.json")
    }
    candidate_reports = {
        p.name[: -len(".report.json")]: p for p in candidate_dir.glob("*.report.json")
    }

    matched_stems = sorted(set(baseline_reports.keys()) & set(candidate_reports.keys()))

    preds_a: List[Set[int]] = []
    preds_b: List[Set[int]] = []
    malicious_sets: List[Set[int]] = []
    used: List[str] = []

    for stem in matched_stems:
        labels_path = labels_dir / f"{stem}.labels.json"
        if not labels_path.exists():
            continue
        preds_a.append(_pid_set_from_report(baseline_reports[stem]))
        preds_b.append(_pid_set_from_report(candidate_reports[stem]))
        malicious_sets.append(_malicious_set_from_labels(labels_path))
        used.append(stem)

    if not used:
        return {
            "matched_snapshots": 0,
            "used_snapshots": [],
            "mcnemar": None,
        }

    b, c = build_contingency(preds_a, preds_b, malicious_sets)
    result = mcnemar_test(b, c)
    return {
        "matched_snapshots": len(matched_stems),
        "used_snapshots": used,
        "mcnemar": result,
    }


def main() -> int:
    parser = build_standard_parser(
        prog="evaluate_extended.py",
        description=(
            "Extended evaluation on a results directory: per-snapshot metrics, "
            "family macro/micro metrics, vote consistency, explanation quality, "
            "and optional McNemar significance comparison."
        ),
        examples=[
            "python scripts/evaluate_extended.py --results-dir results/smoke_one_shot --out-json results/smoke_one_shot/evaluate_extended.json",
            "python scripts/evaluate_extended.py --results-dir results/model_a --compare-dir results/model_b --out-json results/compare_eval.json",
        ],
    )
    parser.add_argument(
        "--results-dir",
        required=True,
        help="Directory containing *.report.json and optional *.votes.json",
    )
    parser.add_argument(
        "--labels-dir",
        default="",
        help="Directory containing labels files; default: <results-dir>/labels",
    )
    parser.add_argument(
        "--compare-dir",
        default="",
        help="Optional second results dir for McNemar paired comparison",
    )
    parser.add_argument(
        "--out-json",
        required=True,
        help="Output JSON file path",
    )
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        raise FileNotFoundError(f"results-dir not found: {results_dir}")

    labels_dir = Path(args.labels_dir) if args.labels_dir else results_dir / "labels"
    if not labels_dir.exists():
        raise FileNotFoundError(f"labels-dir not found: {labels_dir}")

    payload = {
        "primary": _collect_snapshot_entries(results_dir, labels_dir),
    }

    if args.compare_dir:
        compare_dir = Path(args.compare_dir)
        if not compare_dir.exists():
            raise FileNotFoundError(f"compare-dir not found: {compare_dir}")
        payload["comparison"] = {
            "baseline_dir": str(results_dir),
            "candidate_dir": str(compare_dir),
            "labels_dir": str(labels_dir),
            "result": _build_mcnemar_section(results_dir, compare_dir, labels_dir),
        }

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
