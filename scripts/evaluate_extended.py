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


def _snapshot_stem(report_path: Path) -> str:
    if report_path.name == "report.json":
        return report_path.parent.name
    if report_path.name.endswith(".report.json"):
        return report_path.name[: -len(".report.json")]
    return report_path.stem


def _collect_report_files(results_dir: Path) -> List[Path]:
    report_files = set(results_dir.rglob("report.json"))
    report_files.update(results_dir.rglob("*.report.json"))
    return sorted(report_files)


def _collect_snapshot_entries(results_dir: Path, snapshot_to_family: Dict[str, str], gt_cfg_path: str) -> Dict[str, Any]:
    report_files = _collect_report_files(results_dir)
    per_snapshot: List[Dict[str, Any]] = []
    family_results: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []

    for report_path in report_files:
        stem = _snapshot_stem(report_path)

        if report_path.name == "report.json":
            artifacts_path = report_path.parent / "artifacts.json"
            votes_path = report_path.parent / "votes.json"
        else:
            artifacts_path = report_path.parent / f"{stem}.artifacts.json"
            votes_path = report_path.parent / f"{stem}.votes.json"

        labels_path = results_dir / "labels" / f"{stem}.labels.json"
        if not labels_path.exists():
            labels_path = report_path.parent / "labels" / f"{stem}.labels.json"

        # Get family from manifest or default to unknown
        family = snapshot_to_family.get(stem.lower(), "unknown")
        if family == "unknown" and labels_path.exists():
            label_data = _read_json(labels_path)
            family = str(label_data.get("family", family)) if isinstance(label_data, dict) else family

        if artifacts_path.exists():
            metrics = evaluate(str(report_path), str(artifacts_path), family, gt_cfg_path)
        elif labels_path.exists():
            metrics = evaluate(str(report_path), str(labels_path))
        else:
            skipped.append(
                {
                    "snapshot": stem,
                    "reason": f"artifacts_or_labels_not_found:{artifacts_path}",
                }
            )
            continue

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

        per_snapshot.append(
            {
                "snapshot": stem,
                "family": family,
                "report_path": str(report_path),
                "artifacts_path": str(artifacts_path),
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

        family_entry = {
            "family": family,
            "pred_report_path": str(report_path),
        }
        if artifacts_path.exists():
            family_entry["artifacts_path"] = str(artifacts_path)
        elif labels_path.exists():
            family_entry["labels_path"] = str(labels_path)
        family_results.append(family_entry)

    aggregated = evaluate_multi(family_results, gt_cfg_path)

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
        "overall": overall,
        "family_metrics": aggregated,
        "per_snapshot": per_snapshot,
        "skipped": skipped,
    }


def _build_mcnemar_section(
    baseline_dir: Path,
    candidate_dir: Path,
    snapshot_to_family: Dict[str, str],
    gt_cfg_path: str,
) -> Dict[str, Any]:
    baseline_reports = { _snapshot_stem(p): p for p in _collect_report_files(baseline_dir) }
    candidate_reports = { _snapshot_stem(p): p for p in _collect_report_files(candidate_dir) }

    matched_stems = sorted(set(baseline_reports.keys()) & set(candidate_reports.keys()))

    preds_a: List[Set[int]] = []
    preds_b: List[Set[int]] = []
    malicious_sets: List[Set[int]] = []
    used: List[str] = []

    # Import label helpers locally
    from src.evaluation.metrics import _labels_from_artifacts, _labels_from_labels_path

    for stem in matched_stems:
        if baseline_reports[stem].name == "report.json":
            artifacts_path = baseline_dir / stem / "artifacts.json"
        else:
            artifacts_path = baseline_reports[stem].parent / f"{stem}.artifacts.json"

        labels_path = baseline_dir / "labels" / f"{stem}.labels.json"
        if not labels_path.exists():
            labels_path = baseline_reports[stem].parent / "labels" / f"{stem}.labels.json"

        family = snapshot_to_family.get(stem.lower(), "unknown")

        if artifacts_path.exists():
            _, malicious = _labels_from_artifacts(str(artifacts_path), family, gt_cfg_path)
        elif labels_path.exists():
            _, malicious = _labels_from_labels_path(str(labels_path))
        else:
            continue
        
        preds_a.append(_pid_set_from_report(baseline_reports[stem]))
        preds_b.append(_pid_set_from_report(candidate_reports[stem]))
        malicious_sets.append(malicious)
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
        help="Directory containing *.report.json, *.artifacts.json, and optional *.votes.json",
    )
    parser.add_argument(
        "--gt-cfg",
        default="config/ground_truth_process_names.json",
        help="Path to ground truth signatures JSON",
    )
    parser.add_argument(
        "--manifest",
        default="results/snapshot_manifest.json",
        help="Path to snapshot manifest JSON to resolve families",
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

    gt_cfg_path = args.gt_cfg
    if not Path(gt_cfg_path).exists():
        raise FileNotFoundError(f"gt-cfg not found: {gt_cfg_path}")

    # Load manifest to get family mapping
    manifest_path = Path(args.manifest)
    snapshot_to_family = {}
    if manifest_path.exists():
        manifest = _read_json(manifest_path)
        for row in manifest:
            name = str(row.get("file_name", "")).lower()
            snapshot_to_family[name] = str(row.get("family", "unknown"))

    payload = {
        "primary": _collect_snapshot_entries(results_dir, snapshot_to_family, gt_cfg_path),
    }

    if args.compare_dir:
        compare_dir = Path(args.compare_dir)
        if not compare_dir.exists():
            raise FileNotFoundError(f"compare-dir not found: {compare_dir}")
        payload["comparison"] = {
            "baseline_dir": str(results_dir),
            "candidate_dir": str(compare_dir),
            "result": _build_mcnemar_section(results_dir, compare_dir, snapshot_to_family, gt_cfg_path),
        }

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
