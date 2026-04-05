import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser


METHOD_ORDER = {
    "LLM": 0,
    "Rule": 1,
    "XGBoost": 2,
}


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _read_csv(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"CSV not found: {path}")
    with p.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader]


def _read_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"JSON not found: {path}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def _pick_llm_model(overall_rows: List[Dict[str, Any]], model_hint: str) -> str:
    if model_hint:
        models = {str(r.get("model", "")).strip() for r in overall_rows}
        if model_hint not in models:
            raise ValueError(
                f"Requested --llm-model '{model_hint}' not found in LLM overall summary. "
                f"Available: {sorted(m for m in models if m)}"
            )
        return model_hint

    if not overall_rows:
        raise ValueError("LLM overall summary is empty")

    def _key(r: Dict[str, Any]) -> Tuple[int, float, float]:
        return (
            _to_int(r.get("samples"), 0),
            _to_float(r.get("f1"), 0.0),
            _to_float(r.get("accuracy"), 0.0),
        )

    best = max(overall_rows, key=_key)
    model = str(best.get("model", "")).strip()
    if not model:
        raise ValueError("Cannot infer LLM model from overall summary")
    return model


def _compute_rule_overall(snapshot_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = sum(_to_int(r.get("tp"), 0) for r in snapshot_rows)
    fp = sum(_to_int(r.get("fp"), 0) for r in snapshot_rows)
    fn = sum(_to_int(r.get("fn"), 0) for r in snapshot_rows)
    tn = sum(_to_int(r.get("tn"), 0) for r in snapshot_rows)

    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    triage_efficiency = (tp + fp) / total if total else 0.0

    return {
        "method": "Rule",
        "model": "rule_v1",
        "samples": len(snapshot_rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "triage_efficiency": triage_efficiency,
        "hallucination_rate": "",
    }


def _write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _fmt(x: Any) -> str:
    if x == "":
        return ""
    try:
        return f"{float(x):.4f}"
    except (TypeError, ValueError):
        return str(x)


def _build_report_md(
    title: str,
    llm_model: str,
    overall_rows: List[Dict[str, Any]],
    family_long_rows: List[Dict[str, Any]],
) -> str:
    lines = [
        f"# {title}",
        "",
        f"Selected LLM model: {llm_model}",
        "",
        "## Overall Comparison",
        "",
        "| Method | Model | Samples | Accuracy | Precision | Recall | F1 | Triage Efficiency | Hallucination Rate |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for r in overall_rows:
        lines.append(
            "| {method} | {model} | {samples} | {accuracy} | {precision} | {recall} | {f1} | {triage_efficiency} | {hallucination_rate} |".format(
                method=r.get("method", ""),
                model=r.get("model", ""),
                samples=r.get("samples", ""),
                accuracy=_fmt(r.get("accuracy", "")),
                precision=_fmt(r.get("precision", "")),
                recall=_fmt(r.get("recall", "")),
                f1=_fmt(r.get("f1", "")),
                triage_efficiency=_fmt(r.get("triage_efficiency", "")),
                hallucination_rate=_fmt(r.get("hallucination_rate", "")),
            )
        )

    lines.extend(
        [
            "",
            "## Family-level Comparison",
            "",
            "| Family | Method | Model | Samples | Accuracy | Precision | Recall | F1 | Triage Efficiency |",
            "|---|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )

    for r in family_long_rows:
        lines.append(
            "| {family} | {method} | {model} | {samples} | {accuracy} | {precision} | {recall} | {f1} | {triage_efficiency} |".format(
                family=r.get("family", ""),
                method=r.get("method", ""),
                model=r.get("model", ""),
                samples=r.get("samples", ""),
                accuracy=_fmt(r.get("accuracy", "")),
                precision=_fmt(r.get("precision", "")),
                recall=_fmt(r.get("recall", "")),
                f1=_fmt(r.get("f1", "")),
                triage_efficiency=_fmt(r.get("triage_efficiency", "")),
            )
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- Rule overall is micro-aggregated from baseline snapshot metrics (sum TP/FP/FN/TN).",
            "- LLM rows are taken from family benchmark outputs for the selected model.",
            "- XGBoost overall is taken from xgb_overall_summary.json.",
        ]
    )

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = build_standard_parser(
        prog="export_final_comparison_table.py",
        description="Merge LLM, Rule baseline, and XGBoost metrics into final comparison outputs.",
        examples=[
            "python scripts/export_final_comparison_table.py --llm-model qwen/qwen3.6-plus:free --out-dir results/final_comparison/full_chain_current_data",
        ],
    )
    parser.add_argument("--llm-overall-csv", default="results/benchmark/full_chain_current_data/overall_summary.csv")
    parser.add_argument("--llm-family-csv", default="results/benchmark/full_chain_current_data/family_summary.csv")
    parser.add_argument("--llm-model", default="")

    parser.add_argument("--rule-snapshot-csv", default="results/baseline_rule/full_chain_current_data/baseline_snapshot_metrics.csv")
    parser.add_argument("--rule-family-csv", default="results/baseline_rule/full_chain_current_data/baseline_family_summary.csv")

    parser.add_argument("--xgb-overall-json", default="results/baseline_xgboost/full_chain_current_data/xgb_overall_summary.json")
    parser.add_argument("--xgb-family-csv", default="results/baseline_xgboost/full_chain_current_data/xgb_family_summary.csv")

    parser.add_argument("--out-dir", default="results/final_comparison/full_chain_current_data")
    parser.add_argument("--title", default="Final Comparison: LLM vs Rule vs XGBoost")
    args = parser.parse_args()

    llm_overall = _read_csv(args.llm_overall_csv)
    llm_family = _read_csv(args.llm_family_csv)
    rule_snapshot = _read_csv(args.rule_snapshot_csv)
    rule_family = _read_csv(args.rule_family_csv)
    xgb_overall = _read_json(args.xgb_overall_json)
    xgb_family = _read_csv(args.xgb_family_csv)

    selected_llm_model = _pick_llm_model(llm_overall, args.llm_model)

    llm_overall_row = None
    for r in llm_overall:
        if str(r.get("model", "")).strip() == selected_llm_model:
            llm_overall_row = r
            break
    if llm_overall_row is None:
        raise ValueError(f"Cannot find selected LLM model in overall summary: {selected_llm_model}")

    overall_rows = [
        {
            "method": "LLM",
            "model": selected_llm_model,
            "samples": _to_int(llm_overall_row.get("samples"), 0),
            "accuracy": _to_float(llm_overall_row.get("accuracy"), 0.0),
            "precision": _to_float(llm_overall_row.get("precision"), 0.0),
            "recall": _to_float(llm_overall_row.get("recall"), 0.0),
            "f1": _to_float(llm_overall_row.get("f1"), 0.0),
            "triage_efficiency": _to_float(llm_overall_row.get("triage_efficiency"), 0.0),
            "hallucination_rate": _to_float(llm_overall_row.get("hallucination_rate"), 0.0),
        },
        _compute_rule_overall(rule_snapshot),
        {
            "method": "XGBoost",
            "model": str(xgb_overall.get("model", "xgboost-baseline")),
            "samples": _to_int(xgb_overall.get("samples_test"), 0),
            "accuracy": _to_float(xgb_overall.get("accuracy"), 0.0),
            "precision": _to_float(xgb_overall.get("precision"), 0.0),
            "recall": _to_float(xgb_overall.get("recall"), 0.0),
            "f1": _to_float(xgb_overall.get("f1"), 0.0),
            "triage_efficiency": _to_float(xgb_overall.get("triage_efficiency"), 0.0),
            "hallucination_rate": "",
        },
    ]

    family_long_rows: List[Dict[str, Any]] = []

    for r in llm_family:
        model = str(r.get("model", "")).strip()
        if model != selected_llm_model:
            continue
        family_long_rows.append(
            {
                "family": str(r.get("family", "")),
                "method": "LLM",
                "model": selected_llm_model,
                "samples": _to_int(r.get("samples"), 0),
                "accuracy": _to_float(r.get("accuracy"), 0.0),
                "precision": _to_float(r.get("precision"), 0.0),
                "recall": _to_float(r.get("recall"), 0.0),
                "f1": _to_float(r.get("f1"), 0.0),
                "triage_efficiency": _to_float(r.get("triage_efficiency"), 0.0),
            }
        )

    for r in rule_family:
        family_long_rows.append(
            {
                "family": str(r.get("family", "")),
                "method": "Rule",
                "model": "rule_v1",
                "samples": _to_int(r.get("samples"), 0),
                "accuracy": _to_float(r.get("accuracy"), 0.0),
                "precision": _to_float(r.get("precision"), 0.0),
                "recall": _to_float(r.get("recall"), 0.0),
                "f1": _to_float(r.get("f1"), 0.0),
                "triage_efficiency": _to_float(r.get("triage_efficiency"), 0.0),
            }
        )

    for r in xgb_family:
        family_long_rows.append(
            {
                "family": str(r.get("family", "")),
                "method": "XGBoost",
                "model": str(xgb_overall.get("model", "xgboost-baseline")),
                "samples": _to_int(r.get("samples"), 0),
                "accuracy": _to_float(r.get("accuracy"), 0.0),
                "precision": _to_float(r.get("precision"), 0.0),
                "recall": _to_float(r.get("recall"), 0.0),
                "f1": _to_float(r.get("f1"), 0.0),
                "triage_efficiency": _to_float(r.get("triage_efficiency"), 0.0),
            }
        )

    family_long_rows.sort(
        key=lambda x: (
            str(x.get("family", "")),
            METHOD_ORDER.get(str(x.get("method", "")), 99),
        )
    )

    family_wide_map: Dict[str, Dict[str, Any]] = {}
    for row in family_long_rows:
        fam = str(row.get("family", ""))
        method = str(row.get("method", ""))
        key = method.lower()

        cur = family_wide_map.setdefault(fam, {"family": fam})
        cur[f"samples_{key}"] = row.get("samples", "")
        cur[f"accuracy_{key}"] = row.get("accuracy", "")
        cur[f"precision_{key}"] = row.get("precision", "")
        cur[f"recall_{key}"] = row.get("recall", "")
        cur[f"f1_{key}"] = row.get("f1", "")
        cur[f"triage_efficiency_{key}"] = row.get("triage_efficiency", "")

    family_wide_rows = sorted(family_wide_map.values(), key=lambda x: str(x.get("family", "")))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    overall_csv = out_dir / "final_overall_comparison.csv"
    family_long_csv = out_dir / "final_family_comparison_long.csv"
    family_wide_csv = out_dir / "final_family_comparison_wide.csv"
    report_md = out_dir / "final_comparison_report.md"
    meta_json = out_dir / "final_comparison_meta.json"

    _write_csv(
        overall_csv,
        overall_rows,
        [
            "method",
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

    _write_csv(
        family_long_csv,
        family_long_rows,
        [
            "family",
            "method",
            "model",
            "samples",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "triage_efficiency",
        ],
    )

    _write_csv(
        family_wide_csv,
        family_wide_rows,
        [
            "family",
            "samples_llm",
            "accuracy_llm",
            "precision_llm",
            "recall_llm",
            "f1_llm",
            "triage_efficiency_llm",
            "samples_rule",
            "accuracy_rule",
            "precision_rule",
            "recall_rule",
            "f1_rule",
            "triage_efficiency_rule",
            "samples_xgboost",
            "accuracy_xgboost",
            "precision_xgboost",
            "recall_xgboost",
            "f1_xgboost",
            "triage_efficiency_xgboost",
        ],
    )

    report_md.write_text(
        _build_report_md(
            title=args.title,
            llm_model=selected_llm_model,
            overall_rows=overall_rows,
            family_long_rows=family_long_rows,
        ),
        encoding="utf-8",
    )

    meta_json.write_text(
        json.dumps(
            {
                "selected_llm_model": selected_llm_model,
                "overall_rows": len(overall_rows),
                "family_rows": len(family_long_rows),
                "overall_csv": str(overall_csv),
                "family_long_csv": str(family_long_csv),
                "family_wide_csv": str(family_wide_csv),
                "report_md": str(report_md),
            },
            ensure_ascii=True,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "selected_llm_model": selected_llm_model,
                "overall_csv": str(overall_csv),
                "family_long_csv": str(family_long_csv),
                "family_wide_csv": str(family_wide_csv),
                "report_md": str(report_md),
                "meta_json": str(meta_json),
            },
            ensure_ascii=True,
            indent=2,
        )
    )
