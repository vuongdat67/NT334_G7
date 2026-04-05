import argparse
import csv
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.baselines.rule import _extract_rows, _find_value, _looks_random_name, _to_int
from src.cli.help_format import build_standard_parser
from src.config.loader import load_json
from src.forensics.volatility import VolatilityRunner


SYSTEM_PROCESS_NAMES = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "winlogon.exe",
    "spoolsv.exe",
    "runtimebroker.exe",
    "taskhostw.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "ctfmon.exe",
}


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _safe_div(a: float, b: float) -> float:
    if b == 0:
        return 0.0
    return a / b


def _metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
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


def _infer_provider(model: str) -> str:
    if "/" in model:
        return model.split("/", 1)[0]
    return "xgboost"


def _build_manifest_index(manifest_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for r in manifest_rows:
        file_name = str(r.get("file_name", ""))
        idx[Path(file_name).stem] = r
    return idx


def _char_entropy(name: str) -> float:
    if not name:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for ch in name:
        counts[ch] += 1
    total = float(len(name))
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def _digit_ratio(name: str) -> float:
    if not name:
        return 0.0
    return sum(ch.isdigit() for ch in name) / max(1, len(name))


def _hex_ratio(name: str) -> float:
    if not name:
        return 0.0
    lowered = name.lower()
    return sum(ch in "0123456789abcdef" for ch in lowered) / max(1, len(lowered))


def _extract_process_rows(artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    ps_rows = _extract_rows(artifacts.get("windows.pslist"))
    vad_rows = _extract_rows(artifacts.get("windows.vadinfo"))
    mal_rows = _extract_rows(artifacts.get("windows.malfind"))

    pid_info: Dict[int, Dict[str, Any]] = {}
    rwx_count: Dict[int, int] = defaultdict(int)
    malfind_hits: Dict[int, int] = defaultdict(int)
    malfind_mz_hits: Dict[int, int] = defaultdict(int)
    malfind_shellcode_hits: Dict[int, int] = defaultdict(int)
    child_count: Dict[int, int] = defaultdict(int)

    for row in ps_rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        if pid is None:
            continue

        ppid = _to_int(_find_value(row, ["ppid", "parentpid", "inheritedfrompid"]))
        name = str(_find_value(row, ["imagefilename", "processname", "name", "imagename"]) or "").strip()
        threads = _to_int(_find_value(row, ["threads", "threadcount"]))

        pid_info[pid] = {
            "pid": pid,
            "ppid": ppid if ppid is not None else -1,
            "process_name": name,
            "threads": threads if threads is not None else 0,
        }

    for pid, info in pid_info.items():
        parent_pid = info.get("ppid", -1)
        if isinstance(parent_pid, int) and parent_pid >= 0:
            child_count[parent_pid] += 1

    for row in vad_rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        if pid is None:
            continue
        prot = str(_find_value(row, ["protection", "protectionstring", "protect"]) or "").lower()
        if "execute" in prot and "write" in prot:
            rwx_count[pid] += 1

    for row in mal_rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        if pid is None:
            continue

        blob = " ".join(str(v) for v in row.values()).lower()
        malfind_hits[pid] += 1
        if "mz" in blob:
            malfind_mz_hits[pid] += 1
        if any(k in blob for k in ["shellcode", "pushad", "jmp", "call", "xor"]):
            malfind_shellcode_hits[pid] += 1

    rows: List[Dict[str, Any]] = []
    for pid, info in pid_info.items():
        raw_name = str(info.get("process_name", ""))
        name = raw_name.lower().strip()
        parent_pid = int(info.get("ppid", -1))
        parent_name = ""
        if parent_pid in pid_info:
            parent_name = str(pid_info[parent_pid].get("process_name", "")).lower().strip()

        rows.append(
            {
                "pid": pid,
                "ppid": parent_pid,
                "process_name": raw_name,
                "name_len": float(len(name)),
                "digit_ratio": float(_digit_ratio(name)),
                "hex_ratio": float(_hex_ratio(name)),
                "name_entropy": float(_char_entropy(name)),
                "has_exe_suffix": 1.0 if name.endswith(".exe") else 0.0,
                "looks_random_name": 1.0 if _looks_random_name(raw_name) else 0.0,
                "is_system_name": 1.0 if name in SYSTEM_PROCESS_NAMES else 0.0,
                "threads": float(info.get("threads", 0) or 0),
                "child_count": float(child_count.get(pid, 0)),
                "parent_is_system": 1.0 if parent_name in SYSTEM_PROCESS_NAMES else 0.0,
                "has_rwx_vad": 1.0 if rwx_count.get(pid, 0) > 0 else 0.0,
                "rwx_vad_count": float(rwx_count.get(pid, 0)),
                "has_malfind": 1.0 if malfind_hits.get(pid, 0) > 0 else 0.0,
                "malfind_count": float(malfind_hits.get(pid, 0)),
                "malfind_mz_count": float(malfind_mz_hits.get(pid, 0)),
                "malfind_shellcode_count": float(malfind_shellcode_hits.get(pid, 0)),
            }
        )

    rows.sort(key=lambda x: int(x["pid"]))
    return rows


def _select_manifest_rows(manifest: List[Dict[str, Any]], category: str, limit: int) -> List[Dict[str, Any]]:
    rows = []
    for row in manifest:
        cat = str(row.get("category", "unknown"))
        if category != "all" and category != cat:
            continue
        rows.append(row)
    if limit > 0:
        rows = rows[:limit]
    return rows


def _write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _as_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if hasattr(value, "item"):
        return float(value.item())
    return float(value)


def _choose_threshold(y_true: List[int], y_prob: List[float], min_recall_target: float) -> float:
    candidates = [x / 100 for x in range(15, 91, 2)]
    best_score: Tuple[float, float, float] = (-1.0, -1.0, -1.0)
    best_threshold = 0.5

    for t in candidates:
        y_pred = [1 if p >= t else 0 for p in y_prob]
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true,
            y_pred,
            average="binary",
            zero_division=0,
        )
        precision_f = _as_float(precision)
        recall_f = _as_float(recall)
        f1_f = _as_float(f1)

        recall_ok = 1.0 if recall_f >= min_recall_target else 0.0
        score = (recall_ok, f1_f, recall_f)
        if score > best_score:
            best_score = score
            best_threshold = t

    return round(best_threshold, 4)


def _family_summary(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_family: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_family[str(r.get("family", "Unknown"))].append(r)

    summary = []
    for family, fr in sorted(by_family.items(), key=lambda x: x[0]):
        y_true = [int(x.get("label", 0)) for x in fr]
        y_pred = [int(x.get("predicted", 0)) for x in fr]
        m = _metrics(y_true, y_pred)
        summary.append(
            {
                "family": family,
                "samples": len(fr),
                **m,
            }
        )
    return summary


def _paper_markdown(path: Path, rows: List[Dict[str, Any]], title: str) -> None:
    lines = [
        f"# {title}",
        "",
        "| Family | Samples | Accuracy | Precision | Recall | F1 | Triage Efficiency |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            "| {family} | {samples} | {accuracy:.4f} | {precision:.4f} | {recall:.4f} | {f1:.4f} | {triage_efficiency:.4f} |".format(
                **r
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = build_standard_parser(
        prog="run_xgboost_baseline.py",
        description="Train and evaluate XGBoost process-level baseline from Volatility artifacts and labels.",
        examples=[
            "python scripts/run_xgboost_baseline.py --config config/config.json --manifest results/snapshot_manifest.json --labels-dir results/labels --category all",
        ],
    )
    parser.add_argument("--config", default="config/config.json")
    parser.add_argument("--manifest", default="results/snapshot_manifest.json")
    parser.add_argument("--labels-dir", default="results/labels")
    parser.add_argument("--category", default="all", choices=["all", "benign", "ransomware", "benign-tool", "unknown"])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--min-recall-target", type=float, default=0.6)
    parser.add_argument("--threshold", type=float, default=-1.0)
    parser.add_argument("--out-dir", default="results/baseline_xgboost")
    args = parser.parse_args()

    random.seed(args.random_state)

    cfg = load_json(args.config)
    manifest_rows = _read_json(args.manifest)
    manifest_idx = _build_manifest_index(manifest_rows)
    selected = _select_manifest_rows(manifest_rows, args.category, args.limit)

    if len(selected) == 0:
        raise ValueError("No snapshot rows selected. Check --category and --limit.")

    plugins = cfg.get("volatility_plugins") or [
        "windows.pslist",
        "windows.vadinfo",
        "windows.malfind",
    ]

    volatility = VolatilityRunner(
        cfg["volatility_script_path"],
        plugin_timeout_seconds=cfg.get("volatility_plugin_timeout_seconds"),
    )

    feature_rows: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []

    for row in selected:
        file_name = str(row.get("file_name", ""))
        snapshot = Path(file_name).stem
        memory_path = str(row.get("file_path", ""))
        category = str(row.get("category", "unknown"))
        family = str(row.get("executable", "Unknown"))

        label_path = Path(args.labels_dir) / f"{snapshot}.labels.json"
        if not label_path.exists():
            skipped.append({"snapshot": snapshot, "reason": "missing_label"})
            continue

        label_data = _read_json(str(label_path))
        all_pids = set(int(x) for x in label_data.get("all_pids", []) if isinstance(x, int))
        malicious = set(int(x) for x in label_data.get("malicious_pids", []) if isinstance(x, int))

        try:
            artifacts = volatility.collect(memory_path, plugins)
        except Exception as e:  # noqa: BLE001
            skipped.append({"snapshot": snapshot, "reason": f"volatility_error:{e}"})
            continue

        proc_rows = _extract_process_rows(artifacts)
        for p in proc_rows:
            pid = int(p["pid"])
            if all_pids and pid not in all_pids:
                continue
            feature_rows.append(
                {
                    "snapshot": snapshot,
                    "file_name": file_name,
                    "family": family,
                    "category": category,
                    "label": 1 if pid in malicious else 0,
                    **p,
                }
            )

    if len(feature_rows) == 0:
        raise ValueError("No feature rows collected. Check labels and volatility configuration.")

    df = pd.DataFrame(feature_rows)

    feature_cols = [
        "name_len",
        "digit_ratio",
        "hex_ratio",
        "name_entropy",
        "has_exe_suffix",
        "looks_random_name",
        "is_system_name",
        "threads",
        "child_count",
        "parent_is_system",
        "has_rwx_vad",
        "rwx_vad_count",
        "has_malfind",
        "malfind_count",
        "malfind_mz_count",
        "malfind_shellcode_count",
    ]

    for c in feature_cols:
        if c not in df.columns:
            df[c] = 0.0

    y = df["label"].astype(int)
    if y.nunique() < 2:
        raise ValueError("Need at least two classes in labels to train XGBoost baseline.")

    X = df[feature_cols].astype(float)

    test_size = float(args.test_size)
    if test_size <= 0 or test_size >= 1:
        raise ValueError("--test-size must be in (0, 1)")

    try:
        X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
            X,
            y,
            df.index,
            test_size=test_size,
            random_state=args.random_state,
            stratify=y,
        )
    except ValueError:
        X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
            X,
            y,
            df.index,
            test_size=test_size,
            random_state=args.random_state,
            stratify=None,
        )

    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    scale_pos_weight = (neg / pos) if pos > 0 else 1.0

    model = XGBClassifier(
        n_estimators=350,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        random_state=args.random_state,
    )
    model.fit(X_train, y_train)

    train_prob = model.predict_proba(X_train)[:, 1].tolist()
    chosen_threshold = args.threshold if args.threshold >= 0 else _choose_threshold(
        y_train.astype(int).tolist(),
        train_prob,
        min_recall_target=float(args.min_recall_target),
    )

    test_prob = model.predict_proba(X_test)[:, 1].tolist()
    y_pred = [1 if p >= chosen_threshold else 0 for p in test_prob]
    overall = _metrics(y_test.astype(int).tolist(), y_pred)

    pred_df = df.loc[idx_test].copy().reset_index(drop=True)
    pred_df["score"] = test_prob
    pred_df["predicted"] = y_pred

    family_rows = _family_summary(pred_df.to_dict(orient="records"))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    features_csv = out_dir / "xgb_process_features.csv"
    preds_csv = out_dir / "xgb_process_predictions.csv"
    family_csv = out_dir / "xgb_family_summary.csv"
    overall_json = out_dir / "xgb_overall_summary.json"
    split_json = out_dir / "xgb_split_info.json"
    importance_csv = out_dir / "xgb_feature_importance.csv"
    paper_md = out_dir / "xgb_paper_style_table.md"

    df.to_csv(features_csv, index=False, encoding="utf-8")
    pred_df.to_csv(preds_csv, index=False, encoding="utf-8")

    _write_csv(
        family_csv,
        family_rows,
        ["family", "samples", "tp", "fp", "fn", "tn", "accuracy", "precision", "recall", "f1", "triage_efficiency"],
    )

    overall_payload = {
        "model": "xgboost-baseline",
        "provider": _infer_provider("xgboost-baseline"),
        "threshold": chosen_threshold,
        "samples_total": int(len(df)),
        "samples_train": int(len(X_train)),
        "samples_test": int(len(X_test)),
        "positive_train": pos,
        "negative_train": neg,
        **overall,
    }
    overall_json.write_text(json.dumps(overall_payload, ensure_ascii=True, indent=2), encoding="utf-8")

    split_payload = {
        "random_state": args.random_state,
        "test_size": test_size,
        "threshold": chosen_threshold,
        "selected_snapshots": sorted(set(str(x) for x in df["snapshot"].tolist())),
        "skipped_snapshots": skipped,
        "feature_columns": feature_cols,
    }
    split_json.write_text(json.dumps(split_payload, ensure_ascii=True, indent=2), encoding="utf-8")

    importance_rows = []
    importances = model.feature_importances_.tolist()
    for name, score in sorted(zip(feature_cols, importances), key=lambda x: -x[1]):
        importance_rows.append({"feature": name, "importance": round(float(score), 8)})

    _write_csv(importance_csv, importance_rows, ["feature", "importance"])
    _paper_markdown(paper_md, family_rows, "XGBoost Baseline Family Benchmark")

    print(
        json.dumps(
            {
                "features_csv": str(features_csv),
                "predictions_csv": str(preds_csv),
                "family_csv": str(family_csv),
                "overall_json": str(overall_json),
                "split_json": str(split_json),
                "importance_csv": str(importance_csv),
                "paper_md": str(paper_md),
                "threshold": chosen_threshold,
                "rows_total": int(len(df)),
                "rows_test": int(len(X_test)),
                "skipped_snapshots": skipped,
            },
            ensure_ascii=True,
            indent=2,
        )
    )
