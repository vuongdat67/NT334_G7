import argparse
import csv
import json
import os
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser
from src.config.loader import load_json
from src.pipeline.runner import run_pipeline_config


def _safe_slug(text: str) -> str:
    return (
        text.replace("/", "_")
        .replace(":", "_")
        .replace(" ", "_")
        .replace("-", "_")
        .lower()
    )


def _infer_provider(model: str) -> str:
    if "/" in model:
        return model.split("/", 1)[0]
    return "unknown"


def _pick_error(votes: List[Dict[str, Any]]) -> str:
    parse_error = any(bool(v.get("parse_error")) for v in votes if isinstance(v, dict))
    api_errors = [str(v.get("api_error")) for v in votes if isinstance(v, dict) and v.get("api_error")]

    parts = []
    if parse_error:
        parts.append("parse_error")
    if api_errors:
        parts.append("api_error:" + api_errors[0])

    return " | ".join(parts)


def _write_tracker_csv(rows: List[Dict[str, Any]], out_csv: str) -> None:
    path = Path(out_csv)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "snapshot",
        "model",
        "provider",
        "suspicious_count",
        "dropped_by_post_filter",
        "runtime_seconds",
        "parse_error/api_error",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k) for k in fieldnames})


def _write_model_summary(rows: List[Dict[str, Any]], profiles: List[Dict[str, Any]], out_csv: str) -> None:
    by_model: Dict[str, Dict[str, Any]] = {}
    token_map = {p.get("model"): p.get("token_B") for p in profiles}

    for r in rows:
        model = str(r.get("model"))
        provider = str(r.get("provider"))
        runtime = float(r.get("runtime_seconds", 0) or 0)
        suspicious = int(r.get("suspicious_count", 0) or 0)
        dropped = int(r.get("dropped_by_post_filter", 0) or 0)
        has_error = bool(r.get("parse_error/api_error"))

        cur = by_model.setdefault(
            model,
            {
                "model": model,
                "provider": provider,
                "token_B": token_map.get(model),
                "runs": 0,
                "error_runs": 0,
                "avg_suspicious_count": 0.0,
                "avg_dropped_by_post_filter": 0.0,
                "avg_runtime_seconds": 0.0,
            },
        )

        cur["runs"] += 1
        cur["error_runs"] += 1 if has_error else 0
        cur["avg_suspicious_count"] += suspicious
        cur["avg_dropped_by_post_filter"] += dropped
        cur["avg_runtime_seconds"] += runtime

    summary_rows = []
    for _, cur in by_model.items():
        runs = max(1, int(cur["runs"]))
        cur["avg_suspicious_count"] = round(cur["avg_suspicious_count"] / runs, 3)
        cur["avg_dropped_by_post_filter"] = round(cur["avg_dropped_by_post_filter"] / runs, 3)
        cur["avg_runtime_seconds"] = round(cur["avg_runtime_seconds"] / runs, 3)
        summary_rows.append(cur)

    path = Path(out_csv)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "model",
            "provider",
            "token_B",
            "runs",
            "error_runs",
            "avg_suspicious_count",
            "avg_dropped_by_post_filter",
            "avg_runtime_seconds",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)


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


def _category_counts(manifest: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in manifest:
        cat = str(row.get("category", "unknown"))
        counts[cat] = counts.get(cat, 0) + 1
    return counts


def _env_or_default(env_key: str, fallback: str) -> str:
    value = os.getenv(env_key)
    if value is None or value.strip() == "":
        return fallback
    return value.strip()


def _env_bool(env_key: str, fallback: bool) -> bool:
    value = os.getenv(env_key)
    if value is None:
        return fallback
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_profiles(profile_path: str) -> List[Dict[str, Any]]:
    path = Path(profile_path)
    if path.exists():
        profiles = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(profiles, list):
            raise ValueError("Model profiles file must be a JSON list")
        return profiles

    model_list = os.getenv("MODEL_LIST", "").strip()
    if model_list:
        profiles = []
        for model in model_list.split(","):
            model = model.strip()
            if not model:
                continue
            profiles.append(
                {
                    "model": model,
                    "provider": _infer_provider(model),
                    "token_B": None,
                    "enabled": True,
                }
            )
        if profiles:
            return profiles

    raise FileNotFoundError(
        f"Model profiles file not found: {profile_path}. "
        "Set MODEL_LIST in .env as a comma-separated fallback."
    )


if __name__ == "__main__":
    load_dotenv()

    parser = build_standard_parser(
        prog="run_model_comparison.py",
        description="Run multi-model comparison over a snapshot manifest and export tracker outputs.",
        examples=[
            "python scripts/run_model_comparison.py --base-config config/config.json --model-profiles config/model_profiles.json --manifest results/snapshot_manifest.json --category all",
        ],
    )
    parser.add_argument(
        "--base-config",
        default=_env_or_default("BASE_CONFIG_FILE", "config/config.json"),
        help="Base config JSON",
    )
    parser.add_argument(
        "--model-profiles",
        default=_env_or_default("MODEL_PROFILES_FILE", "config/model_profiles.json"),
        help="Model profiles JSON",
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
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=int(_env_or_default("SNAPSHOT_LIMIT", "0")),
        help="Max snapshots (0 = all)",
    )
    parser.add_argument(
        "--experiment-name",
        default=_env_or_default("EXPERIMENT_NAME", "default"),
        help="Experiment name used for output folder grouping",
    )
    parser.add_argument(
        "--results-root",
        default=_env_or_default("RESULTS_ROOT", "results/experiments"),
        help="Root directory for comparison outputs",
    )
    parser.add_argument(
        "--skip-model-on-error",
        action=argparse.BooleanOptionalAction,
        default=_env_bool("SKIP_MODEL_ON_ERROR", True),
        help=(
            "If enabled, once a model hits parse/API error on one snapshot, "
            "the model is skipped for remaining snapshots"
        ),
    )
    parser.add_argument("--out-csv", default="")
    parser.add_argument("--out-summary-csv", default="")
    parser.add_argument("--out-json", default="")
    args = parser.parse_args()

    base_cfg = load_json(args.base_config)
    all_profiles = _load_profiles(args.model_profiles)
    profiles = [p for p in all_profiles if bool(p.get("enabled", True))]
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))

    if len(profiles) == 0:
        print(
            json.dumps(
                {
                    "rows": 0,
                    "message": "No enabled models found",
                    "model_profiles": args.model_profiles,
                    "hint": "Set enabled=true in profile entries or provide MODEL_LIST in .env",
                },
                ensure_ascii=True,
                indent=2,
            )
        )
        sys.exit(0)

    selected_rows = _select_manifest_rows(manifest, args.category, args.limit)

    experiment_root = Path(args.results_root) / args.experiment_name
    runs_dir = experiment_root / "runs"
    tracker_dir = experiment_root / "tracker"
    runs_dir.mkdir(parents=True, exist_ok=True)
    tracker_dir.mkdir(parents=True, exist_ok=True)

    out_csv = args.out_csv or str(tracker_dir / "experiment_tracker.csv")
    out_summary_csv = args.out_summary_csv or str(tracker_dir / "model_comparison_summary.csv")
    out_json = args.out_json or str(tracker_dir / "experiment_tracker.json")

    counts = _category_counts(manifest)
    if len(selected_rows) == 0:
        print(
            json.dumps(
                {
                    "rows": 0,
                    "message": "No snapshots selected for this category filter",
                    "category": args.category,
                    "available_category_counts": counts,
                    "hint": "Run build_snapshot_manifest again and verify file names or category filter",
                },
                ensure_ascii=True,
                indent=2,
            )
        )
        sys.exit(0)

    tracker_rows: List[Dict[str, Any]] = []
    all_runs_meta: List[Dict[str, Any]] = []
    skipped_models: List[Dict[str, str]] = []

    for profile in profiles:
        model = str(profile.get("model"))
        provider = str(profile.get("provider") or _infer_provider(model))
        model_skipped = False
        skip_reason = ""
        skip_snapshot = ""

        for row in selected_rows:
            snapshot = str(row.get("file_name"))
            memory_path = str(row.get("file_path"))

            cfg = deepcopy(base_cfg)
            cfg["llm_model"] = model
            cfg["memory_dump_path"] = memory_path

            # Allow profile-level overrides for model-specific behavior.
            for key in [
                "llm_provider",
                "llm_reasoning_enabled",
                "llm_force_json_response_format",
                "llm_timeout_seconds",
                "llm_max_output_tokens",
                "temperature",
                "prompt_profile",
                "prompt_strategy",
                "ransomware_hint",
                "prompt_hallucination_check",
                "prompt_recall_boost",
            ]:
                if key in profile:
                    cfg[key] = profile[key]

            model_slug = _safe_slug(model)
            snapshot_slug = _safe_slug(snapshot)
            run_dir = runs_dir / model_slug / snapshot_slug
            cfg["output_report_path"] = str(run_dir / "report.json")
            cfg["output_votes_path"] = str(run_dir / "votes.json")
            cfg["output_artifacts_path"] = str(run_dir / "artifacts.json")

            started = time.perf_counter()
            run_error = ""
            suspicious_count = 0
            dropped_count = 0
            parse_or_api = ""

            try:
                report = run_pipeline_config(cfg)
                suspicious_count = len(report.get("suspicious_processes", []))
                dropped_count = int(report.get("post_filter", {}).get("dropped_count", 0))

                votes_path = Path(cfg["output_votes_path"])
                if votes_path.exists():
                    votes = json.loads(votes_path.read_text(encoding="utf-8"))
                    if isinstance(votes, list):
                        parse_or_api = _pick_error(votes)
            except Exception as e:  # noqa: BLE001
                run_error = str(e)
                parse_or_api = f"api_error:{run_error}"

            runtime_seconds = round(time.perf_counter() - started, 3)

            tracker_row = {
                "snapshot": snapshot,
                "model": model,
                "provider": provider,
                "suspicious_count": suspicious_count,
                "dropped_by_post_filter": dropped_count,
                "runtime_seconds": runtime_seconds,
                "parse_error/api_error": parse_or_api,
            }
            tracker_rows.append(tracker_row)

            all_runs_meta.append(
                {
                    "snapshot": snapshot,
                    "memory_dump_path": memory_path,
                    "model": model,
                    "provider": provider,
                    "token_B": profile.get("token_B"),
                    "runtime_seconds": runtime_seconds,
                    "error": run_error,
                    "report_path": cfg["output_report_path"],
                    "votes_path": cfg["output_votes_path"],
                    "artifacts_path": cfg["output_artifacts_path"],
                }
            )

            if args.skip_model_on_error and parse_or_api:
                model_skipped = True
                skip_reason = parse_or_api
                skip_snapshot = snapshot
                break

        if model_skipped:
            skipped_models.append(
                {
                    "model": model,
                    "provider": provider,
                    "snapshot": skip_snapshot,
                    "reason": skip_reason,
                }
            )

    _write_tracker_csv(tracker_rows, out_csv)
    _write_model_summary(tracker_rows, profiles, out_summary_csv)

    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(out_json).write_text(
        json.dumps(all_runs_meta, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "rows": len(tracker_rows),
                "tracker_csv": out_csv,
                "summary_csv": out_summary_csv,
                "meta_json": out_json,
                "experiment_root": str(experiment_root),
                "skip_model_on_error": bool(args.skip_model_on_error),
                "skipped_models": skipped_models,
            },
            ensure_ascii=True,
            indent=2,
        )
    )
