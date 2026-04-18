import argparse
import math
import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cli.help_format import build_standard_parser
from src.config.loader import load_json
from src.data.manifest import build_manifest, write_manifest_csv, write_manifest_json
from src.evaluation.metrics import evaluate
from src.forensics.volatility import VolatilityRunner
from src.labels.intersection import build_label_from_intersection, write_label_file
from src.pipeline.runner import attach_hidden_process_diff, run_pipeline_config
from src.prompts.builder import build_prompt


def _read_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _family_candidates(
    snapshot_row: Dict[str, Any],
    family_to_processes: Dict[str, List[str]],
    default_candidates: List[str],
) -> List[str]:
    family = str(snapshot_row.get("executable", "Unknown")).strip()
    if family in family_to_processes:
        return list(family_to_processes[family])
    lower_map = {k.lower(): v for k, v in family_to_processes.items()}
    return list(lower_map.get(family.lower(), default_candidates))


def _env_or_default(env_key: str, fallback: str) -> str:
    value = os.getenv(env_key)
    if value is None or value.strip() == "":
        return fallback
    return value.strip()


def _artifact_clean_flags(artifacts: Dict[str, Any]) -> Dict[str, bool]:
    flags: Dict[str, bool] = {}
    for plugin, data in artifacts.items():
        bad = False
        if isinstance(data, dict):
            bad = bool("raw_output" in data or data.get("parse_error"))
        flags[plugin] = not bad
    return flags


def _estimate_tokens(text: str, chars_per_token: float) -> int:
    safe = max(1.0, float(chars_per_token))
    return int(math.ceil(len(text) / safe))


def _build_prompt_for_cfg(
    cfg: Dict[str, Any],
    prompt_template: str,
    decision_rules: Dict[str, Any],
    artifacts: Dict[str, Any],
) -> str:
    return build_prompt(
        prompt_template,
        decision_rules,
        artifacts,
        max_rows_per_plugin=cfg.get("artifact_max_rows_per_plugin"),
        max_artifact_json_chars=int(cfg.get("artifact_max_json_chars", 3500)),
        strategy=str(cfg.get("prompt_strategy", "chain_of_thought")),
        ransomware_hint=str(cfg.get("ransomware_hint", "unknown")),
        include_hallucination_check=bool(cfg.get("prompt_hallucination_check", True)),
        recall_boost=bool(cfg.get("prompt_recall_boost", False)),
        prompt_profile=str(cfg.get("prompt_profile", "legacy")),
    )


def main() -> int:
    load_dotenv()

    parser = build_standard_parser(
        prog="run_smoke.py",
        description="Run one-shot smoke flow for one snapshot: manifest -> labels -> batch triage -> evaluate.",
        examples=[
            "python scripts/run_smoke.py --config config/config.json --ground-truth-config config/ground_truth_process_names.json",
            "python scripts/run_smoke.py --category benign --snapshot-index 0 --out-dir results/smoke_one_shot",
        ],
    )
    parser.add_argument(
        "--config",
        default=_env_or_default("BASE_CONFIG_FILE", "config/config.json"),
        help="Base config JSON",
    )
    parser.add_argument(
        "--provider",
        default="",
        choices=["", "openrouter", "gemini", "nvidia", "openai", "claude", "lmstudio", "ollama"],
        help="Optional provider override for this run (sets LLM_PROVIDER at runtime).",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="Optional base URL override for this run (e.g. http://192.168.30.1:1234/v1).",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Optional model override for this run.",
    )
    parser.add_argument(
        "--ground-truth-config",
        default="config/ground_truth_process_names.json",
        help="Ground-truth family process-name mapping",
    )
    parser.add_argument(
        "--data-dir",
        default=_env_or_default("MEMORY_DUMP_FOLDER", "data"),
        help="Dataset root directory containing snapshots",
    )
    parser.add_argument(
        "--manifest",
        default=_env_or_default("SNAPSHOT_MANIFEST_FILE", "results/snapshot_manifest.json"),
        help="Existing manifest JSON used when --no-rebuild-manifest",
    )
    parser.add_argument(
        "--rebuild-manifest",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Rebuild manifest from --data-dir before selecting smoke snapshot",
    )
    parser.add_argument(
        "--category",
        default="all",
        choices=["all", "benign", "ransomware", "benign-tool", "unknown"],
        help="Snapshot category filter before picking one row",
    )
    parser.add_argument(
        "--snapshot-index",
        type=int,
        default=0,
        help="Index in filtered snapshot list (0-based)",
    )
    parser.add_argument(
        "--out-dir",
        default="results/smoke_one_shot",
        help="Output directory for smoke artifacts and summary",
    )
    parser.add_argument(
        "--low-token-mode",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use compact prompt settings (fewer rows, fewer output tokens, 1 voting run).",
    )
    parser.add_argument(
        "--max-estimated-input-tokens",
        type=int,
        default=3000,
        help="Estimated input-token budget for one LLM call. If exceeded, auto-focus reduction is applied.",
    )
    parser.add_argument(
        "--chars-per-token",
        type=float,
        default=4.0,
        help="Heuristic chars/token used for token estimation.",
    )
    args = parser.parse_args()

    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider

    cfg = load_json(args.config)
    if args.base_url:
        cfg["llm_base_url"] = str(args.base_url)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.rebuild_manifest:
        manifest_rows = build_manifest(args.data_dir)
        manifest_json = out_dir / "manifest_full.json"
        manifest_csv = out_dir / "manifest_full.csv"
        write_manifest_json(manifest_rows, str(manifest_json))
        write_manifest_csv(manifest_rows, str(manifest_csv))
    else:
        manifest_rows = _read_json(args.manifest)
        manifest_json = Path(args.manifest)

    if not isinstance(manifest_rows, list):
        raise ValueError("Manifest must be a JSON list")

    filtered = []
    for row in manifest_rows:
        if not isinstance(row, dict):
            continue
        cat = str(row.get("category", "unknown"))
        if args.category != "all" and cat != args.category:
            continue
        dump_path = str(row.get("file_path", ""))
        if dump_path and Path(dump_path).exists():
            filtered.append(row)

    if len(filtered) == 0:
        raise ValueError(
            "No eligible snapshots found after filtering. "
            "Try --rebuild-manifest and verify data directory paths."
        )

    if args.snapshot_index < 0 or args.snapshot_index >= len(filtered):
        raise ValueError(
            f"snapshot-index out of range: {args.snapshot_index}. Available range: 0..{len(filtered)-1}"
        )

    selected = filtered[args.snapshot_index]
    smoke_manifest = out_dir / "snapshot_manifest_smoke_1.json"
    smoke_manifest.write_text(json.dumps([selected], ensure_ascii=True, indent=2), encoding="utf-8")

    file_name = str(selected.get("file_name", "unknown.elf"))
    snapshot_stem = Path(file_name).stem
    dump_path = str(selected.get("file_path", ""))
    family = str(selected.get("executable", "Unknown"))
    selected_category = str(selected.get("category", "unknown")).strip().lower()
    is_ransomware_case = selected_category == "ransomware" or args.category == "ransomware"

    gt_cfg = _read_json(args.ground_truth_config)
    family_to_processes = gt_cfg.get("family_process_names", {})
    default_candidates = gt_cfg.get("default_candidates", [])

    labels_dir = out_dir / "labels"
    labels_dir.mkdir(parents=True, exist_ok=True)
    label_path = labels_dir / f"{snapshot_stem}.labels.json"

    volatility = VolatilityRunner(
        cfg["volatility_script_path"],
        plugin_timeout_seconds=cfg.get("volatility_plugin_timeout_seconds"),
    )
    pslist_output = volatility.run_plugin(dump_path, "windows.pslist")
    candidates = _family_candidates(selected, family_to_processes, default_candidates)
    label = build_label_from_intersection(pslist_output, candidates, family, file_name)
    write_label_file(label, str(label_path))

    run_cfg = deepcopy(cfg)
    if args.model:
        run_cfg["llm_model"] = str(args.model)

    if is_ransomware_case:
        run_cfg["ransomware_hint"] = family.lower()
        run_cfg["prompt_recall_boost"] = True
        run_cfg["prompt_strategy"] = "high_recall"

    if args.low_token_mode:
        run_cfg["majority_runs"] = 1
        run_cfg["llm_max_output_tokens"] = min(
            int(run_cfg.get("llm_max_output_tokens", 220)),
            220,
        )
        run_cfg["artifact_max_json_chars"] = min(
            int(run_cfg.get("artifact_max_json_chars", 1800)),
            1800,
        )
        if is_ransomware_case:
            run_cfg["artifact_max_rows_per_plugin"] = {
                "default": 20,
                "windows.pslist": 35,
                "windows.vadinfo": 4,
                "windows.malfind": 4,
            }
            run_cfg["prompt_strategy"] = "high_recall"
            run_cfg["prompt_recall_boost"] = True
        else:
            run_cfg["artifact_max_rows_per_plugin"] = {
                "default": 20,
                "windows.pslist": 20,
                "windows.vadinfo": 8,
                "windows.malfind": 8,
            }
            run_cfg["prompt_strategy"] = "basic"

    # Preflight estimate: if prompt looks too large, apply stronger focus settings.
    preview_plugins = run_cfg.get("volatility_plugins") or [
        "windows.pslist",
        "windows.vadinfo",
        "windows.malfind",
    ]
    preview_artifacts = volatility.collect(
        dump_path,
        preview_plugins,
        parallel=bool(run_cfg.get("volatility_parallel_plugins", False)),
        max_workers=int(run_cfg.get("volatility_max_workers", 2)),
    )
    preview_artifacts = attach_hidden_process_diff(preview_artifacts)
    prompt_template = Path(cfg["prompt_template_path"]).read_text(encoding="utf-8")
    decision_rules = _read_json(cfg["decision_rules_path"])

    if is_ransomware_case:
        decision_rules = deepcopy(decision_rules)
        decision_rules["family_hint"] = family
        decision_rules["family_candidate_process_names"] = list(candidates)
        existing_focus = decision_rules.get("ransomware_focus")
        if not isinstance(existing_focus, list):
            existing_focus = []
        decision_rules["ransomware_focus"] = existing_focus + [
            "Prioritize process names and direct children matching family_candidate_process_names.",
            "For windows.pslist, treat late-session user processes as equally important as early boot processes.",
            "When evidence exists, prefer returning candidate processes with medium confidence over empty output.",
        ]

    preview_prompt_before = _build_prompt_for_cfg(
        run_cfg,
        prompt_template,
        decision_rules,
        preview_artifacts,
    )
    est_before = _estimate_tokens(preview_prompt_before, args.chars_per_token)
    budget = max(1, int(args.max_estimated_input_tokens))
    budget_exceeded = est_before > budget
    auto_focus_applied = False
    auto_focus_rounds = 0

    if budget_exceeded:
        auto_focus_applied = True
        run_cfg["majority_runs"] = 1
        run_cfg["llm_max_output_tokens"] = min(
            int(run_cfg.get("llm_max_output_tokens", 160)),
            160,
        )
        run_cfg["artifact_max_json_chars"] = min(
            int(run_cfg.get("artifact_max_json_chars", 1200)),
            1200,
        )
        if is_ransomware_case:
            run_cfg["artifact_max_rows_per_plugin"] = {
                "default": 12,
                "windows.pslist": 20,
                "windows.vadinfo": 2,
                "windows.malfind": 2,
            }
            run_cfg["prompt_strategy"] = "high_recall"
            run_cfg["prompt_recall_boost"] = True
        else:
            run_cfg["artifact_max_rows_per_plugin"] = {
                "default": 12,
                "windows.pslist": 12,
                "windows.vadinfo": 4,
                "windows.malfind": 4,
            }
            run_cfg["prompt_strategy"] = "basic"

    preview_prompt_after = _build_prompt_for_cfg(
        run_cfg,
        prompt_template,
        decision_rules,
        preview_artifacts,
    )
    est_after = _estimate_tokens(preview_prompt_after, args.chars_per_token)

    # If still above budget, keep tightening payload in bounded rounds.
    while est_after > budget and auto_focus_rounds < 4:
        auto_focus_rounds += 1
        auto_focus_applied = True

        current_chars = int(run_cfg.get("artifact_max_json_chars", 1200))
        run_cfg["artifact_max_json_chars"] = max(500, int(current_chars * 0.75))

        if auto_focus_rounds == 1:
            if is_ransomware_case:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 10,
                    "windows.pslist": 16,
                    "windows.vadinfo": 2,
                    "windows.malfind": 2,
                }
            else:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 10,
                    "windows.pslist": 10,
                    "windows.vadinfo": 3,
                    "windows.malfind": 3,
                }
            run_cfg["llm_max_output_tokens"] = min(int(run_cfg.get("llm_max_output_tokens", 140)), 140)
        elif auto_focus_rounds == 2:
            if is_ransomware_case:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 8,
                    "windows.pslist": 14,
                    "windows.vadinfo": 2,
                    "windows.malfind": 2,
                }
            else:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 8,
                    "windows.pslist": 8,
                    "windows.vadinfo": 2,
                    "windows.malfind": 2,
                }
            run_cfg["llm_max_output_tokens"] = min(int(run_cfg.get("llm_max_output_tokens", 120)), 120)
        elif auto_focus_rounds == 3:
            if is_ransomware_case:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 6,
                    "windows.pslist": 12,
                    "windows.vadinfo": 2,
                    "windows.malfind": 2,
                }
            else:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 6,
                    "windows.pslist": 6,
                    "windows.vadinfo": 2,
                    "windows.malfind": 2,
                }
            run_cfg["llm_max_output_tokens"] = min(int(run_cfg.get("llm_max_output_tokens", 96)), 96)
        else:
            if is_ransomware_case:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 5,
                    "windows.pslist": 10,
                    "windows.vadinfo": 1,
                    "windows.malfind": 1,
                }
            else:
                run_cfg["artifact_max_rows_per_plugin"] = {
                    "default": 5,
                    "windows.pslist": 5,
                    "windows.vadinfo": 1,
                    "windows.malfind": 1,
                }
            run_cfg["llm_max_output_tokens"] = min(int(run_cfg.get("llm_max_output_tokens", 80)), 80)

        preview_prompt_after = _build_prompt_for_cfg(
            run_cfg,
            prompt_template,
            decision_rules,
            preview_artifacts,
        )
        est_after = _estimate_tokens(preview_prompt_after, args.chars_per_token)

    run_cfg["memory_dump_path"] = dump_path
    run_cfg["output_report_path"] = str(out_dir / f"{snapshot_stem}.report.json")
    run_cfg["output_votes_path"] = str(out_dir / f"{snapshot_stem}.votes.json")
    run_cfg["output_artifacts_path"] = str(out_dir / f"{snapshot_stem}.artifacts.json")

    report = run_pipeline_config(run_cfg)

    votes_data = _read_json(run_cfg["output_votes_path"])
    usage_prompt_tokens = 0
    usage_completion_tokens = 0
    usage_total_tokens = 0
    usage_records = 0
    vote_api_error_count = 0
    vote_parse_error_count = 0
    vote_repaired_count = 0
    if isinstance(votes_data, list):
        for vote in votes_data:
            if not isinstance(vote, dict):
                continue
            if vote.get("api_error"):
                vote_api_error_count += 1
            if vote.get("parse_error"):
                vote_parse_error_count += 1
            if vote.get("repaired_json"):
                vote_repaired_count += 1
            usage = vote.get("usage")
            if not isinstance(usage, dict):
                continue
            usage_prompt_tokens += int(usage.get("prompt_tokens", 0) or 0)
            usage_completion_tokens += int(usage.get("completion_tokens", 0) or 0)
            usage_total_tokens += int(usage.get("total_tokens", 0) or 0)
            usage_records += 1

    artifacts = _read_json(run_cfg["output_artifacts_path"])
    clean_flags = _artifact_clean_flags(artifacts)

    prompt = _build_prompt_for_cfg(run_cfg, prompt_template, decision_rules, artifacts)

    eval_metrics = evaluate(run_cfg["output_report_path"], str(label_path))
    summary = {
        "status": "ok",
        "selected_snapshot": file_name,
        "memory_dump_path": dump_path,
        "provider": cfg.get("llm_provider", ""),
        "model": run_cfg.get("llm_model", cfg.get("llm_model", "")),
        "low_token_mode": bool(args.low_token_mode),
        "effective_majority_runs": int(run_cfg.get("majority_runs", 0)),
        "effective_llm_max_output_tokens": int(run_cfg.get("llm_max_output_tokens", 0)),
        "effective_artifact_max_json_chars": int(run_cfg.get("artifact_max_json_chars", 0)),
        "token_budget": {
            "chars_per_token": float(args.chars_per_token),
            "max_estimated_input_tokens": int(args.max_estimated_input_tokens),
            "estimated_input_tokens_before": int(est_before),
            "estimated_input_tokens_after": int(est_after),
            "budget_exceeded_before": bool(budget_exceeded),
            "auto_focus_applied": bool(auto_focus_applied),
            "auto_focus_rounds": int(auto_focus_rounds),
            "budget_met_after": bool(est_after <= budget),
        },
        "llm_usage": {
            "usage_records": int(usage_records),
            "prompt_tokens": int(usage_prompt_tokens),
            "completion_tokens": int(usage_completion_tokens),
            "total_tokens": int(usage_total_tokens),
        },
        "vote_quality": {
            "api_error_count": int(vote_api_error_count),
            "parse_error_count": int(vote_parse_error_count),
            "repaired_json_count": int(vote_repaired_count),
        },
        "manifest_used": str(manifest_json),
        "smoke_manifest": str(smoke_manifest),
        "label_path": str(label_path),
        "report_path": run_cfg["output_report_path"],
        "votes_path": run_cfg["output_votes_path"],
        "artifacts_path": run_cfg["output_artifacts_path"],
        "suspicious_count": len(report.get("suspicious_processes", [])),
        "evaluation": eval_metrics,
        "artifact_clean_flags": clean_flags,
        "prompt_contains_raw_output": "raw_output" in prompt,
        "prompt_contains_parse_error": "parse_error" in prompt,
        "prompt_chars": len(prompt),
    }

    summary_path = out_dir / "smoke_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
