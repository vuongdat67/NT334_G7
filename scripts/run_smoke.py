import argparse
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
from src.pipeline.runner import run_pipeline_config
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
        choices=["", "openrouter", "gemini", "openai", "claude", "lmstudio", "ollama"],
        help="Optional provider override for this run (sets LLM_PROVIDER at runtime).",
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
    args = parser.parse_args()

    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider

    cfg = load_json(args.config)
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
        run_cfg["artifact_max_rows_per_plugin"] = {
            "default": 20,
            "windows.pslist": 20,
            "windows.vadinfo": 8,
            "windows.malfind": 8,
        }
        run_cfg["prompt_strategy"] = "basic"

    run_cfg["memory_dump_path"] = dump_path
    run_cfg["output_report_path"] = str(out_dir / f"{snapshot_stem}.report.json")
    run_cfg["output_votes_path"] = str(out_dir / f"{snapshot_stem}.votes.json")
    run_cfg["output_artifacts_path"] = str(out_dir / f"{snapshot_stem}.artifacts.json")

    report = run_pipeline_config(run_cfg)

    artifacts = _read_json(run_cfg["output_artifacts_path"])
    clean_flags = _artifact_clean_flags(artifacts)

    prompt_template = Path(cfg["prompt_template_path"]).read_text(encoding="utf-8")
    decision_rules = _read_json(cfg["decision_rules_path"])
    prompt = build_prompt(
        prompt_template,
        decision_rules,
        artifacts,
        max_rows_per_plugin=run_cfg.get("artifact_max_rows_per_plugin"),
        max_artifact_json_chars=int(run_cfg.get("artifact_max_json_chars", 3500)),
        strategy=str(run_cfg.get("prompt_strategy", "chain_of_thought")),
        ransomware_hint=str(run_cfg.get("ransomware_hint", "unknown")),
        include_hallucination_check=bool(run_cfg.get("prompt_hallucination_check", True)),
        recall_boost=bool(run_cfg.get("prompt_recall_boost", False)),
        prompt_profile=str(run_cfg.get("prompt_profile", "legacy")),
    )

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
