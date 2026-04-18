import json
from pathlib import Path

from src.config.loader import load_json
from src.forensics.psscan_diff import detect_hidden_pids
from src.forensics.post_filter import apply_conservative_post_filter
from src.forensics.volatility import VolatilityRunner
from src.llm.client import LLMClient, majority_vote
from src.prompts.builder import build_prompt


def attach_hidden_process_diff(artifacts: dict) -> dict:
    if not isinstance(artifacts, dict):
        return artifacts
    if "windows.psscan" not in artifacts:
        return artifacts

    diff = detect_hidden_pids(
        artifacts.get("windows.pslist"),
        artifacts.get("windows.psscan"),
    )
    if not isinstance(diff, dict):
        return artifacts

    hidden_rows = diff.get("hidden_rows")
    if isinstance(hidden_rows, list) and len(hidden_rows) > 20:
        diff = dict(diff)
        diff["hidden_rows"] = hidden_rows[:20]
        diff["hidden_rows_truncated"] = len(hidden_rows) - 20

    artifacts["windows.hidden_process_diff"] = diff
    return artifacts


def run_pipeline_config(cfg: dict) -> dict:

    if not cfg.get("memory_dump_path"):
        raise ValueError(
            "memory_dump_path is empty. Set MEMORY_DUMP_FILE in .env or provide it in config/config.json"
        )

    prompt_template = Path(cfg["prompt_template_path"]).read_text(encoding="utf-8")
    decision_rules = load_json(cfg["decision_rules_path"])

    volatility_plugin_timeout_seconds = cfg.get("volatility_plugin_timeout_seconds")
    volatility = VolatilityRunner(
        cfg["volatility_script_path"],
        plugin_timeout_seconds=volatility_plugin_timeout_seconds,
    )
    artifacts = volatility.collect(
        cfg["memory_dump_path"],
        cfg["volatility_plugins"],
        parallel=bool(cfg.get("volatility_parallel_plugins", False)),
        max_workers=int(cfg.get("volatility_max_workers", 2)),
    )
    artifacts = attach_hidden_process_diff(artifacts)

    artifact_max_rows_per_plugin = cfg.get("artifact_max_rows_per_plugin")
    artifact_max_json_chars = int(cfg.get("artifact_max_json_chars", 24000))
    prompt_strategy = str(cfg.get("prompt_strategy", "chain_of_thought"))
    ransomware_hint = str(cfg.get("ransomware_hint", "unknown"))
    include_hallucination_check = bool(cfg.get("prompt_hallucination_check", True))

    prompt = build_prompt(
        prompt_template,
        decision_rules,
        artifacts,
        max_rows_per_plugin=artifact_max_rows_per_plugin,
        max_artifact_json_chars=artifact_max_json_chars,
        strategy=prompt_strategy,
        ransomware_hint=ransomware_hint,
        include_hallucination_check=include_hallucination_check,
        recall_boost=bool(cfg.get("prompt_recall_boost", False)),
        prompt_profile=str(cfg.get("prompt_profile", "legacy")),
    )

    llm_model = cfg.get("llm_model", cfg.get("openai_model", "gpt-4o-mini"))
    llm_api_key_env = cfg.get("llm_api_key_env", "OPENAI_API_KEY")
    llm_base_url = cfg.get("llm_base_url")
    llm_timeout_seconds = float(cfg.get("llm_timeout_seconds", 30))
    llm_max_output_tokens = cfg.get("llm_max_output_tokens", 400)
    llm_force_json_response_format = bool(
        cfg.get("llm_force_json_response_format", True)
    )
    llm_reasoning_enabled = cfg.get("llm_reasoning_enabled")

    if not llm_model:
        raise ValueError(
            "llm_model is empty. Set LLM_MODEL in .env or provide it in config/config.json"
        )

    if not llm_api_key_env:
        raise ValueError(
            "llm_api_key_env is empty. Set LLM_API_KEY_ENV in .env or provide it in config/config.json"
        )

    llm = LLMClient(
        model=llm_model,
        temperature=cfg.get("temperature", 0),
        api_key_env=llm_api_key_env,
        base_url=llm_base_url,
        timeout_seconds=llm_timeout_seconds,
        max_output_tokens=llm_max_output_tokens,
        force_json_response_format=llm_force_json_response_format,
        reasoning_enabled=llm_reasoning_enabled,
    )

    votes = []
    runs = int(cfg.get("majority_runs", 3))
    for _ in range(runs):
        votes.append(llm.triage_once(prompt))

    final_report = majority_vote(votes)

    if bool(cfg.get("post_filter_enabled", True)):
        final_report = apply_conservative_post_filter(final_report, artifacts, cfg)

    output_artifacts_path = cfg.get("output_artifacts_path")
    if output_artifacts_path:
        artifacts_path = Path(output_artifacts_path)
        artifacts_path.parent.mkdir(parents=True, exist_ok=True)
        artifacts_path.write_text(
            json.dumps(artifacts, ensure_ascii=True, indent=2), encoding="utf-8"
        )

    votes_path = Path(cfg["output_votes_path"])
    votes_path.parent.mkdir(parents=True, exist_ok=True)
    votes_path.write_text(
        json.dumps(votes, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    report_path = Path(cfg["output_report_path"])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(final_report, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    return final_report


def run_pipeline(config_path: str) -> dict:
    cfg = load_json(config_path)
    return run_pipeline_config(cfg)
