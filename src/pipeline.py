import json
from pathlib import Path

from src.config_loader import load_json
from src.llm_client import LLMClient, majority_vote
from src.post_filter import apply_conservative_post_filter
from src.prompt_builder import build_prompt
from src.volatility_wrapper import VolatilityRunner


def run_pipeline(config_path: str) -> dict:
    cfg = load_json(config_path)

    prompt_template = Path(cfg["prompt_template_path"]).read_text(encoding="utf-8")
    decision_rules = load_json(cfg["decision_rules_path"])

    volatility = VolatilityRunner(cfg["volatility_script_path"])
    artifacts = volatility.collect(cfg["memory_dump_path"], cfg["volatility_plugins"])

    artifact_max_rows_per_plugin = cfg.get("artifact_max_rows_per_plugin")
    artifact_max_json_chars = int(cfg.get("artifact_max_json_chars", 24000))

    prompt = build_prompt(
        prompt_template,
        decision_rules,
        artifacts,
        max_rows_per_plugin=artifact_max_rows_per_plugin,
        max_artifact_json_chars=artifact_max_json_chars,
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

    Path(cfg["output_votes_path"]).write_text(
        json.dumps(votes, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    Path(cfg["output_report_path"]).write_text(
        json.dumps(final_report, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    return final_report
