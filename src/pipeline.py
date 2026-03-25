import json
from pathlib import Path

from src.config_loader import load_json
from src.llm_client import LLMClient, majority_vote
from src.prompt_builder import build_prompt
from src.volatility_wrapper import VolatilityRunner


def run_pipeline(config_path: str) -> dict:
    cfg = load_json(config_path)

    prompt_template = Path(cfg["prompt_template_path"]).read_text(encoding="utf-8")
    decision_rules = load_json(cfg["decision_rules_path"])

    volatility = VolatilityRunner(cfg["volatility_script_path"])
    artifacts = volatility.collect(cfg["memory_dump_path"], cfg["volatility_plugins"])

    prompt = build_prompt(prompt_template, decision_rules, artifacts)

    llm = LLMClient(model=cfg["openai_model"], temperature=cfg.get("temperature", 0))

    votes = []
    runs = int(cfg.get("majority_runs", 3))
    for _ in range(runs):
        votes.append(llm.triage_once(prompt))

    final_report = majority_vote(votes)

    Path(cfg["output_votes_path"]).write_text(
        json.dumps(votes, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    Path(cfg["output_report_path"]).write_text(
        json.dumps(final_report, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    return final_report
