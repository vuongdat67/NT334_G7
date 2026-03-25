import json


def build_prompt(template_text: str, decision_rules: dict, artifacts: dict) -> str:
    payload = {
        "decision_rules": decision_rules,
        "artifacts": artifacts,
    }
    return (
        template_text.strip()
        + "\n\nDecision rules and forensic artifacts:\n"
        + json.dumps(payload, ensure_ascii=True)
    )
