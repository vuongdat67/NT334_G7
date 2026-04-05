"""
Richer triage prompt package inspired by the n2-volgpt structure.
This module is optional and can be enabled via config: prompt_profile = "n2".
"""

from typing import Dict

SYSTEM_PROMPT = """You are an expert digital forensics investigator specializing in memory forensics and malware triage.
Your task is to identify suspicious Windows processes that may be linked to ransomware behavior.

Rules:
1. Standard Windows system processes are normal unless there is strong contradictory evidence.
2. Suspicious indicators include random-like names, known malware names, suspicious parent chains, RWX VAD, malfind MZ/shellcode.
3. Return only valid JSON as requested in the output template.
"""

DECISION_RULES = """TRIAGE DECISION RULES:
[RULE1] Process name: random strings, known ransomware names, or typo-masquerade names are suspicious.
[RULE2] Parent-child: benign binaries spawned by suspicious parent should be escalated.
[RULE3] VAD: PAGE_EXECUTE_READWRITE regions are strong injection indicators.
[RULE4] Malfind: MZ header or shellcode patterns indicate injected payload.
"""

JSON_SCHEMA_GUIDE = """INPUT DATA SCHEMA:
- decision_rules: policy object used by the pipeline.
- artifacts.windows.pslist/windows.vadinfo/windows.malfind: compact Volatility outputs.
"""

OUTPUT_TEMPLATE = """OUTPUT JSON FORMAT:
{
  "suspicious_processes": [
    {
      "pid": 0,
      "process_name": "",
      "reason": "",
      "confidence": 0.0
    }
  ]
}
"""

FEW_SHOT_EXAMPLES: Dict[str, str] = {
    "unknown": """Example:
Input signal: random process name + RWX VAD.
Expected: suspicious, high confidence.
""",
    "wannacry": """Example:
Input signal: process name like ed01ebfbc9eb5b and child wanadecryptor.
Expected: suspicious lineage, high confidence.
""",
    "cerber": """Example:
Input signal: process name cerber and child mshta.exe.
Expected: suspicious parent chain, high confidence.
""",
}


def _build_common_header() -> str:
    return (
        SYSTEM_PROMPT.strip()
        + "\n\n"
        + DECISION_RULES.strip()
        + "\n\n"
        + JSON_SCHEMA_GUIDE.strip()
        + "\n\n"
        + OUTPUT_TEMPLATE.strip()
    )


def build_basic_prompt(payload_json: str) -> str:
    return (
        _build_common_header()
        + "\n\nAnalysis strategy: direct triage."
        + "\n\nMEMORY ARTIFACTS JSON:\n"
        + payload_json
    )


def build_chain_of_thought_prompt(payload_json: str) -> str:
    return (
        _build_common_header()
        + "\n\nAnalysis strategy: structured checklist."
        + "\n1) Validate process names."
        + "\n2) Evaluate parent-child lineage."
        + "\n3) Correlate RWX VAD and malfind indicators."
        + "\n4) Keep only evidence-grounded findings."
        + "\n\nMEMORY ARTIFACTS JSON:\n"
        + payload_json
    )


def build_few_shot_prompt(payload_json: str, ransomware_family: str = "unknown") -> str:
    family = (ransomware_family or "unknown").strip().lower()
    examples = FEW_SHOT_EXAMPLES.get(family, FEW_SHOT_EXAMPLES["unknown"])
    return (
        _build_common_header()
        + "\n\nAnalysis strategy: few-shot references."
        + "\nExamples:\n"
        + examples.strip()
        + "\n\nMEMORY ARTIFACTS JSON:\n"
        + payload_json
    )


def build_prompt_by_strategy(
    strategy: str,
    payload_json: str,
    ransomware_family: str = "unknown",
) -> str:
    normalized = (strategy or "chain_of_thought").strip().lower()
    if normalized == "basic":
        return build_basic_prompt(payload_json)
    if normalized == "few_shot":
        return build_few_shot_prompt(payload_json, ransomware_family=ransomware_family)
    return build_chain_of_thought_prompt(payload_json)


def build_hallucination_check_prompt(original_result_json: str, payload_json: str) -> str:
    return (
        "Review and correct previous triage output."
        "\nCheck false positives on standard Windows processes."
        "\nReturn corrected JSON only."
        "\n\nPREVIOUS OUTPUT:\n"
        + original_result_json
        + "\n\nMEMORY ARTIFACTS JSON:\n"
        + payload_json
    )
