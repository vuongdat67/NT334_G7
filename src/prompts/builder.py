import json
from copy import deepcopy


PREFERRED_ROW_KEYS = [
    "pid",
    "ppid",
    "name",
    "process_name",
    "ImageFileName",
    "Process",
    "Parent",
    "parent_name",
    "protection",
    "Protection",
    "vad_start",
    "vad_end",
    "start",
    "end",
    "tag",
    "flags",
]


DEFAULT_FEW_SHOT = {
    "unknown": [
        {
            "input": {
                "pid": 1500,
                "ppid": 900,
                "name": "xk7p2mq9r",
                "vad_suspicious": [{"protection": "PAGE_EXECUTE_READWRITE"}],
            },
            "analysis": "Random process name with RWX memory is a strong ransomware indicator.",
            "label": "suspicious",
        },
        {
            "input": {
                "pid": 680,
                "ppid": 568,
                "name": "svchost.exe",
                "parent_name": "services.exe",
            },
            "analysis": "Expected Windows process hierarchy.",
            "label": "normal",
        },
    ],
    "wannacry": [
        {
            "input": {"pid": 1234, "ppid": 680, "name": "ed01ebfbc9eb5b"},
            "analysis": "Random hexadecimal name consistent with WannaCry process naming.",
            "label": "suspicious",
        },
        {
            "input": {"pid": 1456, "ppid": 1234, "name": "wanadecryptor"},
            "analysis": "Known WannaCry component and suspicious lineage.",
            "label": "suspicious",
        },
    ],
    "cerber": [
        {
            "input": {"pid": 2000, "ppid": 900, "name": "cerber"},
            "analysis": "Known ransomware family process name.",
            "label": "suspicious",
        },
        {
            "input": {"pid": 2100, "ppid": 2000, "name": "mshta.exe"},
            "analysis": "Legitimate binary but parent already malicious.",
            "label": "suspicious",
        },
    ],
}


def _truncate_artifacts_rows(
    artifacts: dict, max_rows_per_plugin: dict[str, int]
) -> dict:
    truncated = deepcopy(artifacts)
    for plugin, data in truncated.items():
        if isinstance(data, list):
            max_rows = int(max_rows_per_plugin.get(plugin, max_rows_per_plugin.get("default", 80)))
            if len(data) > max_rows:
                truncated[plugin] = {
                    "rows": data[:max_rows],
                    "_rows_total": len(data),
                    "_rows_truncated": len(data) - max_rows,
                }
            else:
                truncated[plugin] = {"rows": data}
            continue

        if not isinstance(data, dict):
            continue
        rows = data.get("rows")
        if isinstance(rows, list):
            max_rows = int(max_rows_per_plugin.get(plugin, max_rows_per_plugin.get("default", 80)))
            if len(rows) > max_rows:
                data["rows"] = rows[:max_rows]
                data["_rows_total"] = len(rows)
                data["_rows_truncated"] = len(rows) - max_rows
    return truncated


def _enforce_max_chars(artifacts: dict, max_chars: int) -> dict:
    working = deepcopy(artifacts)
    while len(json.dumps(working, ensure_ascii=True)) > max_chars:
        changed = False
        for plugin, data in working.items():
            if isinstance(data, list) and len(data) > 10:
                new_len = max(10, len(data) // 2)
                working[plugin] = data[:new_len]
                changed = True
                continue

            if not isinstance(data, dict):
                continue
            rows = data.get("rows")
            if isinstance(rows, list) and len(rows) > 10:
                new_len = max(10, len(rows) // 2)
                data["rows"] = rows[:new_len]
                data["_rows_compacted_to"] = new_len
                changed = True
        if not changed:
            break
    return working


def _compact_scalar(value, max_chars: int = 120):
    if isinstance(value, str) and len(value) > max_chars:
        return value[: max_chars - 3] + "..."
    return value


def _compact_row_fields(artifacts: dict, max_fields_per_row: int = 8) -> dict:
    compacted = deepcopy(artifacts)

    def compact_one_row(row: dict) -> dict:
        # Prefer stable forensic keys first, then fill with remaining short fields.
        selected = {}
        for key in PREFERRED_ROW_KEYS:
            if key in row and row[key] not in (None, ""):
                selected[key] = _compact_scalar(row[key])
            if len(selected) >= max_fields_per_row:
                return selected

        for key, value in row.items():
            if key in selected or value in (None, ""):
                continue
            if isinstance(value, (dict, list)):
                continue
            selected[key] = _compact_scalar(value)
            if len(selected) >= max_fields_per_row:
                break
        return selected

    for _, data in compacted.items():
        if not isinstance(data, dict):
            continue
        rows = data.get("rows")
        if not isinstance(rows, list):
            continue
        new_rows = []
        for row in rows:
            if isinstance(row, dict):
                new_rows.append(compact_one_row(row))
            else:
                new_rows.append(_compact_scalar(row))
        data["rows"] = new_rows

    return compacted


def build_prompt(
    template_text: str,
    decision_rules: dict,
    artifacts: dict,
    max_rows_per_plugin: dict[str, int] | None = None,
    max_artifact_json_chars: int = 24000,
    strategy: str = "chain_of_thought",
    ransomware_hint: str = "unknown",
    include_hallucination_check: bool = True,
    recall_boost: bool = False,
    prompt_profile: str = "legacy",
) -> str:
    if max_rows_per_plugin is None:
        max_rows_per_plugin = {
            "default": 80,
            "windows.pslist": 80,
            "windows.vadinfo": 50,
            "windows.malfind": 40,
        }

    compact_artifacts = _truncate_artifacts_rows(artifacts, max_rows_per_plugin)
    compact_artifacts = _compact_row_fields(compact_artifacts)
    compact_artifacts = _enforce_max_chars(compact_artifacts, max_artifact_json_chars)

    payload = {
        "decision_rules": decision_rules,
        "artifacts": compact_artifacts,
    }

    normalized_profile = (prompt_profile or "legacy").strip().lower()

    if normalized_profile in {"n2", "advanced", "triage_v2"}:
        from src.prompts.triage_prompt import build_prompt_by_strategy

        prompt_text = build_prompt_by_strategy(
            strategy=strategy,
            payload_json=json.dumps(payload, ensure_ascii=True),
            ransomware_family=ransomware_hint,
        )
        hallucination_block = _build_hallucination_block() if include_hallucination_check else ""
        recall_boost_block = _build_recall_boost_block() if recall_boost else ""
        return prompt_text + hallucination_block + recall_boost_block

    strategy_block = _build_strategy_block(strategy, ransomware_hint)
    hallucination_block = _build_hallucination_block() if include_hallucination_check else ""
    recall_boost_block = _build_recall_boost_block() if recall_boost else ""

    return (
        template_text.strip()
        + strategy_block
        + hallucination_block
        + recall_boost_block
        + "\n\nDecision rules and forensic artifacts:\n"
        + json.dumps(payload, ensure_ascii=True)
    )


def _build_strategy_block(strategy: str, ransomware_hint: str) -> str:
    normalized = (strategy or "chain_of_thought").strip().lower()

    if normalized == "basic":
        return "\n\nAnalysis strategy: Basic direct triage using provided decision rules."

    if normalized == "few_shot":
        examples = DEFAULT_FEW_SHOT.get(ransomware_hint, DEFAULT_FEW_SHOT["unknown"])
        return (
            "\n\nAnalysis strategy: Few-shot triage with prior examples."
            "\nUse the examples below as pattern references only."
            f"\nExamples:\n{json.dumps(examples, ensure_ascii=True)}"
        )

    if normalized == "high_recall":
        return (
            "\n\nAnalysis strategy: High-recall forensic triage."
            "\n1) Prioritize catching potential ransomware lineage over strict pruning."
            "\n2) If parent process is suspicious, investigate direct children aggressively."
            "\n3) Treat RWX VAD or malfind signals as strong escalation factors."
            "\n4) When uncertain but evidence exists, keep process with medium confidence."
            "\n5) Return final JSON only."
        )

    # Default: chain-of-thought style checklist without exposing internal reasoning text.
    return (
        "\n\nAnalysis strategy: Structured forensic checklist."
        "\n1) Validate process names against known Windows system processes."
        "\n2) Review parent-child relationships for anomalies."
        "\n3) Prioritize RWX VAD and malfind indicators."
        "\n4) Flag suspicious lineage cascade only with concrete parent evidence."
        "\n5) Return final JSON only."
    )


def _build_hallucination_block() -> str:
    return (
        "\n\nHallucination control:"
        "\n- Do not mark a process suspicious without at least one concrete indicator from input artifacts."
        "\n- Avoid generic claims not grounded in given fields."
        "\n- For system process names (svchost.exe, explorer.exe, lsass.exe), require strong corroboration"
        "  such as malfind or suspicious parent chain."
    )


def _build_recall_boost_block() -> str:
    return (
        "\n\nRecall optimization mode:"
        "\n- Minimize false negatives for ransomware-related processes."
        "\n- If a process has at least one meaningful indicator and belongs to a suspicious chain,"
        "  prefer keeping it with confidence >= 0.5 instead of dropping."
    )
