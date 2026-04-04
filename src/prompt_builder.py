import json
from copy import deepcopy


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


def build_prompt(
    template_text: str,
    decision_rules: dict,
    artifacts: dict,
    max_rows_per_plugin: dict[str, int] | None = None,
    max_artifact_json_chars: int = 24000,
) -> str:
    if max_rows_per_plugin is None:
        max_rows_per_plugin = {
            "default": 80,
            "windows.pslist": 80,
            "windows.vadinfo": 50,
            "windows.malfind": 40,
        }

    compact_artifacts = _truncate_artifacts_rows(artifacts, max_rows_per_plugin)
    compact_artifacts = _enforce_max_chars(compact_artifacts, max_artifact_json_chars)

    payload = {
        "decision_rules": decision_rules,
        "artifacts": compact_artifacts,
    }
    return (
        template_text.strip()
        + "\n\nDecision rules and forensic artifacts:\n"
        + json.dumps(payload, ensure_ascii=True)
    )
