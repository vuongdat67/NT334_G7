from src.prompts.builder import _compact_row_fields, build_prompt


def test_compact_row_fields_truncates_and_limits_fields():
    artifacts = {
        "windows.pslist": {
            "rows": [
                {
                    "pid": 10,
                    "ppid": 4,
                    "name": "very-long-process-name.exe",
                    "ImageFileName": "very-long-process-name.exe",
                    "extra_1": "x" * 300,
                    "extra_2": "keep",
                    "extra_3": "keep",
                    "extra_4": "keep",
                    "extra_5": "keep",
                    "extra_6": "keep",
                }
            ]
        }
    }

    compacted = _compact_row_fields(artifacts, max_fields_per_row=8)
    row = compacted["windows.pslist"]["rows"][0]

    assert len(row.keys()) <= 8
    assert "pid" in row
    assert "ppid" in row
    assert any(str(v).endswith("...") for v in row.values())


def test_build_prompt_legacy_contains_compacted_payload_marker():
    template = "You are triage system."
    rules = {"pslist": ["rule"]}
    artifacts = {
        "windows.pslist": {
            "rows": [{"pid": 1, "name": "abc", "note": "n" * 200} for _ in range(50)]
        }
    }

    prompt = build_prompt(
        template,
        rules,
        artifacts,
        max_rows_per_plugin={"default": 10, "windows.pslist": 10},
        max_artifact_json_chars=1200,
        strategy="basic",
        prompt_profile="legacy",
    )

    assert "Decision rules and forensic artifacts:" in prompt
    assert "rows" in prompt
