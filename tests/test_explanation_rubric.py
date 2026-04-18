from src.evaluation.explanation_rubric import score_explanation, score_report_explanations


# ---------------------------------------------------------------------------
# score_explanation
# ---------------------------------------------------------------------------

def test_empty_reason_scores_zero():
    s = score_explanation("")
    assert s["total"] == 0
    assert s["quality_band"] == "poor"


def test_high_quality_explanation():
    reason = (
        "Process has PAGE_EXECUTE_READWRITE VAD region and malfind shows MZ header. "
        "Examine the VAD dump to confirm injected PE payload."
    )
    s = score_explanation(reason)
    assert s["technical_accuracy"] == 3
    assert s["specificity"] == 2
    assert s["actionability"] == 2
    assert s["total"] == 7
    assert s["quality_band"] == "excellent"


def test_generic_reason_scores_low():
    reason = "Process looks suspicious and appears unusual."
    s = score_explanation(reason)
    assert s["technical_accuracy"] == 0
    assert s["total"] <= 2
    assert s["quality_band"] == "poor"


def test_medium_quality_reason():
    reason = "Random process name spawned from a suspicious parent process. Further analysis needed."
    s = score_explanation(reason)
    assert s["technical_accuracy"] >= 2
    assert s["actionability"] >= 1
    assert s["quality_band"] in ("fair", "good")


def test_shellcode_mention_gives_accuracy_3():
    s = score_explanation("shellcode detected in memory region")
    assert s["technical_accuracy"] == 3


def test_parent_mention_gives_accuracy_2():
    s = score_explanation("spawned from a known malware parent")
    assert s["technical_accuracy"] == 2


def test_actionability_concrete():
    s = score_explanation("run malfind to verify injected code")
    assert s["actionability"] == 2


def test_actionability_vague():
    s = score_explanation("requires further analysis by an investigator")
    assert s["actionability"] == 1


def test_quality_band_boundaries():
    # total 0 → poor
    assert score_explanation("")["quality_band"] == "poor"
    # total 7 → excellent (already tested above)


# ---------------------------------------------------------------------------
# score_report_explanations
# ---------------------------------------------------------------------------

def test_score_report_empty():
    result = score_report_explanations([])
    assert result["mean_total"] == 0.0
    assert result["item_scores"] == []


def test_score_report_aggregation():
    items = [
        {"pid": 1, "process_name": "a.exe", "reason": "shellcode in VAD, examine VAD region"},
        {"pid": 2, "process_name": "b.exe", "reason": "looks suspicious"},
    ]
    result = score_report_explanations(items)
    assert len(result["item_scores"]) == 2
    assert 0.0 <= result["mean_total"] <= 7.0
    assert sum(result["band_distribution"].values()) == 2


def test_score_report_reason_preview_truncated():
    long_reason = "x" * 200
    items = [{"pid": 10, "reason": long_reason}]
    result = score_report_explanations(items)
    preview = result["item_scores"][0]["reason_preview"]
    assert len(preview) <= 124  # 120 chars + "…"
    assert preview.endswith("…")
