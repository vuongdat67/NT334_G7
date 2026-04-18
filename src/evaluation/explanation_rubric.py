"""
Heuristic-based scoring of LLM triage explanation quality.

The rubric is derived from the evaluation criteria described in evaluate.txt
(based on paper analysis). Each explanation (the "reason" field in a
suspicious_processes item) is scored on three dimensions:

  Dimension 1 — Technical accuracy (0–3 points)
    Measures whether the explanation references real forensic evidence.
    0: Wrong, irrelevant, or empty.
    1: Partially correct — mentions some evidence but contains inaccuracies.
    2: Technically correct but lacking specific artifact detail.
    3: Accurate, grounded in concrete artifact fields (PID, VAD, malfind, etc.).

  Dimension 2 — Specificity (0–2 points)
    Measures how precisely the explanation names forensic features.
    0: Generic claim only ("process looks suspicious").
    1: Names a specific feature (process name, parent process, RWX).
    2: Names feature AND links it to evidence from the input artifacts.

  Dimension 3 — Actionability (0–2 points)
    Measures whether the explanation guides the investigator's next step.
    0: No follow-up suggestion.
    1: Vague suggestion ("further analysis needed").
    2: Concrete suggestion ("examine VAD region", "check parent chain with psscan").

Maximum score: 7 points.
Quality bands: 0–2 = poor, 3–4 = fair, 5–6 = good, 7 = excellent.

This is a heuristic approximation. For a fully rigorous evaluation, use an
LLM-as-judge approach (call the LLM to score each explanation against the rubric).
"""
import re
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Keyword sets used by the heuristic scorer
# ---------------------------------------------------------------------------

# Strong forensic evidence keywords → technical accuracy score 3
_ACCURACY_HIGH = {
    "page_execute_readwrite", "rwx", "malfind", "mz", "shellcode",
    "pe header", "inject", "injection", "process hollowing",
    "vad", "vadinfo", "psscan", "hidden process",
}

# Partial evidence keywords → technical accuracy score 2
_ACCURACY_MED = {
    "parent", "ppid", "child", "spawn", "lineage",
    "process name", "random", "hex", "alphanumeric",
    "known ransomware", "malware", "suspicious name",
}

# Specificity: concrete artifact reference
_SPECIFICITY_HIGH = {
    "pid", "ppid", "vadinfo", "malfind", "psscan", "pslist",
    "page_execute", "mz", "shellcode", "0x",
}

# Actionability: concrete next-step phrases or keyword pairs.
# Checked both as whole substrings and via (_ACTION_VERBS + _ACTION_TARGETS) combo below.
_ACTIONABILITY_HIGH = {
    "examine vad", "check vad", "inspect vad",
    "vad dump", "vad region",
    "check parent", "examine parent",
    "run malfind", "run psscan",
    "memory dump", "further memory",
    "disassemble", "analyze binary", "extract",
    "check cmdline", "check network",
}

# If any action verb appears with any forensic target → concrete suggestion.
_ACTION_VERBS = {"examine", "check", "inspect", "run", "analyse", "analyze", "dump", "extract"}
_ACTION_TARGETS = {"vad", "malfind", "psscan", "cmdline", "parent", "network", "binary", "memory"}

_ACTIONABILITY_MED = {
    "further analysis", "investigate", "manual review",
    "should be examined", "requires analysis", "warrants attention",
}

# Generic/low-quality phrases (penalise accuracy score)
_GENERIC_ONLY = {
    "looks suspicious", "appears suspicious", "seems suspicious",
    "not a system process", "unusual", "unknown process",
    "not enough information", "uncertain", "cannot determine",
}


def _lower(text: str) -> str:
    return text.lower()


def _contains_any(text: str, keywords: set) -> bool:
    t = _lower(text)
    return any(k in t for k in keywords)


def _score_technical_accuracy(reason: str) -> int:
    if not reason.strip():
        return 0
    if _contains_any(reason, _ACCURACY_HIGH):
        return 3
    if _contains_any(reason, _ACCURACY_MED):
        return 2
    # Pure generic claim with no real evidence
    if _contains_any(reason, _GENERIC_ONLY):
        return 0
    return 1  # Something present but not clearly categorised


def _score_specificity(reason: str) -> int:
    if not reason.strip():
        return 0
    # Both a specific feature AND an artifact reference → 2
    has_artifact = _contains_any(reason, _SPECIFICITY_HIGH)
    has_feature = _contains_any(reason, _ACCURACY_MED | _ACCURACY_HIGH)
    if has_artifact and has_feature:
        return 2
    if has_feature or has_artifact:
        return 1
    return 0


def _score_actionability(reason: str) -> int:
    if not reason.strip():
        return 0
    t = _lower(reason)
    # Direct phrase match
    if _contains_any(reason, _ACTIONABILITY_HIGH):
        return 2
    # Verb + forensic-target combo (e.g. "examine the VAD", "run a malfind scan")
    has_verb = any(v in t for v in _ACTION_VERBS)
    has_target = any(tgt in t for tgt in _ACTION_TARGETS)
    if has_verb and has_target:
        return 2
    if _contains_any(reason, _ACTIONABILITY_MED):
        return 1
    return 0


def score_explanation(reason: str) -> Dict[str, Any]:
    """
    Score a single LLM explanation string on the three rubric dimensions.

    Args:
        reason: the "reason" field from a suspicious_processes item.

    Returns:
        {
          "technical_accuracy": int (0–3),
          "specificity":        int (0–2),
          "actionability":      int (0–2),
          "total":              int (0–7),
          "quality_band":       str ("poor" | "fair" | "good" | "excellent"),
        }
    """
    acc = _score_technical_accuracy(reason)
    spe = _score_specificity(reason)
    act = _score_actionability(reason)
    total = acc + spe + act

    if total <= 2:
        band = "poor"
    elif total <= 4:
        band = "fair"
    elif total <= 6:
        band = "good"
    else:
        band = "excellent"

    return {
        "technical_accuracy": acc,
        "specificity": spe,
        "actionability": act,
        "total": total,
        "quality_band": band,
    }


def score_report_explanations(
    suspicious_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Score all explanation strings in a triage report's suspicious_processes list.

    Args:
        suspicious_items: list of dicts with at least a "reason" key
                          (from triage_report.json["suspicious_processes"]).

    Returns:
        {
          "item_scores":        [{pid, process_name, reason_preview, ...score fields}],
          "mean_total":         float,
          "mean_accuracy":      float,
          "mean_specificity":   float,
          "mean_actionability": float,
          "band_distribution":  {"poor": int, "fair": int, "good": int, "excellent": int},
        }
    """
    if not suspicious_items:
        return {
            "item_scores": [],
            "mean_total": 0.0,
            "mean_accuracy": 0.0,
            "mean_specificity": 0.0,
            "mean_actionability": 0.0,
            "band_distribution": {"poor": 0, "fair": 0, "good": 0, "excellent": 0},
        }

    item_scores = []
    band_dist: Dict[str, int] = {"poor": 0, "fair": 0, "good": 0, "excellent": 0}

    for item in suspicious_items:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason", ""))
        scores = score_explanation(reason)
        band_dist[scores["quality_band"]] = band_dist.get(scores["quality_band"], 0) + 1
        item_scores.append(
            {
                "pid": item.get("pid"),
                "process_name": item.get("process_name", ""),
                "reason_preview": reason[:120] + ("…" if len(reason) > 120 else ""),
                **scores,
            }
        )

    n = len(item_scores)
    return {
        "item_scores": item_scores,
        "mean_total": round(sum(s["total"] for s in item_scores) / n, 4),
        "mean_accuracy": round(sum(s["technical_accuracy"] for s in item_scores) / n, 4),
        "mean_specificity": round(sum(s["specificity"] for s in item_scores) / n, 4),
        "mean_actionability": round(sum(s["actionability"] for s in item_scores) / n, 4),
        "band_distribution": band_dist,
    }
