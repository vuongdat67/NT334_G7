from src.evaluation.hallucination import (
    SYSTEM_ALLOWLIST,
    TRUNCATION_BENIGN_PREFIXES,
    KNOWN_BENIGN_UNUSUAL,
    analyze_hallucination_taxonomy,
)
from src.forensics.post_filter import DEFAULT_SYSTEM_ALLOWLIST


def test_system_allowlist_is_same_as_post_filter():
    """Bug fix: hallucination.py must use post_filter's allowlist as single source."""
    assert SYSTEM_ALLOWLIST is DEFAULT_SYSTEM_ALLOWLIST


def test_type_name_flags_system_process():
    items = [{"pid": 10, "process_name": "svchost.exe", "reason": "suspicious", "confidence": 0.6}]
    result = analyze_hallucination_taxonomy(
        items,
        malicious_pids=set(),
        process_by_pid={10: {"pid": 10, "ppid": 4, "name": "svchost.exe"}},
    )
    assert result["type_name_count"] >= 1
    assert result["fp_total"] == 1
    assert result["hallucination_rate"] == 1.0


def test_type_cascade_detected():
    # pid 20 is FP; pid 30 is child of 20 → cascade
    items = [
        {"pid": 20, "process_name": "malware.exe", "reason": "random name", "confidence": 0.9},
        {"pid": 30, "process_name": "cmd.exe", "reason": "spawned from parent", "confidence": 0.5},
    ]
    process_by_pid = {
        20: {"pid": 20, "ppid": 4, "name": "malware.exe"},
        30: {"pid": 30, "ppid": 20, "name": "cmd.exe"},
    }
    result = analyze_hallucination_taxonomy(items, malicious_pids=set(), process_by_pid=process_by_pid)
    assert result["type_cascade_count"] >= 1


def test_type_misspelled_detected():
    # "trustedinstall" is a known EPROCESS-truncated name
    items = [{"pid": 50, "process_name": "trustedinstall", "reason": "unusual name", "confidence": 0.7}]
    process_by_pid = {50: {"pid": 50, "ppid": 4, "name": "trustedinstall"}}
    result = analyze_hallucination_taxonomy(items, malicious_pids=set(), process_by_pid=process_by_pid)
    assert result["type_misspelled_count"] >= 1


def test_type_unknown_detected_for_known_benign_unusual():
    items = [{"pid": 60, "process_name": "defrag.exe", "reason": "possibly suspicious", "confidence": 0.4}]
    process_by_pid = {60: {"pid": 60, "ppid": 4, "name": "defrag.exe"}}
    result = analyze_hallucination_taxonomy(items, malicious_pids=set(), process_by_pid=process_by_pid)
    assert result["type_unknown_count"] >= 1


def test_true_positive_not_counted_as_fp():
    items = [{"pid": 100, "process_name": "ransomware.exe", "reason": "random name", "confidence": 0.95}]
    process_by_pid = {100: {"pid": 100, "ppid": 4, "name": "ransomware.exe"}}
    result = analyze_hallucination_taxonomy(
        items, malicious_pids={100}, process_by_pid=process_by_pid
    )
    assert result["fp_total"] == 0
    assert result["hallucination_rate"] == 0.0


def test_empty_returns_zero():
    result = analyze_hallucination_taxonomy([], malicious_pids=set(), process_by_pid={})
    assert result["fp_total"] == 0
    assert result["hallucination_rate"] == 0.0
