from typing import Any, Dict, List, Set

from src.forensics.post_filter import (
    DEFAULT_STRONG_REASON_KEYWORDS,
    DEFAULT_SYSTEM_ALLOWLIST,
)

# Use the same allowlist as post_filter — single source of truth.
# Bug fix: previously this was a separate smaller set (10 entries vs 20 in post_filter),
# causing inconsistent hallucination rates depending on which module was used.
SYSTEM_ALLOWLIST = DEFAULT_SYSTEM_ALLOWLIST

# Known Windows process names that get truncated to 14–15 visible chars by the
# EPROCESS ImageFileName field. When the LLM flags one of these truncated names
# as suspicious it is a "misspelled process" FP (paper Sec 5.1.2).
# Note: the paper states 14-char limit; Volatility 3 typically surfaces 15 visible
# characters (null-terminated CHAR[15] field), so we match on the first 15 chars.
TRUNCATION_BENIGN_PREFIXES: Set[str] = {
    "googlecrashhan",   # → googlecrashhandler.exe
    "trustedinstall",   # → trustedinstaller.exe
    "searchprotocol",   # → searchprotocolhost.exe
    "microsoftedgeup",  # → microsoftedgeupdate.exe
    "backgroundtran",   # → backgroundtransfer*.exe
}

# Benign but rare/unusual processes that are common "unknown process" FP sources
# identified in paper Sec 5.1.3 (defrag.exe, setup.exe, wmpnetwk.exe, etc.).
KNOWN_BENIGN_UNUSUAL: Set[str] = {
    "defrag.exe",
    "setup.exe",
    "wmpnetwk.exe",
    "msiexec.exe",
    "vssvc.exe",
    "vssadmin.exe",
    "msdtc.exe",
    "taskeng.exe",
    "werfault.exe",
    "wbemhost.exe",
    "wbemprvse.exe",
}

# Generic reason keywords: LLM had no concrete forensic evidence for the FP.
_GENERIC_REASON_TOKENS = {
    "unknown", "uncertain", "not enough", "insufficient", "generic",
    "possibly", "might be", "could be", "cannot determine",
    "unusual parent", "file output is disabled",
}


def _reason_text(item: Dict[str, Any]) -> str:
    return str(item.get("reason", "")).lower()


def _has_strong_signal(reason: str) -> bool:
    return any(k in reason for k in DEFAULT_STRONG_REASON_KEYWORDS)


def analyze_hallucination_taxonomy(
    suspicious_items: List[Dict[str, Any]],
    malicious_pids: Set[int],
    process_by_pid: Dict[int, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Classify false-positive predictions into hallucination categories.

    Categories:
      type_name        – FP on a known Windows system process (paper Sec 5.1.1).
      type_relationship – FP caused by incorrect parent-child reasoning.
      type_cascade     – FP caused by hallucinated cascade from an upstream FP.
      type_misspelled  – FP on a name truncated by EPROCESS 14/15-char limit (Sec 5.1.2).
      type_unknown     – FP on a rare benign process with no concrete indicator (Sec 5.1.3).
    """
    pred_pids: Set[int] = set()
    for x in suspicious_items:
        pid_val = x.get("pid") if isinstance(x, dict) else None
        if isinstance(pid_val, int):
            pred_pids.add(pid_val)
    fp_pids = pred_pids - malicious_pids

    type_name: List[int] = []
    type_relationship: List[int] = []
    type_cascade: List[int] = []
    type_misspelled: List[int] = []
    type_unknown: List[int] = []

    for item in suspicious_items:
        if not isinstance(item, dict):
            continue
        pid = item.get("pid")
        if not isinstance(pid, int) or pid not in fp_pids:
            continue

        proc = process_by_pid.get(pid, {})
        name = str(proc.get("name", item.get("process_name", ""))).lower()
        reason = _reason_text(item)
        strong = _has_strong_signal(reason)

        # --- type_name: FP on a recognised Windows system process ---
        if name in SYSTEM_ALLOWLIST:
            type_name.append(pid)

        # --- type_relationship: wrong parent-child reasoning ---
        if any(k in reason for k in ["parent", "child", "spawn", "lineage"]):
            ppid = proc.get("ppid")
            if isinstance(ppid, int) and ppid not in malicious_pids:
                type_relationship.append(pid)

        # --- type_cascade: FP child of another FP ---
        ppid = proc.get("ppid")
        if isinstance(ppid, int) and ppid in fp_pids:
            type_cascade.append(pid)

        # --- type_misspelled: EPROCESS truncation of a known-benign long name ---
        if name[:15] in TRUNCATION_BENIGN_PREFIXES or name in TRUNCATION_BENIGN_PREFIXES:
            type_misspelled.append(pid)

        # --- type_unknown: rare benign process or generic-only reasoning ---
        is_known_benign_unusual = name in KNOWN_BENIGN_UNUSUAL
        is_generic_only = (
            any(tok in reason for tok in _GENERIC_REASON_TOKENS) and not strong
        )
        if name not in SYSTEM_ALLOWLIST and (is_known_benign_unusual or is_generic_only):
            type_unknown.append(pid)

    denom = max(1, len(pred_pids))
    return {
        "fp_total": len(fp_pids),
        "type_name_count": len(set(type_name)),
        "type_relationship_count": len(set(type_relationship)),
        "type_cascade_count": len(set(type_cascade)),
        "type_misspelled_count": len(set(type_misspelled)),
        "type_unknown_count": len(set(type_unknown)),
        "hallucination_rate": round(len(fp_pids) / denom, 6),
    }
