"""
Cross-reference windows.pslist and windows.psscan to detect hidden processes.

A PID present in psscan but absent from pslist indicates a potentially hidden or
unlinked process — a strong indicator of rootkit or ransomware process-hiding
techniques (paper Sec 2.1, Volatility 3 upgrade from paper's Vol 2.5.2).

Usage:
    from src.forensics.psscan_diff import detect_hidden_pids

    diff = detect_hidden_pids(
        artifacts.get("windows.pslist"),
        artifacts.get("windows.psscan"),
    )
    # diff["hidden_pids"] → sorted list of PIDs in psscan but not pslist
"""
import re
from typing import Any, Dict, List, Optional, Set


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        v = int(value.strip())
        return v if v > 0 else None
    return None


def _extract_rows(artifact: Any) -> List[Dict[str, Any]]:
    if isinstance(artifact, list):
        return [r for r in artifact if isinstance(r, dict)]
    if isinstance(artifact, dict):
        rows = artifact.get("rows")
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    return []


def _extract_pids(artifact: Any) -> Set[int]:
    """Return the set of PIDs found in a plugin artifact."""
    pids: Set[int] = set()
    for row in _extract_rows(artifact):
        for key, value in row.items():
            if _normalize_key(key) in ("pid", "processid", "uniqueprocessid"):
                pid = _to_int(value)
                if pid is not None:
                    pids.add(pid)
                    break
    return pids


def detect_hidden_pids(
    pslist_artifact: Any,
    psscan_artifact: Any,
) -> Dict[str, Any]:
    """
    Compare windows.pslist and windows.psscan outputs to find hidden processes.

    A PID that appears in psscan but not in pslist has been unlinked from the
    active process list — a classic rootkit / ransomware anti-forensics technique.

    Args:
        pslist_artifact: output of windows.pslist plugin (list or {rows: [...]})
        psscan_artifact: output of windows.psscan plugin (list or {rows: [...]})

    Returns:
        {
          "pslist_pid_count": int,
          "psscan_pid_count": int,
          "hidden_pid_count": int,
          "hidden_pids": [int, ...],       # sorted, in psscan but not pslist
          "hidden_rows": [{...}, ...],     # full psscan rows for hidden PIDs
          "terminated_pid_count": int,     # in pslist but not psscan (exited processes)
        }
    """
    if pslist_artifact is None and psscan_artifact is None:
        return {
            "pslist_pid_count": 0,
            "psscan_pid_count": 0,
            "hidden_pid_count": 0,
            "hidden_pids": [],
            "hidden_rows": [],
            "terminated_pid_count": 0,
        }

    pslist_pids = _extract_pids(pslist_artifact) if pslist_artifact is not None else set()
    psscan_pids = _extract_pids(psscan_artifact) if psscan_artifact is not None else set()

    hidden_pids = psscan_pids - pslist_pids

    # Collect full rows for hidden PIDs to surface in the prompt.
    hidden_rows: List[Dict[str, Any]] = []
    for row in _extract_rows(psscan_artifact):
        for key, value in row.items():
            if _normalize_key(key) in ("pid", "processid", "uniqueprocessid"):
                pid = _to_int(value)
                if pid in hidden_pids:
                    hidden_rows.append(row)
                break

    # PIDs in pslist but not psscan are processes that have exited since pslist ran;
    # this is usually benign but reported for completeness.
    terminated_pids = pslist_pids - psscan_pids

    return {
        "pslist_pid_count": len(pslist_pids),
        "psscan_pid_count": len(psscan_pids),
        "hidden_pid_count": len(hidden_pids),
        "hidden_pids": sorted(hidden_pids),
        "hidden_rows": hidden_rows,
        "terminated_pid_count": len(terminated_pids),
    }
