import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set


def _normalize_name(name: str) -> str:
    return str(name or "").strip().lower()


def _trim_windows_image_name(name: str) -> str:
    n = _normalize_name(name)
    # The Windows EPROCESS ImageFileName field is CHAR[15] (null-terminated),
    # giving 14 visible characters per the paper (Sec 5.1.2). Volatility 3
    # surfaces the full 15-byte field without the null, so we trim to 15 here
    # to match Volatility 3 output faithfully. If a future parser exposes only
    # 14 chars, change this constant to 14.
    return n[:15]


def _find_value(row: Dict[str, Any], candidates: Iterable[str]) -> Any:
    if not isinstance(row, dict):
        return None

    normalized_candidates = {re.sub(r"[^a-z0-9]", "", c.lower()) for c in candidates}
    for key, value in row.items():
        nk = re.sub(r"[^a-z0-9]", "", str(key).lower())
        if nk in normalized_candidates:
            return value
    return None


def _to_int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def extract_pslist_rows(pslist_output: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(pslist_output, list):
        return [x for x in pslist_output if isinstance(x, dict)]

    if isinstance(pslist_output, dict):
        rows = pslist_output.get("rows")
        if isinstance(rows, list):
            return [x for x in rows if isinstance(x, dict)]

    return []


def build_label_from_intersection(
    pslist_output: Dict[str, Any],
    candidate_process_names: Iterable[str],
    family: str,
    snapshot: str,
) -> Dict[str, Any]:
    rows = extract_pslist_rows(pslist_output)

    name_candidates: Set[str] = set()
    for name in candidate_process_names:
        n = _normalize_name(name)
        if not n:
            continue
        name_candidates.add(n)
        name_candidates.add(_trim_windows_image_name(n))

    all_pids: List[int] = []
    malicious_pids: List[int] = []
    process_table: List[Dict[str, Any]] = []

    for row in rows:
        pid = _to_int(_find_value(row, ["pid", "processid"]))
        ppid = _to_int(_find_value(row, ["ppid", "parentpid", "inheritedfromuniqueprocessid"]))
        name = _find_value(row, ["imagefilename", "processname", "name", "imagename"])
        process_name = _normalize_name(name)
        process_trim = _trim_windows_image_name(process_name)

        if pid is None:
            continue
        all_pids.append(pid)

        is_malicious = process_name in name_candidates or process_trim in name_candidates
        if is_malicious:
            malicious_pids.append(pid)

        process_table.append(
            {
                "pid": pid,
                "ppid": ppid,
                "name": process_name,
                "name_trimmed": process_trim,
                "is_malicious_by_intersection": is_malicious,
            }
        )

    return {
        "snapshot": snapshot,
        "family": family,
        "label_method": "intersection(runtime_candidate_names, pslist_names)",
        "candidate_process_names": sorted(name_candidates),
        "all_pids": sorted(set(all_pids)),
        "malicious_pids": sorted(set(malicious_pids)),
        "processes": process_table,
    }


def write_label_file(label: Dict[str, Any], out_path: str) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(label, ensure_ascii=True, indent=2), encoding="utf-8")